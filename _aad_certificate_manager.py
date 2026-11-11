#!/usr/bin/env python3
"""One-time BYOA bootstrap + self key rollover for Samba4 Entra sync.

This is an experimental helper for an unsupported SOAP-based sync client.
It NEVER sends or changes directory users/groups/passwords.

bootstrap: interactively authorize Entra application creation via delegated admin login.
status:    local certificate health check.
verify:    obtain a non-interactive app token with current certificate.
rotate:    self-roll app key using MS Graph /applications/{id}/addKey.
cleanup:   optionally remove retired app keys after a grace period.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
import logging
import secrets
import sys
from pathlib import Path
import tempfile
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import jwt
import requests

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
SYNC_APP_ID = "6bf85cfa-ac8a-4be5-b5de-425a0d0dc016"
SYNC_SCOPE = SYNC_APP_ID + "/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
# Microsoft Graph PowerShell's public client (delegated admin device login).
ADMIN_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
ADMIN_SCOPES = ["Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.Read.All"]


def missing_application_roles(scope: str, token: str) -> set[str]:
    expected = {
        SYNC_SCOPE: {"ADSynchronization.ReadWrite.All"},
        GRAPH_SCOPE: {"User.Read.All", "Group.Read.All"},
    }.get(scope, set())
    claims = jwt.decode(token, options={"verify_signature": False})
    return expected - set(claims.get("roles") or [])


def acquire_application_token(app, scope: str) -> str:
    """Wait until Microsoft Entra issues a token containing the required app roles."""
    import msal
    while True:
        result = app.acquire_token_for_client(scopes=[scope])
        if "access_token" not in result:
            raise RuntimeError(f"Token request for {scope} was rejected: {result.get('error')} - {result.get('error_description')}")
        token = result["access_token"]
        missing = missing_application_roles(scope, token)
        if not missing:
            return token
        # MSAL may cache a token without roles. Evict it before the next request.
        cache = app.token_cache
        for entry in list(cache.search(msal.TokenCache.CredentialType.ACCESS_TOKEN)):
            if entry.get("secret") == token:
                cache.remove_at(entry)
        print(
            f"[TOKEN] Missing permissions in latest {scope} access token: {', '.join(sorted(missing))}. "
            "Microsoft Entra permission propagation may still be in progress. "
            "Waiting 1 minute (60 seconds) before requesting a new token...",
            flush=True,
        )
        time.sleep(60)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def now():
    return datetime.now(timezone.utc)


def password(base: Path, create: bool = False):
    """Reuse a user-supplied secret, or auto-create a local 0600 secret.

    Automatic local storage intentionally trades off hardware-backed secrecy
    for fully unattended sync. Back up BOTH the PFX and this file securely.
    """
    value = os.environ.get("ENTRA_SYNC_PFX_PASSWORD")
    if value:
        if len(value) < 16:
            raise RuntimeError("ENTRA_SYNC_PFX_PASSWORD must contain at least 16 characters")
        return value.encode("utf-8")

    path = base / ".pfx-passphrase"
    if path.exists():
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise RuntimeError("The PFX passphrase file must be private (chmod 600)")
        return path.read_bytes().strip()
    if not create:
        raise RuntimeError("Missing PFX passphrase: restore the .pfx-passphrase file or the ENTRA_SYNC_PFX_PASSWORD secret. DO NOT create a new application")
    # Base directory is already created private under a lock during bootstrap.
    data = secrets.token_urlsafe(36).encode("ascii")
    save_secure(path, data + b"\n")
    return data


def atomic_json(path: Path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.chmod(name, 0o600)
            json.dump(obj, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_secure(path: Path, content: bytes):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def read_state(base: Path):
    path = base / "state.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(base: Path, value):
    atomic_json(base / "state.json", value)


@contextmanager
def lock(base: Path):
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    if base.stat().st_mode & 0o077:
        raise RuntimeError("The certificate directory must be private (chmod 700).")
    with (base / ".lock").open("a+") as stream:
        os.chmod(base / ".lock", 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another instance of the certificate manager is already running.") from exc
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def build_certificate(passphrase: bytes, days: int):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    start, end = now() - timedelta(minutes=5), now() + timedelta(days=days)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Samba4-Python-Entra-Sync")])
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256()))
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"samba4-entra-sync", key=key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase))
    return pfx, cert


def load_pfx(path: Path, passphrase: bytes):
    try:
        key, cert, _ = pkcs12.load_key_and_certificates(path.read_bytes(), passphrase)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Unable to open the PFX: check its passphrase or restore the backup. DO NOT recreate the application") from exc
    if key is None or cert is None:
        raise RuntimeError("The PFX does not contain a valid private key and certificate")
    return key, cert


def cert_thumb(cert):
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def cred(cert):
    return {
        "type": "AsymmetricX509Cert", "usage": "Verify",
        "displayName": "Samba4 Python Entra Sync",
        "key": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        "startDateTime": iso(cert.not_valid_before_utc),
        "endDateTime": iso(cert.not_valid_after_utc),
    }


def new_pfx_file(base: Path, passphrase: bytes, days: int):
    content, cert = build_certificate(passphrase, days)
    name = "cert-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8] + ".pfx"
    path = base / "certs" / name
    save_secure(path, content)
    return "certs/" + name, cert


def switch_current(base: Path, relpath: str):
    # Atomic symlink replacement: no moment where current.pfx points nowhere.
    tmp = base / (".current-" + uuid.uuid4().hex[:8])
    tmp.symlink_to(relpath)
    os.replace(tmp, base / "current.pfx")


def active_pfx(base: Path):
    path = base / "current.pfx"
    if not path.exists():
        raise RuntimeError("current.pfx not found: initialization is incomplete; run bootstrap again")
    return path


def auth_admin(tenant: str, client_id: str, *, proxies=None, verify=True):
    import msal
    app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}", proxies=proxies, verify=verify)
    flow = app.initiate_device_flow(scopes=ADMIN_SCOPES)
    if "user_code" not in flow:
        raise RuntimeError("Administrator sign-in failed: " + str(flow.get("error_description", "device flow")))
    print("Administrator authorization (one-time setup):")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError("Administrator authentication failed: " + str(result.get("error_description", result.get("error"))))
    return result["access_token"]


def app_token(tenant: str, client: str, pfx: Path, passphrase: bytes, scope: str, *, proxies=None, verify=True):
    import msal
    app = msal.ConfidentialClientApplication(
        client_id=client, authority=f"https://login.microsoftonline.com/{tenant}",
        client_credential={"private_key_pfx_path": str(pfx), "passphrase": passphrase.decode("utf-8")}, proxies=proxies, verify=verify)
    return acquire_application_token(app, scope)


class Graph:
    def __init__(self, token, proxies=None, verify=True):
        self.token = token
        self.proxies = proxies
        self.verify = verify

    def call(self, method, path, *, body=None, params=None):
        resp = requests.request(
            method, GRAPH + path, params=params,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"},
            json=body, timeout=30, proxies=self.proxies, verify=self.verify)
        if resp.status_code >= 400:
            try:
                error = resp.json().get("error", {})
                detail = f"{error.get('code')} - {error.get('message')}"
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"Microsoft Graph {method} {path}: HTTP {resp.status_code}: {detail[:400]}")
        return resp.json() if resp.content else {}

    def find_sp(self, app_id: str):
        query = {"$filter": f"appId eq '{app_id}'", "$select": "id,appId,displayName,appRoles"}
        values = self.call("GET", "/servicePrincipals", params=query).get("value", [])
        if len(values) > 1:
            raise RuntimeError(f"Multiple service principals found for {app_id}")
        return values[0] if values else None

    def find_application(self, display: str):
        safe = display.replace("'", "''")
        values = self.call("GET", "/applications", params={
            "$filter": f"displayName eq '{safe}'", "$select": "id,appId,displayName"}).get("value", [])
        if len(values) > 1:
            raise RuntimeError("Multiple applications have this name; manual review is required")
        return values[0] if values else None


def role_id(sp, role_name):
    for r in sp.get("appRoles", []):
        if r.get("value") == role_name and "Application" in r.get("allowedMemberTypes", []) and r.get("isEnabled", True):
            return r["id"]
    raise RuntimeError(f"Application permission {role_name} is missing from {sp.get('displayName')}")


def ensure_assignments(graph, sp_id, permissions):
    assignments = graph.call("GET", f"/servicePrincipals/{sp_id}/appRoleAssignments",
                             params={"$select": "appRoleId,resourceId"}).get("value", [])
    existing = {(r["resourceId"], r["appRoleId"]) for r in assignments}
    for resource_id, role in permissions:
        if (resource_id, role) not in existing:
            graph.call("POST", f"/servicePrincipals/{sp_id}/appRoleAssignments", body={
                "principalId": sp_id, "resourceId": resource_id, "appRoleId": role})
            print(f"Permission granted: {resource_id} / {role}")


def bootstrap(base: Path, tenant: str, name: str, admin_client_id: str, days: int, *, graph_read=True, proxies=None, verify=True):
    # User-login must never happen in the scheduler/sync process.
    with lock(base):
        state = read_state(base)
        if state and state.get("status") == "ready":
            if not (base / "current.pfx").exists():
                raise RuntimeError("Application already exists but the local PFX is missing: restore the backup or recover the certificate with an administrator. Do not recreate the application.")
            return
        if state and state["tenant_id"] != tenant:
            raise RuntimeError("This directory is already configured for another tenant")
        # Require admin explicitly; ephemeral device-code login is not cached.
        token = auth_admin(tenant, admin_client_id, proxies=proxies, verify=verify)
        graph = Graph(token, proxies=proxies, verify=verify)
        pwd = password(base, create=(state is None))
        if state is None:
            cert_path, cert = new_pfx_file(base, pwd, days)
            state = {
                "tenant_id": tenant,
                "display_name": name + " [" + uuid.uuid4().hex[:8] + "]",
                "bootstrap_cert": cert_path,
                "status": "pending",
                "created_at": iso(now()),
                "include_graph_reads": graph_read,
                "retired": [],
            }
            save_state(base, state)
        else:
            cert_path = state["bootstrap_cert"]
            _, cert = load_pfx(base / cert_path, pwd)
            graph_read = state.get("include_graph_reads", True)
        sync_sp = graph.find_sp(SYNC_APP_ID)
        graph_sp = graph.find_sp(GRAPH_APP_ID) if graph_read else None
        if sync_sp is None or (graph_read and graph_sp is None):
            raise RuntimeError("The Microsoft Sync/Graph service principal was not found in this tenant; manual verification is required")
        permissions = [(sync_sp["id"], role_id(sync_sp, "ADSynchronization.ReadWrite.All"))]
        resources = [{"resourceAppId": SYNC_APP_ID, "resourceAccess": [{"id": permissions[0][1], "type": "Role"}]}]
        if graph_read:
            read_roles = [role_id(graph_sp, x) for x in ("User.Read.All", "Group.Read.All")]
            permissions += [(graph_sp["id"], rid) for rid in read_roles]
            resources.append({"resourceAppId": GRAPH_APP_ID,
                              "resourceAccess": [{"id": rid, "type": "Role"} for rid in read_roles]})
        if not state.get("app_object_id"):
            existing = graph.find_application(state["display_name"])
            if existing is None:
                existing = graph.call("POST", "/applications", body={
                    "displayName": state["display_name"],
                    "signInAudience": "AzureADMyOrg",
                    "keyCredentials": [cred(cert)],
                    "requiredResourceAccess": resources,
                })
            state.update({"app_id": existing["appId"], "app_object_id": existing["id"]})
            save_state(base, state)
        # Reapply desired permissions idempotently after a partial bootstrap.
        graph.call("PATCH", f"/applications/{state['app_object_id']}", body={"requiredResourceAccess": resources})
        sp = graph.find_sp(state["app_id"])
        if sp is None:
            sp = graph.call("POST", "/servicePrincipals", body={"appId": state["app_id"]})
        state["service_principal_id"] = sp["id"]
        save_state(base, state)
        ensure_assignments(graph, sp["id"], permissions)
        # Token permission propagation can lag after appRoleAssignments.
        # Never set ready until Microsoft has issued tokens with this key.
        for scope in ([SYNC_SCOPE, GRAPH_SCOPE] if graph_read else [SYNC_SCOPE]):
            last_error = None
            for attempt in range(6):
                try:
                    app_token(tenant, state["app_id"], base / cert_path, pwd, scope, proxies=proxies, verify=verify)
                    last_error = None
                    break
                except RuntimeError as exc:
                    last_error = exc
                    if attempt < 5:
                        time.sleep(3)
            if last_error is not None:
                raise RuntimeError("Application created, but its token is not available yet; rerun AAD from an administrator terminal to continue") from last_error
        switch_current(base, cert_path)
        state.update({"status": "ready", "active_cert": cert_path, "active_key_id": None})
        # For cleanup after the first rotation, attempt keyId lookup with delegated admin.
        try:
            props = graph.call("GET", f"/applications/{state['app_object_id']}", params={"$select": "keyCredentials"})
            thumb = base64.b64encode(cert.fingerprint(hashes.SHA1())).decode()
            for item in props.get("keyCredentials", []):
                if item.get("customKeyIdentifier") == thumb:
                    state["active_key_id"] = item.get("keyId")
                    break
        except RuntimeError:
            pass  # Optional. Rotation does not depend on it.
        save_state(base, state)
        print("Initialization completed. Client ID:", state["app_id"])
        print("Active certificate:", str(base / "current.pfx"))
        print("Validate SOAP operations in a test tenant before any synchronization.")


def pop_token(app_object_id: str, old_pfx: Path, passphrase: bytes):
    key, cert = load_pfx(old_pfx, passphrase)
    issued = int(time.time())
    thumb = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).rstrip(b"=").decode()
    claims = {
        "aud": "00000002-0000-0000-c000-000000000000",
        "iss": app_object_id,
        "nbf": issued - 60,
        "exp": issued + 540,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"x5t": thumb})


def rotate(base: Path, threshold: int, days: int, force: bool, *, proxies=None, verify=True):
    with lock(base):
        state = read_state(base)
        if not state or state.get("status") != "ready":
            raise RuntimeError("Initialization is incomplete. Run bootstrap first.")
        pwd = password(base)
        current = active_pfx(base)
        _, active = load_pfx(current, pwd)
        remaining = (active.not_valid_after_utc - now()).total_seconds() / 86400
        if remaining <= 0:
            raise RuntimeError("The active certificate has expired: automatic rotation is not possible; administrator intervention is required")
        if not force and remaining > threshold and not state.get("pending_cert"):
            print(f"Certificate remains valid for {remaining:.1f} days. Rotation is not required (threshold: {threshold} days).")
            return
        pending = state.get("pending_cert")
        if not pending:
            pending, new_cert = new_pfx_file(base, pwd, days)
            state["pending_cert"] = pending
            save_state(base, state)
        else:
            _, new_cert = load_pfx(base / pending, pwd)
        # Recovery: if Graph accepted addKey before a crash, new PFX can already request tokens.
        works = False
        try:
            app_token(state["tenant_id"], state["app_id"], base / pending, pwd, SYNC_SCOPE, proxies=proxies, verify=verify)
            works = True
        except RuntimeError:
            pass
        new_key_id = state.get("pending_key_id")
        if not works:
            if not state.get("pending_key_id"):
                current_graph_token = app_token(state["tenant_id"], state["app_id"], current, pwd, GRAPH_SCOPE, proxies=proxies, verify=verify)
                graph = Graph(current_graph_token, proxies=proxies, verify=verify)
                # Only the application's own key, with signed proof of possession.
                result = graph.call("POST", f"/applications/{state['app_object_id']}/addKey", body={
                    "keyCredential": cred(new_cert),
                    "passwordCredential": None,
                    "proof": pop_token(state["app_object_id"], current, pwd),
                })
                new_key_id = result.get("keyId") or new_key_id
                state["pending_key_id"] = new_key_id
                save_state(base, state)
            # If a previous attempt already published a key, retry authentication
            # instead of adding another copy of the same key to Entra.
            last_error = None
            for _ in range(6):
                try:
                    app_token(state["tenant_id"], state["app_id"], base / pending, pwd, SYNC_SCOPE, proxies=proxies, verify=verify)
                    works = True
                    break
                except RuntimeError as exc:
                    last_error = exc
                    time.sleep(5)
            if not works:
                raise RuntimeError("New certificate published, but the synchronization token is still rejected; "
                                   "the previous certificate has been kept. Retry rotate later. " + str(last_error))
        # Only switch after Microsoft issued a real sync token for new cert.
        old_path = state.get("active_cert")
        old_key_id = state.get("active_key_id")
        switch_current(base, pending)
        if old_path and old_key_id:
            state.setdefault("retired", []).append({"cert": old_path, "key_id": old_key_id, "retired_at": iso(now())})
        state.update({"active_cert": pending, "active_key_id": new_key_id})
        state.pop("pending_cert", None)
        state.pop("pending_key_id", None)
        save_state(base, state)
        print("Rotation succeeded. New certificate:", pending)
        print("Previous certificate retained for rollback; remove retired keys separately using the cleanup command.")


def cleanup(base: Path, grace: int, *, proxies=None, verify=True):
    with lock(base):
        state = read_state(base)
        if not state or state.get("status") != "ready":
            raise RuntimeError("Initialization is incomplete")
        pwd = password(base)
        current = active_pfx(base)
        token = app_token(state["tenant_id"], state["app_id"], current, pwd, GRAPH_SCOPE, proxies=proxies, verify=verify)
        graph = Graph(token, proxies=proxies, verify=verify)
        keep = []
        for item in state.get("retired", []):
            retired_at = datetime.fromisoformat(item["retired_at"].replace("Z", "+00:00"))
            if now() - retired_at < timedelta(days=grace) or not item.get("key_id"):
                keep.append(item)
                continue
            graph.call("POST", f"/applications/{state['app_object_id']}/removeKey", body={
                "keyId": item["key_id"],
                "proof": pop_token(state["app_object_id"], current, pwd),
            })
            # Private key file deliberately retained for admin-controlled backup cleanup.
            print("Old key removed from Entra:", item["key_id"])
        state["retired"] = keep
        save_state(base, state)
        print("Entra key cleanup completed. Historical PFX files were not deleted.")


def status(base: Path):
    state = read_state(base)
    if not state:
        print("No installation found. Run bootstrap once.")
        return
    print("Tenant:", state["tenant_id"])
    print("Application:", state.get("app_id", "not yet created"))
    print("Status:", state.get("status"))
    if (base / "current.pfx").exists():
        _, cert = load_pfx(base / "current.pfx", password(base))
        left = (cert.not_valid_after_utc - now()).total_seconds() / 86400
        print(f"Active certificate: {cert_thumb(cert)} / expires on {iso(cert.not_valid_after_utc)} / {left:.1f} days remaining")
    if state.get("pending_cert"):
        print("Pending rotation:", state["pending_cert"])
    if state.get("retired"):
        print("Retired certificates awaiting cleanup:", len(state["retired"]))


def ensure_identity(base: Path, tenant_id: str, *, threshold: int = 30, days: int = 90, proxies=None, verify=True):
    """Called directly by AADInternals.__init__: bootstrap once, rotate when due.

    No network access during normal init when the cert is healthy. Fail closed
    when local identity material is missing; never generate a replacement app.
    """
    state = read_state(base)
    if state and state.get("tenant_id") != tenant_id:
        raise RuntimeError("The certificate directory belongs to another tenant; no action was taken")
    if state is None and (base / "certs").exists() and any((base / "certs").glob("*.pfx")):
        raise RuntimeError("state.json is missing, but local certificates exist: restore the state before initializing to avoid creating a duplicate application")
    if not state or state.get("status") != "ready":
        if not sys.stdin.isatty():
            raise RuntimeError("Initial Entra setup requires an interactive terminal (administrator device-code sign-in), not a background service")
        bootstrap(base, tenant_id, "Samba4-Python-Entra-Sync", ADMIN_CLIENT_ID, days, proxies=proxies, verify=verify)
        state = read_state(base)

    # A missing local PFX is not the same as a first install. Creating a new PFX
    # without re-registering its public key would make authentication fail.
    current = active_pfx(base)
    pwd = password(base)
    _, certificate = load_pfx(current, pwd)
    remaining = (certificate.not_valid_after_utc - now()).total_seconds() / 86400
    if remaining <= 0:
        raise RuntimeError("PFX certificate expired: administrator intervention is required")

    if remaining <= threshold or state.get("pending_cert"):
        try:
            rotate(base, threshold=threshold, days=days, force=False, proxies=proxies, verify=verify)
        except (RuntimeError, OSError, requests.RequestException) as exc:
            # Keep syncing with a still-valid existing certificate. Do not
            # advance local state or delete any key if the remote call failed.
            logging.getLogger(__name__).warning(
                "Entra certificate rotation failed (%.1f days remaining): %s", remaining, exc)
    # Old keys are removed after a grace period, only if Graph confirms it.
    state = read_state(base)
    retired = state.get("retired", [])
    if retired and any(r.get("key_id") and now() - datetime.fromisoformat(
            r["retired_at"].replace("Z", "+00:00")) >= timedelta(days=14) for r in retired):
        try:
            cleanup(base, grace=14, proxies=proxies, verify=verify)
        except (RuntimeError, OSError, requests.RequestException) as exc:
            logging.getLogger(__name__).warning("Cleanup of retired Entra keys postponed: %s", exc)

    return {
        "app_id": state["app_id"],
        "pfx_path": active_pfx(base),
        "passphrase": pwd.decode("utf-8"),
    }


def verify(base: Path):
    state = read_state(base)
    if not state or state.get("status") != "ready":
        raise RuntimeError("Initialization is incomplete")
    pwd = password(base)
    app_token(state["tenant_id"], state["app_id"], active_pfx(base), pwd, SYNC_SCOPE)
    print("OK: Microsoft issued a synchronization access token using the certificate.")
    if state.get("include_graph_reads"):
        app_token(state["tenant_id"], state["app_id"], active_pfx(base), pwd, GRAPH_SCOPE)
        print("OK: Microsoft issued a Microsoft Graph access token.")
    print("Warning: this test does not validate acceptance of SOAP operations.")


def main():
    parser = argparse.ArgumentParser(description="Manage application identities for the Samba4 Entra Sync project")
    parser.add_argument("command", choices=("plan", "bootstrap", "status", "verify", "rotate", "cleanup"))
    parser.add_argument("--state-dir", type=Path, default=Path("/root/entra_aba"))
    parser.add_argument("--tenant-id", help="Tenant GUID (required for bootstrap)")
    parser.add_argument("--name", default="Samba4-Python-Entra-Sync")
    parser.add_argument("--admin-client-id", default=ADMIN_CLIENT_ID, help="Public client for initial setup only")
    parser.add_argument("--days", type=int, default=90, help="New certificate validity, default 90 days")
    parser.add_argument("--threshold-days", type=int, default=30)
    parser.add_argument("--grace-days", type=int, default=14)
    parser.add_argument("--force", action="store_true", help="Force early rotation (test environment)")
    parser.add_argument("--no-graph-reads", action="store_true", help="Do not grant Graph read permissions")
    parser.add_argument("--apply", action="store_true", help="Confirm changes to remote resources")
    args = parser.parse_args()
    if args.days < 7 or args.days > 365:
        parser.error("--days must be between 7 and 365")
    if args.threshold_days < 1 or args.grace_days < 0:
        parser.error("Invalid threshold or grace period")
    if args.command == "plan":
        print("Initial setup: RSA 2048 certificate, Entra application, service principal, and permissions")
        print("After setup: OAuth access token without refresh token; rotation via Graph addKey/self PoP")
        print("No users, groups, or passwords are created or modified")
    elif args.command == "bootstrap":
        if not args.tenant_id:
            parser.error("--tenant-id is required for bootstrap")
        try:
            uuid.UUID(args.tenant_id)
        except ValueError:
            parser.error("--tenant-id must be a GUID")
        if not args.apply:
            parser.error("Add --apply to authorize application creation and permission assignment")
        bootstrap(args.state_dir, args.tenant_id, args.name, args.admin_client_id, args.days,
                  graph_read=not args.no_graph_reads)
    elif args.command == "status":
        status(args.state_dir)
    elif args.command == "verify":
        verify(args.state_dir)
    elif args.command == "rotate":
        if not args.apply:
            parser.error("Add --apply to authorize certificate rotation in Microsoft Entra")
        rotate(args.state_dir, args.threshold_days, args.days, args.force)
    elif args.command == "cleanup":
        if not args.apply:
            parser.error("Add --apply to authorize removal of retired keys in Microsoft Entra")
        cleanup(args.state_dir, args.grace_days)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, requests.RequestException) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
