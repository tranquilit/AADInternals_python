# AADInternals python

Reimplementation of part of the AAdinternals (https://github.com/Gerenios/AADInternals) project.

this project focuses on the synchronization of users, groups and password "azure ad"

Please note that this project uses Microsoft APIs not officially documented. Microsoft may break compatibility at any time


# Install Notes

```
git clone https://github.com/tranquilit/AADInternals_python
cd AADInternals_python
git submodule update --progress --init -- "python_wcfbin"
```

Install dependency 
-----------------------------

```
apt-get install python3-passlib python3-xmltodict python3-requests python3-msal -y
```


If you are not under debian or if you do not have the packages available :

```
pip3 install -r requirements.txt
```

# Use main 

Exemple:

```
python3 main.py -help
python3 main.py --domain mydomain.com set_azureadobject  -help
python3 main.py --domain mydomain.com set_azureadobject --SourceAnchor=test00 --userPrincipalName=test00@mydomain.com
python3 main.py --domain mydomain.com set_userpassword --sourceanchor=test00 --password password
python3 main.py --domain mydomain.com get_syncconfiguration
```



