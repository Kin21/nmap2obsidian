# nmap2obsidian

- Simple script to create folder structure and markdown files based on hardcoded template.
- Intended to use in Obsidian for notes managements during penetration testing and utilizing its visualization features.
- Folders are build based on the nmap scripts results provided in form of xml file
- Additional folders for new hosts or new discovered services can be added to same vault 
- [python-libnmap](https://github.com/savon-noir/python-libnmap/tree/master) is used for Nmap scans parse

# Host updates

- If we have different scans for same host:
```commandline
nmap scanme.nmap.org -p 22 -oX s1.xml -sC -sV
nmap scanme.nmap.org -p 80 -oX s2.xml -sC -sV
nmap scanme.nmap.org -p 9929 -oX s3.xml -sC -sV
```
- It is possible to add new discovered services into the vault
> [!WARNING]
> This is experemental feature that can result in notes corruption, backup before usage ...

If host IP that is already added to notes will be found in new scan results,
its folder will be updated with new discovered services 
```bash
# This will trigger host update if same IP in s1.xml and s2.xml
python .\nmap2obsidian.py -f .\s1.xml --vault_name test
python .\nmap2obsidian.py -f .\s2.xml --vault_name test

# Or specify all files
 python .\nmap2obsidian.py -f .\s2.xml .\s1.xml .\s3.xml --vault_name test
```

# Help section
```
usage: nmap2obsidian [-h] [-f files [files ...]] [--vault_name VAULT_NAME] [--delete_vault] [--init_vault] [--raw_import RAW_IMPORT] [--raw_h {1,2,3,4,5}]
                     [--header HEADER]

This program allows you to create folder structure for notes that are written in Markdown by using nmap scan results as input.

options:
  -h, --help            show this help message and exit
  -f files [files ...]  Nmap scan result saved as xml files to parse
  --vault_name VAULT_NAME
                        Name of the root folder for notes
  --delete_vault        Delete vault folder
  --init_vault          Init vault
  --raw_import RAW_IMPORT
                        Import raw txt files that represents logs\raw commands output and append to Raw.md
  --raw_h {1,2,3,4,5}   Number of # to use for header
  --header HEADER       Headers that will be used for inserted text or filename if not provided
  ```

# Examples 
```bash
# Create new Obsidian vault
python .\nmap2obsidian.py --init_vault  --vault_name test
# Import Nmap scan results
python .\nmap2obsidian.py -f .\scan1.xml .\scan2.xml --vault_name test
```
Network visualization in Obsidian:
![Network visualization with obsidian](screenshots/graph_view_example.png)

Tree of created vault:
```poweshell
C:.
|   Notes.md
|   Raw.md
|   Report.md
|
|
+---172.16.5.130
|   |   172.16.5.130.md
|   |   Raw.md
|   |
|   +---Open ports
|   |       135-msrpc tcp.md
|   |       139-netbios-ssn tcp.md
|   |       1433-ms-sql-s tcp.md
|   |       16001-mc-nmf tcp.md
|   |       3389-ms-wbt-server tcp.md
|   |       445-microsoft-ds tcp.md
|   |       80-http tcp.md
|   |       808-ccproxy-http tcp.md
|   |
|   +---Raw files
|   \---Screenshots
+---172.16.5.225
|   |   172.16.5.225.md
|   |   Raw.md
|   |
|   +---Open ports
|   |       22-ssh tcp.md
|   |       3389-ms-wbt-server tcp.md
|   |
|   +---Raw files
|   \---Screenshots
+---172.16.5.5
|   |   172.16.5.5.md
|   |   Raw.md
|   |
|   +---Open ports
|   |       135-msrpc tcp.md
|   |       139-netbios-ssn tcp.md
|   |       3268-ldap tcp.md
|   |       3269-ldap tcp.md
|   |       3389-ms-wbt-server tcp.md
|   |       389-ldap tcp.md
|   |       445-microsoft-ds tcp.md
|   |       464-kpasswd5 tcp.md
|   |       53-domain tcp.md
|   |       593-ncacn_http tcp.md
|   |       636-ldap tcp.md
|   |       88-kerberos-sec tcp.md
|   |
|   +---Raw files
|   \---Screenshots
+---config
|       config.json
|
\---Raw files
    \---Nmap Scan Results
```