# Tools

## Recon

### Scanning
#### nmap
```
# -sV for version detection
# -sC for "--script default"
$ nmap -sV -sC $IP
```

#### Nikto

### Enumeration
#### ffuf
Add ```-o filename.txt``` to output to a file, and stdout.
##### Subdomain enumeration
```
# Use -fs to filter on response size
# -fc to filter on response code
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -H "Host: FUZZ.domain.thm" -fs FILTER -u http://domain.thm
```

##### File extension:
```
$ ffuf -w wordlist.txt -u http://server.thm/FUZZ -e .jpg,.png
```

#### gobuster
Basic enumeration:
```
$ gobuster -z --no-error dir -u http://$IP/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```


#### wpscan

#### find
```
# Find files with the suid bit set:
$ find / -perm -type f /u=s,g=s -exec ls -lh {} \; 2>/dev/null

# Alternatively:
$ find / -type f -perm -04000 -ls 2>/dev/null

# Find files owned by a group
$ find / -group groupname -type -f -exec ls -lh {} \; 2>/dev/null

# Find files owned by a user
$ find / -user username -type f -exec ls -lh {} \; 2>/dev/null
```

## Transfer files from attack box to target
### http
```
$ python3 -m http.server
```

### FTP
```
$ python3 -m pyftpdlib
```

## Priv Esc
## setcap
If setcap has suid bit:
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#privesc-container-escape
