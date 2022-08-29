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
##### Subdomain enumeration
```
# Use -fs to filter on response size
# -fc to filter on response code
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -H "Host: FUZZ.adana.thm" -fs FILTER -u http://adana.thm

# File extension:
$ ffuf -w wordlist.txt -u http://server.thm/FUZZ -e .jpg,.png
```

#### gobuster

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
