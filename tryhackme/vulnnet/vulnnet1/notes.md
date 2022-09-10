# https://tryhackme.com/room/vulnnet1
## Recon
### nmap
```
$ nmap -sS vulnnet.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-10 15:14 UTC
Nmap scan report for vulnnet.thm (10.10.143.64)
Host is up (0.064s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```
$ nmap -sV -script default -p 22,80 vulnnet.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-10 15:15 UTC
Nmap scan report for vulnnet.thm (10.10.143.64)
Host is up (0.064s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ea:c9:e8:67:76:0a:3f:97:09:a7:d7:a6:63:ad:c1:2c (RSA)
|   256 0f:c8:f6:d3:8e:4c:ea:67:47:68:84:dc:1c:2b:2e:34 (ECDSA)
|_  256 05:53:99:fc:98:10:b5:c3:68:00:6c:29:41:da:a5:c9 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: VulnNet
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Enumeration
#### Directory
```
$ ffuf -u http://vulnnet.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -s
img
css
js
fonts
server-status
```

Two files in js:
```
[ ]	index__7ed54732.js	2021-01-23 20:08 	3.8K
[ ]	index__d8338055.js	2021-01-23 20:08 	2.0K
```
In index__d833055.js there is a URL: (had to look in a writeup for this)
```
http://vulnnet.thm/index.php?referer=
```

```
ffuf -u http://broadcast.vulnnet.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
misc                    [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 83ms]
22                      [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 83ms]
page                    [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 83ms]
17                      [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 83ms]
16                      [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 84ms]
features                [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 84ms]
23                      [Status: 401, Size: 468, Words: 42, Lines: 15, Duration: 83ms]
```

All results in 401 (forbidden), which means the directory enumeration
isn't possible without authentication.

#### Subdomain
Found 5829 by running without -fs and see what size every result reported.
```
$ ffuf -u http://vulnnet.thm -H "Host: FUZZ.vulnnet.thm" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fs 5829
broadcast
Broadcast
```

Navigating to http://broadcast.vulnnet.thm results in a http-login prompt (basic authentication).

#### Filenames
```
$ ffuf -u http://vulnnet.thm/FUZZ -e .php,.txt,.html -w /usr/share/seclists/Discovery/Web-Content/big.txt
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 64ms]
.htaccess.php           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 62ms]
.htaccess.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 65ms]
.htaccess.html          [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 63ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 62ms]
.htpasswd.php           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 63ms]
.htpasswd.html          [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 63ms]
.htpasswd.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 63ms]
LICENSE.txt             [Status: 200, Size: 1109, Words: 208, Lines: 26, Duration: 84ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 91ms]
fonts                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 101ms]
img                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 65ms]
index.php               [Status: 200, Size: 5829, Words: 1689, Lines: 142, Duration: 63ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 63ms]
login.html              [Status: 200, Size: 2479, Words: 633, Lines: 70, Duration: 62ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 66ms]
```
LICENSE.TXT stands out
##### LICENSE.TXT
```
/* zlib.h -- interface of the 'zlib' general purpose compression library
  version 1.2.11, January 15th, 2017

  Copyright (C) 1995-2017 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu

*/
```

Tried to Google to find out if any project matched 



#### Website
The "Get Started" button leads to /login which "Isn't found on this server".
The "Sign in" in the upper right corner directs to /login.html which contains a
login form. The "Sign up" and "Forgot password" part doesn't seem to do anything.

Clicking on the login button with an empty user:pass as asdf:reqw redirects to this URL:
```
http://vulnnet.thm/login.html?login=asdf&password=reqw#
```

# Exploitation

## hydra:
Tried to crack the passwords using hydra. For broadcast.vulnnet.thm, vulnnet.thm/login.html.
But unsuccessfully.
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f vulnnet.thm http-get-form "/login.html:login=^USER^&password=^PASS^:F=invalid"
```


## Cracking
### hydra
Try to crack the broadcast.vulnnet.thm using hydra.
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f broadcast.vulnnet.thm http-get /
```


# Questions
1. What is the user flag?

2. What is the root flag?
