---
author: northmatrix
categories:
  - tryhackme
math: false
media_subpath: /assets/img/rooms/rabbit-store
comments: true
image:
  path: /logo.png
  alt: A top hat 
title: Rabbit Store
tags: 
date created: 2025‑07‑13 17:43:18 +01:00
date modified: 2025‑07‑16 18:22:15 +01:00
---

## Overview

Rabbit Store is a Medium ranked TryHackMe room focusing on privilege escalation and exploiting web vulnerabilities such as SSRF.

![](Pasted%20image%2020250714002541.png)

## Initial Enumeration

First step was to run an nmap scan.

```bash
root@ip-10-10-158-19:~/Room# nmap -sT -T5 -p10.10.57.245
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-13 18:15 BST
Nmap scan report for ip-10-10-57-245.eu-west-1.compute.internal (10.10.57.245)
Host is up (0.00049s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
4369/tcp  open  epmd
25672/tcp open  unknown
MAC Address: 02:B8:99:FD:8B:E9 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 9.27 seconds
```

Here we can see that a webserver is running on port 80 when visiting this in a browser we are redirected to cloudsite.thm which at the moment resolves to nothing. So we need to add it  
to our `/etc/hosts`. Note i also added storage.cloudsite.thm which appeard later while enumerating the websites webpages.

```bash
127.0.0.1       localhost
127.0.0.1       vnc.tryhackme.tech
127.0.1.1       tryhackme.lan   tryhackme
10.10.57.245    cloudsite.thm storage.cloudsite.thm

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

After adding this and then revisiting the specified hostname i was then greeted with a webpage a for a "Cloud Hosting Platform".

![](Pasted%20image%2020250713193127.png)

## Exploitation

Visiting the Resigtration/Login page i was able to create an account with email: `username@username.com` and password: `password`.

![](Pasted%20image%2020250713193557.png)

After creating my account and logging in was greeted with a messaege incdicating that i dont have access to this service. In addition to this i noticed i now had a JWT stored in my cookies.  

![](Pasted%20image%2020250713194028.png)

Inspecting this JWT in <https://jwt.io> showed that there was a key-value pair "subscription" set to "inactive".

![](Pasted%20image%2020250713194153.png)

I tried a few things at this point such as changing this value to "active" and then sending another request to the `/dashboard/active` to see if proper signature checks were in place … they where. At these point i began inspecting the signup request closer in burpsuite to see if there was somehow to change the subscription status.  

![](Pasted%20image%2020250713194439.png)

Here i tried adding the key-value pair "subscription" and setting it to "active" to see if i was able to exploit a Mass assignment vulnerability. Luckily this worked as i was nearly out of ideas.

![](Pasted%20image%2020250713194717.png)

Upon login i was now instead greeted with a file upload form.

![](Pasted%20image%2020250713194918.png)

At this point i tried uploading a reverse shell but noticed that the file extension was removed i later scrolled down and saw that they told me this. So at this point i decided to instead focus on the upload from URL form hoping to be able to exploit some kind of Local File Inclusion or SSRF vulnerability.

![](Pasted%20image%2020250713200548.png)

After experimenting a bit with some URLS i found that if entering <http://localhost:80> i was able to request the a webpage from the webserver running on localhost port 80 this was the same as the public-facing site but we have now confirmed the existence of a SSRF vulnerability. Now all we need to do is find a way to exploit this.

![](Pasted%20image%2020250713200628.png)

My first idea here was to maybe view a page that i am not yet able to on the webserver but i had not yet found any so at this point i went back to directory scanning the website to see if there were any restricted areas. I first began enumerating the `http://storage.cloudsite.thm/api/` endpoint so what other endpoints there where.

```bash
root@ip-10-10-158-19:~/Room# gobuster dir -u storage.cloudsite.thm/api -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt  -e
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://storage.cloudsite.thm/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://storage.cloudsite.thm/api/Login                (Status: 405) [Size: 36]
http://storage.cloudsite.thm/api/docs                 (Status: 403) [Size: 27]
http://storage.cloudsite.thm/api/login                (Status: 405) [Size: 36]
http://storage.cloudsite.thm/api/register             (Status: 405) [Size: 36]
http://storage.cloudsite.thm/api/uploads              (Status: 401) [Size: 32]
Progress: 20473 / 20474 (100.00%)
===============================================================
Finished
===============================================================

```

Looking at this i saw that i already used the login, register and uploads endpoints but had not yet encountered the docs endpoint upon visiting this i was greeted with the below json response.

```json
{"message":"Access denied"}
```

Initially i tried passing the url <http://localhost:80/api/docs> but soon realised the api was not located here after looking back at previous requests made when signing up i noticed the X-Powered-By: Express header indicating that the api was creating using express js looking online i found that common pactice when using express js is to have it listen on port 3000 so i tried the same request this time on port 3000.

![](Pasted%20image%2020250713204041.png)

This was a success and upon visiting the path of the uploaded file i was served the documentation of the api.

```
Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format.
```

Looking at this documentation the only endpoint i have not yet visited is the /fetch_messeges_from_chatbot additionally the developer note on this does indicate that it likely still has a few bugs as a matter of it still being under development. Sending a post request to this endpoint from my attacking machine returned an error: username parameter is required. upon adding the username to the json and resending the post request i got the following response.

![](Pasted%20image%2020250713210010.png)

Here we can see that a html page is returned with a message in `<h1>` tags telling us the chatbot is under developmnet. To test for Server-Side Template Injection (SSTI) I passed `{% raw %}{{4*4}}{% endraw %}` in the input this returned 16 which confirms that this templating engine is vulnerable.

![](Pasted%20image%2020250713210412.png)

Using the below username we are able to get Remote Code Execution now all we need to do is upload a small reverse shell command.

![](Pasted%20image%2020250713212120.png)

I started running a netcat listener on port 1234 and i then sent the following request

![](Pasted%20image%2020250713212350.png)

My listener then caught the reverse shell and i now a reverse shell connection to the server from here i stabalised my shell with usual commands. and eventually got the following setup.

![](Pasted%20image%2020250713212510.png)

Upon visiting the home directory of the user i found the first flag.

![](Pasted%20image%2020250713212611.png)

## Privilege Escalation

The next step was to try and evelvate my privileges so i am able to read the root flag. First i ran `cat /etc/passwd` to see if there where any interesting user services,

```bash
azrael@forge:/var/lib/rabbitmq$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
...
...
colord:x:121:127:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
gdm:x:123:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```

Here i noticed the rabbitmq (not on most ctf machines so likely part of the privilege escalation process) user which is a user created by rabbitmq (a free and opensource software that supports AMQP 1.0 and MQTT 5.0 protocols and is used for decouping services) visiting the directoires where rabbitmq stores its data i saw the following.

![](Pasted%20image%2020250713220007.png)

As you can see in the above the `.erlang.cookie` is world readable using this cookie we are able to authenticate with the rabbitmq node. In order to connect with the node we need to add the hostname of the target to our `/etc/hosts` this will allow us to connect to the node below we are connceting to the node and listing the users here we see 2 one that is a hint and one that is root.

```bash
root@ip-10-10-158-19:/tmp# sudo sudo rabbitmqctl --erlang-cookie "JQkMAknSiSahN5zb" --node rabbit@forge list_users
Listing users …
user	tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.	[]
root	[administrator]
```

This below command exports the entire rabbitmq configuration including hashed passwords.

```bash
root@ip-10-10-158-19:/tmp# sudo sudo rabbitmqctl --erlang-cookie "JQkMAknSiSahN5zb" --node rabbit@forge export_definitions /tmp/definitions
Exporting definitions in JSON to a file at "/tmp/definitions" …
```

This is the previous commands output.

```bash
root@ip-10-10-158-19:/tmp# cat definitions 
{"bindings":[],"exchanges":[],"global_parameters":[{"name":"cluster_name","value":"rabbit@forge"}],"parameters":[],"permissions":[{"configure":".*","read":".*","user":"root","vhost":"/","write":".*"}],"policies":[],"queues":[{"arguments":{},"auto_delete":false,"durable":true,"name":"tasks","type":"classic","vhost":"/"}],"rabbit_version":"3.9.13","rabbitmq_version":"3.9.13","topic_permissions":[{"exchange":"","read":".*","user":"root","vhost":"/","write":".*"}],"users":[{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.","password_hash":"vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K","tags":[]},{"hashing_algorithm":"rabbit_password_hashing_sha256","limits":{},"name":"root","password_hash":"49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF","tags":["administrator"]}],"vhosts":[{"limits":[],"metadata":{"description":"Default virtual host","tags":[]},"name":"/"}]}
```

According to rabbitmq docs the the rabbitmq_password stored here is in the following format. where password is the same password used for the root account. where a salt is 4 bytes.

```
rabbitmq_password = base64(salt + sha256(salt + password))
```

We can then get the root password by converting from base64 then to hex and removing the first 4 bytes.

![](Pasted%20image%2020250714001744.png)

The remaining `e3d7ba85295***************************************14811ed194f98073585` is the root password. After loggin in there is a root flag located in `/root/root.txt`.
