## Nmap

```Bash
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol                                                                                                                               2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.910

```



## HTTP

### 80端口

目录爆破，没有东西，忽略

```Bash
/images               (Status: 301) [Size: 313] [--> http://10.10.10.160/images/]
/index.html           (Status: 200) [Size: 3844]
/upload               (Status: 301) [Size: 313] [--> http://10.10.10.160/upload/]
/css                  (Status: 301) [Size: 310] [--> http://10.10.10.160/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.160/js/]
/fonts                (Status: 301) [Size: 312] [--> http://10.10.10.160/fonts/]
/server-status        (Status: 403) [Size: 300]

```



### 10000端口

https

![](https://secure2.wostatic.cn/static/2nNNLToQSXVM9wgYULEq6o/image.png?auth_key=1677500799-oMu29EPp9x6E1BTDfRAQ3N-0-ad1a2cb8ed9e987356867ced8ba3701e)

用户名不能猜，目录爆破异常

MiniServ 有确认的poc，只有msf版本

```Bash
└─# searchsploit -m linux/remote/46984.rb
  Exploit: Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/46984
     Path: /usr/share/exploitdb/exploits/linux/remote/46984.rb
    Codes: CVE-2019-12840

```

搜索下CVE-2019-12840 相关github的poc，都是需要用户名密码的，先找到用户名密码

差点又忘了使用域名，在访问http://10.10.10.160:10000时已经提示跳转到了postman：10000

先用gobuster爆破子域名，没有结果，直接对主域名目录爆破还是没有结果

猜SQL注入，用admin' 出现报错，

![](https://secure2.wostatic.cn/static/nDAM1mw53SzDkrtEoF9LSH/image.png?auth_key=1677500799-iCEccxTazfZFZowQ6WaVnP-0-ab38103c583991a6c627a81a3283209b)



POST也可能是指CVE-2019-15107

![](https://secure2.wostatic.cn/static/2x6CVz4G5qsSeQYwvqaV46/image.png?auth_key=1677500799-5W8a8bLoHwyxqHwx9LCAjb-0-1056249ee993999f1e77894c82055b2c)

POC不能执行



## Redis

```Bash
└─# searchsploit redis
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
Redis - Replication Code Execution (Metasploit)                                             | linux/remote/48272.rb
Redis 4.x / 5.x - Unauthenticated Code Execution (Metasploit)                               | linux/remote/47195.rb
Redis 5.0 - Denial of Service                                                               | linux/dos/44908.txt
Redis-cli < 5.0 - Buffer Overflow (PoC)                                                     | linux/local/44904.py

```

可以未授权访问

```Bash
┌──(root㉿walle)-[/home/machines/linux/postman]
└─# redis-cli -h 10.10.10.160
10.10.10.160:6379>
10.10.10.160:6379>
10.10.10.160:6379> save
OK
10.10.10.160:6379>

```

从hacktricks找到一个非常有用的poc

[n0b0dyCN/redis-rogue-server: Redis(<=5.0.5) RCE (github.com)](https://github.com/n0b0dyCN/redis-rogue-server)

对redis的post原理有详细介绍，猜测postman的靶场名称可能就是指这个漏洞

> extension://bocbaocobfecmglnmeaeppambideimao/pdf/viewer.html?file=https%3A%2F%[2F2018.zeronights.ru](http://2F2018.zeronights.ru)%2Fwp-content%2Fuploads%2Fmaterials%2F15-redis-post-exploitation.pdf



尝试这个poc没有成功，手动触发不能正常写入，大概率是权限被限制，或者redis根本就没有启动

![](https://secure2.wostatic.cn/static/dNbTTmoBfDJ2iWsJM7v7Nv/image.png?auth_key=1677500799-5bbAxSq7UStRowHyrjyQLT-0-e92f4ea8ecc4f08b90349f06ea012dc3)

尝试改写ssh文件，无权限

![](https://secure2.wostatic.cn/static/jTaG22NTMEjBUmbQ2RrwFu/image.png?auth_key=1677500799-mYuvMTkhmNq9qDAasPYCJP-0-53c377a5af223bc7b027b3c106683fea)

msf所有poc失败

判定是一个rabbit hole



未找到入口，看0dxf的题解，redis是可写的，我这里是不能写的，只能是靶场有bug，重启下写入正常了。。。

![](https://secure2.wostatic.cn/static/7wRAocr2ttHi5H3AUmHUBf/image.png?auth_key=1677500799-b3U9h8ctjHTbdHghTGzGhA-0-e8f4c156d06e1a1dd991a141c3a5b54a)



尝试直接往upload/目录下写payload写不进去，尝试用redis目录的的ssh，这里有redis用户，才可以这么操作；拿到shell后发现整个html都是root所属，没有写权限。



POC参考

[iw00tr00t/Redis-Server-Exploit: This will give you shell access on the target system if redis server is not configured properly and faced on the internet without any authentication (github.com)](https://github.com/iw00tr00t/Redis-Server-Exploit)

手动

![](https://secure2.wostatic.cn/static/9yy23nXZVRvbueqUPHaSHF/image.png?auth_key=1677500799-npd17tZdopnCeagJKq5n5g-0-68da99f24cf9463db362ea859c1e1804)



## Privilege Escalation

拿到的ssh shell权限非常低，user.txt都看不到

尝试直接进行内核提权

```Bash
└─# searchsploit 4.15 | grep Kernel
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (cron | linux/local/47164.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (dbus | linux/local/47165.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (ldpr | linux/local/47166.sh
Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (polk | linux/local/47167.sh
Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak                                    | linux/local/44325.c

```

执行全部失败，靶机未安装pkexec

```Bash
redis@Postman:~$ ./47164.sh
[-] newuidmap is not installed
redis@Postman:~$ ./47165.sh
[-] newuidmap is not installed
redis@Postman:~$ ./47166.sh
[-] newuidmap is not installed
redis@Postman:~$ ./47167.sh
[-] pkexec is not installed

```



### redis → Matt

翻了下其他目录，找到了Mata的私钥备份

![](https://secure2.wostatic.cn/static/egqjooZ4qZiCK8oD3njrEh/image.png?auth_key=1677500799-qaRwJvh7XrbATwV29suGrc-0-3cd6f13418d470afca9ea1f234989a0c)

使用该私钥登录 依然要求输入秘钥

![](https://secure2.wostatic.cn/static/77KdGhN9eagMAKZ8gMRj1U/image.png?auth_key=1677500799-acdGK92hf4NZ2UJiN93qD1-0-a1efb53aa7c6b4d8c4242e4d2f1088cb)

这个私钥的格式比较特殊，是openssl ASN格式，不确定这里有什么用



尝试从上面的webmin密码修改入手，无法修改配置文件

![](https://secure2.wostatic.cn/static/6f7osdKBb245ESy5B88WRa/image.png?auth_key=1677500799-pog6CRmzh9XJERUdcSRwwF-0-ce23036e093e2ec05f6b93beedeee6e6)



使用LinEnum

这个phpsessionclean时间间隔30分钟

![](https://secure2.wostatic.cn/static/t9YYvgNPFcoUzC1bP21xSm/image.png?auth_key=1677500799-rCyagsRiP81fiC5iwogd88-0-265424a20e6fc3eea9cd5af5e357a53f)

这个timers的配置看不到，在cron里面能找到

每30分钟phpsession过期删除，那是不是可以通过这个找到生效的session去登录

```Bash
# Look for and purge old sessions every 30 minutes
09,39 *     * * *     root   [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi

```

通过burp抓包，并没有发现请求中带有cookie字段，思路可能不对，先搞清楚这个脚本再说

```Bash
redis@Postman:/etc/cron.d$ ls -lh /usr/lib/php/sessionclean
-rwxr-xr-x 1 root root 2.9K Jan 17  2018 /usr/lib/php/sessionclean

# 按照脚本内容找到默认存放session的位置，是一个只能写不能读的目录
redis@Postman:/var/lib/php$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Aug 25  2019 .
drwxr-xr-x 38 root root 4096 Sep 29  2020 ..
drwxr-xr-x  3 root root 4096 Aug 25  2019 modules
drwx-wx-wt  2 root root 4096 Jan 30  2018 sessions
redis@Postman:/var/lib/php$ cd sessions/
redis@Postman:/var/lib/php/sessions$ ls
ls: cannot open directory '.': Permission denied
redis@Postman:/var/lib/php/sessions$ ls -ld
drwx-wx-wt 2 root root 4096 Jan 30  2018 .

```

这篇文章讲了如何利用 session.upload_progress 参数为on时上传恶意木马，但是这里我们没有文件包含的漏洞，也没有www的写权限； 

继续看脚本

如果在session的保存路径中找了为sess_*名称的文件，然后判断存活时间并进行删除，没有找到可以攻击的地方。看题解

原来还是上面的key，rsa的privatekey是极其敏感的东西，任何时候都不会随意泄漏，不过这里的破解是第一次碰到



### rsa key crack

[https://www.wolai.com/pDuuCVTnGUfTynAWwPPw5Q#sy7kDQG4SWzqkcjaYiFji2](https://www.wolai.com/pDuuCVTnGUfTynAWwPPw5Q#sy7kDQG4SWzqkcjaYiFji2)

拿到一个秘钥为 computer2008，但是这个密码只是在本地解密，也不是passphrase for key 

更不是Matt用户直接使用的ssh密码，因为这个靶机根本不允许Matt直接ssh登录

![](https://secure2.wostatic.cn/static/ccJ8LuXZggZNwC3iN4jeHZ/image.png?auth_key=1677500799-j5fp21vNweMFaWgcaUwSkz-0-d1e3f612966f089a3476249c9c229dfb)

### 
Matt → Root

通过Matt的histrory记录在这里存在一个脚本，没发现有什么用

![](https://secure2.wostatic.cn/static/hKdUmdhn5SCdVek4raAMTT/image.png?auth_key=1677500799-7PFSaY2dzjGA1sNJoHjXNx-0-16b3a288e46d72cf66ba53260f32a3e1)

看了下题解，Matt用户就是webmin的登录账号。。。  看了下题解，回到上面的匹配版本CVE, github找个脚本直接拿到root

![](https://secure2.wostatic.cn/static/6cUQZCCP7AALe7Wz4DeZgg/image.png?auth_key=1677500799-dyGV4WzPJhXoHizebrX25S-0-7ac133b3770e20b3b8830a0ad7ca3130)



