## nmap

```Bash
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

```

```Bash
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



## 80

httpd版本没有发现有问题

目录爆破没有发现东西



这个题目的难点:

1、目录爆破，用gobuster或者feroxbuster只能看到cig-bin目录，找不到里面的user.sh 文件；

用dirbuster才可以很快扫出来，没有确定原因。

![](https://secure2.wostatic.cn/static/s6hF51D72gjMjnuzRinnvt/image.png?auth_key=1677500071-6YPX9UVcRDqMdY4VKifcgW-0-a5fbf2ba1848655bc2e841eef5d8c8ce)

2、关于shellshock的漏洞这个点，没有明确的提示，exp基本是靠靶场名称猜的







