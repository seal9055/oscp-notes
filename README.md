# oscp-notes

Passed OSCP in January 2021. These are the notes I took along my journey to achieving it. 

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
     'python3 /usr/share/doc/python3-impacket/examples/samrdump.py <RHOST>'

-    Dump Info  
     `rpcclient -U "" <RHOST>`
