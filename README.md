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
         /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt<br><br>
         
`TCP 21: FTP`
 
 -   Download Everything  
     `wget -m ftp://anonymous:anonymous@<ip>`
   
-    Ftp Nmap Scan  
     `nmap --script ftp-anon,ftp-bounce,ftp-brute,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum,ftp-syst -p21 <RHOST>`

-    Ssl Ftp Connection  
     `openssl s_client -connect <RHOST>:21 -starttls ftp`
     <br>
`TCP 22: SSH`

-    Bruteforce  
     `hydra -l root -P /usr/share/wordlists/password/10k <RHOST> -t 4 ssh`
     <br>
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
     `RCPT TO:<user>`
    <br>
`TCP 53: DNS`

-    Standard Enum  

         nslookup  
         server <RHOST>  
         127.0.0.1  
         <RHOST>  
      
-    Zone Transfer  
     `dig axfr @<RHOST> <dnsname>`
