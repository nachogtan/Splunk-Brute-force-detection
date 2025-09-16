# Brute-Force Detection in Windows with Splunk (MITRE ATT&CK T1110)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Tech: Splunk](https://img.shields.io/badge/Tech-Splunk-blue.svg)](https://www.splunk.com/)
[![MITRE: T1110](https://img.shields.io/badge/MITRE-T1110-orange.svg)](https://attack.mitre.org/techniques/T1110/)
 Project overview
This repository contains a lab and detection pipeline for simulating brute-force attacks (MITRE ATT&CK T1110) against a Windows Server and analyzing Windows security events in Splunk. The project includes SPL queries, dashboard examples, an L1 analyst playbook and reproducible attack scripts (for lab use only).

**Environment:** isolated lab (Kali attacker → Debian router/firewall → Windows Server victim with Splunk UF → Splunk Enterprise).  
**Goal:** demonstrate ingestion, detection, triage and basic response for brute-force activity.

## Table of contents
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Attack simulation (lab only)](#attack-simulation-lab-only)
- [Splunk Analysis (SPL)](#splunk-analysis-spl)
- [Dashboards & Alerts](#dashboards--alerts)
- [MITRE ATT&CK mapping](#mitre-attck-mapping)
- [Playbook (L1)](#playbook-l1)
- [Evidence & artifacts](#evidence--artifacts)
- [Repository structure](#repository-structure)
- [Security & ethics](#security--ethics)
- [License](#license)
- [Contact / Author](#contact--author)

## Architecture
Lab components
- Splunk Enterprise: `192.168.1.129` (index: `main`)
- Windows Server (victim + Splunk UF): `192.168.60.20`
- Debian router/firewall (syslog): `192.168.56.10`
- Kali Linux (attacker): `192.168.70.30`
  
<img width="1319" height="897" alt="home-lab-top" src="https://github.com/user-attachments/assets/7e3d3882-fda0-4806-8619-880a4449014e" />


## Requirements
- Splunk Enterprise
- Splunk Universal Forwarder on Windows Server
- Windows Server (2022)
- Kali Linux with `hydra`, `curl`
- Debian router (rsyslog and iptables logging enabled)
- Sysmon configured on Windows for richer telemetry


### Preparation
1. Configure Windows Firewall to allow incoming `RDP` connections from the Kali attacker IP.

```Powershell
PS C:\Users\Administrator> New-NetFirewallRule -DisplayName "Allo RDP from kali" -Direction Inbound -LocalPort 3389 -Protocol TCP -RemoteAddress 192.168.70.30 -Action Allow


Name                          : {3cf629d2-6945-4ddb-81b8-03ac35fafec4}
DisplayName                   : Allo RDP from kali
Description                   :
DisplayGroup                  :
Group                         :
Enabled                       : True
Profile                       : Any
Platform                      : {}
Direction                     : Inbound
Action                        : Allow
EdgeTraversalPolicy           : Block
LooseSourceMapping            : False
LocalOnlyMapping              : False
Owner                         :
PrimaryStatus                 : OK
Status                        : The rule was parsed successfully from the store. (65536)
EnforcementStatus             : NotApplicable
PolicyStoreSource             : PersistentStore
PolicyStoreSourceType         : Local
RemoteDynamicKeywordAddresses : {}

```

2. Ensure RDP is enabled on the Windows Server (port `3389`).  

```Powershell
PS C:\Users\Administrator>
>> Get-NetTCPConnection -LocalPort 3389

LocalAddress                        LocalPort RemoteAddress                       RemotePort State       Appl
                                                                                                         iedS
                                                                                                         etti
                                                                                                         ng
------------                        --------- -------------                       ---------- -----       ----
::                                  3389      ::                                  0          Listen
0.0.0.0                             3389      0.0.0.0                             0          Listen
```

3. Create temporary lab accounts with known passwords for testing.  
4. Take a snapshot of Windows Server in case a rollback is needed.

## Attack simulation (Red Team)
**WARNING:** Run all actions **ONLY** in an isolated lab environment. Do NOT run on production or external networks.

### Overview
This simulation demonstrates a controlled brute-force attack (`MITRE ATT&CK T1110`) against a Windows Server RDP service to generate failed logon events for Splunk detection.

### Target
- Windows Server IP: `192.168.60.20`
- Test account(s) for brute-force: `gates.b@corp.com`

### Attacker
- Kali Linux IP: `192.168.70.30`
- Tools: hydra, nmap, curl

Now that we have the lab set up to imitate this TTP, we are going to run our first commands on the attack machine.
1. The first step is to perform a quick nmap scan to the target network looking for live hosts for vulnerabilities.

```zsh
└─$ nmap -sS -sV -O 192.168.60.1/24
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-16 10:35 EDT
Nmap scan report for 192.168.60.1
Host is up (0.00068s latency).
All 1000 scanned ports on 192.168.60.1 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

Nmap scan report for 192.168.60.20
Host is up (0.0014s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-16 14:36:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: corp.com0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2016 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (97%), Microsoft Windows 11 21H2 (91%), Microsoft Windows Server 2016 (91%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: WIN-E00DDLM1BPK; OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 256 IP addresses (2 hosts up) scanned in 19.39 seconds
```
This initial Nmap scan identifies the IP of the domain controller and enumerates its open ports. The next step is to simulate a controlled brute-force attack using the `T1110` technique.

**MITRE ATT&CK Mapping:**  
- Technique: T1110 – Brute Force  
- Sub-technique: T1110.001 – Password Guessing  
- Vector: RDP login attempts on Windows Server  
- Data sources: Windows Security logs (4625), Splunk UF, syslog

2. Next, we ran a dictionary attack against the target machine using the well-known  `/usr/share/wordlists/rockyou.txt.gz`.

```zsh
hydra -l gates.b@corp.com -P /usr/share/wordlists/rockyou.txt.gz rdp://192.168.60.20
```
- This command attempts to log in via RDP using the specified username and passwords from the wordlist.
- Each failed login attempt will generate a Windows Security Event 4625, which will be collected by the Splunk Universal Forwarder.

### Splunk Analysis

After running the lab attack simulation (or simulating failed logins), we can analyze the data in Splunk to detect brute-force attempts.

### 1. Search for Failed Logins (Windows Event 4625)
```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name, src_ip
| sort -count
```

