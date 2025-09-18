## Incident Report – Brute Force Attempt

**Date:** 2025-09-16  
**Host analyzed:** WIN-E00DDLM1BPK  
**Event ID:** 4625 (Failed Logon)  
**MITRE ATT&CK:** T1110 – Brute Force, Sub-technique T1110.001 – Password Guessing  

---

### Summary
During routine security log monitoring, I identified a significant number of failed logon attempts (Event ID 4625) on host `WIN-E00DDLM1BPK`.  
A refined query revealed a total of **3,636 failed logon events**, all originating from the same source IP `192.168.70.30` and targeting the account `gates.b@corp.com`.

The frequency and volume of the events indicated a **brute-force dictionary attack** over RDP (port 3389, confirmed active and listening on the host).

---

### Findings
- **Attacker IP:** `192.168.70.30`
- **Target account:** `gates.b@corp.com` 
- **Total failed attempts:** 3,636  
- **Attack vector:** Remote Desktop Protocol (RDP, TCP/3389)  
- **Detection source:** Windows Security Logs ingested into Splunk  

---

### Analysis
The activity matches MITRE ATT&CK technique **T1110 (Brute Force)** and sub-technique **T1110.001 (Password Guessing)**.  
This type of activity poses a significant risk of unauthorized access, lateral movement, and privilege escalation.

---

### Actions Taken
1. Queried Splunk logs to confirm source IP and targeted account.  
2. Verified open RDP port (3389) on the host.  
3. Created a Splunk alert to detect >5 failed logon attempts in 15 minutes.  
4. Implemented a firewall rule to block inbound/outbound traffic from attacker IP `192.168.70.30`.  

---

### Recommendations
- Review and tighten **password policies** (complexity, expiration, lockout thresholds).  
- Audit **account permissions** for `gates.b@corp.com`.  
- Restrict or monitor RDP access more closely.  
- Consider enabling **MFA** for remote access.  
- Add the detection to the SOC **playbook** for brute-force triage.  


