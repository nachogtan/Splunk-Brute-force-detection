# L1 Analyst Playbook — Brute-Force Detection (MITRE T1110)

**Purpose:**
This playbook guides a Level 1 (L1) SOC analyst through triage, validation, containment (where authorized), evidence collection, escalation, and follow-up for alerts related to brute-force activity targeting Windows RDP services (Windows EventCode 4625 / MITRE ATT&CK T1110).

---

## Quick summary (one-line)
Alert: Multiple failed RDP logon attempts detected (> threshold) from the same source IP or across many accounts. Potential credential stuffing / brute-force attack.

**Fields to capture from the alert:**
- Alert ID / savedsearch name
- Timestamp (UTC)
- Source_Network_Address (attacker IP)
- Account_Name(s) targeted
- Host(s) affected (ComputerName / Workstation_Name)
- Number of failed attempts and time window
- Logon_Type (expect 10 for RDP)
- Status/SubStatus codes (if available)
- Splunk search job link or dashboard link

---

## Pre-requisites & notes
- Only act inside an isolated lab or authorized production environment. Follow your org's change-control and escalation procedures.
- Use the Splunk saved search/dashboard linked in the alert to jump straight into context.
- If you are not authorized to perform containments (firewall blocks, AD actions), escalate to L2 with the evidence collected.

---

## Triage & validation steps (L1)
1. **Open the alert** and note the key fields listed above.
2. **Run the primary validation search** in Splunk to view related events (last 24 hours):

```spl
index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624) Host=<HOST> OR Account_Name="<ACCOUNT>" OR Source_Network_Address=<IP>
| sort 0 _time
| table _time, EventCode, Account_Name, Source_Network_Address, Workstation_Name, Logon_Type, Status, Sub_Status, AuthenticationPackageName
```

3. **Confirm logon type**: validate `Logon_Type=10` (RemoteInteractive / RDP). If Logon_Type is different, note that in findings.
4. **Check failure reason codes**: examine Status/SubStatus to determine if failures are due to wrong password (`0xc000006a`) or other causes. Document codes and map to friendly text.

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625 Host=<HOST>
| rex field=Message "Status:\s+(0x[0-9A-Fa-f]+)" max_match=0
| rex field=Message "Sub Status:\s+(0x[0-9A-Fa-f]+)" max_match=0
| stats count by Source_Network_Address, Account_Name, Status, Sub_Status
| sort -count
```

5. **Assess scope**: determine if the source IP targets many accounts or many hosts.

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625 Logon_Type=10
| stats count AS total_fails, dc(Account_Name) AS distinct_accounts, values(Host) AS hosts by Source_Network_Address
| sort - total_fails
```

6. **Search for subsequent success**: detect any `4624` (successful logon) that follows a burst of failures for the same account within a short window.

```spl
index=main sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624) Logon_Type=10 Account_Name="<ACCOUNT>"
| sort 0 _time
| streamstats window=20 values(EventCode) as recent_events by Account_Name
| where EventCode=4624 AND mvcount(mvfilter(match(recent_events,"4625"))) >= 5
| table _time, Account_Name, Source_Network_Address, recent_events
```

7. **Correlate with network/firewall logs** (if available) from the router/syslog to confirm inbound connection attempts from the source IP.

```spl
index=main sourcetype=iptables OR sourcetype=syslog host=<ROUTER_HOST> Source_Network_Address=<IP>
| table _time, host, _raw
```

8. **Check reputation / whitelists**: If your org maintains an IP allowlist or internal scan list, check whether the IP is known/expected.

---

## Decision matrix (L1)
- **Benign / False Positive**: single/few attempts from a known/managed scanner or internal IP; no pattern of repeated attempts and no successes. **Action:** Mark as `Benign`, add note, close alert.
- **Likely Brute-force (investigate further)**: repeated failures (> threshold), same source or many accounts targeted, Logon_Type consistent with RDP. **Action:** Contain if authorized, or escalate to L2 with evidence.
- **Compromise Suspected**: success after multiple failures or lateral activity from the same source. **Action:** Escalate to L2/IR immediately; follow incident response runbook.

---

## Containment (if authorized) — suggested actions
> **Only perform these if you have explicit authorization to modify network or identity controls.**

1. **Block source IP** at perimeter / host firewall (temporary):
   - Example iptables block on Debian router:

```bash
sudo iptables -A INPUT -s <IP> -j DROP
sudo iptables-save > /etc/iptables/rules.v4
```

2. **Isolate host** from network if compromise suspected (coordinate with L2/IR).
3. **Force account lockout / password reset** for highly targeted accounts (coordinate with AD/Identity team).
4. **Enable MFA / ensure MFA is enforced** for the affected account(s) if available.

Document every action with timestamps and the approving party.

---

## Evidence collection (required when escalating)
- Export Splunk search results to CSV (include `_time`, `EventCode`, `Account_Name`, `Source_Network_Address`, `Workstation_Name`, `Logon_Type`, `Status`, `Sub_Status`).
- Collect firewall logs showing inbound connections from the source IP.
- Snapshot or export related Sysmon events if configured (network connect, process creation, etc.).
- Note any successful logons (4624) and their source IPs and hostnames.
- Preserve VM snapshots if a host shows signs of compromise.

---

## Escalation checklist (what to include when escalating to L2/IR)
- Alert ID, timestamp, and link to Splunk search/dashboard.
- Summary: source IP, targeted accounts, host(s), number of fails, timeframe.
- Copies of exported evidence (CSV) and firewall logs.
- Any containment actions taken (and who authorized them).
- Recommended next steps (e.g. block IP, credential resets, forensic imaging).

---

## Communication templates (short)
**Internal notification (to L2/IR):**
> Subject: [INCIDENT] Suspected brute-force on HOST <hostname> — escalate to L2
>
> Body: Detected >X failed RDP logons from <IP> targeting <account(s)> during <time window>. Evidence exported and attached. No confirmed successful login yet / successful login detected (choose one). Actions taken: <list>. Please advise next steps.

**User notification (if required by policy):**
> We detected repeated login attempts against your account <account>. For your security, we recommend changing your password and verifying MFA settings. Do not reuse passwords across services.

---

## Post-incident / Follow-up
- Ensure all containment actions are rolled back when safe (e.g., remove temporary firewall blocks when appropriate). Document rollback.
- Review detection thresholds and refine to reduce false positives.
- Add any new IOCs (source IPs) to monitoring lists for watchlisting.
- Run root cause analysis and update the playbook with lessons learned.

---

## Appendix: Common Windows status codes (examples)
- `0xc000006a` — Wrong password
- `0xc000006d` — Account logon failure (unknown user name or bad password)
- `0xc000006e` — User logon failure: account restriction

*(Map additional codes in your README with links to Microsoft docs.)*

---

## Appendix: Useful Splunk saved searches (names suggested)
- `BruteForce_RDP_MultiFail_By_IP` — detects >5 fails in 5 min per IP
- `BruteForce_RDP_MultiAccount_By_IP` — detects same IP attacking >5 accounts
- `SuccessAfterFails_RDP` — detects 4624 after 5+ 4625 in short window

---

## Versioning & contacts
- Playbook version: 1.0 — 2025-09-18
- Author / Contact: [Your Name] — add your contact details
- License: MIT

---

*End of playbook.*

