
```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
```
```spl	
09/16/2025 09:00:46 AM
LogName=Security
EventCode=4625
EventType=0
ComputerName=WIN-E00DDLM1BPK.corp.com
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=18609
Keywords=Audit Failure
TaskCategory=Logon
OpCode=Info
Message=An account failed to log on.

Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		S-1-0-0
	Account Name:		gates.b@corp.com
	Account Domain:		

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	kali
	Source Network Address:	192.168.70.30
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	Transited Services:	-
	Package Name (NTLM only):	-
	Key Length:		0

This event is generated when a logon request fails. It is generated on the computer where access was attempted.

The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.

The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).

The Process Information fields indicate which account and process on the system requested the logon.

The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.

The authentication information fields provide detailed information about this specific logon request.
	- Transited services indicate which intermediate services have participated in this logon request.
	- Package name indicates which sub-protocol was used among the NTLM protocols.
	- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.
Collapse

    Account_Name = - Account_Name = gates.b@corp.com
    Source_Network_Address = 192.168.70.30
    host = WIN-E00DDLM1BPK
    source = WinEventLog:Security
    sourcetype = WinEventLog:Security
```


---

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name, src_ip
| sort -count
```
---

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625 Source_Network_Address=192.168.70.30
| stats count by Account_Name, Failure_Reason
```
---

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count as FailedAttempts by Source_Network_Address, Account_Name
| where FailedAttempts > 5
| sort - FailedAttempts
```

---

DASHBOARD

```spl
index="main" source="WinEventLog:Security"
| stats count by EventCode
| sort count
```

```spl
index="main" source="WinEventLog:Security" EventCode=4625
| stats count by EventCode
| table count
```
```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| timechart span=1h count as FailedAttempts
```
```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name
| where Account_Name="gates.b@corp.com"
```
```spl
index="main" source="WinEventLog:Security" Source_Network_Address=192.168.70.30
| stats count by Source_Network_Address
| table Source_Network_Address
```

