```Ps
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
