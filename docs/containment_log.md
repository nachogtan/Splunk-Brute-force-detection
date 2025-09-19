# Containment Log

Record of containment actions

- **Incident ID:** 
- **Date / Time (UTC):** 
- **Analyst:** 
- **Attacker IP:** 192.168.70.30
- **Affected host(s):** WIN-E00DDLM1BPK
- **Action taken:** (e.g., block IP on Debian firewall)
- **Command executed (example):**


```bash
sudo iptables -A INPUT -s 192.168.70.30 -j DROP
sudo iptables -A OUTPUT -d 192.168.70.30 -j DROP
sudo iptables -A FORWARD -s 192.168.70.30 -j DROP
sudo iptables -A FORWARD -d 192.168.70.30 -j DROP
```
