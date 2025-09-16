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
- [Splunk searches (SPL)](#splunk-searches-spl)
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

