🛡️ Splunk + MITRE ATT&CK Detection Lab
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red?style=for-the-badge&logo=target&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-10.2.1-green?style=for-the-badge&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.15-blue?style=for-the-badge&logo=windows&logoColor=white)
![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-Latest-orange?style=for-the-badge)
![Detection Rate](https://img.shields.io/badge/Detection%20Rate-4%2F4%20%E2%80%94%20100%25-brightgreen?style=for-the-badge)
---
📋 Project Overview
A hands-on adversary emulation and detection lab built to simulate real-world attack techniques mapped to the MITRE ATT&CK framework and detect them using Splunk Enterprise as the SIEM platform.
Four high-frequency attack techniques — observed in active ransomware pre-deployment phases and APT lateral movement campaigns — were simulated using Atomic Red Team on a Windows VM. Each simulation generated endpoint telemetry captured by Sysmon v15.15, forwarded to Splunk, and detected using purpose-built SPL detection queries.
Detection Rate: 4/4 — 100%
> This lab demonstrates practical SOC L1 analyst skills: log ingestion, endpoint telemetry configuration, SIEM query writing, threat detection, MITRE ATT&CK mapping, and detection dashboard creation.
---
🏗️ Lab Architecture
Virtual Machine Setup
VM	OS	IP Address	Role
Windows VM	Windows 11 Enterprise (Build 26100)	`192.168.50.2`	Attack Target + Sysmon + Universal Forwarder + Atomic Red Team
Ubuntu VM	Ubuntu 24 LTS	`192.168.50.4`	Splunk Enterprise SIEM Server
All VMs run on VirtualBox connected via an isolated internal network (`192.168.50.0/24`). The host machine is fully isolated from the lab network. No external connectivity is required — all adversary emulation runs locally on the Windows VM.
ASCII Architecture Diagram
```
┌─────────────────────────────────────────────────────────────────────┐
│                        LAB INTERNAL NETWORK                         │
│                        192.168.50.0/24                              │
│                                                                     │
│  ┌──────────────────────────────┐      ┌────────────────────────┐  │
│  │       WINDOWS VM             │      │       UBUNTU VM        │  │
│  │    192.168.50.2              │      │    192.168.50.4        │  │
│  │                              │      │                        │  │
│  │  ┌────────────────────────┐  │      │  ┌──────────────────┐  │  │
│  │  │   Atomic Red Team      │  │      │  │ Splunk Enterprise│  │  │
│  │  │  (Attack Simulation)   │  │      │  │    10.2.1        │  │  │
│  │  └────────────┬───────────┘  │      │  │  Port 8000 (UI)  │  │  │
│  │               │generates     │      │  │  Port 9997 (recv)│  │  │
│  │  ┌────────────▼───────────┐  │      │  └────────▲─────────┘  │  │
│  │  │    Sysmon v15.15       │  │      │           │            │  │
│  │  │ (SwiftOnSecurity cfg)  │  │      │    logs received       │  │
│  │  │  EventCode 1,3,7,11..  │  │      │    via TCP 9997        │  │
│  │  └────────────┬───────────┘  │      │           │            │  │
│  │               │telemetry     │      └───────────┼────────────┘  │
│  │  ┌────────────▼───────────┐  │                  │               │
│  │  │ Splunk Universal       │──┼──────────────────┘               │
│  │  │ Forwarder 9.2.1        │  │   TCP 9997 log forwarding        │
│  │  │ inputs.conf configured │  │                                  │
│  │  └────────────────────────┘  │                                  │
│  └──────────────────────────────┘                                  │
│                                                                     │
│  Log Sources Forwarded:                                             │
│  ├── XmlWinEventLog:Microsoft-Windows-Sysmon/Operational            │
│  ├── WinEventLog:Security                                           │
│  ├── WinEventLog:System                                             │
│  └── linux_secure (Ubuntu SSH auth events)                          │
└─────────────────────────────────────────────────────────────────────┘
```
---
🔧 Tools & Versions
Tool	Version	Purpose
Splunk Enterprise	10.2.1	SIEM platform — log ingestion, search, alerting, dashboards
Sysmon (System Monitor)	v15.15	Granular Windows endpoint telemetry — process, network, file, registry events
SwiftOnSecurity Sysmon Config	Latest	Community-trusted Sysmon config — suppresses noise, preserves high-fidelity signals
Splunk Universal Forwarder	9.2.1	Ships Windows + Sysmon logs to Splunk over TCP 9997
Atomic Red Team	Latest	MITRE ATT&CK-mapped adversary emulation library
---
📊 Log Sources
Sourcetype	Event Count	SOC Relevance
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`	5,428+	Primary detection source — process creation, network connections, file events
`WinEventLog:Security`	4,416+	Authentication events — 4624/4625 logon, privilege escalation
`WinEventLog:System`	1,525+	Service installation (7045), unexpected shutdowns
`linux_secure`	148+	Ubuntu SSH authentication events
---
⚔️ Attack Simulations & Detections
All four techniques were simulated using `Invoke-AtomicTest` on the Windows VM and detected in Splunk using purpose-built SPL queries.
#	Technique ID	Name	Tactic	Tool Used	EventCode	Events Detected
1	T1059.001	PowerShell Execution (Mimikatz)	Execution	Invoke-Mimikatz via IEX download cradle	Sysmon EventCode=1	2 ✅
2	T1053.005	Scheduled Task Persistence	Persistence	schtasks.exe via PowerShell → cmd	Sysmon EventCode=1	3 ✅
3	T1003.001	LSASS Memory Credential Dump	Credential Access	rundll32.exe + comsvcs.dll MiniDump (LotL)	Sysmon EventCode=1	5 ✅
4	T1110.001	Brute Force Password Guessing	Credential Access	Atomic Red Team LDAP brute force	WinSecurity EventCode=4625	5 ✅
> **LotL Note:** T1003.001 uses only Microsoft-signed Windows binaries (rundll32 + comsvcs.dll), bypassing traditional AV signature detection. Detection is exclusively behavioral via Sysmon CommandLine inspection.
---
🔍 SPL Detection Queries
T1059.001 — PowerShell Mimikatz Execution
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*mimikatz*" OR CommandLine="*sekurlsa*"
| table _time, Image, CommandLine, ParentImage, User
| sort - _time
```
> **Query Logic:** `EventCode=1` filters to Sysmon Process Creation events. Wildcard search on `CommandLine` catches Mimikatz execution regardless of obfuscation level in Atomic Test 1. `ParentImage` field confirms the unusual `cmd.exe → powershell.exe` process ancestry.
---
T1053.005 — Suspicious Scheduled Task Creation
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*schtasks*" OR CommandLine="*T1053*"
| table _time, Image, CommandLine, ParentImage, User
| sort - _time
```
> **Query Logic:** Catches any invocation of `schtasks.exe`. Legitimate task creation does not originate from PowerShell or cmd.exe interactively. The `/ru system` and `/sc onstart` flags visible in `CommandLine` confirm SYSTEM-level persistence intent — P1 escalation trigger in most SOC playbooks.
---
T1003.001 — LSASS Memory Credential Dump
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*lsass*" OR CommandLine="*comsvcs*" OR CommandLine="*MiniDump*"
| table _time, Image, CommandLine, ParentImage, User
| sort - _time
```
> **Query Logic:** `CommandLine="*MiniDump*"` is effectively a definitive IOC — no legitimate tool invokes MiniDump via rundll32 in normal operations. Combined with `comsvcs` and `lsass` co-occurrence, confidence in malicious intent approaches certainty.
---
T1110.001 — Brute Force Failed Logins
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Failure_Reason, Source_Network_Address, Workstation_Name
| sort - _time
```
> **Query Logic:** Uses Windows Security log (not Sysmon) — brute force is best detected at the authentication layer. `EventCode=4625` captures every failed logon. In production, pair with a `stats count` threshold alert (5+ failures per account within 60 seconds) to minimize false positives.
Production threshold query:
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5
```
---
📈 Detection Results
```
┌────────────────────────────────────────────────────────────┐
│                   DETECTION SUMMARY                        │
│                                                            │
│  T1059.001  PowerShell/Mimikatz      2 events    ✅ DETECTED│
│  T1053.005  Scheduled Task           3 events    ✅ DETECTED│
│  T1003.001  LSASS Credential Dump    5 events    ✅ DETECTED│
│  T1110.001  Brute Force              5 events    ✅ DETECTED│
│                                                            │
│  Detection Rate: 4/4 ─── 100%                              │
│  Total Events Analyzed: 11,517+                            │
└────────────────────────────────────────────────────────────┘
```
---
🗺️ MITRE ATT&CK Coverage
#	Technique ID	Name	Tactic	Log Source	EventCode	Result
1	T1059.001	PowerShell Execution	Execution	Sysmon	1	✅ DETECTED
2	T1053.005	Scheduled Task	Persistence	Sysmon	1	✅ DETECTED
3	T1003.001	LSASS Memory Dump	Credential Access	Sysmon	1	✅ DETECTED
4	T1110.001	Password Guessing	Credential Access	WinEventLog:Security	4625	✅ DETECTED
---
🖥️ Splunk Detection Dashboard
A unified MITRE ATT&CK Detection Dashboard was built in Splunk Classic Dashboards providing a single-pane-of-glass monitoring view with:
Attack Detection Timeline — color-coded column chart showing all technique detections over time
T1059.001 Panel — Mimikatz PowerShell execution events with full CommandLine visible
T1053.005 Panel — Scheduled task creation events with ParentImage for process ancestry analysis
T1003.001 Panel — LSASS dump events with dump file path for forensic follow-up
T1110.001 Panel — Failed logon events with Account_Name and Source_Network_Address
---
💡 Skills Demonstrated
Skill Area	Evidence
SIEM Administration	Configured Splunk 10.2.1, enabled TCP receiver (port 9997), managed indexes and sourcetypes
Endpoint Telemetry	Deployed Sysmon v15.15 with SwiftOnSecurity config, resolved Windows event log access permissions
Log Forwarding	Configured Splunk Universal Forwarder 9.2.1 with custom `inputs.conf` for Sysmon and WinEventLog
SPL Query Writing	Built 4 detection queries using EventCode filters, wildcard CommandLine searches, table formatting
Threat Detection	Detected all 4 simulated techniques with 100% coverage — zero missed detections
MITRE ATT&CK	Mapped all detections to Tactic, Technique, and Sub-technique across 3 tactic categories
Process Tree Analysis	Identified suspicious parent-child chains (PowerShell → cmd → schtasks, powershell → rundll32)
Dashboard Creation	Built multi-panel SOC dashboard with timeline chart + 4 detection tables in Splunk
Attack Documentation	Documented attack chains, detection logic, and analyst observations in a professional report
---
📁 Repository Structure
```
Splunk-MITRE-ATTandCK-Detection-Lab/
├── README.md                          # This file
├── Report/
│   └── Splunk_MITRE_ATTandCK_SOC_Report.docx   # Full lab report
├── SPL-Queries/
│   ├── T1059_001_Mimikatz.spl
│   ├── T1053_005_ScheduledTask.spl
│   ├── T1003_001_LSASS_Dump.spl
│   └── T1110_001_BruteForce.spl
├── Dashboard/
│   └── MITRE_ATTandCK_Dashboard.xml   # Splunk dashboard XML
└── Screenshots/
    ├── log_sources_verified.png
    ├── mimikatz_detection.png
    ├── scheduled_task_detection.png
    ├── lsass_dump_detection.png
    ├── bruteforce_detection.png
    └── dashboard_overview.png
```
---
🚀 How to Replicate This Lab
Prerequisites
VirtualBox (or VMware)
Windows 11 Enterprise ISO
Ubuntu 24 LTS ISO
Splunk Enterprise Free License
Steps
Set up Ubuntu VM — install Splunk Enterprise, enable TCP receiver on port 9997
Set up Windows VM — install Sysmon with SwiftOnSecurity config, install Splunk Universal Forwarder
Configure forwarder — create `inputs.conf` to forward Sysmon and Security logs to Ubuntu Splunk
Install Atomic Red Team — `IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force`
Run simulations — `Invoke-AtomicTest T1059.001 -TestNumbers 1`, etc.
Detect in Splunk — run SPL queries from the `SPL-Queries/` folder
Build dashboard — import `Dashboard/MITRE_ATTandCK_Dashboard.xml`
---
👤 Author
Paulson K Babu (Jude)
SOC L1 Analyst Candidate | MCA Graduate
APJ Abdul Kalam Technological University, Kerala, India
![GitHub](https://img.shields.io/badge/GitHub-joseph920744-black?style=flat-square&logo=github)
![LinkedIn](https://img.shields.io/badge/LinkedIn-paulson--babu-blue?style=flat-square&logo=linkedin)
---
> *This project is part of a structured cybersecurity home lab portfolio built to demonstrate practical SOC L1 analyst capabilities through hands-on adversary emulation and detection engineering.*
