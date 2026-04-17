# 🔴 Threat Hunting — Full Intrusion Chain Investigation via Splunk

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Threat%20Hunting-purple?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-WinRM%20%7C%20Mimikatz%20%7C%20DLL%20Hijack%20%7C%20Persistence-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1021%20%7C%20T1003%20%7C%20T1574%20%7C%20T1546-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20Windows%20Security%20Logs-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Hunt Title** | Full Intrusion Chain — WinRM to Account Manipulation |
| **Date** | February 10, 2026 |
| **Affected Host** | ATTACKDEFENSE |
| **Attacker IP** | 10.0.0.56 |
| **Affected User** | Administrator |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full intrusion chain confirmed |

---

## 🎯 Scenario

A series of security alerts were triggered by a Splunk SIEM deployment
indicating a potential intrusion chain. The alerts suggested a complete
attack progression — from initial remote access, through credential theft,
persistence establishment, and finally account manipulation.

The objective was to use Splunk to correlate logs, validate each alert,
and piece together the attacker's actions step by step.

This is **threat hunting** — taking 8 alerts from a dashboard and
reconstructing the full story behind them using raw log evidence.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Splunk** | Log correlation and threat hunting queries |
| **Sysmon** | Endpoint telemetry — process, network, file, registry, memory |
| **Windows Security Logs** | Account manipulation events |
| **Windows PowerShell Logs** | Command execution evidence |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Sysmon Event ID 1 | Process creation — execution chain |
| Sysmon Event ID 10 | Process access — LSASS memory access |
| Sysmon Event ID 11 | File creation — malicious files dropped |
| Sysmon Event ID 13 | Registry modification — persistence |
| Windows PowerShell Event 800 | Pipeline execution — download commands |
| Windows Security Event 4733 | Group membership removal |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1021.006 — WinRM | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/006/) |
| MITRE T1003.001 — LSASS Dumping | [attack.mitre.org](https://attack.mitre.org/techniques/T1003/001/) |
| MITRE T1574.010 — Services File Permissions | [attack.mitre.org](https://attack.mitre.org/techniques/T1574/010/) |
| MITRE T1546.007 — Netsh Helper DLL | [attack.mitre.org](https://attack.mitre.org/techniques/T1546/007/) |
| MITRE T1098 — Account Manipulation | [attack.mitre.org](https://attack.mitre.org/techniques/T1098/) |
| Mimikatz Reference | [github.com/gentilkiwi](https://github.com/gentilkiwi/mimikatz) |

---

## 🔍 Hunt Methodology

```
Stage 1 → Initial Remote Access     (WinRM authentication evidence)
Stage 2 → Tool Staging              (malicious files delivered)
Stage 3 → Credential Theft          (Mimikatz LSASS dump)
Stage 4 → Persistence               (DLL + registry)
Stage 5 → Account Manipulation      (group removal + password change)
```

---

## 📊 Alert Dashboard Overview

> 📸 Screenshot — Splunk Alert Dashboard

```
Critical Alerts:  3
High Priority:    3
Medium Priority:  2
Total Events:     8
```

| Alert | Severity | MITRE | Time |
|---|---|---|---|
| Suspicious WinRM Remote Login | Medium | T1021.006 | 11:48 |
| Suspicious File Download Activity | High | T1105 | 11:48 |
| Suspicious Process Accessing LSASS | Critical | T1003.001 | 11:48:52 |
| Credential Dumping Keywords Detected | Critical | T1003.001 | 11:48:52 |
| Unsigned DLL Written to System32 | High | T1574 | 11:49:52 |
| Suspicious Registry Modification | Critical | T1546.007 | 11:50:03 |
| Admin Group Members Removed | Medium | T1098 | 11:50 |
| Administrator Password Changed | High | T1098 | 11:50 |

Reading the dashboard alone already told the story — 8 alerts in under
2 minutes, all on the same host, all pointing to a single attacker at
`10.0.0.56`. The hunt began.

---

## 🕵️ Investigation

### Stage 1 — Initial Remote Access: WinRM

The first alert flagged a suspicious WinRM login from `10.0.0.56` to
`ATTACKDEFENSE` using the `Administrator` account. WinRM (Windows Remote
Management) is a legitimate remote management protocol — but when used
by an attacker with stolen credentials, it provides a full interactive
PowerShell session on the target machine.

> **🔍 Question 1: How do we confirm the authentication was really via WinRM?**

The answer came from multiple log sources all pointing to the same process:

```
wsmprovhost.exe
```

> 📸 Screenshot — wsmprovhost.exe as parent process

**`wsmprovhost.exe` is the Windows Remote Management Provider Host.**
This process only exists when someone connects via WinRM remotely — it
hosts PowerShell sessions on the target machine on behalf of a remote
caller. You will never see this process from local activity.

```
wsmprovhost.exe present = someone is connected remotely via WinRM
No exceptions.
```

Additional confirmation:
```
HostName:        ServerRemoteHost  ← "Remote" explicitly in the name
HostApplication: wsmprovhost.exe -Embedding ← embedding = remote session
Source IP:       10.0.0.56         ← attacker's machine
User:            ATTACKDEFENSE\Administrator ← privileged account used
```

> **🔍 Why WinRM Is Dangerous For Attackers**
> WinRM gives an authenticated attacker a full PowerShell terminal on
> the target machine — indistinguishable from a local admin session in
> terms of capability. Everything the attacker did from this point was
> executed through this single remote session.

---
