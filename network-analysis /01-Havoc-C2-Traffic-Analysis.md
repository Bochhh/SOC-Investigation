# 🔴 Hunting Havoc C2 — Network Forensics Investigation

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-C2%20%7C%20Malware%20Delivery%20%7C%20Lateral%20Movement-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1071%20%7C%20T1059%20%7C%20T1105%20%7C%20T1570-blue?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **File** | mal01.pcapng |
| **Date** | February 05, 2026 |
| **Target** | 10.0.0.156 (Victim Machine) |
| **Attacker Infrastructure** | 10.0.0.155 / 185.53.179.200 / ww38.bobmovies.us |
| **C2 Framework** | Havoc C2 — Demon Agent |
| **Payload** | checkmate.exe (99 KB) |
| **Severity** | 🔴 Critical |
| **Status** | Full compromise confirmed — administrative access achieved |

---

## 🎯 Scenario

This investigation focuses on analyzing malicious network traffic associated with a Command and Control (C2) framework. The objective was to perform packet analysis on a PCAP file to:

- ✅ Identify indicators of compromise
- ✅ Identify the C2 framework involved
- ✅ Extract cryptographic keys (AES Key and IV)
- ✅ Decrypt encrypted C2 communications
- ✅ Reveal attacker commands and access level

The lab demonstrates real-world techniques used by security analysts to investigate suspected malware infections and understand attacker activities through network forensics.

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| `mal01.pcapng` | Full network packet capture of the compromise |

---

## 📚 Resources

| Resource | Link |
|---|---|
| Havoc C2 Framework | [GitHub — HavocFramework](https://github.com/HavocFramework/Havoc) |
| Havoc Defines.h | [DEMON_MAGIC_VALUE](https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/Defines.h) |
| Havoc AesCrypt.h | [CTR Mode](https://github.com/HavocFramework/Havoc) |
| MITRE T1071.001 | [Application Layer Protocol](https://attack.mitre.org/techniques/T1071/001/) |
| MITRE T1105 | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1059.001 | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1570 | [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/) |
| CyberChef | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) |

---

## 🔍 Investigation Methodology
```
Step 1 → Protocol Analysis     (what traffic exists in the PCAP?)
Step 2 → HTTP Traffic Analysis (find suspicious requests and payloads)
Step 3 → Payload Extraction    (export and hash the malware)
Step 4 → C2 Identification     (identify the framework from signatures)
Step 5 → Beaconing Analysis    (confirm C2 heartbeat pattern)
Step 6 → Key Extraction        (extract AES key and IV from packets)
Step 7 → Decryption            (decrypt C2 communications in CyberChef)
```

---

## 🕵️ Investigation

### Step 1 — Protocol Hierarchy Analysis

The first thing I did was open the PCAP in Wireshark and run a protocol hierarchy analysis to understand what traffic existed before touching any individual packet.
```
Wireshark → Statistics → Protocol Hierarchy
```
><img width="977" height="457" alt="1m" src="https://github.com/user-attachments/assets/f0d3b61c-e92f-466c-9f1e-c988cf2633f2" />

| Protocol | Packets | % | Observation |
|---|---|---|---|
| **TCP** | 11,030 | 98.4% | Almost all traffic is TCP |
| **TLS** | 6,634 | 59.2% | Majority is encrypted — C2 hides in HTTPS |
| **HTTP** | 158 | 1.4% | Small but critical — cleartext entry point |
| **DNS** | 138 | 1.2% | Domain resolution — will reveal C2 domains |

TLS at 59.2% means most C2 communication is encrypted. The 158 HTTP packets are the entry point — that is where the story starts.

---

### Step 2 — HTTP Traffic Analysis

I filtered for HTTP traffic:
```
Filter: http
```
> <img width="1201" height="215" alt="2m" src="https://github.com/user-attachments/assets/0a9f479e-f933-445d-909c-05da369a881a" />

Immediately several things stood out:

#### Finding  — Malware Delivery 🚨🚨
```
GET /checkmate.exe HTTP/1.1
Source: 10.0.0.156 → 10.0.0.155:8000
Response: HTTP/1.0 200 OK (application/x-msdos-program)
```

An internal server at `10.0.0.155` served a Windows executable to the victim. `10.0.0.155` was already compromised — the attacker used it as an internal staging server.

---

### Step 3 — Payload Extraction and Hashing

I exported `checkmate.exe` directly from Wireshark:
```
File → Export Objects → HTTP → checkmate.exe → Save
```

Then calculated the hash:
```powershell
Get-FileHash -Algorithm MD5 checkmate.exe
```
> <img width="915" height="317" alt="2mm" src="https://github.com/user-attachments/assets/78894e85-06d0-4cdb-8b9e-7c0d4fb53dd3" />

```
MD5: 55DF2A3DD566B967E5F5141936724C7B
```

Submitted to **VirusTotal** — no matches found.

> <img width="811" height="344" alt="3m" src="https://github.com/user-attachments/assets/eb2e231a-b587-4a92-84da-9835760b7098" />


| Result | Meaning |
|---|---|
| Found on VirusTotal | Known commodity malware |
| **Not found on VirusTotal** | **Custom compiled implant — targeted attack** |

The attacker compiled `checkmate.exe` specifically for this operation.

---
