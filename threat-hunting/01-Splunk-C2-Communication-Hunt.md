# 🔴 Threat Hunting — C2 Communication via application_form.pdf.exe

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Threat%20Hunting-purple?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-Trojan%20%7C%20C2%20%7C%20Persistence%20%7C%20Recon-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1071%20%7C%20T1059%20%7C%20T1136%20%7C%20T1053-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20VirusTotal-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Hunt Title** | C2 Communication via Anomalous Extension Binary |
| **Date** | June 6, 2024 |
| **Affected Host** | ip-172-31-13-20.us-east-2.compute.internal |
| **Affected User** | LetsDefend |
| **Malicious File** | application_form.pdf.exe |
| **C2 IP** | 13.232.55.12 |
| **C2 Port** | 30 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Active C2 communication confirmed |

---

## 🎯 Scenario

A security tool alerted on a suspicious file with an anomalous extension. The objective was to hunt through Splunk logs to uncover C2 communication and attacker activities — demonstrating proactive threat hunting skills rather than reactive alert triage.

This is **threat hunting** — starting from a single suspicious indicator and following the evidence trail to reconstruct the full attack chain.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Splunk** | Log aggregation and threat hunting queries |
| **Sysmon** | Endpoint telemetry — process, network, file, registry events |
| **VirusTotal** | IP and hash reputation validation |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| `sysmon.json` | Sysmon logs ingested into Splunk |
| Sysmon Event ID 1 | Process creation events |
| Sysmon Event ID 3 | Network connection events |
| Sysmon Event ID 11 | File creation events |
| Sysmon Event ID 13 | Registry modification events |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1071 — C2 Application Layer Protocol | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1059.003 — Windows Command Shell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/003/) |
| MITRE T1136 — Create Account | [attack.mitre.org](https://attack.mitre.org/techniques/T1136/) |
| MITRE T1036 — Masquerading | [attack.mitre.org](https://attack.mitre.org/techniques/T1036/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |

---

## 🔍 Hunt Methodology
```
Step 1 → Network Connections    (Event ID 3 — who is calling home?)
Step 2 → File Creation          (Event ID 11 — how did the file arrive?)
Step 3 → Process Execution      (Event ID 1 — what did it spawn?)
Step 4 → Attacker Commands      (Event ID 1 — what did cmd.exe run?)
Step 5 → Persistence            (Event ID 1 — was a new user created?)
Step 6 → PowerShell Activity    (Event ID 1+11 — any scripts dropped?)
Step 7 → Firewall Correlation   (Event ID 13 — when did the system respond?)
```

---

## 🕵️ Hunt

### Step 1 — Network Connections: Finding the C2

The hunt started with **Sysmon Event ID 3** — Network Connection events. This event logs every outbound connection a process makes, including the destination IP, port, and the process responsible.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-15-134.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=3
| table _time, Event.EventData.Image, Event.EventData.DestinationIp,
  Event.EventData.DestinationPort, Event.EventData.User
```

> <img width="902" height="398" alt="1" src="https://github.com/user-attachments/assets/bb13c141-6e71-4270-9906-7396ac8e186d" />

```
Time:             2026-04-02 04:22:06
Process:          C:\Users\LetsDefend\Downloads\application_form.pdf.exe
Destination IP:   13.232.55.12
Destination Port: 30
User:             DESKTOP-ND6FH5D\LetsDefend
```

**Two immediate red flags:**

**1 — Double Extension Masquerading**
```
application_form.pdf.exe
```
The file uses a double extension — disguised as a PDF but the real extension is `.exe`. This is the **anomalous extension** the security tool flagged. Windows hides known extensions by default, so the file appears as `application_form.pdf` to the user — a classic social engineering trick.

**2 — Non-Standard C2 Port**
```
Port 30 — no standard service assignment
```
Legitimate applications use well-known ports (80, 443, 8080). Port 30 indicates the attacker deliberately configured their C2 server on an obscure port to avoid basic firewall detection rules.

> **🔍 Why Event ID 3 first?**
> Network connections are the most direct evidence of C2 communication. A binary sitting idle tells us little — but the moment it reaches out to an external IP, it reveals the attacker's infrastructure. Event ID 3 shows us which process made the connection, where it went, and on which port.

---

### Step 2 — File Creation: How Did It Arrive?

With the malicious binary identified, I used **Sysmon Event ID 11** to find how `application_form.pdf.exe` landed on the system.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-15-134.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=11 "application_form.pdf.exe"
| table Event.EventData.Image, Event.EventData.TargetFilename
```

> <img width="1075" height="399" alt="2" src="https://github.com/user-attachments/assets/3b6da1fa-b3e8-45de-bdfd-b7c26fc40824" />

```
Image:       C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
TargetFile:  C:\Users\LetsDefend\Downloads\application_form.pdf.exe:Zone.Identifier
```

**1 — Microsoft Edge downloaded the file**
```
msedge.exe created application_form.pdf.exe
→ User clicked a malicious link in the browser
```

**2 — Zone.Identifier confirms internet origin**
```
:Zone.Identifier = NTFS Alternate Data Stream
→ Windows tags all files downloaded from the internet
→ Confirms external web source — not USB or internal share
```

> **🔍 Why Event ID 11?**
> File creation events answer "how did it get here." The Image field tells us which process created the file. msedge.exe as the creator means browser-based download — pointing to a phishing link or drive-by download.

---

### Step 3 — Process Execution: The Attack Chain

I hunted **Sysmon Event ID 1** to see the full execution chain spawned by `application_form.pdf.exe`.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-13-20.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=1 "application_form.pdf.exe"
| table Event.EventData.UtcTime, Event.EventData.CommandLine,
  Event.EventData.ParentCommandLine
```

> <img width="1210" height="265" alt="3" src="https://github.com/user-attachments/assets/11bc9455-c12b-41ea-ad3c-7617862ddd2f" />

```
2024-06-06 09:28:07  application_form.pdf.exe   Parent: Explorer.EXE
2024-06-06 09:28:55  cmd.exe                    Parent: application_form.pdf.exe
```
```
Explorer.EXE (user double-clicked the file)
    ↓
application_form.pdf.exe (trojan executed)
    ↓
cmd.exe (command shell spawned)
```

**Explorer.EXE as parent confirms manual execution** — the user double-clicked the file thinking it was a PDF. The trojan immediately spawned `cmd.exe` to begin attacker commands.

> **🔍 Why Event ID 1?**
> Process Creation gives us the full parent-child relationship. `cmd.exe` spawned by a file from the Downloads folder is an immediate red flag. Legitimate PDF files do not open command prompts.

---
### Step 4 — Attacker Commands: What Did cmd.exe Run?

I expanded to find all commands executed through `cmd.exe`.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-13-20.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=1 "cmd.exe"
| table Event.EventData.UtcTime, Event.EventData.CommandLine,
  Event.EventData.ParentCommandLine
```

> <img width="1186" height="396" alt="4" src="https://github.com/user-attachments/assets/81465b0e-1499-429a-9a9e-82b44be8f7b6" />


| Time | Command | Purpose |
|---|---|---|
| 09:28:55 | `cmd.exe` spawned | Shell opened by trojan |
| 09:28:59 | `whoami` | Check current user and privileges |
| 09:29:22 | `tasklist` | Enumerate running processes |
| 09:40:46 | `powershell.exe` | Upgrade to PowerShell for advanced capabilities |

This is a textbook **post-exploitation reconnaissance sequence:**
```
Get a shell → check who I am → enumerate processes → upgrade to PowerShell
```

---

### Step 5 — Persistence: New User Created

I hunted for `net user` commands to check if the attacker created a backdoor account.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-13-20.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=1 "net"
| table Event.EventData.UtcTime, Event.EventData.CommandLine,
  Event.EventData.ParentCommandLine
```

> <img width="1172" height="319" alt="5" src="https://github.com/user-attachments/assets/7a6953b5-4717-4ad4-b39f-84acd62a2566" />

```
2024-06-06 09:31:57  net user jumpadmin U7gk54skuvhs@1 /add
2024-06-06 09:32:07  net user   ← verifying the account was created
```

**Persistence confirmed:**
```
Username:  jumpadmin
Password:  U7gk54skuvhs@1
```

The username `jumpadmin` is deliberately chosen to blend with legitimate administrator accounts — a common technique to avoid suspicion during a casual review of user accounts.

---

### Step 6 — PowerShell Activity: Scripts Dropped

I investigated what PowerShell did after being launched by `cmd.exe`.

**Splunk query — files created by PowerShell (Event ID 11):**
```splunk
source="sysmon.json" host="ip-172-31-13-20.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=11 "powershell.exe"
| table Event.System.TimeCreated.#attributes.SystemTime,
  Event.EventData.TargetFilename, Event.EventData.Image
```
> <img width="1213" height="427" alt="6" src="https://github.com/user-attachments/assets/14b34936-6d34-44ef-8d3d-d2b723b3a638" />

```
2024-06-06T09:40:47Z  C:\Users\LetsDefend\AppData\Local\Temp\__PSScriptPolicyTest_i4gtmd03.cxz.ps1
2024-06-06T09:41:44Z  C:\Windows\Temp\tmp.ps1
2024-06-06T09:42:08Z  C:\Users\LetsDefend\AppData\Local\Temp\__PSScriptPolicyTest_kzd5gc12.vcd.ps1
```

**Splunk query — PowerShell command line (Event ID 1):**
```splunk
source="sysmon.json" host="ip-172-31-13-20.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=1 "powershell.exe"
| table Event.System.TimeCreated.#attributes.SystemTime, Event.EventData.CommandLine
```

> <img width="1174" height="315" alt="7" src="https://github.com/user-attachments/assets/5c3e94e7-260a-4d0b-8ef5-e9e98d08640c" />

```
2024-06-06T09:42:08Z
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass
```

**Two findings:**

**1 — Execution Policy Bypass**
```
-ep bypass → ignores system script execution policy
→ Allows unsigned malicious scripts to run without restriction
```

**2 — Scripts Dropped in Temp**
```
C:\Windows\Temp\tmp.ps1  ← unknown payload — contents require forensic review
```
Temp directories are commonly used for staging because they are writable
by all users and often excluded from antivirus scanning.

---
### Step 7 — Firewall Correlation: System Response

The final step was correlating the attacker's timeline with the system
administrator's containment response using **Sysmon Event ID 13** —
Registry Value Set — since Windows Firewall rules are stored in the registry.

**Splunk query:**
```splunk
source="sysmon.json" host="ip-172-31-1-116.us-east-2.compute.internal"
sourcetype="_json" "Event.System.EventID"=13 "FirewallPolicy"
| table Event.System.TimeCreated.#attributes.SystemTime,
  Event.EventData.Details, Event.EventData.TargetObject, Event.EventData.Image
| uniq
```

>  <img width="1072" height="263" alt="8" src="https://github.com/user-attachments/assets/f05d86d3-d88c-4c41-843e-0832de524d63" />


> <img width="941" height="460" alt="9" src="https://github.com/user-attachments/assets/a97fa783-df15-468a-97d4-aa88cb14db4b" />

```
Time:         2024-06-06T09:46:03Z
Event Type:   SetValue
Image:        C:\Windows\system32\svchost.exe
TargetObject: HKLM\System\CurrentControlSet\Services\SharedAccess\
              Parameters\FirewallPolicy\FirewallRules\{06FFAC87-...}
Details:      v2.30|Action=Block|Active=TRUE|Dir=Out|RA4=13.232.55.12|Name=secevent1|
User:         NT AUTHORITY\LOCAL SERVICE
```

Firewall rule breakdown:
```
Action=Block     ← blocking traffic
Active=TRUE      ← rule is live
Dir=Out          ← outbound connections
RA4=13.232.55.12 ← blocking the C2 IP specifically
Name=secevent1   ← rule created by the administrator
```

The containment happened at **09:46:03** — approximately **18 minutes**
after the trojan first executed at 09:28:07. That 18-minute window is
where all attacker activity occurred.

> **🔍 Why Event ID 13 for firewall correlation?**
> Windows Firewall rules are stored in the registry. When an administrator
> adds a rule, it writes to HKLM\...\FirewallPolicy — which Sysmon logs
> as Event ID 13. This lets us pinpoint exactly when containment happened
> relative to the attacker's activity timeline.

---
