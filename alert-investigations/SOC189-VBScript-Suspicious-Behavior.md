# 🟡 SOC189 — VBScript Suspicious Behavior Detected

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Medium-yellow?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-Phishing%20%7C%20VBScript%20%7C%20RAT%20%7C%20Persistence-orange?style=flat)
![Verdict](https://img.shields.io/badge/Verdict-True%20Positive-red?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1566%20%7C%20T1059%20%7C%20T1547%20%7C%20T1071-blue?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Event ID** | 139 |
| **Alert** | SOC189 - VBScript Suspicious Behavior Detected |
| **Date** | April 20, 2023 — 09:42 AM |
| **Severity** | 🟡 Medium |
| **Hostname** | David |
| **IP Address** | 172.16.17.31 |
| **Related Binary** | Purchase_Order.xls.vbs |
| **Binary Path** | C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs |
| **MD5** | 8FAF36EDFAE1EC0E8ECCD3C562C03903 |
| **Device Action** | Allowed — not blocked |
| **Verdict** | ✅ True Positive — Active RAT infection confirmed |

---

## 🎯 Scenario

On April 20, 2023 at 09:42 AM, an alert was triggered by SOC rule SOC189 — VBScript Suspicious Behavior Detected. The rule fired after a VBScript file attempted to access sensitive system resources not related to its expected functionality, specifically the Windows Registry.

The L1 analyst noted the hash matched a known wshrat variant and escalated for further investigation. My task was to confirm whether this was a true positive, trace the full attack chain, and determine the scope of compromise.

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Alert dashboard | SOC189 alert details and metadata |
| Email gateway | Incoming email logs for david@letsdefend.io |
| VirusTotal | Hash reputation analysis |
| Endpoint logs | Process, network, and browser history for 172.16.17.31 |
| Sysmon Event ID 13 | Registry modification evidence |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1566 — Phishing | [attack.mitre.org](https://attack.mitre.org/techniques/T1566/) |
| MITRE T1059.005 — VBScript | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/005/) |
| MITRE T1547.001 — Registry Run Keys | [attack.mitre.org](https://attack.mitre.org/techniques/T1547/001/) |
| MITRE T1071 — C2 Protocol | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) |
| Sysmon Event IDs | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |

---

## 🔍 Investigation Methodology
```
Step 1 → Hash Reputation Check     (is this file known malicious?)
Step 2 → Initial Access             (how did it arrive on the network?)
Step 3 → Execution Confirmation     (was it actually run?)
Step 4 → Post-Execution Behavior    (what did it do after running?)
         → C2 Communication
         → Persistence
         → Privilege Escalation
         → Lateral Movement
Step 5 → Expanded Search            (any other machines affected?)
Step 6 → Remediation & Recovery
```

---

## 🕵️ Investigation

### Step 1 — Hash Reputation Check

The first step was to check the reputation of the file hash provided in the alert.
```
MD5: 8FAF36EDFAE1EC0E8ECCD3C562C03903
```

> 📸 <img width="892" height="386" alt="21" src="https://github.com/user-attachments/assets/74777d94-5f61-4563-a586-0e3cef528cc1" />

```
Detections:      33 / 62 engines flagged as malicious
Community Score: -46  ← strongly malicious
File:            Purchase_Order.xls.vbs
Size:            527.62 KB
```

**Behavioral tags:**

| Tag | Meaning |
|---|---|
| `vba` | VBA/VBScript based malware |
| `calls-wmi` | Uses Windows Management Instrumentation |
| `direct-cpu-clock-access` | Sandbox evasion technique |
| `runtime-modules` | Loads modules at runtime — evades static analysis |
| `long-sleeps` | Sleeps to evade sandbox timeouts |
| `persistence` | Confirmed persistence mechanism |
| `malware` | Confirmed malicious |

**VirusTotal Code Insights:**
```
"VBScript designed to establish and maintain remote control over a
 compromised system. Employs an initial layer of obfuscation to hide
 its primary script content, which is deobfuscated during execution."
```

**Verdict: Confirmed malicious — wshrat variant (Remote Access Trojan)**

> The filename `Purchase_Order.xls.vbs` uses a double extension — disguised
> as an Excel spreadsheet to trick the user into executing it.

---

### Step 2 — Initial Access: How Did It Arrive?

With the file confirmed malicious I checked the email gateway for
`david@letsdefend.io` around the alert time.

#### The Phishing Email — GoDaddy Brand Impersonation

> <img width="604" height="216" alt="223" src="https://github.com/user-attachments/assets/391dce9c-5aad-4d24-8d21-0813fece7209" />

```
From:     support@gododdy.com
To:       david@letsdefend.io
Subject:  Your domain registration has confirmed
Date:     Apr 20, 2023 08:55 AM
Action:   Allowed
```

At first glance this appeared to be a legitimate GoDaddy order
confirmation email. However, I investigated the embedded links
using **Browserling** to safely analyze the URL behavior without
executing it on a real machine.

> <img width="609" height="319" alt="45" src="https://github.com/user-attachments/assets/47ae9211-fcd4-4bae-9087-4e084d85032b" />


The "Access All Products" button — which appeared legitimate —
actually redirected to a malicious download page:
```
Displayed link:  GoDaddy order confirmation
Real URL:        https://download.cyberlearn.academy/download/download?url=
                 https://files-ld.s3.us-east-2.amazonaws.com/Purchase_Order.zip
```

This is **Brand Impersonation Phishing** — the attacker:

| Step | Technique |
|---|---|
| Spoofed a GoDaddy order confirmation | Built trust using a known brand |
| Replaced the real button URL | Hidden malicious redirect |
| Hosted malware on AWS S3 | Abused trusted cloud infrastructure |
| Named the file Purchase_Order.zip | Matched the email lure context |

**Delivery chain confirmed:**
```
Spoofed GoDaddy email received by David
→ David trusted it — looked like a real order confirmation
→ Clicked "Access All Products" button
→ Redirected to: download.cyberlearn.academy
→ Browser downloaded Purchase_Order.zip from AWS S3
→ David extracted the ZIP
→ Double-clicked Purchase_Order.xls.vbs
   (appeared as Purchase_Order.xls — Windows hid the .vbs extension)
→ WScript.exe executed the RAT
→ Alert triggered at 09:42 AM
```

> This attack succeeded because it exploited **trust** — not a
> technical vulnerability. The email looked real, the brand was
> familiar, and the action (clicking a button in an order email)
> felt natural and expected.
---

### Step 3 — Execution Confirmation

I checked the endpoint process logs for host David (172.16.17.31).

> <img width="593" height="232" alt="145" src="https://github.com/user-attachments/assets/fa9512d8-59c3-4b1b-a36a-d057d5f5be4b" />

```
Event Time:   2023-04-20 09:42:08.918
Process:      WScript.exe
Command Line: "C:\Windows\System32\WScript.exe"
              "C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs"
Parent Name:  Explorer.exe
Parent Path:  C:\Windows\explorer.exe
```

**Execution confirmed.**

| Finding | Meaning |
|---|---|
| `WScript.exe` executed the file | Windows Script Host ran the VBScript |
| Parent process is `Explorer.exe` | David manually double-clicked the file |
| Timestamp matches alert exactly | This is the triggering event |
| Path is in Downloads folder | Confirms ZIP was extracted before execution |

---
### Step 4 — Post-Execution Behavior

#### Persistence — Registry Run Key

I opened Event Viewer and navigated to Sysmon logs:
```
Applications and Services Logs
→ Microsoft → Windows → Sysmon → Operational
Filter: Event ID 13 (Registry Value Set)
```

> 📸 <img width="599" height="393" alt="159" src="https://github.com/user-attachments/assets/ce8e5864-b6b9-48e1-8638-bea3da0dadff" />

```
Event ID:    13 — Registry Value Set
Time:        4/20/2023 9:43:09 AM
Process:     C:\Windows\System32\wscript.exe
PID:         7092
Target Key:  HKCU\S-1-5-21-3163960855-2866672989-1813526453-1008\
             Software\Microsoft\Windows\CurrentVersion\Run\Purchase_Order
Value:       wscript.exe //B
             "C:\Users\LETSDE~1\AppData\Local\Temp\1\Purchase_Order.xls.vbs"
User:        EC2AMAZ-ILGVOIN\LetsDefend
```

**Persistence confirmed** — malware added itself to the Windows startup registry key.

This means:
```
Every time David logs into Windows
→ wscript.exe automatically executes Purchase_Order.xls.vbs
→ C2 connection re-established
→ Attacker regains access automatically
```

The VBScript also **copied itself to the Temp folder:**
```
C:\Users\LETSDE~1\AppData\Local\Temp\1\Purchase_Order.xls.vbs
```
This ensures the payload survives even if the original file in Downloads is deleted.

#### Privilege Escalation
```
No indicators of privilege escalation found.
Malware operated under the current user account context.
```

#### Credential Access
```
No indicators of credential access or password harvesting found.
```

#### Lateral Movement
```
No indicators of lateral movement found.
Infection appears contained to host David (172.16.17.31).
```

---
---

## ⏱️ Complete Attack Timeline
```
Apr 20, 2023


~09:3X AM →  Phishing email received — contained malicious download link
~09:3X AM →  David clicked the link
              Browser downloaded Purchase_Order.zip from AWS S3
~09:4X AM →  David extracted the ZIP
              Double-clicked Purchase_Order.xls.vbs (thought it was Excel)
09:42:08  →  WScript.exe executed the VBScript
              Alert SOC189 triggered
09:43:09  →  Registry Run key created — persistence established
              HKCU\...\CurrentVersion\Run\Purchase_Order
              VBScript copied to AppData\Local\Temp\
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Victim Host** | David — 172.16.17.31 |
| **Malicious File** | Purchase_Order.xls.vbs |
| **File MD5** | 8FAF36EDFAE1EC0E8ECCD3C562C03903 |
| **File Size** | 527.62 KB |
| **Original Path** | C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs |
| **Persistence Path** | C:\Users\LETSDE~1\AppData\Local\Temp\1\Purchase_Order.xls.vbs |
| **Download URL** | https://download.cyberlearn.academy/download/download_file/ |
| **Hosting** | files-ld.s3.us-east-2.amazonaws.com |
| **Registry Key** | HKCU\...\Software\Microsoft\Windows\CurrentVersion\Run\Purchase_Order |
| **Malware Family** | wshrat — WSH RAT |
| **Execution Method** | WScript.exe |

---

## 🗺️ MITRE ATT&CK Mapping

| Phase | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Spoofed GoDaddy email with malicious button redirect |
| Execution | User Execution: Malicious File | T1204.002 | David double-clicked the VBScript |
| Execution | Command and Scripting: VBScript | T1059.005 | WScript.exe executed .vbs file |
| Persistence | Registry Run Keys | T1547.001 | HKCU\...\CurrentVersion\Run\Purchase_Order |
| Defense Evasion | Obfuscated Files | T1027 | VBScript deobfuscates at runtime |
| Defense Evasion | Masquerading | T1036 | Double extension .xls.vbs |


---

## 💡 Key Lessons Learned

**1 — Double Extensions Are a Red Flag**
`Purchase_Order.xls.vbs` appeared as `Purchase_Order.xls` to David because Windows hides known extensions. Always enable "Show file extensions" via GPO across all endpoints.

**2 — The Temp Folder Is a Persistence Indicator**
The malware copied itself to `AppData\Local\Temp\` before creating the registry Run key. Always check the Temp folder during malware investigations.

**3 — Registry Run Key = Automatic Reinfection**
Even if the original file is deleted, the malware persists via the Run key pointing to the Temp folder copy. Remediation must address both the file AND the registry key.

**4 — Sysmon Event ID 13 Is Your Persistence Detector**
Event ID 13 targeting `CurrentVersion\Run` is the definitive indicator of startup persistence. This should be an active detection rule in every SOC.

**5 — 33/62 Detections Is Not 100%**
The file evaded 29 AV engines using obfuscation, long sleeps, and runtime deobfuscation. Behavioral analysis and registry monitoring caught what static analysis missed.

---

## 🔧 Remediation & Recovery

| Priority | Action |
|---|---|
| 🔴 Critical | Isolate host David (172.16.17.31) immediately |
| 🔴 Critical | Delete registry key: HKCU\...\CurrentVersion\Run\Purchase_Order |
| 🔴 Critical | Delete: C:\Users\LETSDE~1\AppData\Local\Temp\1\Purchase_Order.xls.vbs |
| 🔴 Critical | Delete: C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs |
| 🟠 High | Block MD5: 8FAF36EDFAE1EC0E8ECCD3C562C03903 in EDR |
| 🟠 High | Block domain: download.cyberlearn.academy at firewall |
| 🟠 High | Block: files-ld.s3.us-east-2.amazonaws.com |
| 🟠 High | Reset David's credentials — RAT had remote access |
| 🟠 High | Scan all endpoints for the same MD5 hash |
| 🟡 Medium | Enable "Show file extensions" via GPO across all endpoints |
| 🟡 Medium | Add Sysmon alert rule on CurrentVersion\Run modifications |
| 🟡 Medium | Security awareness training — phishing and file extensions |
| 🟢 Low | Review email gateway rules for ZIP archives containing VBS |

---

## ✅ Conclusion — Final Verdict
```
Verdict:  TRUE POSITIVE ✅
Status:   Active RAT infection — host compromised
Scope:    Contained to David (172.16.17.31)
          No lateral movement detected
          No privilege escalation detected
          No credential access detected
```

The attack followed a classic phishing chain:
```
Phishing email → malicious link → ZIP download →
VBScript execution →  persistence via registry Run key
```

> *The attacker didn't need a zero-day.*
> *They needed David to double-click a file.*
> *That's why security awareness matters as much as technical controls.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Sysmon Documentation | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| VirusTotal | [virustotal.com](https://www.virustotal.com) |

---
