# 🔴 Digital Forensics Investigation — USB Data Exfiltration: Payroll & PII Breach

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Digital%20Forensics%20%7C%20Endpoint%20Triage-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-USB%20Exfiltration%20%7C%20PII%20Theft%20%7C%20Insider%20Threat-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1052.001%20%7C%20T1005%20%7C%20T1078-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Registry%20Explorer%20%7C%20ShellBags%20Explorer%20%7C%20JLECmd%20%7C%20Event%20Viewer-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | USB Data Exfiltration — Payroll & PII Breach |
| **Date of Incident** | July 15, 2024 |
| **Affected Machine** | `DESKTOP-ND6FH5D` |
| **MAC Address** | `00:0c:29:eb:ef:7f` |
| **USB Device** | VendorCo — Serial: `563931126217413` |
| **Drive Letter Assigned** | `E:` |
| **Volume GUID** | `{bee66e53-012e-11ee-8012-000c29ebef7f}` |
| **Files Accessed** | `Employee_PII.csv` / `Employees_USDAccounts.csv` |
| **First Connection** | 2024-07-15 03:36:22 AM |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Deliberate USB-based data exfiltration confirmed across multiple artifact sources |

---

## 🎯 Scenario

A recent data breach severely impacted the organization, raising concerns about unauthorized access to sensitive payroll and employee data. Triage data was collected from a suspected endpoint and handed over for forensic analysis. The objective: examine the evidence, uncover signs of unauthorized access or data exfiltration, and determine the root cause of the leak.

What the investigation revealed was precise and deliberate — at 3:36 in the morning, a USB device was connected to workstation `DESKTOP-ND6FH5D`. Within two minutes, the person behind the keyboard had navigated deep into a payroll folder structure and opened two highly sensitive files: `Employee_PII.csv` containing personally identifiable information for all new hires, and `Employees_USDAccounts.csv` containing employee financial account data. The access was surgical — each file opened exactly once, then the session ended.

This writeup traces the full forensic chain across six artifact sources — registry hives, NTFS event logs, ShellBags, Jump Lists, and LNK files — building the complete picture of what happened, when, and what was taken.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Registry Explorer** | Parse SYSTEM and NTUSER.DAT registry hives — USBSTOR, MountPoints2 |
| **ShellBags Explorer** | Parse UsrClass.dat — folder navigation history on USB |
| **JLECmd** | Parse Jump List files — specific files opened per application |
| **Event Viewer** | Parse Microsoft-Windows-Ntfs/Operational log — volume mount events |
| **LECmd** | Parse LNK shortcut files — recently accessed files |

---

## 🗂️ Artifacts Analyzed

| Artifact | File Location | What it provided |
|---|---|---|
| USBSTOR Registry | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | USB device identity, serial number, timestamps |
| NTFS Operational Log | `Microsoft-Windows-Ntfs/Operational.evtx` | Volume mount — drive letter E: assigned |
| ShellBags | `C:\Users\LetsDefend\AppData\Local\Microsoft\Windows\UsrClass.dat` | Folder navigation on USB |
| Jump Lists | `C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` | Specific files opened |
| LNK Files | `C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\Recent\` | File access evidence |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1052.001 — Exfiltration over USB | [attack.mitre.org](https://attack.mitre.org/techniques/T1052/001/) |
| MITRE T1005 — Data from Local System | [attack.mitre.org](https://attack.mitre.org/techniques/T1005/) |
| MITRE T1078 — Valid Accounts | [attack.mitre.org](https://attack.mitre.org/techniques/T1078/) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| Windows USBSTOR Forensics | [forensicswiki.org](https://forensicswiki.org/) |

---

## 🔍 Investigation Methodology

```
Phase 1 → USB Device Identification    (SYSTEM hive — USBSTOR key)
Phase 2 → Volume Mount Confirmation    (NTFS Operational log — Event ID 142)
Phase 3 → Folder Navigation Evidence   (UsrClass.dat — ShellBags Explorer)
Phase 4 → File Access Evidence         (AutomaticDestinations — JLECmd)
Phase 5 → Machine & User Confirmation  (Jump List properties — hostname, MAC)
Phase 6 → Timeline Construction        (All artifacts combined)
```

---

## 🕵️ Investigation

### Phase 1 — USB Device Identification: The SYSTEM Hive & USBSTOR

Every USB forensics investigation begins in the same place — the Windows registry. When a USB storage device is connected to a Windows machine for the first time, Windows automatically creates a registry entry that records the device's identity and connection history. This entry persists permanently — even after the USB is removed, even after the system is rebooted, even years later.

The artifact that captures this is the **USBSTOR** registry key, which lives inside the **SYSTEM** hive.

> ### 🔎 What is the SYSTEM Hive?
> The Windows registry is divided into several "hives" — each a separate file on disk that stores a different category of system configuration. The **SYSTEM** hive (`C:\Windows\System32\config\SYSTEM`) contains hardware configuration, device drivers, service settings, and critically for us — the record of every USB device ever connected to this machine.
>
> When performing forensic analysis, we load this file directly into **Registry Explorer** — an Eric Zimmermann tool designed specifically for forensic registry analysis. It supports "dirty hive" loading (loading LOG1 and LOG2 transaction files alongside the main hive to ensure completeness) and provides a clean tree view with full timestamp visibility.

We opened the SYSTEM hive in Registry Explorer and navigated to:

```
ROOT → ControlSet001 → Enum → USBSTOR
```

> 📸 *Screenshot: Registry Explorer — SYSTEM hive loaded, USBSTOR key expanded showing Disk&Ven_VendorCo... → 563931126217413... → Device Parameters and Properties subkeys*

---

#### Understanding the USBSTOR Architecture

The USBSTOR key has a precise hierarchical structure — each level tells us something specific about the device:

```
USBSTOR
└── Disk&Ven_VendorCo...          ← Level 1: Device Class
        └── 563931126217413...    ← Level 2: Serial Number
                ├── Device Parameters
                │   ├── MediaChange    ← media change events
                │   └── Partmgr        ← partition manager (Count: 4)
                └── Properties
                        ├── {3464f7a4-...}  ← device description
                        ├── {540b947e-...}  ← device capabilities
                        ├── {80497100-...}  ← device class info
                        ├── {83da6326-...}  ← TIMESTAMPS ← most important
                        └── {a8b865dd-...}  ← device interface
```

**Level 1 — `Disk&Ven_VendorCo...`**

This folder's name follows a strict format:
```
Disk & Ven_[Vendor] & Prod_[Product] & Rev_[Revision]
→ Disk     = storage device type
→ Ven_     = vendor/manufacturer name
→ Prod_    = product/model name
→ Rev_     = firmware revision number
```
This identifies the TYPE and MODEL of USB device — in our case, a VendorCo branded drive.

**Level 2 — `563931126217413...` (Serial Number)**

This is the USB device's unique serial number — burned into the device's firmware at manufacturing. Every USB drive has a different one. Forensically, this is the device's fingerprint:
```
Full key name: 563931126217413391 70
Serial number: 563931126217413391 70  (omit &0 suffix per hint)
```

> ### 🔎 Why does the serial number matter?
> The serial number is what allows us to prove that a **specific physical USB device** was used — not just "some USB drive." If law enforcement recovers a USB device from a suspect, the serial number from their device can be matched against the registry entry on the compromised machine. This is chain-of-custody evidence.

**Device Parameters**

```
├── MediaChange  → logs media change events (insert/remove)
└── Partmgr      → partition manager data
                   Count: 4 → four partition-related events recorded
```

**Properties — The Gold Mine**

Each `{GUID}` subfolder under Properties contains specific device attributes:

| GUID | Contents |
|---|---|
| `{3464f7a4-...}` | Device hardware description |
| `{540b947e-...}` | Device capabilities flags |
| `{80497100-...}` | Device class information |
| `{83da6326-...}` | **Device timestamps** ← forensic gold |
| `{a8b865dd-...}` | Device interface information |

---

#### The Timestamp GUID — `{83da6326-...}`

Expanding `{83da6326-...}` reveals the device's connection history through timestamp subkeys:

> 📸 *Screenshot: Registry Explorer — {83da6326-...} expanded showing subkeys 0003, 000A, 0064, 0065, 0066 with 0064 selected and Value showing 2024-07-15 03:36:22*

```
{83da6326-...}
├── 0003  → Unknown
├── 000A  → Unknown
├── 0064  → First Install Date    ← when was this USB FIRST ever connected?
├── 0065  → ???
└── 0066  → Last Arrival          ← when was it last connected?
    0067  → Last Removal          ← when was it last disconnected?
```

**Clicking `0064`:**
```
Value Name:  (default)
Value Type:  RegFileTime
Value:       2024-07-15 03:36:22   ← FIRST INSTALL TIMESTAMP
```

> ### 🔎 What is RegFileTime?
> `RegFileTime` is a Windows timestamp format stored as a 64-bit integer representing the number of 100-nanosecond intervals since January 1, 1601. Registry Explorer automatically converts this to human-readable format. The `0064` subkey records the **very first time** this USB device was ever connected to this specific machine — this timestamp is set once and never changes, making it one of the most reliable forensic timestamps available.

**Finding:**
```
First Install: 2024-07-15 03:36:22 AM
→ This USB was connected for the FIRST TIME at 3:36 AM
→ Middle of the night — not normal business hours 🚨
→ Suggests deliberate, covert action
```

---

#### Device Values at the Serial Number Level

> 📸 *Screenshot: Registry Explorer — serial number key selected, right panel showing HardwareID, CompatibleIDs, ClassGUID, FriendlyName: VendorCo Pro..., ContainerID values*

```
HardwareID:    USBSTOR\Disk...
ClassGUID:     {4d36e967-...}     ← Windows Disk Drive class
Service:       disk
FriendlyName:  VendorCo Pro...    ← device display name
ContainerID:   {f1c88cd7-c32b-59e6-b618-ea11f4b57bc3}
```

> ### 🔎 What is the ContainerID?
> The ContainerID is a unique identifier that links a physical device across multiple registry locations. The same ContainerID appears in `HKLM\SYSTEM\CurrentControlSet\Enum\USB`, `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, and `HKLM\SOFTWARE\Microsoft\Windows Portable Devices`. Using this GUID, we can cross-reference the same device across all registry locations to build a complete picture.

---

### Phase 2 — Volume Mount Confirmation: NTFS Operational Log

With the USB device identified in the registry, the next step was to confirm the volume mount event — specifically, what drive letter Windows assigned to the USB and when.

This evidence comes from the **Microsoft-Windows-Ntfs/Operational** event log — a specialized Windows log that records NTFS filesystem operations including volume mount and dismount events.

> 📸 *Screenshot: Event Viewer — Microsoft-Windows-Ntfs/Operational log showing 26 events, Event ID 142 at 7/15/2024 3:36:24 AM highlighted, details panel showing volume E: and GUID*

```
Log:       Microsoft-Windows-Ntfs/Operational
Event ID:  142
Source:    Ntfs (Microsoft-Windows-Ntfs)
Time:      7/15/2024 3:36:24 AM
Level:     Information
Computer:  DESKTOP-ND6FH5D
User:      SYSTEM
```

**Event Content:**
```
Summary of disk space usage since last event:

Lowest free space in bytes:   9,855,660,032  (~9.18 GB)
Highest free space in bytes:  9,855,660,032  (~9.18 GB)
Page file size in bytes:      0
Volume GUID:   {bee66e53-012e-11ee-8012-000c29ebef7f}
Volume name:   E:                ← 🚨 USB assigned drive letter E:
Is boot volume: false            ← confirms this is NOT the system drive
```

> ### 🔎 What is Event ID 142?
> Event ID 142 in the NTFS Operational log fires when Windows mounts a new NTFS volume and records a summary of disk space statistics. The critical fields for USB forensics are:
> - **Volume name (E:)** — the drive letter assigned to the USB
> - **Volume GUID** — the unique identifier of this specific volume, used to cross-reference with other artifacts
> - **Is boot volume: false** — confirms this is a removable/external drive, not the system disk
> - **Timestamp** — exactly when the volume was mounted

**Key Correlations:**
```
USBSTOR First Install: 2024-07-15 03:36:22 (Registry)
NTFS Event 142:        2024-07-15 03:36:24 (Event Log)
→ 2 second difference = same connection event ✅
→ Registry recorded device detection first
→ NTFS recorded volume mount 2 seconds later (normal behavior)

Volume GUID cross-reference:
NTFS Event 142:  {bee66e53-012e-11ee-8012-000c29ebef7f}
Jump List droid:  bee66e72-012e-11ee-8012-000c29ebef7f
→ Same volume identifier → same USB device ✅
```

> ### 🔎 Why is cross-referencing GUIDs important?
> Each artifact source records the same event from a different perspective. When the Volume GUID from the NTFS log matches the File Droid from the Jump List, we have **independent corroboration** — two completely separate logging systems recording the same device. This type of cross-artifact validation is what makes digital forensic evidence court-admissible.

**Machine Confirmation:**
```
Computer: DESKTOP-ND6FH5D
→ This is the compromised endpoint
→ Cross-confirmed across all subsequent artifacts
```

---

### Phase 3 — Folder Navigation: ShellBags Reveal the Path

The USB was mounted as `E:`. Now we needed to know whether anyone actually opened it and navigated its contents — and if so, exactly where they went. This is where **ShellBags** become invaluable.

> 📸 *Screenshot: ShellBags Explorer — UsrClass.dat loaded, tree showing Desktop → This PC → E: → NewProject_Hires_Data → Payroll_NewHires → Payroll_NewHires → Payroll_data1, with timestamps in right panel*

> ### 🔎 What are ShellBags?
> ShellBags are registry entries that Windows automatically creates whenever a user opens a folder in Windows Explorer. Windows stores each folder's display preferences (icon size, column widths, sort order) so the folder looks the same next time it's opened. As a forensic artifact, ShellBags are extraordinarily valuable because:
>
> **They persist after the USB is removed.** The ShellBag entry remains in the registry long after the device is unplugged.
>
> **They persist after files are deleted.** Even if someone deletes files from the USB, the ShellBag proves the folder was accessed.
>
> **They record the exact navigation path.** Every folder the user opened — no matter how deep — creates its own ShellBag entry.
>
> ShellBags are stored in two locations:
> ```
> NTUSER.DAT   → folders on the local C: drive
> UsrClass.dat → folders on external drives, network shares, ZIP files
>                ← THIS is where USB folder access is recorded
> ```
>
> The physical file location:
> ```
> C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat
> ```
>
> We parse this file with **ShellBags Explorer** from Eric Zimmermann tools.

**What We Found:**

```
Navigation path reconstructed from ShellBags:

Desktop
└── This PC
    └── E:                              ← USB drive opened
        └── NewProject_Hires_Data       ← folder opened on USB
            └── Payroll_NewHires        ← subfolder opened
                └── Payroll_NewHires    ← subfolder opened
                    └── Payroll_data1   ← deepest folder accessed
```

**Timestamps for `NewProject_Hires_Data`:**
```
Name:              NewProject_Hires_Data
Absolute path:     Desktop\This PC\E:\NewProject_Hires_Data
Shell type:        Directory
MRU position:      0   ← most recently used item
# of child bags:   1   ← one subfolder was explored

Target timestamps:
  Created on:      2024-07-15 03:36:46
  Modified on:     2024-07-15 03:36:46
  Last accessed:   2024-07-15 03:36:46

Last interacted:   2024-07-15 03:37:28.892
Registry write:    2024-07-15 03:37:28.892
```

**Timestamps for `Payroll_NewHires`:**
```
Created on:   2024-07-15 03:37:54
Modified on:  2024-07-15 03:37:54
Accessed on:  2024-07-15 03:37:54
Shell type:   Directory
```

> ### 🔎 Reading ShellBag Timestamps
> ShellBags record two types of timestamps that serve different forensic purposes:
>
> **Target timestamps** (Created, Modified, Accessed) — these are the timestamps of the folder itself as recorded on the USB drive's filesystem. They tell us when the folder was created on the USB.
>
> **Last interacted** — this is when the user last opened or interacted with this folder on the local machine. This is the most forensically relevant timestamp — it tells us when the suspect navigated to this location.
>
> **MRU position: 0** means this was the most recently accessed item in that location — the last thing the user opened before the session ended.

---

### Phase 4 — File Access Evidence: Jump Lists Reveal the Files

ShellBags proved which folders were accessed. But we needed to go deeper — which specific **files** were opened, not just folders? For this, we turned to **Jump Lists**.

> ### 🔎 What are Jump Lists?
> Jump Lists are Windows artifacts that track recently opened files on a per-application basis. Every time you open a file with any application, Windows records that file access in a Jump List — storing the full file path, timestamps, file size, and machine identifiers.
>
> Jump Lists are stored in:
> ```
> C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
> ```
>
> Each file in this folder is named after the **App ID** of the application:
> ```
> 9b9cdc69c1c24e2b.automaticDestinations → Notepad 64-bit
> f01b4d95cf55d32a.automaticDestinations → Windows Explorer
> 5f7b5f1e01b83767.automaticDestinations → Quick Access
> ```
>
> We parse these files using **JLECmd** (Jump List Explorer Command line) from Eric Zimmermann tools:
> ```bash
> JLECmd.exe -d "C:\Users\LetsDefend\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" --csv output\
> ```
>
> **Critical forensic value:** Jump Lists persist even after the source file is deleted. The file `Employee_PII.csv` may no longer exist anywhere — but the Jump List proves it was opened, when it was opened, and with which application.

> 📸 *Screenshot: JLECmd output — AutomaticDestinations folder showing 5 files, all modified 7/15/2024 6:38-6:39 AM, listing Quick Access, Notepad 64-bit, Windows Explorer entries*

**AutomaticDestinations Files Found:**
```
5f7b5f1e01b83767.automaticDestinations → Quick Access          7/15/2024 6:38 AM  — 2 LNK files
9b9cdc69c1c24e2b.automaticDestinations → Notepad 64-bit        7/15/2024 6:38 AM  — 2 LNK files 🚨
d06c94537ecaee12.automaticDestinations → Unknown               7/15/2024 6:38 AM  — 0 LNK files
f01b4d95cf55d32a.automaticDestinations → Windows Explorer 8.1  7/15/2024 6:39 AM  — 12 LNK files 🚨
f18460fded109990.automaticDestinations → Windows Connected Dev  6/3/2023 1:16 AM  — 1 LNK file
```

**Notepad 64-bit Jump List — Entry #0001:**

> 📸 *Screenshot: JLECmd — Notepad 64-bit Jump List expanded showing Entry #0001 and #0002, bottom panel showing LocalPath: E:\NewProject_Hires_Data\Payroll_NewHires\Payroll_NewHires\Payroll_data1\Employee_PII.csv*

```
App:                  Notepad 64-bit
App ID:               9b9cdc69c1c24e2b

Entry #0001:
LocalPath:    E:\NewProject_Hires_Data\Payroll_NewHires\
              Payroll_NewHires\Payroll_data1\Employee_PII.csv   🚨🚨🚨
Absolute path: My Computer\E:\NewProject_Hires_Data\Payroll_NewHires\
               Payroll_NewHires\Payroll_data1\Employee_PII.csv
Header.FileSize:        3,168 bytes
TargetCreationDate:     2023-04-02 18:39:40
TargetModificationDate: 2023-04-02 18:39:40
TargetLastAccessedDate: 2023-04-02 18:39:40
LocationFlags:          VolumeIdAndLocalBasePath
```

**Notepad 64-bit Jump List — Entry #0002:**

> 📸 *Screenshot: JLECmd — Entry #0002 showing LocalPath: E:\NewProject_Hires_Data\Payroll_NewHires\Payroll_NewHires\Employees_USDAccounts.csv*

```
Entry #0002:
LocalPath:    E:\NewProject_Hires_Data\Payroll_NewHires\
              Payroll_NewHires\Employees_USDAccounts.csv   🚨🚨🚨
Absolute path: My Computer\E:\NewProject_Hires_Data\Payroll_NewHires\
               Payroll_NewHires\Employees_USDAccounts.csv
Header.FileSize: 3,168 bytes
LocationFlags:   VolumeIdAndLocalBasePath
```

---

### Phase 5 — Machine & User Confirmation: Jump List Properties

The Jump List properties panel provided the final pieces — machine identity, MAC address, and precise access timestamps:

> 📸 *Screenshot: JLECmd — Properties panel showing Hostname: desktop-nd6fh5d, MAC: 00:0c:29:eb:ef:7f, DestList Last modified: 2024-07-15 03:38:07, Interaction count: 1, File droid matching NTFS volume GUID*

```
Entry number:           1
Hostname:               desktop-nd6fh5d          ← confirmed machine name
DestList Created on:    2023-06-02 10:17:57
DestList Last modified: 2024-07-15 03:38:07      ← when file was last accessed
MAC address:            00:0c:29:eb:ef:7f         ← machine hardware identifier
File droid birth:       bee66e72-012e-11ee-8012-000c29ebef7f
File droid:             bee66e72-012e-11ee-8012-000c29ebef7f
Interaction count:      1                         ← file opened exactly ONCE
```

> ### 🔎 What does each property tell us forensically?
>
> **Hostname: `desktop-nd6fh5d`** — Cross-confirms the machine name across three independent sources: NTFS Event 142, USBSTOR registry, and Jump List. Consistent hostname across all artifacts validates the evidence chain.
>
> **MAC Address: `00:0c:29:eb:ef:7f`** — The hardware address of the network interface. The `00:0c:29` prefix identifies this as a VMware virtual machine. The full MAC address uniquely identifies this specific machine and can be used to match against network logs to find this machine's activity.
>
> **DestList Last modified: `2024-07-15 03:38:07`** — This is the precise timestamp of the last file access. Only 1 minute 45 seconds after the USB was plugged in (03:36:22), the suspect had already opened a sensitive file. This speed indicates they knew exactly what they were looking for.
>
> **Interaction count: 1** — Each file was opened exactly one time. This is significant — it was not casual browsing or accidental access. The suspect opened the file, read it (or copied it), and moved on. Deliberate, purposeful access.
>
> **File droid: `bee66e72-012e-11ee-8012-000c29ebef7f`** — This GUID links the accessed file back to the specific volume (USB drive). Comparing this to our NTFS Event 142 Volume GUID (`bee66e53-012e-11ee-8012-000c29ebef7f`) — nearly identical, confirming the same USB volume. Independent corroboration across two completely separate artifact sources.

---

## 📁 Files Confirmed Accessed/Exfiltrated

| File | Full Path | Content | Risk |
|---|---|---|---|
| `Employee_PII.csv` | `E:\NewProject_Hires_Data\Payroll_NewHires\Payroll_NewHires\Payroll_data1\Employee_PII.csv` | Employee PII — names, SSN, DOB, addresses | 🔴🔴 Critical |
| `Employees_USDAccounts.csv` | `E:\NewProject_Hires_Data\Payroll_NewHires\Payroll_NewHires\Employees_USDAccounts.csv` | Employee financial account data | 🔴🔴 Critical |

> ### 🔎 Why are these files so dangerous together?
> `Employee_PII.csv` likely contains: full legal names, Social Security Numbers, dates of birth, home addresses, phone numbers, email addresses.
>
> `Employees_USDAccounts.csv` likely contains: bank account numbers, routing numbers, payment amounts, payroll dates.
>
> **Combined, these two files enable:**
> - Identity theft at scale
> - Wire fraud and unauthorized bank transfers
> - Targeted phishing using real employee data
> - Regulatory violations (GDPR, HIPAA, PCI-DSS, SOX)
> - Mandatory breach notification to affected employees and regulators

---

## ⏱️ Attack Timeline — Reconstructed from Artifacts

| Time (UTC) | Event | Artifact Source | Forensic Evidence |
|---|---|---|---|
| `03:36:22` | 🔴 USB Connected | USBSTOR Registry — `{83da6326}\0064` | First Install timestamp |
| `03:36:24` | 🔴 Volume Mounted as E: | NTFS Event ID 142 | Volume GUID `{bee66e53...}`, drive letter E: |
| `03:36:46` | 🔴 USB Drive Opened | ShellBags — UsrClass.dat | `E:` ShellBag created |
| `03:36:46` | 🔴 Folder Accessed | ShellBags — UsrClass.dat | `E:\NewProject_Hires_Data` ShellBag created |
| `03:37:28` | 🔴 Subfolder Browsed | ShellBags — UsrClass.dat | `Payroll_NewHires` last interacted |
| `03:37:54` | 🔴 Deep Folder Accessed | ShellBags — UsrClass.dat | `Payroll_data1` ShellBag created |
| `03:38:07` | 🔴🔴 PII File Opened | Jump Lists — Notepad 64-bit | `Employee_PII.csv` opened — interaction count: 1 |
| `03:38:07` | 🔴🔴 Financial File Opened | Jump Lists — Notepad 64-bit | `Employees_USDAccounts.csv` opened — interaction count: 1 |
| `06:38:00` | 🔴 Explorer Activity | Jump Lists — Windows Explorer | 12 LNK entries recorded |
| `06:39:00` | 🔴 Final Activity | Jump Lists — Windows Explorer | Last recorded USB activity |

**Total active session:** ~3 hours (03:36 → 06:39)
**Time from USB connection to file access:** 1 minute 45 seconds
**Files accessed per session:** 2 confirmed

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| Machine | `DESKTOP-ND6FH5D` | Compromised endpoint |
| MAC | `00:0c:29:eb:ef:7f` | Machine network interface |
| USB Serial | `563931126217413` | Unique USB device identifier |
| Volume GUID | `{bee66e53-012e-11ee-8012-000c29ebef7f}` | USB volume identifier |
| Drive Letter | `E:` | USB assigned drive letter |
| File | `Employee_PII.csv` | PII data — accessed and likely exfiltrated |
| File | `Employees_USDAccounts.csv` | Financial account data — accessed and likely exfiltrated |
| Path | `E:\NewProject_Hires_Data\Payroll_NewHires\Payroll_NewHires\` | Exfiltration source path |
| Timestamp | `2024-07-15 03:36:22` | First USB connection |
| Timestamp | `2024-07-15 03:38:07` | File access time |
| App ID | `9b9cdc69c1c24e2b` | Notepad 64-bit — application used to open files |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Collection | Data from Local System | T1005 | Payroll CSV files accessed from USB |
| Exfiltration | Exfiltration over Physical Medium — USB | T1052.001 | USB device connected, files accessed |
| Defense Evasion | Valid Accounts | T1078 | Physical access to logged-in workstation used |

---

## 🚨 Immediate Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Preserve all triage artifacts — do not modify the evidence machine |
| 🔴 Immediate | Identify and interview the user of `DESKTOP-ND6FH5D` — who had physical access at 3:36 AM? |
| 🔴 Immediate | Review physical access logs — building entry/exit records for July 15, 2024 03:00-07:00 AM |
| 🔴 Immediate | Initiate breach notification process — PII and financial data confirmed exposed |
| 🟠 High | Recover the USB device — serial `563931126217413` — for physical evidence |
| 🟠 High | Notify affected employees — their PII and financial accounts are compromised |
| 🟠 High | Alert financial institutions — `Employees_USDAccounts.csv` may enable wire fraud |
| 🟠 High | Review CCTV footage — identify who was at the workstation at 3:36 AM |
| 🟠 High | Check if `Employee_PII.csv` and `Employees_USDAccounts.csv` exist elsewhere — was this a copy or the original? |
| 🟡 Medium | Implement USB device control policy — block unauthorized USB devices via Group Policy or EDR |
| 🟡 Medium | Enable USB device audit logging across all endpoints |
| 🟡 Medium | Deploy DLP (Data Loss Prevention) solution — alert on sensitive file access to external drives |
| 🟡 Medium | Review who had legitimate access to `NewProject_Hires_Data` folder structure |

---

## 📋 What to Investigate Next

**1. Identify the User**
```
MountPoints2 registry key:
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
→ Contains per-user USB mount history
→ Will confirm which user account mounted this USB
→ Tool: Registry Explorer → load NTUSER.DAT
```

**2. Prefetch Analysis**
```
C:\Windows\Prefetch\
→ Was any program run FROM the USB?
→ Tool: PECmd (Eric Zimmermann)
→ Look for executables run from E: drive
```

**3. Check for Local Copies**
```
Were the files copied FROM USB TO the machine?
→ Check $MFT for new files created on C: at 03:36-06:39
→ Check Recent Items folder for locally saved copies
→ Tool: MFTECmd → Timeline Explorer
```

**4. Network Activity During Session**
```
Was data sent externally during the 3-hour session?
→ Check firewall/proxy logs for 03:36-06:39 AM July 15
→ Look for large outbound transfers
→ Check email logs — was anything emailed out?
```

**5. USN Journal Analysis**
```
$UsnJrnl records every file operation on NTFS
→ Check for file copy operations during the window
→ Tool: MFTECmd --us flag
→ Will show if files were copied to local drive
```

---

## 📝 Lessons Learned

> **The attacker needed only 106 seconds from USB insertion to opening sensitive files.**
> This wasn't opportunistic — it was planned. The suspect knew the folder structure, knew the filenames, and knew exactly where the sensitive data was stored. The 3:36 AM timestamp suggests this was done deliberately outside business hours to avoid detection.

Key takeaways:

- **USB devices are one of the most common data exfiltration vectors** — yet many organizations have no controls on which USB devices can connect to which machines. A simple Group Policy setting to whitelist approved USB devices would have prevented this entirely
- **ShellBags and Jump Lists persist after deletion** — the suspect may have deleted the files or formatted the USB, but these artifacts remain on the machine indefinitely. Forensic evidence survives cleanup attempts
- **3:36 AM is not normal business hours** — anomalous access time is a critical indicator. User behavior analytics (UBA) tools that baseline normal activity patterns would have triggered an alert the moment this session began
- **Two files, one minute, interaction count 1** — the access pattern screams insider knowledge. An external attacker stumbling onto a machine would browse, explore, make mistakes. This was surgical precision
- **Cross-artifact validation is what makes evidence reliable** — the Volume GUID appears in the NTFS log AND the Jump List. The hostname appears in the NTFS log AND the Jump List. When independent artifacts agree, the evidence is solid

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1052.001 — USB Exfiltration | [attack.mitre.org](https://attack.mitre.org/techniques/T1052/001/) |
| MITRE T1005 — Data from Local System | [attack.mitre.org](https://attack.mitre.org/techniques/T1005/) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| Windows ShellBags Forensics | [sans.org](https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags/) |
| USB Forensics — USBSTOR | [forensicswiki.org](https://forensicswiki.org/wiki/USB_History_Viewing) |
| Jump Lists Forensics | [forensicswiki.org](https://forensicswiki.org/wiki/Jump_Lists) |

---

*Writeup by: Moetez Bouchlaghem | SOC-Investigation-Lab*
