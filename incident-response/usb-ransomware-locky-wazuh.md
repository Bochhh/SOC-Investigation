# 🔴 Incident Response — USB-Delivered Ransomware: Locky Outbreak Across HR & Finance

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Incident%20Response%20%7C%20Threat%20Hunting-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-USB%20Delivery%20%7C%20Ransomware%20%7C%20Remote%20Access%20Backdoor-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1091%20%7C%20T1486%20%7C%20T1059.001%20%7C%20T1219%20%7C%20T1078-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20SentinelOne%20%7C%20Wazuh%20Discover-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | USB-Delivered Ransomware — Locky Outbreak Across HR & Finance |
| **Date of Incident** | August 22, 2024 |
| **Primary Affected Machine** | `HR-WS-124` |
| **Secondary Affected Machine** | `FIN-WS-301` |
| **Primary User** | `j.doe` |
| **Secondary User** | `a.smith@newcorp.com` |
| **USB Device Vendor** | SanDisk |
| **USB Serial Number** | `SN1234567890` |
| **Drive Letter Assigned** | `F:` |
| **Ransomware Family** | `Ransomware.Win32.Locky` |
| **Malicious Binary** | `encryptor.exe` — `F:\data\j.doe\AppData\Roaming\encryptor.exe` |
| **SHA256 Hash** | `1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890` |
| **Files Confirmed Encrypted** | 25 files across C:, D:, and E: drives |
| **Ransom Notes Dropped** | 5 directories confirmed |
| **Backdoor Installed** | AnyDesk Remote Desktop — via MSI silent install |
| **Incident ID** | `INC-20250626-987654` |
| **Detection Engine** | SentinelOne — static_ai |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — USB-delivered Locky ransomware confirmed. Mass encryption across two departments, human-operated backdoor installed, second machine infected via physical USB transfer. |

---

## 🎯 Scenario

It started with a USB drive. At `14:12:54 UTC` on August 22, 2024, a SanDisk removable drive was plugged into workstation `HR-WS-124` by user `j.doe` — an employee in the HR department. Windows mounted it as drive `F:`. SentinelOne saw it. Wazuh logged it. At that moment, nobody raised an alarm — USB drives get plugged in every day.

What followed over the next 45 minutes was a systematic, human-operated ransomware attack that tore through two departments, encrypted 25 confirmed files across five drives, dropped ransom notes in every directory it touched, installed a persistent remote access backdoor, and then physically moved to a second machine in the Finance department.

The malicious binary — `encryptor.exe` — was hiding inside a folder path on the USB designed to look like a legitimate Windows user profile: `F:\data\j.doe\AppData\Roaming\`. The moment it executed, `Ransomware.Win32.Locky` went to work. Within 35 minutes, ransom notes were appearing across `C:\Shared\Sales\`, `D:\Backups\Personal\`, the user's Desktop, Documents, and Downloads folders — all simultaneously, all within the same second. The encryption wave hit Finance folders, Legal documents, HR files, Project blueprints, Accounting records, and client contracts.

Then the attack revealed its most dangerous layer: ten minutes after the encryption wave, AnyDesk Remote Desktop was silently installed via MSI package — meaning a human operator on the other end was maintaining live access to the compromised machine.

And then the USB moved. At `15:50:03`, the same drive — serial `SN1234567890` — was plugged into `FIN-WS-301`, a Finance department workstation operated by `a.smith@newcorp.com`, on an entirely different network subnet (`10.1.55.78`). The infection was not contained. It had crossed department boundaries physically, bypassing every network firewall and segmentation control in place.

This writeup traces the complete attack chain across seven investigation phases — from the first USB mount event to the scope expansion pivot that confirmed the outbreak — using Wazuh SIEM alert data and SentinelOne EDR telemetry.

---

## 🛠️ Tools Used

| Tool | Role |
|---|---|
| **Wazuh SIEM** | Central log aggregation, alert indexing, threat detection across all agents |
| **Wazuh Discover** | Timeline scoping, DQL querying, histogram analysis, event pivoting |
| **SentinelOne EDR** | Endpoint detection — static_ai engine, process monitoring, file creation tracking |

---

## 🗂️ Log Sources Analyzed

| Source | What It Provided |
|---|---|
| `wazuh-alerts-*` | All security events across the environment — 13 hits in the initial 30-minute window |
| SentinelOne device_activity logs | USB mount events — vendor, serial, drive letter, username, timestamp |
| SentinelOne threat_detected logs | Ransomware binary identification — hash, path, MITRE techniques |
| SentinelOne file_creation_detected logs | Ransom note drops — directory mapping, process attribution |
| SentinelOne encrypt_file_activity logs | Encrypted file enumeration — filenames, paths, batch detection |
| Windows EventChannel logs | AnyDesk MSI installation — MsiInstaller, rule ID 60617 |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1091 — Replication Through Removable Media | [attack.mitre.org](https://attack.mitre.org/techniques/T1091/) |
| MITRE T1486 — Data Encrypted for Impact | [attack.mitre.org](https://attack.mitre.org/techniques/T1486/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1219 — Remote Access Software | [attack.mitre.org](https://attack.mitre.org/techniques/T1219/) |
| MITRE T1078 — Valid Accounts | [attack.mitre.org](https://attack.mitre.org/techniques/T1078/) |
| Locky Ransomware Analysis | [cisa.gov](https://www.cisa.gov/) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com/) |
| SentinelOne Threat Intelligence | [sentinelone.com](https://www.sentinelone.com/blog/) |

---

## 🔍 Investigation Methodology

```
Phase 1 → USB Mount Detection        (Wazuh — SentinelOne device_activity event)
Phase 2 → Ransomware Identification  (SentinelOne — threat_detected, static_ai engine)
Phase 3 → Timeline Scoping           (Wazuh Discover — +30min window, histogram analysis)
Phase 4 → Ransom Note Mapping        (file_creation_detected — directory traversal evidence)
Phase 5 → Encryption Wave Analysis   (encrypt_file_activity — 25 files, 5 drives, 6 batches)
Phase 6 → Backdoor Discovery         (Windows EventChannel — AnyDesk MSI install, rule 60617)
Phase 7 → Scope Expansion            (DQL pivot on serial SN1234567890 — second machine found)
```

---

## 🕵️ Investigation

### Phase 1 — USB Mount Detection: The Infection Vector Arrives

Every incident has a moment zero — the single event from which everything else flows. In this investigation, that moment was logged at `2024-08-22T14:12:54 UTC`. A SanDisk USB drive was plugged into workstation `HR-WS-124`, and Windows mounted it as drive `F:`.

What makes this event forensically significant is not just that a USB was plugged in — USB drives get connected hundreds of times a day in any organization. What matters is every detail attached to this specific event: the machine it was connected to, the user who connected it, the serial number that uniquely identifies the physical device, and the exact second it happened. These details become the anchor of our entire timeline.

Wazuh captured this through SentinelOne's device activity telemetry:

> 📸 *Screenshot: Wazuh event — data.activity_type: drive_mount, data.device_vendor: SanDisk, data.device_serial_number: SN1234567890, data.drive_letter: F:, data.username: j.doe, data.mount_time: 2024-08-22T14:12:54*

```
agent.name              → wazuh-server
data.agent_name         → HR-WS-124
data.agent_id           → A1B2C3D4E5F6
data.device_ip          → 10.0.12.45
data.device_mac         → 00:1A:2B:3C:4D:5E
data.device_vendor      → SanDisk
data.device_serial_number → SN1234567890
data.drive_letter       → F:
data.activity_type      → drive_mount
data.mount_type         → removable_storage
data.action_taken       → allowed
data.mount_time         → 2024-08-22T14:12:54
data.username           → j.doe
data.product            → SentinelOne
data.os_name            → Windows 10 Enterprise
data.status             → completed
data.timestamp          → Aug 22, 2024 @ 16:12:54.382
```

> ### 🔎 What Is `data.mount_time` vs `data.timestamp` — And Why the 2-Hour Difference?
> Two timestamps appear in this event and they look different — `data.mount_time` shows `14:12:54` while `data.timestamp` shows `16:12:54`. This is not a discrepancy. It is a timezone difference.
>
> `data.mount_time` is recorded by the endpoint agent (SentinelOne) at the OS level — the exact moment Windows said "drive F: is ready." This is in **UTC**.
>
> `data.timestamp` is when Wazuh received and indexed the log into its Elasticsearch backend — displayed in the **browser's local timezone** (UTC+2 in this case).
>
> `14:12:54 UTC = 16:12:54 UTC+2` — the same moment, two representations.
>
> This distinction matters enormously when building attack timelines. A common investigator mistake is mixing UTC and local timestamps, making two simultaneous events appear two hours apart. **Always normalize every timestamp to UTC before constructing a timeline.** In this investigation, all times are expressed in UTC.

> ### 🔎 `data.action_taken: allowed` — The System Let It In
> The USB mount was **allowed** — no policy blocked it. This is the first security gap in the chain. Windows has no native USB device control out of the box, and if no Group Policy or EDR policy was configured to restrict removable storage on `HR-WS-124`, any USB device can mount freely. The attacker knew this — or counted on it.

> ### 🔎 `data.product: SentinelOne` — The EDR That Will Track Everything
> SentinelOne is the endpoint detection and response (EDR) agent deployed on `HR-WS-124`. Unlike traditional antivirus that only scans files, an EDR watches every process, every file operation, every network connection, and every device event in real time. Every piece of evidence in this investigation flows through SentinelOne's telemetry into Wazuh. Without it, most of what we're about to trace would be invisible.

**At this point, the USB is mounted. The attacker's weapon is inside the network perimeter. `j.doe` has no idea what just arrived.**

---

### Phase 2 — Ransomware Identification: The Weapon Reveals Itself

Within moments of the USB mounting, SentinelOne's static AI engine fired. The event type changed from `device_activity` to `threat_detected` — and the picture became immediately clear.

> 📸 *Screenshot: Wazuh event — data.event_type: threat_detected, data.threat_name: Ransomware.Win32.Locky, data.process_name: encryptor.exe, data.process_path: F:\data\j.doe\AppData\Roaming\encryptor.exe, data.detection_engine: static_ai, data.mitre_techniques: T1486, T1059.001*

```
data.event_type         → threat_detected
data.threat_name        → Ransomware.Win32.Locky
data.threat_type        → ransomware
data.process_name       → encryptor.exe
data.process_path       → F:\data\j.doe\AppData\Roaming\encryptor.exe
data.hashes.sha256      → 1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890
data.detection_engine   → static_ai
data.mitre_techniques   → T1486, T1059.001
data.severity           → high
data.incident_id        → INC-20250626-987654
data.status             → resolved
data.agent_name         → HR-WS-124
data.agent_version      → 23.3.2.15
```

> ### 🔎 What Is Ransomware.Win32.Locky?
> **Locky** is one of the most notorious ransomware families ever documented. First emerging in 2016, it spread globally through phishing emails and infected removable media, encrypting hundreds of thousands of machines across hospitals, corporations, and government agencies.
>
> Locky's attack pattern is precise and devastating:
> - It encrypts files using **RSA-2048 + AES-128** — mathematically unbreakable without the decryption key
> - It renames every encrypted file with a `.locky` extension (or variants: `.zepto`, `.odin`, `.aesir`)
> - It drops a ransom note (`README.TXT` or `_Locky_recover_instructions.txt`) in every folder it touches
> - It deletes **Volume Shadow Copies (VSS)** — Windows' built-in backup mechanism — to prevent recovery
> - It enumerates and attacks ALL drives: local partitions, external drives, and mapped network shares
> - It communicates with a C2 server to exchange encryption keys, meaning **decryption without the attacker's server is impossible**
>
> Locky's speed is its most dangerous characteristic — it can encrypt thousands of files in minutes. By the time an alert fires and a human analyst looks at a screen, the damage is already done.

> ### 🔎 `encryptor.exe` Running From `F:\` — Path Masquerading
> The process path `F:\data\j.doe\AppData\Roaming\encryptor.exe` is carefully constructed. The attacker embedded the ransomware binary inside a directory structure that mimics a legitimate Windows user profile path — `AppData\Roaming` is where Windows stores user application data. The goal is visual deception: if a user or junior analyst glances at the path, it could be mistaken for a legitimate application.
>
> But `F:\` is the USB drive. There is nothing legitimate about an executable running from removable media using a spoofed user profile path. This is **T1036 — Masquerading**: making malicious artifacts look like legitimate ones.

> ### 🔎 `data.detection_engine: static_ai` — Caught Before Full Execution
> SentinelOne uses multiple detection layers. `static_ai` means the binary was analyzed **before it fully executed** — the AI engine examined the file's structure, code patterns, entropy, and behavioral signatures and flagged it as malicious based on what it looks like rather than what it did.
>
> This sounds like good news. But `data.status: resolved` does not mean the threat was neutralized before any damage. It means SentinelOne took action — but the encryption process had already started. As we will see in the phases ahead, the ransom notes and encrypted files tell us the ransomware ran long enough to cause significant damage before being flagged.

> ### 🔎 MITRE Techniques: T1486 and T1059.001
> Two MITRE ATT&CK techniques are attributed to this event:
>
> **T1486 — Data Encrypted for Impact**: The primary ransomware technique. The adversary encrypts files to deny access to the victim and create extortion leverage. This is the core of what Locky does.
>
> **T1059.001 — Command and Scripting Interpreter: PowerShell**: This tells us Locky used PowerShell as part of its execution chain. Ransomware commonly uses PowerShell to: disable Windows Defender real-time protection, delete Volume Shadow Copies (`vssadmin delete shadows /all`), modify registry keys for persistence, and execute secondary payloads. The presence of this technique means the attack was not just "run an exe" — it involved scripted automation behind the scenes.

---

### Phase 3 — Timeline Scoping: How We Framed the Investigation Window

Before diving into the flood of events that followed, we needed to set the right search boundaries in Wazuh Discover. The approach here reflects a core principle of ransomware investigation: **anchor to the infection vector, then look forward.**

We took the USB mount timestamp — `14:12:54 UTC` — and opened Wazuh Discover with the index `wazuh-alerts-*`, setting the time window to **USB mount time + 30 minutes**.

> 📸 *Screenshot: Wazuh Discover — DQL search, time range Aug 22, 2024 @ 15:00:00 → 15:30:00 (UTC+2), 13 hits returned, histogram showing spike at ~15:20*

> ### 🔎 Why +30 Minutes? The Forensic Logic Behind the Window
> Ransomware doesn't wait. Locky in particular begins encryption within seconds to minutes of execution. A 30-minute post-infection window captures the complete burst cycle:
>
> - The initial execution and binary detection
> - The first file encryption events
> - Defense evasion actions (shadow copy deletion, script execution)
> - Ransom note drops across all directories
> - Any C2 communication attempts
> - Secondary payload installations
>
> Search too narrow (5 minutes) and you miss delayed actions. Search too wide (24 hours) and you drown in noise from unrelated system events. **30 minutes post-infection is the forensic sweet spot for ransomware triage.** If nothing significant appears in that window, you expand. If the window is dense with events, you have your story.

> ### 🔎 Reading the Histogram — The Spike Is the Story
> The Wazuh Discover histogram plots event frequency over time. What we saw was revealing:
>
> ```
> 15:00  →  1 event   (baseline noise)
> 15:05  →  0 events
> 15:10  →  1 event   (still quiet)
> 15:15  →  0 events
> 15:20  →  9+ events in a single 30-second bucket  ← SPIKE
> 15:25  →  0 events
> ```
>
> That vertical spike at `15:20` is the ransomware doing its work. Multiple events firing simultaneously — this is the characteristic **burst pattern** of ransomware encryption. It doesn't encrypt one file, wait, then encrypt another. It hammers the filesystem across multiple threads as fast as the OS allows.
>
> When you see a sudden vertical spike in your SIEM histogram immediately after a known infection vector event, that spike is your encryption wave. This visual pattern alone is enough to tell an experienced analyst: ransomware is running.

**The 13 hits returned by this search window became the complete evidence set for our investigation. Every event we analyze from this point forward comes from within that 30-minute burst.**

---

### Phase 4 — Ransom Note Mapping: Tracing Every Directory Locky Touched

Ransomware announces its own crime scene. Every directory `encryptor.exe` encrypted, it marked with a `README.TXT` file — a ransom note containing payment instructions. These notes are not just extortion tools; forensically, they are a **map of the encryption damage**.

SentinelOne logged each note creation as a `file_creation_detected` event, with `data.malicious_process: encryptor.exe` providing direct process attribution. Five directories were confirmed hit:

> 📸 *Screenshot: Wazuh event — data.event_type: file_creation_detected, data.created_file: C:\Shared\Sales\README.TXT, data.malicious_process: encryptor.exe, data.related_threat: Ransomware.Win32.Locky, data.timestamp: Aug 22, 2024 @ 16:48:12.367*

> 📸 *Screenshot: Wazuh event — data.created_file: D:\Backups\Personal\README.TXT, data.timestamp: Aug 22, 2024 @ 16:48:12.492*

> 📸 *Screenshot: Wazuh event — data.created_file: C:\Users\j.doe\Documents\README.TXT, data.timestamp: Aug 22, 2024 @ 16:48:12.001*

> 📸 *Screenshot: Wazuh event — data.created_file: C:\Users\j.doe\Desktop\README.TXT, data.timestamp: Aug 22, 2024 @ 16:48:12.123*

> 📸 *Screenshot: Wazuh event — data.created_file: C:\Users\j.doe\Downloads\README.TXT*

**Confirmed ransom note locations:**

```
C:\Users\j.doe\Documents\README.TXT     → 14:48:12.001 UTC
C:\Users\j.doe\Desktop\README.TXT       → 14:48:12.123 UTC
C:\Shared\Sales\README.TXT              → 14:48:12.367 UTC
D:\Backups\Personal\README.TXT          → 14:48:12.492 UTC
C:\Users\j.doe\Downloads\README.TXT     → 14:48:12.??? UTC
```

> ### 🔎 Why Does Locky Drop a Ransom Note in Every Single Folder?
> This is one of Locky's most deliberate design choices — and the reason is pure psychology combined with operational logic.
>
> **Maximum visibility:** If the ransom note existed only in one location, the victim might not find it immediately — or might think only one folder was affected. By dropping `README.TXT` in every encrypted directory, Locky ensures that the moment any user opens ANY folder on the machine, they are confronted with the extortion message. There is no way to miss it. The psychological impact is immediate and total.
>
> **Directory completion marker:** Each ransom note also functions as a technical signal — it is dropped AFTER all files in that directory are encrypted. The note means "this folder is done." The list of ransom notes is therefore a precise map of every directory the ransomware successfully processed.
>
> **Redundancy against deletion:** If IT deletes one ransom note during incident response, there are dozens more across the system. The attacker's payment instructions survive any partial cleanup.
>
> **Escalating psychological pressure:** Imagine being the victim. You open Documents — ransom note. You open Desktop — ransom note. You open Sales — ransom note. You try Downloads — ransom note. Every folder you check confirms the damage is deeper than you thought. This cascading discovery is intentional. It breaks the victim's belief that recovery without paying is possible.

> ### 🔎 The 491-Millisecond Window — Machine Speed Execution
> Look at the timestamps across all five ransom note events:
> ```
> 14:48:12.001  → Documents
> 14:48:12.123  → Desktop
> 14:48:12.367  → C:\Shared\Sales\
> 14:48:12.492  → D:\Backups\Personal\
> ```
> From first to last: **491 milliseconds**. Less than half a second to drop ransom notes across five directories spanning two drives. No human clicks that fast. This is multi-threaded automated execution — Locky running parallel directory traversal threads simultaneously.

> ### 🔎 `D:\Backups\Personal\` — The Backup Drive Was Hit
> The appearance of `D:\Backups\` in the ransom note list is particularly significant. The `D:` drive is a secondary partition — typically used for backups and secondary storage. Locky specifically targets backup locations because **destroying backup access maximizes the pressure to pay**. If your backups are encrypted along with your primary data, your only path to recovery is either a pre-existing offline backup or the attacker's decryption key.

> ### 🔎 `C:\Shared\Sales\` — Shared Folders Mean Colleagues Are Affected Too
> A path under `C:\Shared\` indicates this is a shared folder — accessible by multiple users or machines on the network. `j.doe` is the infected user, but every other employee with access to the `Sales` shared folder could find their files encrypted too, without ever touching a USB drive.

> ### 🔎 `data.action_taken: monitored` — Detection Did Not Mean Prevention
> All ransom note creation events carry `data.action_taken: monitored`. SentinelOne detected each file creation and logged it — but did not block it. The earlier `threat_detected` event had `status: resolved`, suggesting the binary was flagged. But the process had already launched and the encryption was mid-execution. Monitoring after the fact does not undo encryption. **Detection and prevention are not the same thing.**

---

### Phase 5 — Encryption Wave Analysis: The Full Blast Radius

The most damaging phase of the attack arrived at `13:20:06.945 UTC` — a simultaneous burst of six encryption batch events, all fired within the same millisecond, across three parallel SentinelOne detection threads.

> 📸 *Screenshot: Wazuh Discover — three rows at Aug 22, 2024 @ 15:20:06.945, each showing data.encryption_detected: true, data.message: Ransomware - Encrypt File Activity Detected, with data.encrypted_files listing multiple .docx files per row*

> 📸 *Screenshot: Additional three rows at 15:20:06.945 showing Batch 4, 5, and 6 encrypted file lists*

> ### 🔎 Six Batches, One Millisecond — Multi-Threaded Ransomware in Action
> Modern ransomware doesn't encrypt files one by one in a single queue — it spawns multiple threads simultaneously, each processing a batch of files in parallel. The six events we see at the exact same timestamp (`15:20:06.945`) represent six concurrent encryption threads that SentinelOne detected and reported to Wazuh simultaneously.
>
> This is why ransomware causes so much damage so quickly. By the time the first alert fires and a human analyst sees it, multiple threads have already finished encrypting their batches. The human response time (minutes to hours) is no match for the encryption speed (milliseconds per file).

**Complete list of confirmed encrypted files across all six batches:**

**Batch 1 — User Profile & Shared Sales:**
```
C:\Users\j.doe\Documents\Project_Plan.docx
C:\Users\j.doe\Desktop\Budget_2024.docx
C:\Users\j.doe\Downloads\HR_Proposal.docx
C:\Shared\Sales\Q3_Report.docx
D:\Backups\Personal\Resume.docx
```

**Batch 2 — Projects & OneDrive:**
```
C:\Projects\Alpha\Blueprint.docx
C:\Projects\Beta\Specs.docx
C:\Projects\Gamma\Summary.docx
C:\Users\j.doe\OneDrive\Agenda.docx
D:\Teams\Roadmap_Review.docx
```

**Batch 3 — Admin, Marketing & HR Shared:**
```
C:\Admin\Letters\Termination_Letter.docx
C:\Marketing\Campaign2025\Presentation.docx
C:\Docs\Client_Agreement.docx
D:\Work\Engineering\Design_v2.docx
E:\Shared\HR\Training_Schedule.docx
```

**Batch 4 — Finance, Legal & Confidential:**
```
C:\Users\j.doe\Documents\Financial_Statement.docx
C:\Users\j.doe\Desktop\Onboarding_Form.docx
C:\Users\j.doe\Downloads\Sales_Plan.docx
C:\Shared\Legal\Contract_Template.docx
D:\Data\Confidential\Strategy.docx
```

**Batch 5 — Projects & OneDrive (second pass):**
```
C:\Projects\Alpha\Blueprint.docx
C:\Projects\Beta\Specs.docx
C:\Projects\Gamma\Summary.docx
C:\Users\j.doe\OneDrive\Agenda.docx
D:\Teams\Roadmap_Review.docx
```

**Batch 6 — Accounting, Clients & Backup:**
```
C:\Accounting\Audit2025.docx
C:\Clients\XYZ Corp\Proposal.docx
C:\Reports\Weekly_Overview.docx
D:\HR\Leave_Application.docx
E:\Backup\User\Notes.docx
```

**Total confirmed encrypted: 25 unique files across C:, D:, and E: drives.**

> ### 🔎 The Drive Map — How Far Did Locky Reach?
> Mapping encrypted files by drive reveals the full blast radius:
> ```
> C:\ → Primary system drive
>   ├── Users\j.doe\Documents\      personal work files
>   ├── Users\j.doe\Desktop\        active working files
>   ├── Users\j.doe\Downloads\      recent downloads
>   ├── Users\j.doe\OneDrive\       cloud-synced files ← cloud contamination
>   ├── Shared\Sales\               shared business data ← colleagues affected
>   ├── Shared\Legal\               legal documents
>   ├── Projects\Alpha, Beta, Gamma project files ← IP potentially exposed
>   ├── Admin\Letters\              administrative records
>   ├── Marketing\Campaign2025\     marketing assets
>   ├── Accounting\                 financial records
>   ├── Clients\XYZ Corp\           client documents
>   ├── Reports\                    business reporting
>   └── Docs\                       general company documents
>
> D:\ → Secondary/Backup drive
>   ├── Backups\Personal\           personal backups DESTROYED
>   ├── Teams\                      team collaboration files
>   ├── Work\Engineering\           engineering documents
>   ├── Data\Confidential\          confidential strategy data
>   └── HR\                         HR department records
>
> E:\ → Network share or third partition
>   ├── Shared\HR\                  HR shared network folder
>   └── Backup\User\                user backup location DESTROYED
> ```
> **Three drives. Five categories of data. HR, Finance, Legal, Engineering, Sales, Marketing, Accounting — all hit.**

> ### 🔎 `C:\Users\j.doe\OneDrive\` — The Cloud Sync Catastrophe
> One of the encrypted paths is `C:\Users\j.doe\OneDrive\Agenda.docx`. This is not just a local file. The OneDrive client continuously monitors its local sync folder — when any file changes, it pushes the new version to Microsoft's cloud storage.
>
> When Locky encrypted `Agenda.docx`, the OneDrive client saw a file modification event and synced the encrypted version to the cloud, **overwriting the clean original**. Depending on the organization's version history retention settings, the clean version may be recoverable from OneDrive's version history — or it may be permanently overwritten.
>
> More critically: other devices signed into the same Microsoft 365 account will receive the encrypted file through sync. One infected machine becomes a cloud contamination event that propagates to every device that shares the same OneDrive.

> ### 🔎 `D:\Data\Confidential\Strategy.docx` — The Folder Name Tells the Story
> The word "Confidential" in the folder name is not an accident — this was a designated sensitive data storage location. Locky reached it. The business impact of encrypting a file called `Strategy.docx` inside a `Confidential` folder likely includes proprietary business strategy, competitive plans, or executive-level documents. These are exactly the files that maximize ransom pressure.

> ### 🔎 `E:\Shared\HR\` and `E:\Backup\User\` — A Third Drive Confirmed
> Two paths on drive `E:` appear across different batches. Drive `E:` being hit confirms Locky successfully enumerated a third volume — either a third local partition, an external drive, or a mapped network share assigned letter `E:`. The `Shared\HR\` path appearing here and on `C:\` suggests HR data was stored across multiple locations — all now encrypted.

---

### Phase 6 — Backdoor Discovery: The Human Operator Reveals Themselves

At `14:58:17 UTC` — exactly ten minutes after the encryption wave — a Windows Installer event fired. AnyDesk Remote Desktop was silently installed on `HR-WS-124` via an MSI package.

> 📸 *Screenshot: Wazuh event — data.win.system.message: "Windows Installer installed the product. Product Name: AnyDesk Remote Desktop.", data.win.system.providerName: MsiInstaller, rule.description: Application installed AnyDesk Remote Desktop, rule.id: 60617, rule.level: 3, timestamp: Aug 22, 2024 @ 16:58:17.862*

```
data.win.system.message       → "Windows Installer installed the product.
                                  Product Name: AnyDesk Remote Desktop."
data.win.system.providerName  → MsiInstaller
data.win.system.severityValue → INFORMATION
data.win.system.systemTime    → 2024-08-02T20:58:20.862Z
rule.description              → Application installed AnyDesk Remote Desktop
rule.id                       → 60617
rule.level                    → 3
rule.groups                   → windows, windows_application
timestamp                     → Aug 22, 2024 @ 16:58:17.862
```

> ### 🔎 AnyDesk After Ransomware — This Is a Human-Operated Attack
> This single event changes the classification of this incident completely. Let's think about what the sequence means:
>
> ```
> 14:12:54  → USB plugged in by j.doe
> 14:48:12  → Ransom notes dropping, encryption in progress
> 14:58:17  → AnyDesk Remote Desktop installed
> ```
>
> Ten minutes after the encryption wave — someone installed remote access software. AnyDesk is a legitimate remote desktop tool used by IT teams worldwide. But installed silently via MSI on a machine that just finished encrypting 25 files, ten minutes after a ransomware payload executed, it has only one meaning: **a human attacker is on the other end, and they want a persistent live connection to this machine.**
>
> This is the signature of **human-operated ransomware** — as opposed to fully automated ransomware that encrypts and exits. The USB likely carried two payloads: `encryptor.exe` as the ransomware, and an AnyDesk MSI installer as the backdoor — both deployed in sequence as part of a pre-planned toolkit.

> ### 🔎 What Can the Attacker Do With Live AnyDesk Access?
> Once AnyDesk is installed and a remote session is established, the attacker has a full interactive desktop session inside the corporate network. The attack surface expands dramatically:
>
> **Double extortion — data exfiltration:** Even though files are encrypted locally, the attacker can browse the filesystem, copy files to their own infrastructure, and threaten to publish sensitive data publicly if the ransom is not paid. Finance records, client contracts, HR files — all visible on the desktop they now control.
>
> **Lateral movement:** From `HR-WS-124` with `j.doe`'s active session, the attacker can attempt to pivot to other machines on the `10.0.12.45` network — using legitimate credentials, shared drives, or remote management tools. They have a live foothold inside the corporate network.
>
> **Credential harvesting:** With a live desktop session, the attacker can run tools to dump saved browser credentials, harvest Windows credential store entries, or attempt to extract cached domain credentials from memory.
>
> **Persistence beyond the USB:** The USB can be removed and the infected machine isolated — but if AnyDesk is configured with an unattended access password, the attacker retains remote access independently of the physical device. Removing the USB does not remove the backdoor.

> ### 🔎 `MsiInstaller` — Silent Installation, No User Interaction Required
> The provider `MsiInstaller` confirms AnyDesk was installed via a pre-built `.msi` package — not through an interactive installer that would show a window, prompt for confirmation, or require user clicks. Silent MSI installation is a standard technique for deploying software without triggering visible UI elements or UAC prompts.
>
> The `encryptor.exe` almost certainly orchestrated this installation as part of its execution chain — launching the AnyDesk MSI silently as a secondary action after the encryption phase completed.

> ### 🔎 `rule.level: 3` — A Critical Event That Looked Like Noise
> Wazuh assigned this event a severity level of only `3` — informational, low priority. This is because Wazuh's rule engine saw an AnyDesk installation in isolation and correctly classified it as a low-severity software installation event. AnyDesk is legitimate software. IT teams install it all the time.
>
> But in context — AnyDesk installed on a machine that fired a ransomware alert ten minutes earlier — this is a critical escalation. This is precisely the gap that **SIEM correlation rules** are designed to close. A rule that says "if `threat_detected: ransomware` AND `application_installed: remote_access_tool` occur on the same host within 30 minutes → critical alert" would have caught this automatically. Without that correlation, the backdoor installation blends into the background noise and may never be investigated.

---

### Phase 7 — Scope Expansion: Did the USB Spread to Other Machines?

With the primary machine investigation complete, we asked the most important question of any USB incident: **was this USB plugged into any other machine in the organization?**

We pivoted in Wazuh Discover, searching the entire `wazuh-alerts-*` index using the USB's unique serial number as the search key, across a 25-hour window.

> 📸 *Screenshot: Wazuh Discover — DQL query: *SN1234567890*, time range Aug 22, 2024 @ 15:00 → Aug 23, 2024 @ 16:00, 2 hits returned, histogram showing both events clustered at 15:00*

**DQL Query used:**
```
*SN1234567890*
```

**Time window:** `Aug 22, 2024 @ 15:00 → Aug 23, 2024 @ 16:00` (25 hours)

**Result: 2 hits**

> ### 🔎 Why Search by Serial Number — The USB as a Forensic Fingerprint
> Unlike IP addresses that rotate with DHCP, unlike usernames that can be shared across machines, the USB serial number `SN1234567890` is **burned into the device's firmware at manufacturing**. It is globally unique to that one physical drive. It follows the device wherever it goes.
>
> Searching the serial number across all agents and all time is asking: did this weapon visit any other machine? One infected USB passed between three employees = three encrypted machines. We needed to know the true scope before drawing any conclusions.

At first glance, the result seemed to confirm a contained incident — 2 hits, both clustered at `15:00`. But the critical step was not reading the count. It was **opening the results table**.

> 📸 *Screenshot: Wazuh Discover results table — two rows: (1) Aug 22 @ 15:00:16.299 — HR-WS-124 — j.doe — 10.0.12.45 — SN1234567890; (2) Aug 22 @ 15:50:03.629 — FIN-WS-301 — a.smith@newcorp.com — 10.1.55.78 — SN1234567890*

| Time | `data.agent_name` | `data.username` | `data.device_ip` | `data.device_serial_number` |
|---|---|---|---|---|
| `Aug 22 @ 15:00:16.299` | `HR-WS-124` | `j.doe` | `10.0.12.45` | `SN1234567890` |
| `Aug 22 @ 15:50:03.629` | `FIN-WS-301` | `a.smith@newcorp.com` | `10.1.55.78` | `SN1234567890` |

**The same USB serial number appeared on a second machine — `FIN-WS-301` — 50 minutes after the first infection.**

> ### 🔎 The USB Moved From HR to Finance — The Incident Is Not Contained
> The timeline now tells a completely different story:
>
> ```
> 14:12:54  → USB plugged into HR-WS-124 (j.doe) — HR department
> 14:48:12  → Encryption wave completes, ransom notes dropped
> 14:58:17  → AnyDesk installed, human operator gains access
> 15:50:03  → SAME USB plugged into FIN-WS-301 (a.smith) — Finance department
> ```
>
> Fifty minutes after the first infection, this same infected drive was physically carried across the building and plugged into a Finance department workstation. Either `j.doe` carried it there themselves, or they handed the drive to `a.smith` — who plugged it in without knowing it was a weapon.

> ### 🔎 Two Different Network Segments — The Firewall Didn't Matter
> The IP addresses tell the network story:
> ```
> HR-WS-124   → 10.0.12.45   → HR network segment    (10.0.x.x)
> FIN-WS-301  → 10.1.55.78   → Finance network segment (10.1.x.x)
> ```
>
> These are two different subnets. Standard corporate network segmentation keeps HR and Finance on separate VLANs — this is a deliberate security design to prevent lateral movement between departments. A firewall between these segments would block any network-based attack from crossing from `10.0.x.x` to `10.1.x.x`.
>
> But the USB bypassed all of it. No firewall stops a person walking between desks. This is the fundamental challenge of physical attack vectors — they defeat network security controls completely.

> ### 🔎 `a.smith@newcorp.com` — Victim or Accomplice?
> The Finance machine user is `a.smith@newcorp.com` — a completely different person from `j.doe`. Two scenarios exist:
>
> **Scenario A — Innocent victim:** `j.doe` shared the drive with `a.smith` for a legitimate reason — transferring a file, sharing data — not knowing the drive carried ransomware. `a.smith` plugged it in and triggered a second infection unknowingly.
>
> **Scenario B — Coordinated insider threat:** Both users are involved in a deliberate attack — one targeting HR systems, one targeting Finance — working together to maximize damage.
>
> SIEM logs alone cannot determine which scenario is true. This requires HR interviews, physical access review, CCTV footage analysis, and potentially legal or law enforcement involvement.

> ### 🔎 A Critical Lesson: Never Read the Hit Count Alone — Always Read the Data
> After the serial number search returned "2 hits," an easy conclusion would have been: "2 events, same machine — the USB only touched `HR-WS-124`." That conclusion would have been wrong and dangerous.
>
> The histogram showed both events clustered at `15:00` — visually appearing as one cluster. But the results table revealed two distinct rows: two different machines, two different users, two different IP addresses, 50 minutes apart.
>
> **In SIEM investigation, never stop at the summary. Always open the data. The number tells you how much. The table tells you what.**

---

## ⏱️ Complete Attack Timeline

| Time (UTC) | Event | Machine | Actor | Significance |
|---|---|---|---|---|
| `14:12:54` | 🔴 USB mounted — SanDisk `SN1234567890` — drive `F:` | `HR-WS-124` | `j.doe` | Zero hour — infection vector arrives |
| `14:12:54+` | 🔴 `encryptor.exe` detected — `Ransomware.Win32.Locky` — static_ai | `HR-WS-124` | `encryptor.exe` | Weapon identified — execution already in progress |
| `14:48:12.001` | 🔴🔴 Ransom note — `C:\Users\j.doe\Documents\` | `HR-WS-124` | Locky | Encryption confirmed — Documents folder done |
| `14:48:12.123` | 🔴🔴 Ransom note — `C:\Users\j.doe\Desktop\` | `HR-WS-124` | Locky | Desktop encrypted |
| `14:48:12.367` | 🔴🔴 Ransom note — `C:\Shared\Sales\` | `HR-WS-124` | Locky | Shared folder hit — colleagues affected |
| `14:48:12.492` | 🔴🔴 Ransom note — `D:\Backups\Personal\` | `HR-WS-124` | Locky | Backup drive reached — recovery path destroyed |
| `14:48:12.???` | 🔴🔴 Ransom note — `C:\Users\j.doe\Downloads\` | `HR-WS-124` | Locky | Downloads folder encrypted |
| `13:20:06.945` | 🔴🔴🔴 Mass encryption wave — 6 batches, 25 files, C: D: E: | `HR-WS-124` | Locky | Peak destruction — multi-threaded encryption burst |
| `14:58:17` | 🔴🔴🔴 AnyDesk installed via MsiInstaller | `HR-WS-124` | Human operator | Backdoor established — live remote access |
| `15:50:03` | 🔴🔴🔴 **SAME USB mounted on Finance machine** | `FIN-WS-301` | `a.smith` | **Outbreak confirmed — second department infected** |

**Total attack duration (confirmed): ~97 minutes from first USB insertion to second machine infection.**
**Time from USB plug to encryption wave: ~35 minutes.**
**Time from encryption to backdoor: ~10 minutes.**
**Time from first infection to second machine: ~97 minutes.**

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| Hostname | `HR-WS-124` | Primary compromised endpoint — HR department |
| Hostname | `FIN-WS-301` | Secondary compromised endpoint — Finance department |
| IP | `10.0.12.45` | HR-WS-124 network address |
| IP | `10.1.55.78` | FIN-WS-301 network address |
| MAC | `00:1A:2B:3C:4D:5E` | HR-WS-124 primary NIC |
| MAC | `00:16:3E:2C:4D:AF` | Secondary interface / virtual adapter on HR-WS-124 |
| Username | `j.doe` | Primary affected user — HR department |
| Username | `a.smith@newcorp.com` | Secondary affected user — Finance department |
| USB Vendor | `SanDisk` | Physical infection vector |
| USB Serial | `SN1234567890` | Unique USB device identifier — primary forensic pivot |
| Drive Letter | `F:` | USB assigned drive letter on HR-WS-124 |
| File | `encryptor.exe` | Ransomware binary |
| Path | `F:\data\j.doe\AppData\Roaming\encryptor.exe` | Full path of ransomware binary on USB |
| SHA256 | `1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890` | Hash of `encryptor.exe` |
| Threat | `Ransomware.Win32.Locky` | Ransomware family |
| Application | `AnyDesk Remote Desktop` | Backdoor installed post-encryption |
| Installer | `MsiInstaller` | Silent MSI install method |
| Incident ID | `INC-20250626-987654` | SentinelOne incident reference |
| Timestamp | `2024-08-22T14:12:54 UTC` | First USB connection — HR-WS-124 |
| Timestamp | `2024-08-22T14:48:12 UTC` | Ransom notes begin dropping |
| Timestamp | `2024-08-22T14:58:17 UTC` | AnyDesk installation |
| Timestamp | `2024-08-22T15:50:03 UTC` | USB connected to second machine — FIN-WS-301 |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Replication Through Removable Media | T1091 | SanDisk USB `SN1234567890` delivered `encryptor.exe` to `HR-WS-124` and `FIN-WS-301` |
| Execution | User Execution — Malicious File | T1204.002 | `encryptor.exe` executed from `F:\data\j.doe\AppData\Roaming\` |
| Execution | Command and Scripting Interpreter — PowerShell | T1059.001 | MITRE technique attributed by SentinelOne — PowerShell used in execution chain |
| Defense Evasion | Masquerading | T1036 | `encryptor.exe` placed inside fake `AppData\Roaming` path on USB to mimic legitimate software |
| Impact | Data Encrypted for Impact | T1486 | 25 files encrypted across C:, D:, E: drives — ransom notes dropped in 5 directories |
| Command and Control | Remote Access Software | T1219 | AnyDesk installed silently via MSI — human operator maintaining live access |
| Persistence | Valid Accounts | T1078 | Attack executed under `j.doe` active session — legitimate user context used throughout |

---

## 🚨 Immediate Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | **Isolate `HR-WS-124` from the network immediately** — AnyDesk backdoor is active and the attacker may have a live session |
| 🔴 Immediate | **Isolate `FIN-WS-301` from the network** — same USB was connected, assume same payload executed |
| 🔴 Immediate | **Kill the AnyDesk process and uninstall** — terminate the remote access channel before the attacker can act further |
| 🔴 Immediate | **Recover the physical USB drive** — serial `SN1234567890` — preserve as evidence, do not reuse |
| 🔴 Immediate | **Interview `j.doe` and `a.smith`** — determine how the USB was obtained, whether the sharing was intentional, and who else may have touched the drive |
| 🔴 Immediate | **Reset passwords for `j.doe` and `a.smith`** — attacker had live desktop access and may have harvested credentials |
| 🟠 High | **Audit all mapped drives and shared folders** on both machines — determine full encryption scope beyond the 25 confirmed files |
| 🟠 High | **Check OneDrive version history** — `C:\Users\j.doe\OneDrive\Agenda.docx` was encrypted and may have synced to cloud — recover previous version before it expires |
| 🟠 High | **Review `C:\Shared\Sales\` and `E:\Shared\HR\`** — these are shared network paths; determine which other users and machines have access and whether their files are affected |
| 🟠 High | **Check for VSS (Volume Shadow Copy) deletion** — run `vssadmin list shadows` on both machines; if VSS was deleted by Locky, local recovery is impossible |
| 🟠 High | **Search `AnyDesk` connection logs** — AnyDesk stores connection history locally; recover the attacker's AnyDesk ID and any session timestamps |
| 🟠 High | **Hunt for `encryptor.exe` activity on `FIN-WS-301`** — query Wazuh for any `threat_detected` or `file_creation_detected` events from the Finance machine |
| 🟡 Medium | **Search for `.locky` extension files** across all file servers and shared drives — map the full encryption blast radius beyond what SentinelOne captured in batches |
| 🟡 Medium | **Block `SN1234567890` at the EDR layer** — add the serial number to SentinelOne's USB blocklist to prevent the drive from ever mounting again |
| 🟡 Medium | **Notify Finance and HR department heads** — both departments have confirmed encrypted files; users need to know which files are inaccessible |
| 🟡 Medium | **Initiate backup recovery assessment** — `D:\Backups\` was encrypted; identify any offline or cloud backups not affected and begin recovery planning |

---

## 📋 What to Investigate Next

**1. Confirm Execution on FIN-WS-301**
```
Query Wazuh for events from agent FIN-WS-301 after 15:50:03 UTC
→ Look for: threat_detected, file_creation_detected, encrypt_file_activity
→ Determine if encryptor.exe ran on the Finance machine
→ If yes: map the second blast radius separately
```

**2. AnyDesk Session Forensics**
```
On HR-WS-124 (if not already wiped):
→ C:\Users\j.doe\AppData\Roaming\AnyDesk\ad.trace
→ Contains: connection timestamps, attacker AnyDesk ID, session duration
→ Submit attacker AnyDesk ID to AnyDesk abuse team for account information
```

**3. Volume Shadow Copy Status**
```
Run on both machines:
→ vssadmin list shadows
→ If empty: Locky deleted VSS — local recovery impossible
→ If present: attempt file recovery from shadow copies immediately
```

**4. Full File Extension Hunt**
```
Search across all file servers for .locky extension files:
→ Get-ChildItem -Path C:\ -Recurse -Filter *.locky
→ Count gives true scope of encryption beyond SIEM batches
→ Also look for: .zepto, .odin, .aesir (Locky variant extensions)
```

**5. Network Traffic During Attack Window**
```
Review firewall/proxy logs for HR-WS-124 (10.0.12.45) from 14:12 → 15:10 UTC
→ Look for: outbound connections to unknown IPs (C2 key exchange)
→ Locky communicates with C2 server to send encryption keys
→ If C2 IP identified: block at perimeter, pivot on other machines that contacted same IP
```

---

## 📝 Lessons Learned

> **It took 35 minutes from USB insertion to a machine-wide encryption wave. It took 97 minutes for the same USB to reach a second department. The organization had no automated detection that connected these two events.**

This investigation teaches seven hard lessons:

**1. USB Device Control Is Not Optional**
The mount event carried `data.action_taken: allowed` — the USB was permitted to connect with zero friction. A Group Policy or EDR policy restricting removable storage to approved, whitelisted serial numbers would have blocked this drive at mount time. `encryptor.exe` never would have had the opportunity to run. USB device control is one of the cheapest, highest-impact security controls available — and it was absent here.

**2. Detection Is Not Prevention — And the Gap Kills**
SentinelOne's static_ai engine detected `encryptor.exe` and marked the incident as `resolved`. But 25 files were still encrypted and 5 ransom notes were still dropped. Detection fired while encryption was already mid-execution. The lesson: EDR detection without an automated kill response leaves a window of destruction. Configure SentinelOne to **kill and quarantine** immediately on ransomware detection — not just log and resolve.

**3. SIEM Correlation Rules Are What Turn Noise Into Signal**
AnyDesk was installed at `rule.level: 3` — informational. Without context, it is invisible. But AnyDesk + ransomware detection on the same host within 10 minutes is a critical escalation. A correlation rule combining these two event types would have fired an immediate high-severity alert. **The absence of correlation rules allowed a human-operated backdoor to go unnoticed inside the investigation window.**

**4. The Histogram Lies — Always Read the Table**
The serial number search returned "2 hits" in a histogram that visually looked like one cluster. A less thorough investigator would have concluded "contained to one machine" and closed the scope. Opening the results table revealed a second machine, a second user, a second department — 50 minutes after the first infection. **In SIEM investigation, the summary tells you how much. The data tells you what. Never skip the data.**

**5. Physical Attack Vectors Bypass Network Controls**
`HR-WS-124` is on `10.0.12.45`. `FIN-WS-301` is on `10.1.55.78`. Different subnets. Network segmentation designed to contain lateral movement. The USB crossed that boundary by being carried in a person's hand. No firewall, no VLAN, no network detection rule stops a person walking between desks. Physical security, USB restrictions, and security awareness training are the only defenses against this vector.

**6. Backup Drives Are Priority Targets — And They Were Hit**
`D:\Backups\Personal\` received a ransom note in the same 491-millisecond burst as everything else. `E:\Backup\User\` was encrypted in the later batches. Backups stored on locally-mounted drives are not backups — they are a second copy that ransomware will find and encrypt. The **3-2-1 backup rule** (3 copies, 2 different media, 1 offsite/offline) exists precisely for this scenario. Air-gapped or cloud-based backups with version history are the only recovery option when local drives are compromised.

**7. OneDrive Sync Turns Local Ransomware Into a Cloud Incident**
`C:\Users\j.doe\OneDrive\Agenda.docx` being encrypted means the encrypted version propagated to Microsoft 365 cloud storage through OneDrive sync. Every device sharing that OneDrive account received the encrypted file. Check version history immediately — Microsoft 365 retains previous versions for a configurable period. Beyond that window, the clean file is permanently gone from the cloud too.

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1091 — Replication Through Removable Media | [attack.mitre.org](https://attack.mitre.org/techniques/T1091/) |
| MITRE T1486 — Data Encrypted for Impact | [attack.mitre.org](https://attack.mitre.org/techniques/T1486/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1219 — Remote Access Software | [attack.mitre.org](https://attack.mitre.org/techniques/T1219/) |
| MITRE T1036 — Masquerading | [attack.mitre.org](https://attack.mitre.org/techniques/T1036/) |
| Locky Ransomware — CISA Alert | [cisa.gov](https://www.cisa.gov/) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com/) |
| SentinelOne Threat Encyclopedia | [sentinelone.com](https://www.sentinelone.com/blog/) |
| AnyDesk Abuse Reporting | [anydesk.com](https://anydesk.com/en/report-abuse) |
| 3-2-1 Backup Strategy — CISA | [cisa.gov](https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf) |

---

*Writeup by: Moetez Bouchlaghem | SOC-Investigation-Lab*
