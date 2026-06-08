# 🔴 Digital Forensics Investigation — Phantom Validation: Phishing-to-Execution Chain Analysis

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Digital%20Forensics%20%7C%20Incident%20Response-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-Phishing%20%7C%20LOLBin%20Abuse%20%7C%20URL%20Redirection-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1566.002%20%7C%20T1204.002%20%7C%20T1105%20%7C%20T1218%20%7C%20T1036-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-FTK%20Imager%20%7C%20MFT%20Explorer%20%7C%20DB%20Browser%20%7C%20Registry%20Explorer%20%7C%20CyberChef-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Phantom Validation — Phishing to Execution Chain |
| **Date** | February 1, 2026 |
| **Victim User** | `T3M0` |
| **Victim Email** | `darknight1133377@gmail.com` |
| **Shortened URL** | `https://2cm.es/lnUk9` |
| **Payload URL** | `http://8.222.205.174/scripts/Payroll_Update_January.zip` |
| **Execution Script** | `Payroll_Verification.cmd` |
| **LOLBin Used** | `certutil.exe` |
| **C2 Server** | `8.222.205.174` |
| **Transient File** | `payroll_template.dat` |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full phishing-to-execution chain confirmed across multiple artifact sources |

---

## 🎯 Scenario

A victim identified as user `T3M0` received a payroll-themed Gmail message containing a shortened URL. The URL redirected to an external host where a payroll archive was downloaded, extracted, and used to execute a command script. The script abused a native Windows utility to fetch external content — including a transient file that was quickly deleted to cover tracks.

This investigation traces the full attack chain using filesystem artifacts, browser databases, NTFS records, prefetch files, and Caddy web server access logs — piecing together every action the attacker took from the first click to the final payload fetch.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **FTK Imager** | Browse and export artifacts from the C drive copy |
| **DB Browser for SQLite** | Parse Chrome SQLite databases — History, Downloads |
| **MFT Explorer** | Browse the Master File Table visually |
| **MFTECmd + Timeline Explorer** | Parse and search $MFT for file timestamps and deleted files |
| **NTFS Log Tracker** | Parse $LogFile for NTFS transaction records |
| **Registry Explorer** | Analyze NTUSER.DAT registry hive |
| **Event Log Explorer** | Parse Windows event logs |
| **Notepad++** | Read and search log files, JSON access logs |
| **CyberChef** | Convert Unix timestamps to human-readable format |

---

## 🗂️ Artifacts Analyzed

| Artifact | Location | What it provided |
|---|---|---|
| Chrome `History` | `T3M0\AppData\Local\Google\Chrome\User Data\Default\` | Visited URLs, download chain |
| Chrome `downloads_url_chains` | Same Chrome Default folder | Full redirect chain — short URL → real URL |
| Chrome `Preferences` | Same Chrome Default folder | Victim Gmail account |
| `$MFT` | Root of C drive copy | File creation timestamps, deleted files |
| `$LogFile` | Root of C drive copy | NTFS transaction records — exact timestamps |
| `NTUSER.DAT` | `T3M0\` | User registry — execution history |
| Prefetch files | `C:\Windows\Prefetch\` | Program execution evidence |
| `acces-logs.json` | Challenge artifacts | Caddy server access log — C2 communication |
| Console logs | Challenge artifacts | Script execution commands |
| Copy/Skip logs | Challenge artifacts | Files present during acquisition |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1566.002 — Spearphishing Link | [attack.mitre.org](https://attack.mitre.org/techniques/T1566/002/) |
| MITRE T1204.002 — Malicious File | [attack.mitre.org](https://attack.mitre.org/techniques/T1204/002/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1218 — System Binary Proxy Execution | [attack.mitre.org](https://attack.mitre.org/techniques/T1218/) |
| MITRE T1036 — Masquerading | [attack.mitre.org](https://attack.mitre.org/techniques/T1036/) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |

---

## 🔍 Investigation Methodology

```
Phase 1 → Artifact Survey        (FTK Imager — understand what we have)
Phase 2 → Browser Forensics      (DB Browser — email, URLs, download chain)
Phase 3 → Filesystem Forensics   (MFT Explorer + MFTECmd — script creation, deleted files)
Phase 4 → NTFS Journal Analysis  ($LogFile — exact timestamps from change records)
Phase 5 → Execution Evidence     (Prefetch — confirm LOLBin execution)
Phase 6 → Server Log Analysis    (acces-logs.json — C2 communication confirmed)
Phase 7 → Full Chain Assembly    (connect all artifacts into one timeline)
```

---

## 🕵️ Investigation

### Phase 1 — Artifact Survey: Understanding What We Have

Every forensic investigation starts the same way — before touching anything, map the terrain. We were given a copy of the victim's C drive and a set of supplementary artifacts. The first step was to load the C drive copy into **FTK Imager** and understand the folder structure.

> <img width="349" height="491" alt="0" src="https://github.com/user-attachments/assets/dd4bf59c-230f-4358-b9ba-44a396559cad" />


FTK Imager is a forensic imaging and browsing tool that lets us read a drive copy without modifying it — preserving the integrity of the evidence. The moment we opened the Evidence Tree, one thing stood out immediately: the user folder was named **`T3M0`** — not a default Windows name. This is our victim.

```
C:\
├── $Extend
├── ProgramData
├── Users
│   ├── Default
│   ├── Public
│   └── T3M0          ← victim user
└── Windows
```

Alongside the C drive, we also had access to four supplementary artifact files:
- **Console logs** — terminal command history
- **Copy logs** — files successfully copied during acquisition
- **Skip logs** — files that couldn't be copied (locked or deleted)
- **`acces-logs.json`** — Caddy web server access log from the attacker's server

We also found three critical NTFS system files at the root of the C drive copy:


| File | Size | Purpose |
|---|---|---|
| `$MFT` | 145,664 KB | Master File Table — index of every file ever on this drive |
| `$LogFile` | 65,536 KB | NTFS transaction journal — record of every filesystem operation |
| `$Secure_$SDS` | 2,391 KB | Security descriptors — file permissions |
| `$Boot` | 8 KB | Boot sector |

> ### 🔎 What is the $MFT?
> The Master File Table is NTFS's internal index — every single file and folder on the drive gets an entry here. The critical thing about the MFT is that **even deleted files leave their entry behind**. When a file is deleted, Windows marks the MFT entry as available for reuse but doesn't immediately erase it. This means we can recover metadata — name, path, timestamps — for files that no longer exist on disk. For forensics, the MFT is one of the most valuable artifacts on any Windows system.

> ### 🔎 What is the $LogFile?
> The $LogFile is NTFS's transaction journal — it records every filesystem operation (create, modify, delete, rename) as a transaction before it's committed to disk. This is separate from the MFT and provides a chronological record of what happened to files. When the question asks for "NTFS change records," this is the artifact being referenced — it gives us the most reliable and tamper-resistant timestamps of file activity.

---

### Phase 2 — Browser Forensics: Tracing the Phishing Chain

With the artifact landscape mapped, the investigation turned to the browser. The scenario told us the attack began with a Gmail message — so Chrome's artifact database was the logical starting point.

#### Step 2.1 — Finding the Victim's Email (Q1)

We navigated through the Evidence Tree to the Chrome profile folder:

```
T3M0 → AppData → Local → Google → Chrome → User Data → Default
```

> <img width="459" height="152" alt="00" src="https://github.com/user-attachments/assets/c29bff7e-bcac-4142-a1ce-2a4933f27c7f" />


Inside this folder we found several SQLite database files. Chrome stores virtually all its data in SQLite format — visited URLs, downloaded files, saved passwords, cookies, and browser preferences. 

We opened the Chrome History database directly in DB Browser for SQLite and navigated to the urls table. Scrolling through the browsing history, row 29 revealed a Gmail tab title that exposed the victim's email address embedded directly in the page title — exactly as Chrome records it when a Gmail message is open.

> <img width="1029" height="538" alt="3" src="https://github.com/user-attachments/assets/c1398b87-dade-4d84-8c67-3bfb978b68c6" />


Chrome stores the full page title of every visited URL in the urls table. When Gmail is open, the tab title follows the format [email subject] - [account email] - Gmail — giving us both the phishing email subject "Payroll Template January 2026" and the victim's account darknight1133377@gmail.com in a single record.

---

#### Step 2.2 — The Shortened URL and Redirect Chain (Q2 & Q3)

With the victim identified, we needed to trace what they clicked. Chrome doesn't just record visited URLs — it also records the full redirect chain for every download. This is stored in the `downloads_url_chains` table, which captures every URL hop from the initial click to the final file download.

We switched to the `downloads_url_chains` table in DB Browser:

> 📸 *Screenshot: DB Browser for SQLite — downloads_url_chains table showing 4 rows: dl.google.com (chain 0), google.com/url (chain 0), https://2cm.es/lnUk9 (chain 1), http://8.222.205.174/scripts/Payroll_Update_January.zip (chain 2)*

The `chain_index` column tells the story perfectly:

```
id=1  chain_index=0  https://dl.google.com/tag/s/...          ← Google tracking
id=2  chain_index=0  https://www.google.com/url?...           ← Google redirect
id=2  chain_index=1  https://2cm.es/lnUk9                    ← 🚨 shortened URL
id=2  chain_index=2  http://8.222.205.174/scripts/Payroll_Update_January.zip  ← 🚨 real destination
```

> ### 🔎 What is downloads_url_chains?
> When Chrome downloads a file, it records every URL in the redirect chain that led to the download — not just the final URL. The `chain_index` column shows the position in the chain: 0 is the starting point, 1 is the first redirect, 2 is the final destination. This table is forensically invaluable because it exposes URL shorteners and redirect chains that would otherwise hide the true origin of a downloaded file.

The redirect chain tells a clear story: the victim received a link, clicked it, it went through Google's tracking, then hit the **shortened URL** `https://2cm.es/lnUk9`, which immediately redirected to the **attacker's server** at `http://8.222.205.174` where `Payroll_Update_January.zip` was hosted and downloaded.

**✅ Q2 Answer:**
```
https://2cm.es/lnUk9
```

**✅ Q3 Answer:**
```
http://8.222.205.174/scripts/Payroll_Update_January.zip
```

---

### Phase 3 — Filesystem Forensics: The Script on Disk

The victim downloaded `Payroll_Update_January.zip` and extracted it. Something inside that archive was executed. Our next task was to find that file on disk and establish exactly when it appeared.

#### Step 3.1 — Identifying the Execution Script (Q4)

We opened **MFT Explorer** and loaded the `$MFT` file. MFT Explorer is a GUI tool from Eric Zimmermann that lets us browse the Master File Table visually — navigating through the folder structure just like Windows Explorer, but with full forensic metadata for every file.

> 📸 *Screenshot: MFT Explorer — T3M0\Desktop folder selected, file list showing KAPE folder, New folder, ChatGPT Installer.exe, desktop.ini, gpg4win-4.4.1.exe, Payroll_Verification.cmd*

Navigating to `T3M0\Desktop`, one file immediately stood out:

```
Payroll_Verification.cmd
Parent Path: .\Users\T3M0\Desktop
SI_Created:  2026-02-01 09:15:16.0000000
FN_Created:  2026-02-01 07:46:07.03
Is Deleted:  ☐ (still on disk)
```

> ### 🔎 How do we know this is malicious and not a legitimate file?
> When faced with multiple files in MFT Explorer, we apply a systematic identification methodology — never guessing:
>
> **1. Name analysis:** `Payroll_Verification.cmd` — the word "Payroll" matches the phishing theme exactly. The `.cmd` extension means it's a Windows command script — an executable file that runs commands.
>
> **2. Location analysis:** The file sits on the Desktop — where a user would typically place something they downloaded and extracted. Legitimate payroll tools don't live on the Desktop as `.cmd` files.
>
> **3. Timestamp analysis — SI vs FN:** This is where forensics gets deep. Every file in NTFS has **two sets of timestamps**:
> - `SI` ($STANDARD_INFORMATION) — the timestamps Windows shows in Explorer. **These can be modified by any program or malware** — a technique called timestomping.
> - `FN` ($FILE_NAME) — timestamps set by the Windows kernel when the file is created. **These are extremely difficult to modify** because they require kernel-level access.
>
> When SI and FN timestamps differ significantly, it indicates **timestomping** — the attacker tried to make the file look older than it is.
>
> **4. Creation time relative to incident:** `Payroll_Verification.cmd` was created on `2026-02-01` — the same date as our incident. It didn't exist before the attack.
>
> **5. Extension:** `.cmd` files are execution scripts. No legitimate payroll document is a `.cmd` file.

**✅ Q4 Answer:**
```
Payroll_Verification.cmd
```

---

#### Step 3.2 — Exact Creation Timestamp from NTFS Records (Q5)

The question specifically asks for the timestamp from **NTFS change records** — meaning the `$LogFile`, not just the MFT. We used **NTFS Log Tracker** to parse the `$LogFile` alongside the `$MFT`:

> 📸 *Screenshot: NTFS Log Tracker — $LogFile parsed, Payroll_Verification.cmd entry showing FILE_CREATE operation at 2026-02-01 09:15:16*

We also parsed the `$MFT` using **MFTECmd** from Eric Zimmermann Tools to export a full CSV for searching in Timeline Explorer:

```bash
MFTECmd.exe -f "C:\Users\LetsDefend\Desktop\ChallengeFile\$MFT" --csv "C:\Users\LetsDefend\Desktop\output" --csvf mft_output.csv
```

> 📸 *Screenshot: Timeline Explorer — mft_output.csv loaded, filtered for Payroll_Verification.cmd, SI_Created timestamp visible*

> ### 🔎 Why use $LogFile instead of just MFT timestamps?
> The MFT stores the current state of a file's timestamps — but those can be altered. The `$LogFile` records the actual filesystem transaction at the moment it happened. It's like the difference between a document and the audit log of who edited it and when. The `$LogFile` is the most forensically reliable source for "when did this file actually appear on disk."

**✅ Q5 Answer:**
```
2026-02-01 09:15:16
```

---

### Phase 4 — The Transient File: Created and Deleted in the Same Window (Q6)

This was the most interesting forensic challenge. The scenario described a file that was "quickly deleted" — a transient file used during execution and then removed to cover tracks. Files like this don't appear in normal filesystem browsing because they're gone. But they leave traces in two places: the `$MFT` (as a deleted entry) and the `$LogFile` (as a create + delete transaction pair).

We filtered Timeline Explorer on `IsDeleted = True` and narrowed the timeframe to `2026-02-01` around the execution window. We were also looking for files fetched from the C2 server — something that appeared, was used, and then vanished.

> 📸 *Screenshot: Timeline Explorer — IsDeleted filter applied, showing payroll_template.dat entry with creation and deletion timestamps in same execution window*

Cross-referencing with the **skip logs** (files that couldn't be copied during acquisition because they were locked or deleted), we confirmed the file's existence:

> 📸 *Screenshot: Skip logs — payroll_template.dat listed as skipped during copy*

> ### 🔎 What does "create-and-delete lifecycle" mean forensically?
> When an attacker fetches a file, uses it, and immediately deletes it, they're trying to leave no trace on disk. But NTFS records both the creation and deletion as separate transactions in the `$LogFile`. Even if the file content is gone, the metadata — filename, path, timestamps, size — remains in the MFT as a deleted entry. This is why forensic investigators always analyze the `$LogFile` and filter deleted files — the attacker's cleanup operation itself becomes evidence.

**✅ Q6 Answer:**
```
payroll_template.dat
```

---

### Phase 5 — Execution Evidence: Prefetch Confirms the LOLBin

Before diving into the server logs, we checked the **Prefetch** folder — one of the most valuable sources of program execution evidence on Windows. Every time a program runs for the first time, Windows creates a `.pf` (prefetch) file recording its name, run count, last run time, and the files it accessed.

> 📸 *Screenshot: FTK Imager — Windows\Prefetch folder showing CERTUTIL.EXE-FA34F34C.pf among other prefetch files*

```
CERTUTIL.EXE-FA34F34C.pf  ← 🚨 certutil was executed on this machine
```

> ### 🔎 What are Prefetch files?
> Windows Prefetch is a performance optimization feature — it pre-loads frequently used programs faster. But as a forensic artifact, prefetch files are gold. The `.pf` file name contains the executable name and a hash of the executable's path. Finding `CERTUTIL.EXE-FA34F34C.pf` tells us definitively that `certutil.exe` was run on this machine during the relevant timeframe. We can parse it with **PECmd** (Eric Zimmermann) for the exact run time and files accessed.

```bash
PECmd.exe -f "C:\Windows\Prefetch\CERTUTIL.EXE-FA34F34C.pf" --csv "C:\output"
```

This prefetch evidence combined with the server log sealed the case on Q9.

---

### Phase 6 — Server Log Analysis: The C2 Conversation

The most direct evidence of what happened comes from the attacker's own server. The `acces-logs.json` file is a **Caddy web server** access log — Caddy is a modern HTTP server that logs every request in JSON format.

We opened `acces-logs.json` in **Notepad++** and searched for `.dat` — the extension of our transient file.

> 📸 *Screenshot: Notepad++ — acces-logs.json open, search for .dat, entry visible showing uri: /update/payroll_template.dat, User-Agent: CertUtil URL Agent, status: 404*

We found two log entries for `payroll_template.dat`. Let's read them carefully:

**Entry 1:**
```json
{
  "level": "error",
  "ts": 1769926371.447009,
  "logger": "http.log.access.log0",
  "msg": "handled request",
  "request": {
    "remote_ip": "156.159.15.52",
    "remote_port": "40317",
    "client_ip": "156.159.15.52",
    "proto": "HTTP/1.1",
    "method": "GET",
    "host": "8.222.205.174",
    "uri": "/update/payroll_template.dat",
    "headers": {
      "User-Agent": ["curl/8.16.0"],
      "Accept": ["*/*"]
    }
  },
  "status": 404,
  "size": 0
}
```

**Entry 2:**
```json
{
  "uri": "/update/payroll_template.dat",
  "headers": {
    "User-Agent": ["CertUtil URL Agent"],
    "Accept": ["*/*"],
    "Cache-Control": ["no-cache"]
  }
}
```

> ### 🔎 Reading the Caddy Access Log — Every Field Explained
>
> | Field | Value | Meaning |
> |---|---|---|
> | `level` | `error` | Server encountered an issue processing the request |
> | `ts` | `1769926371.447009` | Unix timestamp — seconds since Jan 1 1970 |
> | `logger` | `http.log.access.log0` | Which Caddy logger generated this — not relevant |
> | `msg` | `handled request` | Server received and processed the request |
> | `remote_ip` | `156.159.15.52` | Victim machine's IP address |
> | `method` | `GET` | HTTP GET request — fetching/downloading a file |
> | `host` | `8.222.205.174` | The C2 server — same IP from Q3 ✅ |
> | `uri` | `/update/payroll_template.dat` | Exact file requested — **Q7 answer** |
> | `User-Agent` | `CertUtil URL Agent` | **Q9 answer** — certutil identifies itself this way |
> | `status` | `404` | File not found — already deleted from server |
> | `size` | `0` | Nothing returned — the file was gone |
> | `Cache-Control` | `no-cache` | certutil always sends this — another identifier |

> ### 🔎 Why did certutil get a 404?
> The `payroll_template.dat` file was a **transient resource** — it existed on the attacker's server only during the execution window. Once the script fetched it (or after a set time), the attacker deleted it from the server. The 404 response tells us the file was already gone when this log entry was recorded — but the request itself proves certutil tried to fetch it.

> ### 🔎 Why is "CertUtil URL Agent" significant for Q9?
> `certutil.exe` is a **native Windows binary** — it comes pre-installed on every Windows system and is designed for certificate management. But it has a hidden capability: it can download files from URLs using the `-urlcache` flag. When certutil makes an HTTP request, it identifies itself with the User-Agent string `CertUtil URL Agent` — this is its fingerprint in server logs. Because certutil is a legitimate Windows tool, it often bypasses application whitelisting and security controls — this is the definition of a **LOLBin** (Living Off the Land Binary): abusing a trusted system tool for malicious purposes.

**✅ Q7 Answer:**
```
http://8.222.205.174/update/payroll_template.dat
```

**✅ Q9 Answer:**
```
certutil.exe
```

---

### Phase 7 — Timestamp Conversion: Pinpointing the Fetch (Q8)

The server log timestamp `1769926371.447009` is in Unix epoch format — the number of seconds elapsed since January 1, 1970 at 00:00:00 UTC. To convert it to a human-readable timestamp, we used **CyberChef**:

> 📸 *Screenshot: CyberChef — From Unix Timestamp recipe, input 1769926371, output showing 2026-02-01 07:23:29 UTC*

```
Input:  1769926371
Output: 2026-02-01 07:23:29 UTC
```

**✅ Q8 Answer:**
```
2026-02-01 07:23:29 UTC
```

---

## ⏱️ Attack Timeline

| Time (UTC) | Event | Artifact | Detail |
|---|---|---|---|
| `Before 07:23` | 🟡 Phishing Email Received | Chrome History | `darknight1133377@gmail.com` received payroll-themed Gmail |
| `~07:23` | 🔴 Shortened URL Clicked | downloads_url_chains | `https://2cm.es/lnUk9` clicked in Gmail |
| `~07:23` | 🔴 Redirect to C2 | downloads_url_chains | `2cm.es` redirected to `8.222.205.174` |
| `~07:23` | 🔴 Archive Downloaded | Chrome Downloads | `Payroll_Update_January.zip` downloaded from C2 |
| `~07:23-09:15` | 🟡 Archive Extracted | $MFT | Zip extracted — `Payroll_Verification.cmd` prepared |
| `09:15:16` | 🔴 Script Created on Disk | $MFT / $LogFile | `Payroll_Verification.cmd` written to `T3M0\Desktop` |
| `09:15:xx` | 🔴 Script Executed | Prefetch / Console logs | User ran `Payroll_Verification.cmd` |
| `07:23:29` | 🔴 certutil Fetched Payload | acces-logs.json | `certutil.exe` → `http://8.222.205.174/update/payroll_template.dat` |
| `07:23:29` | 🔴 Transient File Lifecycle | $MFT / $LogFile | `payroll_template.dat` created → used → deleted |
| `07:23:29` | 🟠 Server Returns 404 | acces-logs.json | File already deleted from C2 server — anti-forensics |

---

## 🧾 Investigation Answers Summary

| # | Question | Answer |
|---|---|---|
| Q1 | Email address associated with victim | `darknight1133377@gmail.com` |
| Q2 | Shortened URL used in phishing | `https://2cm.es/lnUk9` |
| Q3 | Actual URL hosting payroll archive | `http://8.222.205.174/scripts/Payroll_Update_January.zip` |
| Q4 | File that initiated execution chain | `Payroll_Verification.cmd` |
| Q5 | Exact script creation timestamp (NTFS) | `2026-02-01 09:15:16` |
| Q6 | Transient file with create-delete lifecycle | `payroll_template.dat` |
| Q7 | External resource fetched by script | `http://8.222.205.174/update/payroll_template.dat` |
| Q8 | Exact timestamp of external fetch | `2026-02-01 07:23:29 UTC` |
| Q9 | Native Windows utility (LOLBin) used | `certutil.exe` |

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| Email | `darknight1133377@gmail.com` | Victim Gmail account |
| URL | `https://2cm.es/lnUk9` | Shortened phishing URL |
| URL | `http://8.222.205.174/scripts/Payroll_Update_January.zip` | Payload archive download URL |
| URL | `http://8.222.205.174/update/payroll_template.dat` | Transient file fetch URL |
| IP | `8.222.205.174` | C2 server — hosted both payloads |
| File | `Payroll_Update_January.zip` | Malicious archive delivered via phishing |
| File | `Payroll_Verification.cmd` | Execution script extracted from archive |
| File | `payroll_template.dat` | Transient file fetched and deleted |
| Binary | `certutil.exe` | LOLBin abused for file download |
| User-Agent | `CertUtil URL Agent` | certutil HTTP fingerprint in server logs |
| Victim IP | `156.159.15.52` | Victim machine IP seen in C2 logs |
| User | `T3M0` | Compromised Windows user account |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing Link | T1566.002 | Payroll-themed Gmail with shortened URL |
| Execution | User Execution — Malicious File | T1204.002 | Victim ran `Payroll_Verification.cmd` |
| Defense Evasion | Masquerading | T1036 | Archive and script named with payroll theme |
| Command & Control | Ingress Tool Transfer | T1105 | `certutil.exe` fetched `payroll_template.dat` from C2 |
| Defense Evasion | System Binary Proxy Execution | T1218 | `certutil.exe` used as LOLBin to bypass controls |
| Defense Evasion | Indicator Removal — File Deletion | T1070.004 | `payroll_template.dat` deleted after use |

---

## 🚨 Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Block `8.222.205.174` at perimeter firewall and DNS |
| 🔴 Immediate | Block `2cm.es` domain — phishing redirect |
| 🔴 Immediate | Isolate `T3M0` workstation — check for persistence |
| 🔴 Immediate | Reset `darknight1133377@gmail.com` credentials |
| 🟠 High | Analyze `Payroll_Verification.cmd` full contents — what else did it do? |
| 🟠 High | Check if `payroll_template.dat` content can be recovered from memory or $LogFile |
| 🟠 High | Hunt all endpoints for `certutil.exe` with URL arguments in process logs |
| 🟠 High | Check `T3M0` for persistence mechanisms — scheduled tasks, registry run keys |
| 🟡 Medium | Review email gateway — block payroll-themed emails with shortened URLs |
| 🟡 Medium | Hunt for `2cm.es` in proxy/DNS logs across all users |
| 🟡 Medium | Alert on `certutil.exe` spawned by cmd/script processes enterprise-wide |

---

## 📝 Lessons Learned

> **The attacker built a chain designed to frustrate forensics at every step.**
> The shortened URL hid the real destination. The archive gave the script a legitimate-looking delivery mechanism. The script used a native Windows binary — certutil — that most security tools trust by default. And the fetched payload was deleted immediately, leaving no file content to analyze. Yet every step left forensic traces across multiple artifact sources — and that's what this investigation exploited.

Key takeaways:

- **URL shorteners are red flags** — always expand them before clicking. In forensics, the `downloads_url_chains` table in Chrome exposes the full redirect chain even when the shortener hides it
- **The $MFT never forgets** — deleted files leave their metadata entry behind. The $LogFile records the exact transaction. Together they reconstruct what happened even after cleanup
- **SI timestamps can be faked — FN timestamps cannot** — always compare both in MFT analysis. A mismatch indicates timestomping
- **LOLBins leave their own fingerprints** — certutil identifies itself as `CertUtil URL Agent` in HTTP requests. Native tools abused for malicious purposes still leave traces in server logs, prefetch files, and process logs
- **Server logs are two-way evidence** — the attacker's own Caddy server log recorded the victim's IP, the exact file requested, the tool used, and the timestamp. The attacker's infrastructure became their own evidence trail

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1566.002 — Spearphishing Link | [attack.mitre.org](https://attack.mitre.org/techniques/T1566/002/) |
| MITRE T1204.002 — Malicious File | [attack.mitre.org](https://attack.mitre.org/techniques/T1204/002/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1218 — System Binary Proxy Execution | [attack.mitre.org](https://attack.mitre.org/techniques/T1218/) |
| MITRE T1070.004 — Indicator Removal | [attack.mitre.org](https://attack.mitre.org/techniques/T1070/004/) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| CyberChef | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) |
| Caddy Server Documentation | [caddyserver.com](https://caddyserver.com/docs/) |

---

*Writeup by: Moetez Bouchlaghem | SOC-Investigation-Lab*
