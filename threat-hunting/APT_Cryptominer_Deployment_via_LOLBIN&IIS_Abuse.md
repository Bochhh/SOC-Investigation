# 🔴 Threat Hunting — APT Cryptominer Deployment via LOLBIN & IIS Abuse

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Threat%20Hunting-purple?style=flat)
![Attack](https://img.shields.io/badge/Attack-Resource%20Hijacking%20%7C%20LOLBIN%20%7C%20Lateral%20Movement-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1197%20%7C%20T1496%20%7C%20T1190%20%7C%20T1071.004-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20Sysmon%20%7C%20OpenCTI-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Hunt Title** | APT Cryptominer Deployment via LOLBIN & IIS Abuse |
| **Date** | August 2, 2024 |
| **Affected Hosts** | app-server-01 / app-server-02 |
| **Affected IPs** | 192.168.58.54 / 192.168.58.55 |
| **Malicious Binaries** | miner.exe / nanominer.exe |
| **Mining Pool** | account.cryptominer.io → 11.22.33.44 |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Active cryptominer confirmed on two hosts |

---

## 🎯 Scenario

A Zabbix monitoring alert reported 95% CPU usage on an internal application server. The objective was to hunt through Wazuh and Sysmon telemetry to determine whether the CPU spike was benign or the result of malicious activity — and if malicious, to trace the full attack chain across the environment.

This is **threat hunting** — starting from a single performance anomaly and following the evidence to uncover an active cryptominer deployment across two internal servers.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Wazuh** | SIEM — log aggregation and alert correlation |
| **Sysmon** | Endpoint telemetry — process, network, DNS, file events |
| **OpenCTI** | Threat intelligence — IOC validation and campaign correlation |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Wazuh alerts index | `wazuh-alerts-4.x-2024.08.02` |
| Zabbix integration logs | CPU usage alerts forwarded to Wazuh |
| Sysmon Event ID 1 | Process creation events |
| Sysmon Event ID 22 | DNS query events |
| Windows Event ID 1033 | Windows Installer product installation |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1197 — BITS Jobs | [attack.mitre.org](https://attack.mitre.org/techniques/T1197/) |
| MITRE T1496 — Resource Hijacking | [attack.mitre.org](https://attack.mitre.org/techniques/T1496/) |
| MITRE T1190 — Exploit Public-Facing Application | [attack.mitre.org](https://attack.mitre.org/techniques/T1190/) |
| MITRE T1071.004 — DNS C2 | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/004/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |

---

## 🔍 Hunt Methodology

```
Step 1 → Performance Alert      (Zabbix — what triggered the hunt?)
Step 2 → Installation Event     (Event ID 1033 — what was installed?)
Step 3 → Process Execution      (Sysmon EID 1 — how was it executed?)
Step 4 → C2 Communication       (Sysmon EID 22 — where is it calling home?)
Step 5 → Threat Intel           (OpenCTI — are IOCs known?)
Step 6 → Lateral Movement       (Wazuh — are other hosts affected?)
Step 7 → Delivery Vector        (Sysmon EID 1 — how did it get in on srv-02?)
```

---

## 🕵️ Hunt

### Step 1 — Performance Alert: What Triggered the Hunt

The hunt began with a **Zabbix CPU alert** forwarded to Wazuh at `2024-08-02T17:19:15Z`:

```
rule.groups:       monitoring, zabbix
data.cpu_usage:    95%
data.host:         app-server-01
data.alert_type:   CPU
agent.ip:          192.168.58.54
agent.name:        zabbix
```

> <img width="1091" height="534" alt="1" src="https://github.com/user-attachments/assets/63f07cc6-2ae4-49ba-9609-bf0699297c51" />


95% sustained CPU usage on an application server with no scheduled workload is an immediate anomaly. This became the pivot point for the investigation — the hunt hypothesis:

```
A cryptominer is consuming compute resources on this host.
```

---
### Step 2 — Installation Event: What Was Installed?

Searching Wazuh for installation events on `app-server-01` around the alert timestamp surfaced **Windows Event ID 1033** — triggered when Windows Installer completes a product installation:

```
data.win.system.eventID:      1033
data.win.eventdata.data:      Cudo Miner: Bitcoin & Crypto Mining Software (Miner.exe)
data.win.system.computer:     app-server-01.local
data.win.system.channel:      Application
data.win.eventdata.binary:    7B46414136443142302D4346...
```

> <img width="1096" height="538" alt="2" src="https://github.com/user-attachments/assets/084b2733-eb81-4d5a-badf-f46efa467f68" />

**Miner installation confirmed.**

> **🔍 Why Event ID 1033?**
>
> EID 1033 is logged by the Windows Installer subsystem (`msiexec`) when an MSI package finishes installing a product. An attacker using a packaged installer rather than just dropping a raw binary indicates **deliberate, structured deployment** — not accidental or opportunistic execution. This is intentional. Someone packaged the miner as a proper Windows installer and ran it on the target system.

---

### Step 3 — Process Execution: How Was It Executed?

Pivoting to **Sysmon Event ID 1** (Process Creation) on `app-server-01` revealed the full execution context:

```
data.win.eventdata.image:             C:\Users\Admin\Downloads\miner.exe
data.win.eventdata.commandLine:       "C:\Users\Admin\Downloads\miner.exe"
data.win.eventdata.currentDirectory:  C:\Windows\Temp\nanominer
data.win.eventdata.parentImage:       C:\Windows\bitsadmin.exe
data.win.eventdata.parentCommandLine: C:\Windows\bitsadmin.EXE
data.win.eventdata.integrityLevel:    Medium
data.win.eventdata.logonId:           0x1b9c1
```

> <img width="1097" height="539" alt="3" src="https://github.com/user-attachments/assets/634cc801-ee47-478d-b9e8-25ea1642e566" />


**Three immediate findings:**

**1 — Execution from user-writable path**
```
C:\Users\Admin\Downloads\miner.exe
→ Not a system directory — attacker-controlled drop location
```

**2 — Second miner already staged on disk**
```
currentDirectory: C:\Windows\Temp\nanominer
→ NanoMiner is also present — the package deployed two miners
```

**3 — Parent process: bitsadmin.exe**
```
bitsadmin.exe → miner.exe
→ Living-off-the-Land Binary (LOLBIN) used to download and execute the payload
```

> **🔍 Why bitsadmin.exe is suspicious here:**
>
> `bitsadmin.exe` is a legitimate Windows binary used to manage Background Intelligent Transfer Service (BITS) jobs — the same technology Windows uses to download updates. Attackers abuse it as a LOLBIN because downloads initiated through BITS blend in with normal Windows traffic and are often allowed by firewalls and AV. Spawning a miner binary from `bitsadmin.exe` is a textbook LOLBIN abuse technique mapped to **MITRE T1197**.

**Hashes extracted:**

| Algorithm | Value |
|---|---|
| MD5 | `514CF877644F22924DA63989F3B56CD9` |
| SHA256 | `E9E77F155877B49867483E8140845ACEBB553FC957BB27D406303E975577B526` |
| IMPHASH | `AS6D0CC37018BFE2CC21063296CADFD5` |

---
### Step 4 — C2 Communication: Where Is It Calling Home?

To identify the mining pool, I filtered **Sysmon Event ID 22** (DNS Query) by the miner process image:

```
data.win.eventdata.image:        C:\Users\Admin\Downloads\miner.exe
data.win.eventdata.queryName:    account.cryptominer.io
data.win.eventdata.queryResults: 11.22.33.44
data.win.eventdata.queryStatus:  0
data.win.system.eventID:         22
data.win.eventdata.utcTime:      2024-08-02 16:21:14.319
data.win.eventdata.user:         APP-SERVER-01\admin
```

> <img width="1107" height="555" alt="4" src="https://github.com/user-attachments/assets/9064123b-ed99-4dc3-97b5-919aaa37fc5c" />

**Mining pool identified:** `account.cryptominer.io` → `11.22.33.44`

> **🔍 Why Event ID 22 and not Event ID 3?**
>
> Sysmon EID 3 logs raw network connections — it would show `11.22.33.44:port` but **not the domain name**. EID 22 logs the DNS resolution request, capturing the human-readable domain before the TCP connection is made. The domain is far more valuable than the IP for threat intelligence correlation, IOC extraction, and firewall blocking rules. Filtering EID 22 by `data.win.eventdata.image` scopes the query directly to the miner process — showing exactly what domains it resolved.

---

### Step 5 — Threat Intelligence: Are These IOCs Known?

Both the domain and MD5 hash were submitted to **OpenCTI** for validation:

> <img width="1026" height="192" alt="5" src="https://github.com/user-attachments/assets/29531c0b-21ca-4f0b-bbea-c6f4cc6a730e" />


| IOC | Type | Tag | Source | Date |
|---|---|---|---|---|
| `account.cryptominer.io` | Domain | CryptoMiner | RiverChildren | Aug 01, 2024 |
| `514CF877644F22924DA63989F3B56CD9` | Hash | CryptoMiner | RiverChildren | Aug 01, 2024 |

Both IOCs were already flagged as **CryptoMiner** by threat intelligence source **RiverChildren** — **one day before** the Zabbix alert fired. This is a known campaign. The IOCs existed in threat intel feeds before detection triggered internally.

```
IOC published:      Aug 01, 2024
Internal detection: Aug 02, 2024
Gap:                24 hours
```

This 24-hour gap represents a missed opportunity — automated IOC ingestion into Wazuh detection rules would have flagged the miner the moment it made its first DNS resolution, before the CPU alert fired.

---
### Step 6 — Lateral Movement: Are Other Hosts Affected?

Using the confirmed MD5 hash, I searched across **all Wazuh agents**:

```
data.win.eventdata.hashes: MD5=514CF877644F22924DA63989F3B56CD9
```

> <img width="1100" height="479" alt="6" src="https://github.com/user-attachments/assets/42d7a9a0-dceb-4136-b2d6-4d74852eaa05" />

A second infected host was found immediately:

```
agent.id:                            023
agent.name:                          app-server-02
agent.ip:                            192.168.58.55
data.win.eventdata.image:            C:\Windows\Temp\nanominer\nanominer.exe
data.win.eventdata.commandLine:      "C:\Windows\Temp\nanominer\nanominer.exe"
data.win.eventdata.currentDirectory: C:\Windows\Temp\nanominer
data.win.eventdata.hashes:           MD5=514CF877644F22924DA63989F3B56CD9
```

**Same hash. Second host. Lateral movement confirmed.**

---
### Step 7 — Delivery Vector: How Did It Get In on srv-02?

The parent process on `app-server-02` is fundamentally different from `app-server-01`:

```
data.win.eventdata.parentImage:       C:\Windows\w3wp.exe
data.win.eventdata.parentCommandLine: C:\Windows\w3wp.EXE
data.win.eventdata.parentProcessId:   5004
```

> <img width="1082" height="552" alt="7 more detail other infected " src="https://github.com/user-attachments/assets/e5ce607b-5072-4eda-824a-794d792f910a" />


| Host | Miner | Parent Process | Delivery Method |
|---|---|---|---|
| app-server-01 | Cudo Miner + NanoMiner | `bitsadmin.exe` | LOLBIN download — T1197 |
| app-server-02 | NanoMiner | `w3wp.exe` | IIS worker process — web shell suspected — T1190 |

> **🔍 Why w3wp.exe as a parent is critical:**
>
> `w3wp.exe` is the IIS (Internet Information Services) worker process — it serves web application requests. It should **never** spawn binaries like a cryptominer. When `w3wp.exe` appears as the parent of a suspicious process, it is a strong indicator that the attacker achieved code execution through the web application layer — either through a **web shell** upload or a **server-side vulnerability exploit**. This points to a completely different initial access vector than `app-server-01`, suggesting the attacker used different delivery mechanisms per target.

---

## 🚧 Dead Ends and Investigation Limits

| Area | What Was Tried | Result |
|---|---|---|
| bitsadmin parent on srv-01 | Sysmon EID 1 — bitsadmin as child process | Not captured — only appeared as parent |
| bitsadmin job details / download URL | EID 1 commandline search | No logs available |
| IIS logs for web shell on srv-02 | w3wp.exe EID 1/11 correlation | No telemetry captured |
| Persistence mechanisms | Scheduled tasks, registry run keys, services | Not found in available logs |
| Pre-bitsadmin activity on srv-01 | Full initial access trace | Insufficient log coverage |

These gaps represent **logging blind spots**, not evidence of absence. A full IR engagement would require host-level forensics, IIS access log review, and file system timeline analysis.

---

## ⏱️ Complete Attack Timeline

```
2024-08-01 22:53  →  IOCs published to OpenCTI (RiverChildren)
                      account.cryptominer.io and MD5 tagged as CryptoMiner
                      [Hunt team had no visibility at this point]

2024-08-02 ??:??  →  Miner deployed on app-server-01
                      bitsadmin.exe downloads and executes miner.exe
                      NanoMiner staged in C:\Windows\Temp\nanominer\

2024-08-02 ??:??  →  Miner deployed on app-server-02
                      w3wp.exe spawns nanominer.exe
                      [IIS/web shell vector — exact time not captured]

2024-08-02 16:21  →  miner.exe resolves account.cryptominer.io → 11.22.33.44
                      Mining pool communication begins (Sysmon EID 22)

2024-08-02 17:19  →  Zabbix alert fires — CPU at 95% on app-server-01
                      Hunt initiated from this trigger

2024-08-02 17:19+ →  Wazuh investigation begins
                      EID 1033 → miner install confirmed
                      EID 1 → bitsadmin LOLBIN delivery confirmed
                      EID 22 → mining pool C2 identified
                      Hash pivot → app-server-02 discovered
                      OpenCTI → IOCs confirmed as known campaign
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Mining Pool Domain** | `account.cryptominer.io` |
| **Mining Pool IP** | `11.22.33.44` |
| **Miner Binary (srv-01)** | `C:\Users\Admin\Downloads\miner.exe` |
| **Miner Binary (srv-02)** | `C:\Windows\Temp\nanominer\nanominer.exe` |
| **MD5** | `514CF877644F22924DA63989F3B56CD9` |
| **SHA256** | `E9E77F155877B49867483E8140845ACEBB553FC957BB27D406303E975577B526` |
| **Infected Host 1** | app-server-01 — 192.168.58.54 |
| **Infected Host 2** | app-server-02 — 192.168.58.55 |
| **LOLBIN Used** | `bitsadmin.exe` |
| **IIS Process Abused** | `w3wp.exe` |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | w3wp.exe spawning nanominer.exe on srv-02 |
| Execution | BITS Jobs | T1197 | bitsadmin.exe as parent of miner.exe on srv-01 |
| Execution | User Execution | T1204 | miner.exe dropped in Downloads — user-context execution |
| Defense Evasion | BITS Jobs LOLBIN | T1197 | bitsadmin used to blend download with Windows traffic |
| C2 | Application Layer Protocol: DNS | T1071.004 | DNS query to account.cryptominer.io from miner.exe |
| Impact | Resource Hijacking | T1496 | 95% CPU consumption on app-server-01 |

---

## 💡 Key Lessons Learned

**1 — Threat Intel Integration Matters**
The IOCs were published in OpenCTI **24 hours before** Zabbix detected the CPU spike. Automated IOC ingestion directly into Wazuh detection rules would have flagged the miner the moment it made its first DNS resolution — before the CPU alert fired.

**2 — LOLBIN Abuse Is Hard to Block, Easy to Detect**
`bitsadmin.exe` is a legitimate Windows binary — blocking it outright breaks Windows Update workflows. But `bitsadmin.exe` spawning a `.exe` from `C:\Users\...\Downloads\` is not legitimate behavior. Behavioral detection rules on LOLBIN parent-child relationships are the right control.

**3 — w3wp.exe Should Never Spawn Binaries**
IIS worker processes executing child processes outside their expected scope is one of the most reliable indicators of web shell activity. This should be a high-priority detection rule in any Windows web server environment.

**4 — Hash Pivoting Reveals Scope**
The investigation started on one host. A single hash search across all agents immediately surfaced the second infected server. Hash-based hunting across the entire environment is a fundamental step after any malware confirmation.

**5 — Logging Gaps Are a Real Risk**
The inability to trace bitsadmin's parent or the IIS initial access vector on srv-02 highlights the cost of incomplete Sysmon coverage. Without the full process tree, the initial access vector remains unknown — leaving potential re-entry paths open.

---

## 🔧 Recommendations

| Priority | Action |
|---|---|
| 🔴 Critical | Isolate app-server-01 and app-server-02 immediately |
| 🔴 Critical | Block `account.cryptominer.io` and `11.22.33.44` at perimeter firewall and DNS |
| 🔴 Critical | Terminate and delete `miner.exe` and `nanominer.exe` from both hosts |
| 🔴 Critical | Investigate IIS on app-server-02 for web shell artifacts |
| 🟠 High | Hunt the same MD5 hash across all remaining Wazuh agents |
| 🟠 High | Search for any other hosts communicating with `11.22.33.44` |
| 🟠 High | Integrate OpenCTI IOC feeds into Wazuh detection rules for automated matching |
| 🟡 Medium | Create behavioral detection rule: bitsadmin.exe spawning executables from user directories |
| 🟡 Medium | Create behavioral detection rule: w3wp.exe spawning any child process |
| 🟡 Medium | Review and expand Sysmon coverage to capture full process trees |
| 🟢 Low | Implement egress filtering to block connections on non-standard mining ports |

---

## ✅ Conclusion

```
Verdict:    TRUE POSITIVE ✅
Malware:    Cudo Miner + NanoMiner (cryptomining campaign)
Hosts:      app-server-01 (192.168.58.54)
            app-server-02 (192.168.58.55)
C2:         account.cryptominer.io → 11.22.33.44
Delivery:   bitsadmin.exe LOLBIN (srv-01) | w3wp.exe IIS abuse (srv-02)
IOC Status: Known campaign — RiverChildren / OpenCTI (Aug 01, 2024)
Gap:        IOCs were available 24 hours before internal detection triggered
```

> *The attacker didn't need zero-days.*
> *They used a Windows built-in binary to download the miner.*
> *They used a web application process to deploy it on the second host.*
> *The IOCs were already in threat intel the day before.*
> *The only thing missing was the connection between the intel and the detection.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com) |
| OpenCTI | [opencti.io](https://www.opencti.io) |

---
