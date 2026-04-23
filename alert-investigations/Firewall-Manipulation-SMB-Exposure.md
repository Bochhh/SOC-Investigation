# 🔴 Alert Investigation — Firewall Manipulation via PowerShell Leading to SMB Exposure

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Alert%20Investigation-blue?style=flat)
![Attack](https://img.shields.io/badge/Attack-Firewall%20Tampering%20%7C%20SMB%20Exposure%20%7C%20RDP%20Access-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1021.001%20%7C%20T1562.004%20%7C%20T1059.001%20%7C%20T1110.003-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20TheHive-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Firewall Manipulation via PowerShell Leading to SMB Exposure |
| **Date** | December 1, 2025 |
| **Affected Host** | `PC02` (`10.0.0.101`) |
| **Affected User** | `brandon` |
| **Attacker IPs** | `66.240.236.116` / `103.114.211.48` (RDP) / `13.233.97.24` / `43.205.212.118` (SMB brute force) |
| **Attack Vector** | RDP → PowerShell firewall tampering → SMB port 445 exposed |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Deliberate firewall manipulation confirmed, SMB brute force followed |

---

## 🎯 Scenario

The investigation started from an unusual angle — not a malware alert, not a brute force flood, but **firewall rule modification events** on `PC02`. Three Windows Security events flagged that SMB inbound rules had been altered. Pulling the thread revealed a calculated sequence: an attacker who had already gained RDP access to `PC02` used PowerShell under user `brandon` to open SMB port 445 to the entire internet — and within minutes, two external IPs were hammering the host with 552 SMB authentication attempts.

This is a **post-exploitation pivot setup** — the attacker wasn't done with `PC02`, they were preparing it as an SMB entry point.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Splunk** | SIEM — log search, SPL queries, event correlation |
| **Sysmon** | Endpoint telemetry — registry, process, and network events |


---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Windows Event ID 4947 | Firewall rule modified — SMB-In rules changed on `PC02` |
| Windows Event ID 4957 | Firewall failed to apply rule — invalid port configuration |
| Sysmon Event ID 12 | Registry key created — `HKLM\...\SharedAccess\Epoch` |
| Sysmon Event ID 13 | Registry value modified — firewall config written by `svchost.exe` |
| Windows Event ID 4104 | PowerShell ScriptBlock — `Set-NetFirewallRule` commands captured |
| Windows Event ID 4103 | PowerShell module logging — `brandon` executed `Set-NetFirewallRule` |
| Sysmon Event ID 3 | Network connection — RDP sessions from external IPs to `PC02:3389` |
| SMB Event ID 551 | SMB logon failures — 552 attempts from two external IPs |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1021.001 — Remote Desktop Protocol | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/) |
| MITRE T1562.004 — Disable or Modify Firewall | [attack.mitre.org](https://attack.mitre.org/techniques/T1562/004/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1110.003 — Password Spraying | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/003/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |

---

## 🔍 Investigation Methodology

```
Step 1 → Entry Point          (WinEventLog:Security — what event codes exist?)
Step 2 → Firewall Events      (EID 4947/4957 — what rules were changed and when?)
Step 3 → Context Expansion    (±5 min window — what happened around the firewall change?)
Step 4 → Registry Activity    (Sysmon EID 12/13 — what wrote to firewall config in registry?)
Step 5 → PowerShell Commands  (EID 4104/4103 — who ran what command?)
Step 6 → Network Connections  (Sysmon EID 3 — how did the attacker get in?)
Step 7 → SMB Brute Force      (EID 551 — what happened after port 445 was opened?)
```

---

## 🕵️ Investigation

### Step 1 — Entry Point: Surveying the Security Log

The investigation began with a broad search across `WinEventLog:Security` on the `syntrix` index — **554 events** returned, with **4 unique EventCodes** present.

>  <img width="1155" height="554" alt="1" src="https://github.com/user-attachments/assets/9e5eecfa-9eb6-43cc-a2ea-38dbb0ce3539" />


```
SPL: index=syntrix sourcetype="WinEventLog:Security"

EventCode Distribution:
4688 → 269 events  (Process Created)
4689 → 266 events  (Process Exited)
4957 → 16 events   (Firewall rule failed to apply)
4947 → 3 events    (Firewall rule modified)
Host: PC02
```

> ### 🔎 Why start with EventCode distribution?
> When investigating an unknown alert, mapping the EventCode landscape gives you the full picture before diving into individual events. Here, `4957` and `4947` immediately stand out — firewall modification events are **never routine noise**. Any change to firewall rules deserves investigation, especially on an endpoint that shouldn't be managing its own firewall policy.

---
### Step 2 — Firewall Rule Failed: EID 4957

Filtering on `EventCode=4957` revealed **16 events**, all targeting `PC02`. The message was consistent across all: Windows Firewall failed to apply the rule `CoreNet-IPHTTPS-In` because the local port resolved to an empty set.

> <img width="1056" height="496" alt="02" src="https://github.com/user-attachments/assets/ab76fbf8-78c6-4ace-becc-8a063ccd3994" />

```
Event ID:   4957 (Firewall Rule Failed to Apply)
Host:       PC02
Rule:       CoreNet-IPHTTPS-In (Core Networking - IPHTTPS TCP-In)
Reason:     Local Port resolved to an empty set
Keywords:   Audit Failure
Count:      16 events
```

> ### 🔎 Why Event ID 4957?
> EID 4957 fires when a firewall rule exists but Windows can't apply it — usually because the rule is misconfigured or was modified incorrectly. Sixteen failures on `CoreNet-IPHTTPS-In` suggests something programmatically touched the firewall configuration and left rules in a broken state. This is a side effect — not the main action, but a clear indicator that something modified the firewall policy.

---
### Step 3 — Firewall Rule Modified: EID 4947

Filtering on `EventCode=4947` returned **3 events**, all on `PC02`, all clustered between `04:35:37` and `04:35:45` on `2025-12-01`. Every event carried the same message: **a Windows Firewall rule was modified**.

>  <img width="1348" height="490" alt="2" src="https://github.com/user-attachments/assets/6d9e2fa6-2d45-460d-aaa8-ddb7bcef8540" />

> <img width="1069" height="546" alt="22" src="https://github.com/user-attachments/assets/b74cad31-3bb0-4f42-b6fa-6c1b8a42c2ab" />



```
Event ID:   4947 (Firewall Rule Modified)
Host:       PC02
Count:      3 events
Timeframe:  04:35:37 AM → 04:35:45 AM (2025-12-01)
Message:    A change was made to the Windows Firewall exception list. A rule was modified.
```

> <img width="1354" height="342" alt="3" src="https://github.com/user-attachments/assets/32b0e67c-5e81-4b7e-959d-df87e49316e8" />

```
Rules Modified:
- FPS-SMB-In-TCP        (File and Printer Sharing SMB-In — TCP 445)
- FileServer-ServerManager-SMB-TCP-In
- SharedAccess\Epoch    (DWORD 0x00000855 / 0x00000856 — firewall epoch counter)
Profile changes: Public → Allow, Domain/Private → FALSE
```

> ### 🔎 Why Event ID 4947?
> EID 4947 is logged every time a Windows Firewall rule is changed. Three modifications in 8 seconds — all targeting SMB port 445 inbound rules — is not an admin making manual changes. This is **scripted firewall manipulation**. The `SharedAccess\Epoch` DWORD incrementing is Windows internally tracking that the firewall policy was reloaded. The attacker opened TCP 445 to the public profile.

---
### Step 4 — Context Expansion: What Happened Around the Firewall Change?

With the firewall modification timestamped at `04:35:37–04:35:45`, a **±5 minute window** was opened around that time to see the full picture — **40 events** returned across **11 EventCodes**.

>  <img width="1302" height="470" alt="222" src="https://github.com/user-attachments/assets/a9cf51e5-b5d2-41ae-9eae-71899ee63436" />

> <img width="1352" height="599" alt="2222" src="https://github.com/user-attachments/assets/8fb7aa86-017b-4f18-b15e-b9a5262a4042" />


Two Sysmon EventCodes immediately stood out: **EID 12** and **EID 13** — registry activity.

---
### Step 5 — Registry Manipulation: Sysmon EID 12 & 13

**Sysmon Event ID 13** (Registry Value Set) showed `svchost.exe` writing to the Windows Firewall registry key at exactly `04:35:45`:

>  <img width="1349" height="522" alt="0003" src="https://github.com/user-attachments/assets/a4684c67-6336-41a0-9b2e-ba726034a1d7" />

> <img width="1072" height="513" alt="2000" src="https://github.com/user-attachments/assets/bc98e2af-62aa-4622-b280-0e47816a63e7" />

> <img width="1096" height="517" alt="20" src="https://github.com/user-attachments/assets/4395ecbc-e177-4480-a9b7-d70dc6910d3f" />




```
Sysmon EID:   13 (Registry Value Set)
Time:         2025-12-01 04:35:45
Process:      C:\Windows\system32\svchost.exe
User:         NT AUTHORITY\NETWORK SERVICE
TargetObject: HKLM\System\CurrentControlSet\Services\SharedAccess\Epoch
RuleName:     technique_id=T1543, technique_name=Service Creation
Host:         PC02
```

**Sysmon Event ID 12** (Registry Key Created/Deleted) confirmed the same key was touched at the same timestamp:

> <img width="1361" height="565" alt="03" src="https://github.com/user-attachments/assets/64ed95ef-db82-4f91-bcde-fc612676ab24" />

> <img width="1113" height="495" alt="003" src="https://github.com/user-attachments/assets/34775f22-00a1-4f26-abfa-c4a8fc2c5729" />



```
Sysmon EID:   12 (Registry Key Created)
Time:         2025-12-01 04:35:45
Process:      svchost.exe
TargetObject: HKLM\System\CurrentControlSet\Services\SharedAccess\Epoch
EventType:    CreateKey
Host:         PC02
```

> ### 🔎 Why Sysmon EID 12 & 13?
> `SharedAccess` is the Windows Firewall service. When a firewall rule is changed via PowerShell (`Set-NetFirewallRule`), Windows translates it to a registry write under `HKLM\...\SharedAccess` and increments the `Epoch` counter to signal the firewall service to reload its policy. Seeing `svchost.exe` write here — triggered by a PowerShell command — is the **registry-level proof** that the firewall was programmatically modified.

---

### Step 6 — PowerShell Commands: Who Did This and What Did They Run?

**Windows Event ID 4104** (ScriptBlock Logging) captured the exact PowerShell commands executed on `PC02`:

> <img width="1068" height="397" alt="7" src="https://github.com/user-attachments/assets/d879ef86-77e1-45f4-88b1-b6dfde872180" />


> <img width="1073" height="411" alt="6" src="https://github.com/user-attachments/assets/6b7680e4-3560-46b3-b7eb-7b9ab2d42b24" />


```powershell
# Command 1 — 04:35:35
Set-NetFirewallRule -DisplayName "File Server Remote Management (SMB-In)" -RemoteAddress Any

# Command 2 — 04:35:45
Set-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -RemoteAddress Any
```

**Windows Event ID 4103** (PowerShell Module Logging) confirmed the executor:

> <img width="874" height="412" alt="9" src="https://github.com/user-attachments/assets/5d7dc60f-a67f-4308-84c2-31b6787bd772" />

```
Event ID:       4103 (PowerShell Module Logging)
Command:        Set-NetFirewallRule
User:           PC02\brandon
Host App:       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Host:           PC02
Time:           2025-12-01 04:35:45
ScriptBlock IDs: 614dd354-3c7c-4000-b903-f22a025afe8a
                 46a01985-d9c2-4a23-bbea-79575af2e2b3
```

> ### 🔎 Why EID 4104 + 4103?
> EID 4104 captures the **actual script content** — the exact PowerShell commands. EID 4103 captures **who ran it and from where**. Together they prove: user `brandon` on `PC02` ran `Set-NetFirewallRule` twice, changing the `RemoteAddress` on both SMB inbound rules to `Any` — meaning **anyone on the internet** can now reach TCP 445 on this machine. This was not an accident. `-RemoteAddress Any` is a deliberate, targeted firewall bypass.

---
### Step 7 — How Did the Attacker Get In? RDP Sessions Confirmed

Checking **Sysmon EID 3** (Network Connection) for inbound connections to `PC02` revealed two RDP sessions before the firewall tampering:

> <img width="1351" height="352" alt="4" src="https://github.com/user-attachments/assets/60d3a487-229c-47fd-be71-73157ef4d300" />

```
Sysmon EID:  3 (Network Connection)
Host:        PC02 (10.0.0.101)

Connection 1:
  Time:        2025-12-01 04:23:29
  Source IP:   66.240.236.116 (port 45280)
  Dest:        10.0.0.101:3389
  → First RDP session established

Connection 2:
  Time:        2025-12-01 04:32:25
  Source IP:   103.114.211.48 (port 55726)
  Dest:        10.0.0.101:3389
  → Second RDP connection — 3 minutes before firewall tampering
```

> ### 🔎 Why Sysmon EID 3?
> EID 3 logs every network connection per process. Port `3389` is RDP — seeing two external IPs connect to `PC02` on RDP **before** the firewall was modified tells us the attacker was already inside. They didn't just tamper with the firewall remotely — they were **sitting on the machine via RDP** when they ran those PowerShell commands. The firewall manipulation was a deliberate next step after gaining access.

---

### Step 8 — The Consequence: SMB Brute Force Storm

After port 445 was opened to `Any`, two external IPs immediately began hammering `PC02` with SMB authentication attempts. **Event ID 551** (SMB logon failure) returned **552 events**:

> <img width="1355" height="444" alt="5" src="https://github.com/user-attachments/assets/9854a78f-db82-47d8-a71c-caa7db68fb9b" />


> <img width="1351" height="475" alt="55" src="https://github.com/user-attachments/assets/f0e66531-7915-46a9-a2ad-e60107b2a81e" />


```
Event ID:    551 (SMB Logon Failure)
Host:        PC02
Count:       552 attempts
Timeframe:   04:39:04 → 04:39:07 (< 4 seconds)
Status:      0xC000006D — bad username or authentication information

Attacking IPs:
  13.233.97.24   → \\13.233.97.24
  43.205.212.118 → \\43.205.212.118
```

> ### 🔎 Why Event ID 551?
> EID 551 is an SMB-specific logon failure. 552 attempts from two IPs in under 4 seconds is a **coordinated SMB brute force** — the exact kind of attack that only becomes possible once port 445 is exposed to the internet. The timing is not a coincidence: firewall opened at `04:35:45`, brute force begins at `04:39:04` — only **3 minutes and 19 seconds later**. These IPs were waiting.

---
## ⏱️ Attack Timeline

| Time | Event | Detail |
|---|---|---|
| `04:23:29` | 🟡 First RDP Session | `66.240.236.116` → `PC02:3389` — attacker gains initial RDP access |
| `04:32:25` | 🟡 Second RDP Session | `103.114.211.48` → `PC02:3389` — second connection, 3 min before tampering |
| `04:35:35` | 🔴 PowerShell Command 1 | `brandon` runs `Set-NetFirewallRule "File Server Remote Management (SMB-In)" -RemoteAddress Any` |
| `04:35:45` | 🔴 PowerShell Command 2 | `brandon` runs `Set-NetFirewallRule "File and Printer Sharing (SMB-In)" -RemoteAddress Any` |
| `04:35:45` | 🔴 Registry Modified | Sysmon EID 12/13 — `svchost.exe` writes `SharedAccess\Epoch` — firewall policy reloaded |
| `04:35:45` | 🔴 Firewall Rules Changed | EID 4947 — 3 SMB-In rules modified, TCP 445 now open to `Any` |
| `04:35:45` | 🟠 Firewall Apply Errors | EID 4957 — 16 rules failed to apply (side effect of bulk modification) |
| `04:39:04` | 🔴 SMB Brute Force Begins | EID 551 — `13.233.97.24` + `43.205.212.118` hammer `PC02` on port 445 |
| `04:39:07` | 🔴 552 SMB Failures | Rapid-fire attempts — 0xC000006D — coordinated credential attack |

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| IP | `66.240.236.116` | First RDP session source — initial attacker access |
| IP | `103.114.211.48` | Second RDP session source — pre-tampering access |
| IP | `13.233.97.24` | SMB brute force attacker IP |
| IP | `43.205.212.118` | SMB brute force attacker IP |
| Host | `PC02` (`10.0.0.101`) | Compromised endpoint |
| User | `brandon` | Account used to run firewall tampering commands |
| Port | `3389` | RDP — initial access vector |
| Port | `445` | SMB — exposed by attacker via firewall rule modification |
| Registry Key | `HKLM\System\CurrentControlSet\Services\SharedAccess\Epoch` | Firewall policy registry key modified |
| Command | `Set-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" -RemoteAddress Any` | Firewall bypass command |
| Command | `Set-NetFirewallRule -DisplayName "File Server Remote Management (SMB-In)" -RemoteAddress Any` | Firewall bypass command |
| ScriptBlock ID | `614dd354-3c7c-4000-b903-f22a025afe8a` | PowerShell ScriptBlock — SMB rule 1 |
| ScriptBlock ID | `46a01985-d9c2-4a23-bbea-79575af2e2b3` | PowerShell ScriptBlock — SMB rule 2 |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Remote Desktop Protocol | T1021.001 | Sysmon EID 3 — RDP from `66.240.236.116` and `103.114.211.48` to `PC02:3389` |
| Defense Evasion | Disable or Modify Firewall | T1562.004 | EID 4947/4104 — `Set-NetFirewallRule -RemoteAddress Any` on SMB-In rules |
| Execution | PowerShell | T1059.001 | EID 4103/4104 — `brandon` executed `Set-NetFirewallRule` via `powershell.exe` |
| Credential Access | Password Spraying / Brute Force | T1110.003 | EID 551 — 552 SMB logon failures from two IPs in <4 seconds |
| Discovery | Network Service Discovery | T1046 | RDP recon followed by targeted SMB port opening |

---

## 🚨 Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Isolate `PC02` from the network |
| 🔴 Immediate | Revoke RDP access — block ports `3389` and `445` at perimeter firewall |
| 🔴 Immediate | Disable account `brandon` — investigate how credentials were obtained |
| 🔴 Immediate | Block `66.240.236.116`, `103.114.211.48`, `13.233.97.24`, `43.205.212.118` at firewall |
| 🟠 High | Restore original firewall rules — remove `-RemoteAddress Any` from all SMB-In rules |
| 🟠 High | Review all RDP logon events on `PC02` — identify how `brandon` was compromised |
| 🟠 High | Check if SMB brute force succeeded — look for EID 551 success codes |
| 🟡 Medium | Audit all PowerShell execution on `PC02` — look for additional commands run by `brandon` |
| 🟡 Medium | Hunt for same firewall modification pattern across all other hosts in the environment |
| 🟡 Medium | Enable PowerShell Constrained Language Mode and AppLocker policies |

---

## 📝 Lessons Learned

> **The attacker didn't break the door down — they walked through RDP and then opened a second door from the inside.**
> The firewall modification was the real threat, not the SMB brute force that followed. Without visibility into `Set-NetFirewallRule` via PowerShell ScriptBlock logging (EID 4104), this attack would have looked like random external SMB noise with no internal cause identified.

Key takeaways:
- Firewall rule modification events (`4947`, `4957`) are **high-value pivot points** — always investigate them, never treat them as noise
- `Set-NetFirewallRule -RemoteAddress Any` on an SMB rule from a non-admin user is an immediate critical alert
- RDP exposed to the internet is the root cause — restricting RDP to VPN or known IPs only would have blocked initial access entirely
- The 3-minute gap between firewall modification (`04:35:45`) and SMB brute force (`04:39:04`) suggests the attacking IPs were pre-staged and waiting for port 445 to open — this was coordinated, not opportunistic

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1021.001 — RDP | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/001/) |
| MITRE T1562.004 — Disable or Modify Firewall | [attack.mitre.org](https://attack.mitre.org/techniques/T1562/004/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1110.003 — Password Spraying | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/003/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Windows Security Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview) |

---
