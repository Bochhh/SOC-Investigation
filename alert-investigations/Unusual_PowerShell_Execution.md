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

Step 1 → Brute Force Detection     (Event ID 4625 — failed logons volume)
Step 2 → Initial Access Confirmed  (Event ID 4624 — successful logon)
Step 3 → PowerShell Execution      (Sysmon EID 1 — encoded command launched)
Step 4 → Payload Decode            (CyberChef — Base64 → IEX DownloadString)
Step 5 → File Drop                 (Sysmon EID 11 — PS1 files written to disk)
Step 6 → C2 Callback               (Sysmon EID 3 — outbound to 10.0.0.11:4444)
Step 7 → AMSI Bypass               (Event ID 4104 — obfuscated ScriptBlock logged)
