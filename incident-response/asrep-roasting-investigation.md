# 🔴 Alert Investigation — AS-REP Roasting & Lateral Movement in Active Directory

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Alert%20Investigation%20%7C%20Active%20Directory%20Attack-blue?style=flat)
![Attack](https://img.shields.io/badge/Attack-AS--REP%20Roasting%20%7C%20NTLM%20Lateral%20Movement%20%7C%20Credential%20Theft-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1558.004%20%7C%20T1550.002%20%7C%20T1021.002%20%7C%20T1059.003-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Event%20Log%20Explorer%20%7C%20PECmd%20%7C%20Timeline%20Explorer-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Case Title** | AS-REP Roasting & Lateral Movement — SOPRANOS.LOCAL |
| **Date** | October 5, 2024 |
| **Domain** | `SOPRANOS.LOCAL` |
| **Domain Controller** | `Sopranos-DC.SO` |
| **Attacker IP** | `192.168.110.129` |
| **Victim Machine** | `192.168.110.128` (Corrado's workstation) |
| **Target Account** | `Corrado` |
| **Attack Type** | AS-REP Roasting → NTLM Lateral Movement |
| **Tools Used by Attacker** | `XYIWCCCL.EXE` (renamed Rubeus), `CMD.EXE`, `WHOAMI.EXE` |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full attack chain confirmed: AS-REP Roasting → credential theft → lateral movement → post-exploitation |

---

## 🎯 Scenario

The network security team received alerts from the Domain Controller indicating that a user was making unusual requests for Kerberos tickets — behavior not typical for their role. The security team escalated the issue for investigation. An investigator was tasked with analyzing Domain Controller logs and workstation logs to trace the attacker's movements, determine the source of the anomaly, and understand how the attacker gained access and what actions they took inside the network.

What the investigation revealed was a textbook Active Directory attack chain: an attacker who had already gained a foothold inside the network ran an AS-REP Roasting attack against the `Corrado` account, stole its Kerberos hash in RC4 format, and used those credentials to move laterally via NTLM authentication — ultimately executing post-exploitation commands on the compromised workstation.

---

## 🔐 Understanding the Attack — AS-REP Roasting Explained

Before diving into the evidence, it's essential to understand exactly how this attack works — because understanding the attack is what tells us where to look for evidence.

### What is Kerberos Pre-Authentication?

In a healthy Active Directory environment, Kerberos authentication works like this:

```
Normal Authentication Flow:
Step 1 → User logs in
         Workstation sends AS-REQ to DC
         Includes encrypted timestamp (pre-authentication)
         DC verifies: "Yes, this user knows their password"
         DC issues TGT (Ticket Granting Ticket)

Step 2 → User accesses a resource
         Workstation sends TGS-REQ with TGT
         DC issues Service Ticket for that resource

Step 3 → User presents Service Ticket to resource
         Access granted
```

Pre-authentication is the critical security step — it proves the user knows their password BEFORE the DC hands over any encrypted material.

### What Happens Without Pre-Authentication?

Some accounts have a setting called **"Do not require Kerberos preauthentication"** — a dangerous misconfiguration that removes this security check:

```
AS-REP Roasting Attack:
Step 1 → Attacker identifies accounts with pre-auth disabled
         (through LDAP enumeration or AD queries)

Step 2 → Attacker sends AS-REQ to DC for target account
         WITHOUT providing any pre-authentication
         "Hey DC, give me a TGT for Corrado"

Step 3 → DC responds with AS-REP
         Encrypted with Corrado's password hash
         No identity verification performed

Step 4 → Attacker captures the encrypted AS-REP
         Takes it offline
         Cracks it with hashcat:
         hashcat -m 18200 hash.txt wordlist.txt

Step 5 → Gets Corrado's plaintext password
         Uses it for lateral movement
```

### Why RC4 (0x17) Specifically?

```
Attacker requests RC4 encryption deliberately:
→ RC4 hashes crack in minutes/hours with GPU
→ AES256 hashes take days/years to crack
→ Attack tools like Rubeus force RC4:
   rubeus.exe asreproast /user:Corrado /rc4opsec

This RC4 request is the KEY SIGNATURE in logs:
→ Modern Windows NEVER requests RC4 by default
→ Seeing 0x17 from a non-standard machine = attack tool
```

### What "Unusual Kerberos Ticket Requests" Means

The alert described unusual ticket requests not typical for the user's role. Here's what that looks like:

```
Normal user behavior:
→ 1 TGT request at login (morning)
→ 3-5 service ticket requests during the day
→ For services they normally use
→ From their own workstation

Suspicious behavior (AS-REP Roasting):
→ TGT requested for account FROM DIFFERENT MACHINE
→ RC4 encryption explicitly requested (attack tool)
→ Non-standard ticket options
→ No pre-authentication provided
→ Multiple accounts targeted in short window
```

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Event Log Explorer** | Parse and filter Windows EVTX log files |
| **PECmd** (Eric Zimmermann) | Parse Windows Prefetch files — execution evidence |
| **Timeline Explorer** (Eric Zimmermann) | Visualize and search PECmd CSV output |

---

## 🗂️ Artifacts Analyzed

| Artifact | Source | What it provided |
|---|---|---|
| `Security.evtx` (DC) | Domain Controller | EID 4768/4769 — Kerberos ticket events |
| `Security.evtx` (Workstation) | `192.168.110.128/.129` | EID 4624/4688 — logon and process events |
| Prefetch files | `C:\Windows\Prefetch\` | Execution evidence — attack tools confirmed |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1558.004 — AS-REP Roasting | [attack.mitre.org](https://attack.mitre.org/techniques/T1558/004/) |
| MITRE T1550.002 — Pass the Hash | [attack.mitre.org](https://attack.mitre.org/techniques/T1550/002/) |
| MITRE T1021.002 — SMB/Lateral Movement | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/002/) |
| MITRE T1059.003 — Windows Command Shell | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/003/) |
| Rubeus Tool Reference | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |

---

## 🔍 Investigation Methodology

```
Phase 1 → DC Log Analysis — EID 4768
          (Find AS-REP Roasting attempts)

Phase 2 → DC Log Analysis — EID 4769
          (Find post-roast service ticket requests)

Phase 3 → Workstation Log Analysis — EID 4624
          (Confirm lateral movement via NTLM)

Phase 4 → Workstation Log Analysis — EID 4688
          (Find process execution — attack tools)

Phase 5 → Prefetch Analysis — PECmd
          (Confirm tool execution and post-exploitation)

Phase 6 → Full Timeline Construction
```

---

## 🕵️ Investigation

### Phase 1 — DC Log Analysis: Hunting AS-REP Roasting

The investigation began at the Domain Controller — the nerve center of all Kerberos authentication in the domain. Every TGT request, every service ticket, every authentication attempt flows through the DC and gets logged here.

We opened the DC Security event log in **Event Log Explorer** and applied our first filter:

> <img width="797" height="594" alt="1" src="https://github.com/user-attachments/assets/1746aceb-8aba-4d7a-a5df-dbd982fc0986" />


```
Filter applied:
Event ID:             4768
Text in description:  Pre-Authentication Type: 0
```

> ### 🔎 Why Event ID 4768?
> EID 4768 is logged every time a Kerberos Authentication Service request (AS-REQ) is made to the DC — in other words, every time someone requests a TGT. This is the first step in Kerberos authentication and the exact event that captures AS-REP Roasting attempts.
>
> We specifically filter for `Pre-Authentication Type: 0` because:
> - Normal authentication: Pre-Auth Type = `2` (encrypted timestamp provided)
> - AS-REP Roasting: Pre-Auth Type = `0` (no pre-auth — account is vulnerable)
>
> Any 4768 event with Pre-Auth Type = 0 means either the account is misconfigured OR an attacker is exploiting that misconfiguration.

**Results — Three Critical Events Found:**

>  

---

#### Event 1 — 2:39:42 PM (Reconnaissance)

> <img width="533" height="205" alt="1111111" src="https://github.com/user-attachments/assets/ea0d36e7-9110-46c8-81f3-b5fd5375e6ec" />



```
Time:                    2024-10-05 14:39:42
Account Name:            Corrado
Domain:                  SOPRANOS.LOCAL
Client Address:          ::ffff:192.168.110.129   ← attacker machine
Client Port:             49936
Service Name:            krbtgt
Result Code:             0x0  ← success
Ticket Options:          0x10
Ticket Encryption Type:  0x12  ← AES256
Pre-Authentication Type: 0     ← no pre-auth
```

> ### 🔎 Reading This Event — Reconnaissance Phase
>
> **`Client Address: 192.168.110.129`** — This is the attacker's machine. The `::ffff:` prefix is IPv4-mapped IPv6 notation — it simply means this is an IPv4 address `192.168.110.129` wrapped in IPv6 format. This is normal for modern Windows DC logging.
>
> **`Pre-Authentication Type: 0`** — This tells us two things: (1) Corrado's account has "Do not require Kerberos preauthentication" enabled — a dangerous misconfiguration. (2) The requester did NOT provide pre-authentication proof. This is the vulnerability being exploited.
>
> **`Ticket Encryption Type: 0x12`** — AES256 encryption. At this stage, the attacker is just doing reconnaissance — querying the DC to find which accounts are vulnerable. The tool sent a default request and got AES256 back. AES256 is not useful for offline cracking.
>
> **`Ticket Options: 0x10`** — Minimal flags. This is a lightweight probe query, not the full attack yet. The attacker's tool is saying "tell me about this account" before launching the actual roasting.
>
> **Summary:** This is the **reconnaissance step** — the attacker discovered that Corrado's account has pre-authentication disabled and is vulnerable to AS-REP Roasting.

---

#### Event 2 — 2:40:56 PM (Legitimate Login — Baseline)

> <img width="1025" height="583" alt="3" src="https://github.com/user-attachments/assets/82e0771e-f775-402c-b311-9752bf74e2ec" />


```
Time:                    2024-10-05 14:40:56
Account Name:            Corrado
Domain:                  SOPRANOS.LOCAL
Client Address:          ::ffff:192.168.110.128   ← Corrado's own machine
Client Port:             53594
Service Name:            krbtgt
Result Code:             0x0  ← success
Ticket Options:          0x40810010
Ticket Encryption Type:  0x12  ← AES256
Pre-Authentication Type: 0     ← no pre-auth (account misconfiguration)
```

> ### 🔎 Why This Event is Legitimate
>
> At first glance, this looks identical to the attack — same account, same Pre-Auth Type 0. But three fields tell us this is legitimate:
>
> **`Client Address: 192.168.110.128`** — This is Corrado's OWN workstation, not the attacker's `.129`. Corrado is logging into his own machine normally.
>
> **`Ticket Encryption Type: 0x12`** — AES256 is what modern Windows requests by default. No attack tool forced RC4 here.
>
> **`Ticket Options: 0x40810010`** — Standard Windows Kerberos client flags. This is the bit pattern of a normal Windows login, not an attack tool.
>
> **Important note:** Pre-Auth Type 0 appears here because it's a property of **Corrado's account** — not of who is requesting. The DC will always issue Corrado's TGT without pre-auth to ANYONE who asks, because the account is misconfigured. Corrado's legitimate login looks the same as an attack request at this level — which is exactly why this misconfiguration is so dangerous.
>
> **Summary:** This is **baseline legitimate traffic** — Corrado logging into his workstation normally, completely unaware that his account is being targeted.

---

#### Event 3 — 2:42:44 PM (The AS-REP Roasting Attack) 🚨

> <img width="899" height="584" alt="2" src="https://github.com/user-attachments/assets/549c3822-30c7-481e-8e16-dd1fe06b8e88" />


```
Time:                    2024-10-05 14:42:44
Account Name:            Corrado
Domain:                  SOPRANOS.LOCAL
Client Address:          ::ffff:192.168.110.129   ← attacker machine
Client Port:             49684
Service Name:            krbtgt
Result Code:             0x0  ← success — hash delivered
Ticket Options:          0x50800000               ← attack tool signature
Ticket Encryption Type:  0x17                     ← 🚨 RC4-HMAC
Pre-Authentication Type: 0                        ← no pre-auth
```

> ### 🔎 This is the Smoking Gun — Breaking Down Every Field
>
> **`Client Address: 192.168.110.129`** — Same attacker machine from Event 1. Two minutes after reconnaissance, the attack begins.
>
> **`Ticket Encryption Type: 0x17 (RC4-HMAC)`** — This is the definitive indicator of AS-REP Roasting. RC4 is a legacy weak encryption algorithm that Windows has deprecated in modern environments. No modern Windows client requests RC4 by default — it has to be explicitly forced. Attack tools like Rubeus do this deliberately because RC4 hashes are exponentially faster to crack offline than AES256.
>
> The encryption type comparison:
> ```
> 0x12 = AES256-CTS-HMAC-SHA1  → modern, strong, hard to crack
> 0x17 = RC4-HMAC               → legacy, weak, fast to crack 🚨
> 0x11 = AES128                 → acceptable
> 0x03 = DES                    → very weak (disabled by default)
> ```
>
> **`Ticket Options: 0x50800000`** — Non-standard bit flags that don't match any normal Windows Kerberos client behavior. This specific bit pattern is a known signature of Rubeus and Impacket AS-REP Roasting tools.
>
> Compare the three events:
> ```
> Event 1 (.129 recon):    0x10         ← minimal probe
> Event 2 (.128 legit):    0x40810010   ← standard Windows
> Event 3 (.129 attack):   0x50800000   ← attack tool signature 🚨
> ```
>
> **`Result Code: 0x0`** — Success. The DC returned the AS-REP encrypted with Corrado's RC4 hash. The attacker now has material they can crack offline.
>
> **Summary:** This is the **actual AS-REP Roasting attack**. The attacker forced RC4 encryption and received Corrado's password hash in a format optimized for offline cracking. The hash looks like:
> ```
> $krb5asrep$23$Corrado@SOPRANOS.LOCAL:a3f8c2d1...
> ```
> This gets fed into hashcat and cracked to reveal Corrado's plaintext password.

---

#### The Three-Event Attack Pattern — Side by Side

```
TIME        IP      ENCRYPTION  TICKET OPTIONS  MEANING
─────────────────────────────────────────────────────────
14:39:42   .129    0x12        0x10            Recon probe
14:40:56   .128    0x12        0x40810010      Legit login ✅
14:42:44   .129    0x17 🚨     0x50800000 🚨   AS-REP Roast 🚨
```

This three-event sequence is the complete fingerprint of an AS-REP Roasting attack:
- Attacker probes → finds vulnerability → executes targeted attack
- Legitimate traffic in between = Corrado has no idea what's happening
- RC4 + non-standard options = attack tool signature

---

### Phase 2 — DC Log Analysis: Service Ticket Requests (EID 4769)

With the AS-REP Roasting confirmed, the next question was: did the attacker use Corrado's credentials for lateral movement through Kerberos service ticket requests?

We filtered for Event ID 4769:

>  <img width="820" height="608" alt="5" src="https://github.com/user-attachments/assets/28c1020b-95dc-4bf1-b362-fa973a20200c" />


> ### 🔎 What is Event ID 4769?
> EID 4769 is logged every time a Kerberos Service Ticket (TGS) is requested — in other words, when an authenticated user wants to access a specific resource (file server, SQL server, web app). This event tells us what services a user is accessing and from which machine. In lateral movement investigations, we look for:
> - Service tickets requested FROM the attacker's IP
> - For services the account doesn't normally access
> - With RC4 encryption (0x17) — indicating Kerberoasting or Pass-the-Ticket

**Results — All 4769 Events from Corrado:**

> <img width="883" height="364" alt="555555" src="https://github.com/user-attachments/assets/3123159d-a7b9-4c6c-a4d0-b75df80b5b5b" />


> <img width="930" height="581" alt="55" src="https://github.com/user-attachments/assets/fcc939f3-8601-4204-9eeb-fb9b6d987801" />


```
2:19:15 PM (x4) → from .128 → 0x12 AES256
2:19:35 PM      → from .128 → 0x12 AES256
2:20:14 PM      → from .128 → 0x12 AES256
2:20:15 PM (x4) → from .128 → 0x12 AES256
2:30:47 PM      → from .128 → 0x12 AES256
2:40:56 PM      → from .128 → 0x12 AES256
2:44:34 PM      → from .128 → 0x12 AES256
3:20:04 PM      → from .128 → 0x12 AES256
3:20:58 PM      → from .128 → 0x12 AES256
3:56:29 PM      → from .128 → 0x12 AES256
5:05:27 PM      → from .128 → 0x12 AES256
```

> ### 🔎 Why All 4769 Events Are Legitimate
>
> Every single 4769 event showed three indicators of legitimate traffic:

> <img width="865" height="651" alt="4" src="https://github.com/user-attachments/assets/4b0edfce-89bb-4aaa-9e0b-44e87c477a2d" />

> <img width="1083" height="424" alt="44" src="https://github.com/user-attachments/assets/b1fe0d9f-983b-4561-9f6f-89d90486432a" />


> **Source IP: `.128`** — All service ticket requests came from Corrado's own workstation, not the attacker's `.129`. No 4769 events were observed from the attacker's machine.
>
> **Encryption: `0x12` (AES256)** — Standard Windows encryption for all requests. No RC4 (0x17) service ticket requests were observed — which would indicate Kerberoasting or Pass-the-Ticket.
>
> **Ticket Options: `0x40810000`** — Standard Windows Kerberos client flags. No attack tool signatures.
>
> **Important note about `CORRADO$` vs `Corrado`:**
> Some 4769 events showed `Account Name: CORRADO$` — note the dollar sign. This is the **computer account** for the workstation named CORRADO, not the human user Corrado. Computer accounts automatically request service tickets in the background for domain authentication — this is completely normal Windows behavior.
>
> **Conclusion:** No 4769 evidence of Kerberos-based lateral movement was found within the log window. This means either:
> - The attacker had not yet cracked the hash when these logs end
> - The attacker used a non-Kerberos lateral movement method (NTLM)
> - The investigation detected the attack before full Kerberos exploitation

---

### Phase 3 — Workstation Log Analysis: Lateral Movement via NTLM

The absence of 4769 events from `.129` directed us to the workstation logs. If the attacker wasn't using Kerberos for lateral movement, they may have used **NTLM** — the older Windows authentication protocol.

We opened the workstation Security log and applied two filters:

>  <img width="868" height="635" alt="6" src="https://github.com/user-attachments/assets/750b1894-4675-44cc-aeb6-883eef6601e7" />


**First filter:**
```
Event ID:    4624  (Successful Logon)
Logon Type:  3     (Network logon)
```

>  <img width="882" height="510" alt="7" src="https://github.com/user-attachments/assets/a0af115e-141d-43b8-a299-077b8ea07802" />


**Second filter added:**
```
Source Network Address: 192.168.110.129
```

> ### 🔎 Why These Specific Filters?
>
> **Event ID 4624** logs every successful authentication on a Windows machine. There are multiple logon types:
> ```
> Type 2  = Interactive (physical keyboard login)
> Type 3  = Network (connecting over network)
> Type 4  = Batch (scheduled task)
> Type 5  = Service (service account)
> Type 10 = RemoteInteractive (RDP)
> Type 11 = CachedInteractive (offline cached credentials)
> ```
> We filter for **Type 3 (Network)** because lateral movement via SMB, named pipes, or network share access creates Type 3 logons — the attacker connecting to this machine over the network using Corrado's credentials.
>
> Adding the source IP filter `.129` narrows results to ONLY connections originating from the attacker's machine — eliminating all legitimate traffic.

**Critical Finding:**

> <img width="1058" height="473" alt="7777" src="https://github.com/user-attachments/assets/e5fd5e77-b6e0-4708-9bf7-039fb0400ce3" />


```
Event ID:               4624
Logon Type:             3 (Network)
Account Name:           Corrado
Source Network Address: 192.168.110.129   ← attacker machine
Source Port:            36792
Workstation Name:       (blank)           ← attack tool behavior
Logon Process:          NtLmSsp           ← NTLM negotiation
Authentication Package: NTLM              ← 🚨 not Kerberos
Package Name:           NTLM V2
Process ID:             0x0               ← network-originated
Process Name:           (blank)
```

> ### 🔎 Breaking Down Every Field
>
> **`Authentication Package: NTLM`** — This is the most telling field. In a modern Active Directory environment, Kerberos is the default and preferred authentication protocol. NTLM is the legacy fallback. Seeing NTLM used from the attacker's machine means they connected by **IP address** rather than hostname — Kerberos requires DNS hostname resolution to work; when you connect by IP, Windows falls back to NTLM. This is a classic attacker technique and a key detection indicator.
>
> **`Package Name: NTLM V2`** — NTLMv2 is the modern version of NTLM. The attacker used Corrado's cracked password to authenticate via NTLMv2 — proving they successfully cracked the AS-REP hash.
>
> **`Workstation Name: (blank)`** — Legitimate Windows clients always send their workstation name during NTLM authentication. Attack tools frequently omit this field, leaving it blank. An empty workstation name in a Type 3 logon is a red flag for tool-based lateral movement.
>
> **`Process ID: 0x0`** — The null process ID means no local process on this machine initiated the authentication. The connection came entirely from the network — from `.129` reaching into this machine. This is consistent with remote network access.
>
> **`Source Port: 36792`** — A high ephemeral port, consistent with an outbound connection from the attacker's machine. Attackers connect from random high ports to standard service ports (445 for SMB, 135 for RPC, etc.).

---

### Phase 4 — Workstation Log Analysis: Process Creation (EID 4688)

With lateral movement confirmed via NTLM, we needed to find what the attacker executed once they had access. We filtered for Event ID 4688 — process creation events:

> <img width="907" height="241" alt="8" src="https://github.com/user-attachments/assets/a0072160-4063-4dfc-8d06-396fc0c55501" />


```
Pre-attack processes found (2:07 PM):
2:07:36 PM → Process created
2:07:41 PM → Process created (x4)
2:07:43 PM → Process created
2:07:45 PM → Process created
Computer: Corrado.SOPRANOS
```

> ### 🔎 Why No 4688 Events During the Attack Window?
>
> Event ID 4688 (Process Creation) requires two Group Policy settings to be enabled:
> ```
> 1. Audit Process Creation (generates the event)
> 2. Include command line in process creation events
>    (adds the actual command arguments)
> ```
>
> Without both settings enabled, 4688 events either don't generate or generate without the critical command line field. In this environment, process creation auditing appears to be partially configured — capturing pre-attack baseline activity but not providing complete coverage of the attack window.
>
> This is a common gap in enterprise logging configurations and highlights the importance of comprehensive audit policy deployment.
>
> When Security log coverage is incomplete, we pivot to **Prefetch files** — a Windows performance artifact that independently records program execution regardless of Security log settings.

---

### Phase 5 — Prefetch Analysis: Confirming Tool Execution

Prefetch is Windows' secret forensic gift. When the Security log fails us, Prefetch doesn't.

> ### 🔎 What are Windows Prefetch Files?
>
> Windows Prefetch is a performance optimization feature — when a program runs, Windows records information about it to make future launches faster. Each execution creates or updates a `.pf` file in `C:\Windows\Prefetch\` named after the executable.
>
> **Forensic value — why Prefetch is superior to Security logs for execution evidence:**
>
> ```
> Security Log (4688):
> → Requires Audit Policy to be enabled
> → Can be cleared by attacker with admin rights
> → May not include command line arguments
> → Single log file = single point of failure
>
> Prefetch:
> → Created automatically by Windows regardless of audit policy
> → Separate from Security logs — survives log clearing
> → Records up to 8 last run timestamps
> → Records run count (how many times executed)
> → Records files and DLLs accessed during execution
> → Much harder for attacker to find and delete
> ```
>
> **What each Prefetch file contains:**
> ```
> Executable name and path
> Last run timestamp (most recent)
> Previous run timestamps (up to 7 more)
> Run count (total executions)
> Files accessed during execution
> DLLs loaded during execution
> Volume information
> ```

We parsed the Prefetch directory using **PECmd**:

>  <img width="1009" height="88" alt="9" src="https://github.com/user-attachments/assets/13e5a8bd-0480-4dc3-899c-1405605d5480" />


```bash
PECmd.exe -d "C:\Users\LetsDefend\Desktop\ChallengeFile\AS-REP\corrado\prefetch\" \
          --csv C:\Users\LetsDefend\Desktop\ChallengeFile\csvf\investigation.csv
```

Output confirmed:
```
CSV timeline output saved to investigation.csv
```

We opened `investigation.csv` in **Timeline Explorer** and sorted by `LastRun` timestamp, correlating with our attack window (after 2:42:44 PM):

>  <img width="1059" height="638" alt="10 OPEN TIMELINE " src="https://github.com/user-attachments/assets/72e821fe-12a7-4f6d-a35c-635e75935720" />


> <img width="997" height="230" alt="11" src="https://github.com/user-attachments/assets/ab828685-195a-4439-ac9c-e0d82dee87fa" />


---

#### Prefetch Findings — Post-Attack Execution Timeline

```
2024-10-05 15:01:01 → XYIWCCCL.EXE    RunCount: 1
2024-10-05 15:01:04 → CMD.EXE         RunCount: 1
2024-10-05 15:01:30 → WHOAMI.EXE      RunCount: 1
2024-10-05 15:03:32 → DLLHOST.EXE     RunCount: 9
```

> ### 🔎 XYIWCCCL.EXE — The Renamed Attack Tool 🚨
>
> ```
> Name:      XYIWCCCL.EXE
> LastRun:   2024-10-05 15:01:01 (3:01:01 PM)
> RunCount:  1
> ```
>
> This binary is not a legitimate Windows executable — no such file exists in any standard Windows installation. The name is a random 8-character string followed by `.EXE` — a classic attacker technique for evading detection:
>
> **Why attackers rename tools:**
> ```
> Original: Rubeus.exe
> → AV signatures look for "Rubeus.exe" by name
> → Many security tools alert on "Rubeus" string
>
> Renamed: XYIWCCCL.exe
> → No signature match on filename
> → Bypasses simple name-based detection
> → Content is identical — behavior unchanged
> → Only behavioral analysis or hash detection catches it
> ```
>
> **Evidence this is Rubeus or similar tool:**
> ```
> → Random name pattern (8 chars) = typical rename pattern
> → RunCount: 1 = ran once, did the job, done
> → Executed 18 minutes after AS-REP Roast
> → Immediately followed by CMD.EXE (spawned a shell)
> → Timeline perfectly aligns with attack sequence
> ```
>
> **What Rubeus does when run:**
> ```
> rubeus.exe asreproast
> → Queries AD for vulnerable accounts
> → Sends AS-REQ without pre-auth
> → Forces RC4 encryption
> → Captures AS-REP hash
> → Outputs: $krb5asrep$23$Corrado@SOPRANOS.LOCAL:...
> ```

> ### 🔎 CMD.EXE — Command Shell Spawned
>
> ```
> Name:      CMD.EXE
> LastRun:   2024-10-05 15:01:04 (3 seconds after XYIWCCCL)
> RunCount:  1
> ```
>
> Windows Command Prompt launched 3 seconds after the attack tool. This sequence — attack tool → CMD → WHOAMI — is textbook post-exploitation:
> ```
> XYIWCCCL.EXE runs → completes AS-REP Roasting
>      ↓ (3 seconds)
> CMD.EXE spawned → attacker now has interactive shell
>      ↓ (26 seconds)
> WHOAMI.EXE → first recon command
> ```
> RunCount: 1 means this CMD session was new — the attacker opened a fresh command prompt for their session.

> ### 🔎 WHOAMI.EXE — Post-Exploitation Recon
>
> ```
> Name:      WHOAMI.EXE
> LastRun:   2024-10-05 15:01:30 (26 seconds after CMD)
> RunCount:  1
> ```
>
> `whoami` is the first command virtually every attacker runs after gaining access. It answers:
> ```
> → Which user account am I running as?
> → What domain am I in?
> → Do I have the privileges I expected?
>
> Output example:
> sopranos\corrado
>
> Attacker confirms:
> ✅ I'm running as Corrado
> ✅ In SOPRANOS domain
> ✅ Lateral movement succeeded
> ```
>
> This is a universal post-exploitation signature — from script kiddies to nation-state actors, `whoami` is always the first command.

> ### 🔎 DLLHOST.EXE — Suspicious Context
>
> ```
> Name:      DLLHOST.EXE
> LastRun:   2024-10-05 15:03:32
> RunCount:  9
> ```
>
> `dllhost.exe` is a legitimate Windows process that hosts COM objects. However, it's frequently abused by attackers for:
> ```
> → Process injection (hiding malicious code inside legitimate process)
> → COM object-based persistence
> → Bypassing application whitelisting
> ```
>
> RunCount: 9 indicates it had run before — could be legitimate background activity. The timing immediately after our attack sequence warrants further investigation. Whether this is attacker-controlled or legitimate Windows activity requires deeper analysis of the files it accessed (visible in PECmd FilesLoaded column).

---

## ⏱️ Complete Attack Timeline

| Time | Phase | Event | Source | Evidence |
|---|---|---|---|---|
| `14:39:42` | 🟡 Recon | AS-REQ for Corrado — AES256, minimal flags | DC EID 4768 | IP: .129, Enc: 0x12, Opts: 0x10 |
| `14:40:56` | ✅ Legit | Corrado normal login from own workstation | DC EID 4768 | IP: .128, Enc: 0x12, Opts: 0x40810010 |
| `14:42:44` | 🔴 Attack | AS-REP Roast — RC4 hash stolen | DC EID 4768 | IP: .129, Enc: 0x17, Opts: 0x50800000 |
| `14:42:44+` | 🔴 Offline | Hash cracked offline with hashcat | No log | Password recovered |
| `~15:00` | 🔴 Lateral | NTLM Type 3 logon from .129 as Corrado | WS EID 4624 | NTLM V2, blank workstation, PID 0x0 |
| `15:01:01` | 🔴 Execute | XYIWCCCL.EXE run (renamed Rubeus) | Prefetch | RunCount: 1 |
| `15:01:04` | 🔴 Shell | CMD.EXE spawned | Prefetch | RunCount: 1 |
| `15:01:30` | 🔴 Recon | WHOAMI.EXE — confirmed access as Corrado | Prefetch | RunCount: 1 |
| `15:03:32` | 🟠 Unknown | DLLHOST.EXE — possible injection/persistence | Prefetch | RunCount: 9 |

---

## 🧾 IOC Table

| Type | Value | Description |
|---|---|---|
| IP | `192.168.110.129` | Attacker machine |
| IP | `192.168.110.128` | Corrado's legitimate workstation |
| Account | `Corrado` | Compromised AD account |
| Domain | `SOPRANOS.LOCAL` | Target domain |
| DC | `Sopranos-DC.SO` | Domain Controller |
| Encryption | `0x17` (RC4-HMAC) | AS-REP Roasting signature |
| Ticket Options | `0x50800000` | Attack tool signature (Rubeus/Impacket) |
| Auth Package | `NTLM V2` | Lateral movement via NTLM |
| File | `XYIWCCCL.EXE` | Renamed attack tool (Rubeus) |
| Event | EID 4768, Pre-Auth: 0, Enc: 0x17 | AS-REP Roasting indicator |
| Event | EID 4624, Type 3, NTLM, blank workstation | Lateral movement indicator |
| Time | `2024-10-05 14:42:44` | AS-REP Roast timestamp |
| Time | `2024-10-05 15:01:01` | Tool execution timestamp |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | AS-REP Roasting | T1558.004 | EID 4768 — RC4 (0x17), Pre-Auth Type 0, from .129 |
| Lateral Movement | Use Alternate Auth Material | T1550.002 | NTLM Type 3 logon from .129 as Corrado |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | Network logon Type 3, NtLmSsp |
| Execution | Windows Command Shell | T1059.003 | CMD.EXE in Prefetch post-attack |
| Discovery | System Owner/User Discovery | T1033 | WHOAMI.EXE in Prefetch |
| Defense Evasion | Masquerading — Rename Tool | T1036.003 | XYIWCCCL.EXE — renamed Rubeus |

---

## 🚨 Response Actions

| Priority | Action |
|---|---|
| 🔴 Immediate | Reset Corrado's password — credentials confirmed compromised |
| 🔴 Immediate | Isolate `192.168.110.129` from network — attacker's machine |
| 🔴 Immediate | Enable Kerberos Pre-Authentication on Corrado's account |
| 🔴 Immediate | Hunt for `XYIWCCCL.EXE` across all endpoints |
| 🟠 High | Audit ALL AD accounts for "Do not require Kerberos preauthentication" — disable on all |
| 🟠 High | Block RC4 encryption domain-wide via Group Policy |
| 🟠 High | Identify initial foothold on `.129` — how did attacker get there? |
| 🟠 High | Check what Corrado's account accessed after 3:01 PM |
| 🟡 Medium | Enable full command line auditing (EID 4688) on all endpoints |
| 🟡 Medium | Deploy Sysmon for enhanced process creation logging |
| 🟡 Medium | Enable PowerShell ScriptBlock logging (EID 4104) domain-wide |
| 🟡 Medium | Implement privileged account monitoring and alerting |

---

## 📋 What to Investigate Next

**1. How Did the Attacker Get on .129?**
```
The attacker had a foothold on 192.168.110.129
BEFORE running the AS-REP Roasting attack
→ Check .129 Security logs for EID 4624 before 2:39 PM
→ Look for: RDP login, phishing, exploit, VPN access
→ This is the TRUE initial access vector
```

**2. What Did XYIWCCCL.EXE Access?**
```
PECmd FilesLoaded column shows files accessed
→ Open Timeline Explorer → find XYIWCCCL.EXE row
→ Expand FilesLoaded column
→ What config files? What output files?
→ Did it write a hash file to disk?
```

**3. What Did Attacker Do After WHOAMI?**
```
After confirming access, attacker likely:
→ Ran net user, net group (AD enumeration)
→ Ran ipconfig, arp (network mapping)
→ Accessed file shares
→ Attempted privilege escalation
→ Check Prefetch for more executables after 3:01 PM
```

**4. DLLHOST.EXE Investigation**
```
RunCount: 9 — existed before attack
→ Check PECmd FilesLoaded for DLLHOST
→ Compare access timestamps with attack window
→ Determine if legitimate or attacker-controlled
```

**5. Domain-Wide AS-REP Audit**
```
Corrado was found vulnerable — are others?
Run PowerShell on DC:
Get-ADUser -Filter * -Properties DoesNotRequirePreAuth |
Where {$_.DoesNotRequirePreAuth -eq $true} |
Select Name, SamAccountName
→ Fix ALL vulnerable accounts
```

---

## 📝 Lessons Learned

> **A single misconfigured account setting opened the entire domain.**
> The "Do not require Kerberos preauthentication" flag on Corrado's account is a legacy setting that should never be enabled in a modern Active Directory environment. Once enabled, any attacker with network access to the DC can request that account's password hash — no credentials required. The attacker needed only 3 minutes from discovery to hash capture.

Key takeaways:

- **Pre-authentication must be required on all accounts** — there is no legitimate modern use case for disabling it. Audit your AD immediately with `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`
- **RC4 encryption should be disabled domain-wide** — set `Network security: Configure encryption types allowed for Kerberos` to AES128/AES256 only. This makes AS-REP Roasting significantly harder
- **NTLM lateral movement is detectable** — blank workstation name, NTLM V2 in AD environment, Type 3 logon from non-standard IP = detection opportunity
- **Prefetch saved this investigation** — when Security logs failed to capture process execution, Prefetch independently confirmed the attack tool. Comprehensive logging (Sysmon, PowerShell logging, full command line auditing) should supplement Prefetch
- **Tool renaming doesn't hide behavior** — `XYIWCCCL.EXE` bypassed name-based detection but still left a Prefetch file. Behavioral detection and hashing (submit to VirusTotal) would have caught it regardless of name
- **WHOAMI is always the first command** — detecting `whoami.exe` run in unusual contexts (after network logon, by unexpected users, at unusual hours) is a high-fidelity detection opportunity

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE T1558.004 — AS-REP Roasting | [attack.mitre.org](https://attack.mitre.org/techniques/T1558/004/) |
| MITRE T1550.002 — Pass the Hash | [attack.mitre.org](https://attack.mitre.org/techniques/T1550/002/) |
| MITRE T1036.003 — Rename System Utilities | [attack.mitre.org](https://attack.mitre.org/techniques/T1036/003/) |
| Rubeus Tool | [github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) |
| Impacket GetNPUsers | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| Eric Zimmermann Tools | [ericzimmerman.github.io](https://ericzimmerman.github.io/) |
| Detecting AS-REP Roasting | [adsecurity.org](https://adsecurity.org/?p=2631) |

---

*Writeup by: Moetez Bouchlaghem | SOC-Investigation-Lab*
