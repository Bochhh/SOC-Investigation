# 🔴 Web Server Attack — CMS Brute Force to Webshell Execution

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Alert%20Investigation-red?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-Brute%20Force%20%7C%20File%20Upload%20%7C%20Webshell%20%7C%20Recon-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1505.003%20%7C%20T1083%20%7C%20T1059-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20Apache%20Access%20Logs-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Date** | November 26, 2025 |
| **Target** | ip-172-31-10-177 — syntrix.com |
| **Attacker IP** | 13.203.202.168 |
| **Attack Vector** | CMS Login Brute Force → File Upload → Webshell |
| **Webshell** | /img/bingo.php |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Webshell deployed and executed |

---

## 🎯 Scenario

On November 26, 2025, Apache access logs on `ip-172-31-10-177` revealed
a series of suspicious POST requests targeting the authentication endpoint
of the Syntrix CMS. What started as a brute force attack against the login
handler quickly escalated into a full webshell deployment — with the
attacker executing operating system commands directly on the web server
within minutes of gaining access.

This write-up reconstructs the full attack chain from the first brute
force attempt to post-exploitation reconnaissance — using only Apache
access logs.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Wazuh** | SIEM — log aggregation and alert correlation |
| **Apache Access Logs** | `/var/log/apache2/access.log` — HTTP request analysis |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| `/var/log/apache2/access.log` | All HTTP requests to the web server |
| Apache sourcetype `apache:access` | Parsed access log fields in Wazuh |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1110 — Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| MITRE T1505.003 — Web Shell | [attack.mitre.org](https://attack.mitre.org/techniques/T1505/003/) |
| MITRE T1083 — File and Directory Discovery | [attack.mitre.org](https://attack.mitre.org/techniques/T1083/) |
| MITRE T1059 — Command and Scripting Interpreter | [attack.mitre.org](https://attack.mitre.org/techniques/T1059/) |
| MITRE T1190 — Exploit Public-Facing Application | [attack.mitre.org](https://attack.mitre.org/techniques/T1190/) |

---

## 🔍 Investigation Methodology

```
Step 1 → Brute Force Analysis    (POST patterns — login attack)
Step 2 → Login Success           (UA change — attacker in CMS)
Step 3 → File Manager Access     (dir.php — upload preparation)
Step 4 → Webshell Upload         (handler.php — bingo.php deployed)
Step 5 → Webshell Execution      (cmd parameter — recon commands)
Step 6 → Impact Assessment       (what was accessed and exfiltrated)
```

---

## 🕵️ Investigation

### Step 1 — Brute Force Against the Login Handler

The investigation started from Apache access logs showing repeated POST
requests to the same endpoint from `13.203.202.168`.

> <img width="1070" height="314" alt="1" src="https://github.com/user-attachments/assets/bd2701dd-a1b0-4f16-94ae-12dedaa29470" />


```
06:25:38  POST /codebase/handler.php?nocache=0.9369408200535481
          Referer: http://syntrix.com/lorem.php?login
          User-Agent: Firefoxy
          Response: 200  330 bytes

06:25:38  POST /codebase/handler.php?nocache=0.8054975114455799
          Referer: http://syntrix.com/lorem.php?login
          Response: 200  647 bytes

06:27:35  POST /codebase/handler.php?nocache=0.9328938628116171
          Response: 200  330 bytes

06:27:36  POST /codebase/handler.php?nocache=0.3207163644434423
          Response: 200  329 bytes
```

**Three signals confirmed this as brute force — not legitimate traffic:**

**1 — The nocache Parameter**
```
?nocache=0.9369408200535481
?nocache=0.8054975114455799
?nocache=0.9328938628116171
```
A different random float number appended to every request. This is an
automated tool technique — it prevents the server from caching responses
and forces each request to be processed fresh. No human typing a login
form manually appends random numbers to URLs. Only automated tools do this.

**2 — The Fake User-Agent**
```
User-Agent: Firefoxy
```
Not a real browser. Firefox is a known browser — "Firefoxy" is not.
This is an automated brute force tool poorly disguising itself as a
browser. The misspelling was the giveaway.

**3 — Repeated Same Endpoint + Consistent Small Responses**
```
330 bytes → failed login response
329 bytes → failed login response
330 bytes → failed login response
```
The same small response size returned repeatedly means the same page
is being returned every time — the "login failed" page. This is the
signature of a tool trying different passwords and receiving the same
rejection over and over.

> **🔍 What is a Login Handler?**
>
> A web application has two parts to its login system:
>
> The **login page** (`lorem.php?login`) — what you see in your browser.
> The HTML form with username and password fields.
>
> The **login handler** (`handler.php`) — the script that actually
> processes the submitted credentials. It checks them against the
> database and returns success or failure.
>
> The attacker skipped the login page entirely and targeted the handler
> directly — sending POST requests with different credential combinations
> at machine speed. The `Referer` header pointing to the login page was
> manually faked to make requests look like they came from a legitimate
> browser session.
>
> ```
> Real user:   loads login page → fills form → POST handler.php
> Attacker:    skips page → POST handler.php directly (faster, automated)
> ```

---

### Step 2 — Login Succeeds — Attacker Enters the CMS

At `06:27:40` the traffic pattern changed completely:

> <img width="1072" height="390" alt="2" src="https://github.com/user-attachments/assets/b691def6-d16a-4b67-820a-6960247191de" />


```
06:27:40  GET /codebase/ck/plugins/oembed/libs/jquery.oembed.min.js?t=IA8F
06:27:40  GET /codebase/ck/plugins/mara/images/hBlobUpload.png?t=IA8F
06:27:40  GET /codebase/ck/plugins/mara/images/hQuickImage.png?t=IA8F
06:27:40  GET /codebase/ck/plugins/texzilla/icons/texzilla.png?t=IA8F
06:27:40  GET /codebase/ck/plugins/oembed/images/icon.png?t=IA8F
Referer:  http://syntrix.com/lorem.php?login
UA:       Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Firefox/95.0
```

**The attacker was now inside the CMS.** Several things changed simultaneously:

**1 — Switch from POST to GET**
The brute force was all POST requests. Now we see GET requests loading
page assets — JavaScript files, images, plugin resources. This is a
browser loading the CMS dashboard after a successful login.

**2 — User-Agent Changed**
```
Before login:  Firefoxy        ← automated tool
After login:   Mozilla/5.0 Firefox/95.0  ← real browser
```
The attacker switched from their brute force tool to a real browser
after gaining access — trying to blend in with legitimate user traffic.

**3 — Multiple Requests at Same Timestamp**
```
All at 06:27:40 — same second
```
A browser loads all page resources in parallel — CSS, JavaScript, images
all requested simultaneously. This is exactly what a real browser does
when loading a page. The brute force requests were sequential — one at a
time. These are parallel — a browser just logged in.

**4 — CKEditor Plugins Visible**
```
/codebase/ck/plugins/ ← CKEditor — rich text editor
```
This CMS uses CKEditor — a common content management system component.
This fingerprints the application and tells the attacker exactly what
CMS they are dealing with.

> **🔍 How to tell attacker activity from browser loading**
>
> This is one of the most important skills in log analysis:
>
> | Signal | Browser Loading | Attacker Activity |
> |---|---|---|
> | Method | GET for assets | POST to endpoints |
> | Same endpoint | No — loads different files | Yes — same target repeated |
> | Timing | All same second (parallel) | Sequential — spaced out |
> | Files requested | CSS, JS, images | PHP files, cmd parameters |
> | Response size | Varies by file | Same size repeating |
> | User-Agent | Consistent real browser | Fake or tool name |
>
> In this investigation the brute force was clearly sequential POST
> requests with a fake UA. The post-login traffic was clearly parallel
> GET requests with a real UA — a browser loading a page.
>
> The method alone is not enough — you must read all signals together.

---
### Step 4 — Webshell Uploaded

At `06:28:34` — 9 seconds after opening the file manager:

> <img width="1078" height="87" alt="3" src="https://github.com/user-attachments/assets/3710e512-dd26-4268-82cd-1f89dbe1b3fd" />


```
06:28:34  POST /codebase/handler.php HTTP/1.1  200  832
          Referer: http://syntrix.com/codebase/dir.php?type=filenew
          User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Firefox/95.0
```

**The webshell was uploaded.**

The same `handler.php` endpoint that processed login attempts now
processed a file upload. The `Referer` confirms it came from the
file manager's new file form.

**Why 832 bytes is significant:**
```
Failed login responses:  329-330 bytes (small — just "login failed" page)
Upload response:         832 bytes     (larger — contains upload confirmation
                                        including the path where file was saved)
```

The 832-byte response almost certainly contained the path where the
uploaded file was saved — `/img/bingo.php` — which the attacker read
to know exactly where their webshell landed.

**The uploaded file: `bingo.php`**

A PHP webshell — a malicious PHP script that accepts a `cmd` parameter
and executes it as an operating system command on the server:

```php

```

Once uploaded, any HTTP request to `bingo.php` with a `cmd` parameter
executes the command on the server and returns the output to the attacker.
The web server becomes a remote terminal.

**Why the `/img/` directory was chosen:**
```
/img/ is typically used for image storage
→ Less monitored than application directories
→ Security tools focused on .php files in code directories
   might miss a .php file buried in an image folder
→ Deliberate evasion — hiding in plain sight
```

---

### Step 5 — Webshell Executed — Post-Exploitation Recon

At `06:29:18` — **44 seconds after the upload** — the attacker accessed
their webshell and began executing commands:

> <img width="1078" height="401" alt="4" src="https://github.com/user-attachments/assets/7c8ffbb3-b63a-4fb0-9b86-fbfb93ae9733" />


```
06:29:18  GET /img/bingo.php?cmd=whoami
          Response: 200  212 bytes

06:29:31  GET /img/bingo.php?cmd=cat%20/etc/hosts
          Response: 200  408 bytes

06:29:39  GET /img/bingo.php?cmd=ls
          Response: 200  232 bytes

06:29:48  GET /img/bingo.php?cmd=ls%20/home
          Response: 200  210 bytes

06:30:14  GET /img/bingo.php?cmd=cat%20/etc/passwd
          Response: 200  1255 bytes
```

URL decoded commands:

| Time | Command | Purpose |
|---|---|---|
| 06:29:18 | `whoami` | Who is the web server running as? |
| 06:29:31 | `cat /etc/hosts` | Read network configuration |
| 06:29:39 | `ls` | List files in current directory |
| 06:29:48 | `ls /home` | Find user accounts on the system |
| 06:30:14 | `cat /etc/passwd` | Dump all system users |

This is a **classic post-exploitation reconnaissance sequence** — the
attacker methodically gathered information about the compromised system
before deciding their next move.

**The response sizes tell what they got back:**

```
whoami          → 212 bytes   ← a username — short output
cat /etc/hosts  → 408 bytes   ← network config file
ls              → 232 bytes   ← directory listing
ls /home        → 210 bytes   ← list of home directories
cat /etc/passwd → 1255 bytes  ← FULL user database dumped
```

The largest response — `1255 bytes` for `/etc/passwd` — confirms the
attacker successfully read the complete list of system user accounts.
This data includes usernames, home directories, and shell assignments
for every account on the system.

**The 44-second gap between upload and first command:**
```
06:28:34  →  File uploaded
             [attacker reads 832-byte response]
             [notes the file path: /img/bingo.php]
             [opens browser tab]
             [types the webshell URL]
06:29:18  →  First command executed
Gap:         44 seconds — consistent with human interaction time
```

---
## ⏱️ Complete Attack Timeline

```
Nov 26, 2025

06:25:38  →  Brute force begins
              POST /codebase/handler.php
              Automated tool — User-Agent: Firefoxy
              nocache parameter — random float per request
              Repeated failed logins (329-330 byte responses)

06:27:36  →  Last brute force attempt

06:27:40  →  LOGIN SUCCEEDED
              CMS dashboard loaded — parallel GET requests
              CKEditor plugins loaded — CMS fingerprinted
              User-Agent switched to real Firefox 95.0

06:28:25  →  File manager opened
              GET /codebase/dir.php?type=filenew
              All file manager assets loaded simultaneously

06:28:34  →  WEBSHELL UPLOADED
              POST /codebase/handler.php
              Referer: dir.php?type=filenew
              Response: 200 832 bytes ← upload confirmed
              bingo.php saved to /img/

06:29:18  →  WEBSHELL ACCESSED — whoami
              GET /img/bingo.php?cmd=whoami
              Response: 200 212 bytes

06:29:31  →  cat /etc/hosts — network mapped
              Response: 200 408 bytes

06:29:39  →  ls — directory listed
              Response: 200 232 bytes

06:29:48  →  ls /home — user accounts identified
              Response: 200 210 bytes

06:30:14  →  cat /etc/passwd — FULL USER DATABASE DUMPED
              Response: 200 1255 bytes
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Attacker IP** | 13.203.202.168 |
| **Target** | ip-172-31-10-177 — syntrix.com |
| **Brute Force UA** | Firefoxy |
| **Brute Force Endpoint** | /codebase/handler.php |
| **Brute Force Pattern** | ?nocache=[random float] |
| **Webshell Path** | /img/bingo.php |
| **Webshell Parameter** | ?cmd=[command] |
| **Data Accessed** | /etc/passwd, /etc/hosts, /home |
| **CMS** | Syntrix CMS with CKEditor |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | CMS login brute forced |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Repeated POST to handler.php with nocache |
| Execution | Server Software Component: Web Shell | T1505.003 | bingo.php uploaded and executed |
| Execution | Command and Scripting Interpreter | T1059 | cmd parameter executing OS commands |
| Discovery | File and Directory Discovery | T1083 | ls, ls /home, cat /etc/passwd |
| Discovery | System Network Configuration Discovery | T1016 | cat /etc/hosts |
| Discovery | System Owner/User Discovery | T1033 | whoami, cat /etc/passwd |
| Defense Evasion | Masquerading | T1036 | bingo.php placed in /img/ directory |

---

## 💡 Key Lessons Learned

**1 — Login Handlers Must Be Rate Limited**
The attacker sent multiple POST requests per second to `handler.php`
with no throttling. Implementing account lockout after N failed attempts
and rate limiting on authentication endpoints would have stopped this
attack before it reached the login success stage.

**2 — File Upload Must Validate File Type**
The CMS allowed a `.php` file to be uploaded through the file manager.
File upload functionality must validate both the file extension and the
actual file content — rejecting any executable file types. Uploading
PHP files through a CMS file manager should never be possible.

**3 — The nocache Pattern Is Detectable**
```
?nocache=[random float] on repeated POST to login endpoint
```
This is a reliable brute force signature. A WAF rule or Wazuh detection
rule matching this pattern would have flagged and blocked the attack
within the first few attempts.

**4 — User-Agent Changes Are Suspicious**
The attacker used `Firefoxy` for brute force then switched to a real
Firefox UA after login. Tracking User-Agent changes from the same IP
within a short window is a useful detection signal — legitimate users
do not switch browsers mid-session.

**5 — PHP Files in Image Directories Are Always Suspicious**
```
/img/bingo.php
```
No legitimate web application serves PHP files from an image directory.
A FIM rule alerting on any `.php` file creation in `/img/`, `/uploads/`,
or `/images/` directories would have caught this immediately.

**6 — Response Size Variation Reveals Success**
```
Failed login:  329-330 bytes (consistent)
Upload success: 832 bytes   (different)
```
Monitoring for response size anomalies on authentication endpoints is
a low-cost, high-value detection method. A sudden larger response from
a previously consistent endpoint signals something different happened.

---

## 🔧 Remediation & Recovery

| Priority | Action |
|---|---|
| 🔴 Critical | Remove /img/bingo.php from the web server immediately |
| 🔴 Critical | Block 13.203.202.168 at firewall and WAF |
| 🔴 Critical | Reset all CMS user account passwords |
| 🔴 Critical | Audit all files uploaded during the attack window |
| 🔴 Critical | Check /etc/passwd for any new accounts created |
| 🟠 High | Implement rate limiting on handler.php login endpoint |
| 🟠 High | Block .php file uploads in CMS file manager |
| 🟠 High | Scan entire web directory for other webshells |
| 🟠 High | Review web server user context — what did whoami return? |
| 🟡 Medium | Deploy WAF rule detecting nocache brute force pattern |
| 🟡 Medium | Enable Wazuh FIM monitoring on web directories |
| 🟡 Medium | Alert on .php file creation in image/upload directories |
| 🟡 Medium | Implement CMS login MFA |
| 🟢 Low | Review CMS file manager permissions — restrict upload types |
| 🟢 Low | Investigate attacker IP 13.203.202.168 on threat intel platforms |

---

## ✅ Conclusion

```
Verdict:   TRUE POSITIVE ✅
Attacker:  13.203.202.168
Target:    syntrix.com — ip-172-31-10-177
Duration:  06:25 → 06:30 (5 minutes total)
Impact:    CMS compromised
           Webshell deployed to /img/bingo.php
           System users dumped via /etc/passwd
           Network config read via /etc/hosts
           Further activity unknown — logs end at 06:30
```

The attacker was fast and deliberate. Five minutes from first brute
force attempt to reading the full system user database. They used a
legitimate CMS feature — the file manager — to deploy their webshell,
and chose the image directory specifically to avoid detection.

The entire attack chain was reconstructed from a single log source —
Apache access logs. No endpoint agent. No Sysmon. Just HTTP requests.
That is the value of proper web server logging.

> *Five minutes.*
> *Brute force. Login. File manager. Webshell. /etc/passwd.*
> *One weak password on a CMS file upload.*
> *That is all it took.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Apache Log Format | [httpd.apache.org](https://httpd.apache.org/docs/current/logs.html) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com) |
| OWASP File Upload | [owasp.org](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) |

---
