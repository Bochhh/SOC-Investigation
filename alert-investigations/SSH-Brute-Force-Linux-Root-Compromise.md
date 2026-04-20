# 🔴 Incident Investigation — SSH Brute Force to Linux Root Compromise

![Status](https://img.shields.io/badge/Status-Complete-green?style=flat)
![Severity](https://img.shields.io/badge/Severity-Critical-red?style=flat)
![Type](https://img.shields.io/badge/Type-Incident%20Investigation-red?style=flat)
![Attack Type](https://img.shields.io/badge/Attack-Brute%20Force%20%7C%20Persistence%20%7C%20Privilege%20Escalation-orange?style=flat)
![MITRE](https://img.shields.io/badge/MITRE-T1110%20%7C%20T1136%20%7C%20T1548%20%7C%20T1562-blue?style=flat)
![Tools](https://img.shields.io/badge/Tools-Wazuh%20%7C%20Linux%20Auth%20Logs-informational?style=flat)

---

## 📋 Case Header

| Field | Detail |
|---|---|
| **Date** | December 24, 2025 |
| **Target** | ip-10-0-0-100 (Linux) |
| **Attacker IP 1** | 206.189.7.182 |
| **Attacker IP 2** | 178.17.58.173 |
| **Lateral Movement IP** | 10.0.0.11 |
| **Compromised Account** | root |
| **Backdoor Account** | eviluser |
| **Severity** | 🔴 Critical |
| **Verdict** | ✅ True Positive — Full Linux root compromise confirmed |

---

## 🎯 Scenario

On December 24, 2025, a series of SSH authentication failures appeared
in Wazuh originating from two external IP addresses targeting a Linux
server. What started as a brute force investigation quickly unfolded
into a full root compromise — with a backdoor account created, privilege
escalation achieved, and lateral movement from an internal machine — all
before the EDR took action.

This write-up walks through every step of the investigation exactly as
it happened — every log entry, every command, every conclusion.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| **Wazuh** | SIEM — log aggregation and alert correlation |
| **Linux Auth Logs** | `/var/log/auth.log` — SSH and sudo activity |
| **PAM Logs** | Pluggable Authentication Module — session tracking |

---

## 🗂️ Artifacts

| Artifact | Description |
|---|---|
| `/var/log/auth.log` | SSH authentication — success and failure events |
| PAM session logs | Login session opened/closed events |
| sudo logs | Privilege escalation commands |
| Wazuh alerts | Correlation and rule-based detections |

---

## 📚 Resources

| Resource | Link |
|---|---|
| MITRE T1110 — Brute Force | [attack.mitre.org](https://attack.mitre.org/techniques/T1110/) |
| MITRE T1136.001 — Create Local Account | [attack.mitre.org](https://attack.mitre.org/techniques/T1136/001/) |
| MITRE T1548.003 — Sudo and Sudo Caching | [attack.mitre.org](https://attack.mitre.org/techniques/T1548/003/) |
| MITRE T1562.001 — Impair Defenses | [attack.mitre.org](https://attack.mitre.org/techniques/T1562/001/) |
| MITRE T1021.004 — Remote Services: SSH | [attack.mitre.org](https://attack.mitre.org/techniques/T1021/004/) |

---

## 🔍 Investigation Methodology

```
Step 1 → Failed Logins      (sshd + PAM — brute force evidence)
Step 2 → Successful Logins  (PAM session opened — did they get in?)
Step 3 → Post-Compromise    (sudo logs — what did they do?)
Step 4 → Account Creation   (useradd + passwd — backdoor account)
Step 5 → Privilege Escalation (sudoers + usermod — permanent root)
Step 6 → Lateral Movement   (eviluser from internal IP 10.0.0.11)
```

---

## 🕵️ Investigation

### Step 1 — The Brute Force Begins

The investigation started when Wazuh surfaced repeated SSH authentication
failures on the target Linux server. Filtering for `sshd: authentication
failed` and `PAM: User login failed` revealed a sustained automated
brute force attack.

> <img width="1109" height="505" alt="1" src="https://github.com/user-attachments/assets/7f02390d-c599-4379-9f66-976bd7e23b8f" />


```
06:44:32  PAM: User login failed       206.189.7.182
06:44:34  sshd: authentication failed  206.189.7.182
06:45:24  PAM: User login failed       206.189.7.182
06:45:26  sshd: authentication failed  206.189.7.182
06:46:14  PAM: User login failed       206.189.7.182
06:46:17  sshd: authentication failed  206.189.7.182
06:47:05  PAM: User login failed       206.189.7.182
06:47:07  sshd: authentication failed  206.189.7.182
06:47:57  PAM: User login failed       206.189.7.182
06:47:59  sshd: authentication failed  206.189.7.182
06:48:47  PAM: User login failed       206.189.7.182
```

> **🔍 Why two log entries per attempt?**
>
> Each failed SSH login generates two separate log events on Linux:
>
> `PAM: User login failed` — logged by the Pluggable Authentication
> Module (PAM), the Linux authentication framework that handles the
> actual credential verification.
>
> `sshd: authentication failed` — logged by the OpenSSH daemon (sshd),
> the service that manages the SSH connection itself.
>
> Both events together confirm a single failed attempt. Seeing them
> repeat in pairs at consistent intervals from the same IP is the
> signature of an automated brute force tool.

The attacker was using approximately **60-90 second intervals** between
attempts — a deliberate pacing strategy to avoid triggering rate-limiting
controls or fail2ban rules that block IPs after too many rapid failures.

---

### Step 2 — The Attacker Rotates IP

Around 07:29, the brute force continued but from a different source IP:

> <img width="1090" height="373" alt="2" src="https://github.com/user-attachments/assets/99f28c6a-6579-4489-ab25-03dbf0bfe0f7" />


```
07:29:55  PAM: User login failed       178.17.58.173
07:29:57  sshd: authentication failed  178.17.58.173
07:29:57  sshd: authentication failed  178.17.58.173
07:29:59  sshd: authentication failed  178.17.58.173
07:30:01  PAM: User login failed       178.17.58.173
07:30:03  sshd: authentication failed  178.17.58.173
07:30:05  PAM: User login failed       178.17.58.173
07:30:07  sshd: authentication failed  178.17.58.173
```

The second phase was **significantly faster** — sub-second intervals,
multiple attempts per second. The attacker switched from `206.189.7.182`
to `178.17.58.173` and increased their speed.

```
Phase 1 — 206.189.7.182:  ~60-90 second intervals (slow — evading detection)
Phase 2 — 178.17.58.173:  sub-second intervals    (fast — aggressive)
```

**Why rotate IPs?**
```
→ The first IP may have been blocked by fail2ban or a firewall rule
→ Switching IPs bypasses IP-based blocking
→ The attacker had access to multiple IPs — VPN, proxy, or botnet
→ This is not a casual attacker — they adapted and continued
```

Also during this phase:

```
07:59:14  →  sshd: Attempt to login using a non-existent user
```

The attacker attempted a username that does not exist on the system —
indicating they were cycling through a username and password wordlist,
not just targeting a known account.

---

### Step 3 — Brute Force Succeeds

Filtering for successful login events — `PAM: Login session opened` and
`sshd: authentication success` — revealed the brute force worked:

> <img width="1112" height="437" alt="3" src="https://github.com/user-attachments/assets/8bcbee8c-e8e0-4d04-953b-f74220aa8038" />


```
06:33:32  PAM: Login session opened  root  ← first root access
07:27:22  PAM: Login session opened  root
07:27:48  PAM: Login session opened  root
07:27:56  PAM: Login session opened  root
07:28:04  PAM: Login session opened  root
07:28:14  PAM: Login session opened  root
07:28:22  PAM: Login session opened  root
07:28:38  PAM: Login session opened  root
07:29:09  PAM: Login session opened  root
08:00:04  PAM: Login session opened  root
09:09:51  PAM: Login session opened  root
```

The attacker gained **root access** — the highest privilege level on
any Linux system. Root has unrestricted access to every file, every
process, every configuration on the machine.

> **🔍 The 06:33 anomaly**
>
> The first successful root session appeared at `06:33:32` — a full
> **11 minutes before** the first detected brute force attempt at
> `06:44:32`. This gap raises an important question: how did the
> attacker get root access before the brute force we detected?
>
> Possible explanations:
> ```
> → Earlier brute force activity outside our filter window
> → A weak or default root password that was guessed quickly
> → A different initial access vector not captured in these logs
> ```
> This remains an open question requiring deeper log analysis
> before the 06:33 window.

---

### Step 4 — Backdoor Account Created

After closing the Wazuh rules session, the attacker created a backdoor
account to ensure persistent access independent of the root account:

> <img width="1327" height="473" alt="33" src="https://github.com/user-attachments/assets/5824720c-4040-4c2d-b6f1-240f07da15c6" />

**07:41:23 — Account created:**

```
sudo: root : TTY=pts/0 ; PWD=/root ; USER=root
COMMAND=/usr/sbin/useradd eviluser

useradd[70821]: new user: name=eviluser, UID=1001, GID=1001,
home=/home/eviluser, shell=/bin/sh, from=/dev/pts/0

useradd[70821]: new group: name=eviluser, GID=1001
```

**07:41:33 — Password set:**

> <img width="1334" height="183" alt="4" src="https://github.com/user-attachments/assets/489f2886-42be-457f-8299-9d57bdd0591b" />


```
sudo: root : TTY=pts/0 ; PWD=/root ; USER=root
COMMAND=/usr/bin/passwd eviluser
```

| Field | Value |
|---|---|
| Username | eviluser |
| UID | 1001 |
| GID | 1001 |
| Home Directory | /home/eviluser |
| Shell | /bin/sh |
| Created from | /dev/pts/0 (SSH terminal) |
| Method | sudo as root |

The attacker created the account and set a password **10 seconds later**
— making it a fully operational login account immediately.

> **🔍 Why create a separate account?**
>
> Root account password reset by defenders → attacker locked out.
> eviluser account still exists → attacker still has access.
>
> A backdoor account provides persistence that survives a root password
> change — one of the first remediation steps defenders take when they
> discover a compromise. The attacker was thinking several steps ahead.

---

### Step 5 — Lateral Movement From Internal IP

At 07:44:37 — only 3 minutes after creating eviluser — the account
received its first login:

> <img width="1323" height="117" alt="5" src="https://github.com/user-attachments/assets/6b5ff8c8-dfa2-4da1-ba35-3c60dd919f98" />

```
07:44:37.580  sshd[70841]: Accepted password for eviluser
              from 10.0.0.11 port 35564 ssh2

07:44:37.623  pam_unix(sshd:session): session opened
              for user eviluser by (uid=0)

07:44:37.623  pam_unix(systemd-user:session): session opened
              for user eviluser by (uid=0)
```

The source IP `10.0.0.11` is an **internal network address** — not the
external attacker IPs we saw earlier. The attacker was now connecting
from inside the network — from a machine they had already compromised.

```
External brute force:   206.189.7.182 / 178.17.58.173
Lateral movement from:  10.0.0.11 (internal)
```

This confirms the attacker had already compromised another internal
machine and was using it as a pivot point — a classic lateral movement
technique that makes the traffic look internal and trusted.

---

### Step 6 — Privilege Escalation Attempt and Success

Immediately after logging in as eviluser, the attacker tried to escalate:

> <img width="1327" height="123" alt="7" src="https://github.com/user-attachments/assets/67b67962-0f00-4777-a0a8-df150ef95f2f" />


**07:45:09 — eviluser tries sudo — DENIED:**

```
sudo: eviluser : user NOT in sudoers
TTY=pts/1 ; PWD=/ ; USER=root
COMMAND=/usr/bin/nano /etc/sudoers

decoder.ftscomment: First time user executed the sudo command
```

eviluser was created as a standard user with no sudo rights — the
attempt to edit `/etc/sudoers` was blocked by the system.

**07:45:25 — Root edits /etc/sudoers — SUCCESS:**

> <img width="1307" height="490" alt="6" src="https://github.com/user-attachments/assets/3d413ed6-e3e0-4073-bd5b-5f10cdba28f7" />


```
sudo: root : TTY=pts/0 ; PWD=/root ; USER=root
COMMAND=/usr/bin/nano /etc/sudoers
```

**16 seconds later** — the attacker switched to the root terminal
(`pts/0`) and ran the exact same command successfully. The attacker had
two terminals open simultaneously — `pts/0` (root) and `pts/1` (eviluser)
— and immediately compensated for the denied attempt.

> **🔍 What is /etc/sudoers?**
>
> `/etc/sudoers` is the configuration file that controls which users
> can run commands with root privileges via `sudo`. By editing it with
> root access, the attacker could add a line like:
> ```
> eviluser ALL=(ALL) NOPASSWD: ALL
> ```
> This gives eviluser the ability to run any command as root — without
> even needing a password — permanently.

**07:57:40 — eviluser added to sudo group directly:**

```
sudo: root : TTY=pts/0 ; PWD=/root ; USER=root
COMMAND=/usr/sbin/usermod -aG sudo eviluser
```

As a final reinforcement, the attacker also added eviluser directly
to the `sudo` group using `usermod -aG sudo eviluser`. This is a
cleaner, more reliable method than editing the sudoers file manually —
group membership persists and is enforced system-wide.

```
-aG sudo eviluser
→ append (-a) eviluser to group (-G) sudo
→ eviluser can now run any command as root
→ survives root password resets
→ survives reboots
→ permanent backdoor with full privilege escalation
```

---

### Step 7 — EDR Responds

After the final eviluser login at 07:58:10, the EDR detected the
malicious activity and took action — stopping the attacker's session.

```
07:58:10  →  PAM: Login session opened — eviluser  ← final session
             [EDR detects and responds]
             Attacker access terminated
```

Despite the EDR response, the attacker had already achieved:
```
✅ Root access via brute force
✅ Wazuh detection rules tampered
✅ Backdoor account created with password
✅ /etc/sudoers modified
✅ eviluser added to sudo group
✅ Lateral movement from 10.0.0.11
```

---

## ⏱️ Complete Attack Timeline

```
Dec 24, 2025

06:33:32  →  First root session opened
              [vector unknown — pre-dates detected brute force]

06:44:32  →  Brute force phase 1 begins — 206.189.7.182
              ~60-90 second intervals — slow and deliberate
              PAM + sshd failure pairs

07:29:55  →  Brute force phase 2 begins — 178.17.58.173
              Sub-second intervals — high speed
              IP rotated — first IP likely blocked

07:30:07  →  Last failed attempt — 178.17.58.173
07:30:53  →  Brute force SUCCESS — root login
              sudo nano /var/ossec/etc/rules/local_rules.xml
              Wazuh detection rules tampered

07:41:23  →  useradd eviluser
              UID=1001, home=/home/eviluser, shell=/bin/sh
07:41:33  →  passwd eviluser — account fully operational

07:44:37  →  eviluser authenticates from 10.0.0.11
              Lateral movement — internal network pivot

07:45:09  →  eviluser tries sudo /etc/sudoers → DENIED
              First sudo attempt — not in sudoers

07:45:25  →  root edits /etc/sudoers → SUCCESS
              eviluser granted permanent sudo rights

07:57:40  →  usermod -aG sudo eviluser
              eviluser added to sudo group — permanent escalation

07:58:10  →  eviluser final login
              EDR responds — attacker stopped
```

---

## 🧩 IOCs — Indicators of Compromise

| Type | Value |
|---|---|
| **Attacker IP 1** | 206.189.7.182 |
| **Attacker IP 2** | 178.17.58.173 |
| **Internal Pivot IP** | 10.0.0.11 |
| **Target Host** | ip-10-0-0-100 |
| **Compromised Account** | root |
| **Backdoor Account** | eviluser |
| **UID** | 1001 |
| **Home Directory** | /home/eviluser |
| **Shell** | /bin/sh |
| **Files Modified** | /var/ossec/etc/rules/local_rules.xml |
| **Files Modified** | /etc/sudoers |

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 | PAM + sshd failure pairs from two IPs |
| Initial Access | Valid Accounts | T1078 | Root login success after brute force |
| Persistence | Create Account: Local Account | T1136.001 | useradd eviluser + passwd |
| Privilege Escalation | Sudo and Sudo Caching | T1548.003 | /etc/sudoers modified + usermod -aG sudo |
| Defense Evasion | Impair Defenses: Disable Tools | T1562.001 | nano /var/ossec/etc/rules/local_rules.xml |
| Lateral Movement | Remote Services: SSH | T1021.004 | eviluser login from internal 10.0.0.11 |

---

## 💡 Key Lessons Learned

**1 — IP Rotation Is a Sign of a Determined Attacker**
Switching from `206.189.7.182` to `178.17.58.173` when the first IP
was blocked shows the attacker was persistent and had resources.
IP-based blocking alone is not sufficient — behavioral detection on
authentication failure patterns regardless of source IP is required.

**2 — Root SSH Should Never Be Exposed**
The entire attack was possible because root could authenticate directly
via SSH. Disabling root SSH login (`PermitRootLogin no` in sshd_config)
and requiring key-based authentication would have stopped this attack
completely.

**3 — Monitoring Systems Are Targets Too**
The attacker's first action after getting root was to edit Wazuh
detection rules. Security tooling is part of the attack surface.
Monitoring configuration files should be read-only to all but the
Wazuh service itself — and any modification should trigger an immediate
critical alert.

**4 — Two Terminals = Two Problems**
The attacker had root and eviluser sessions open simultaneously —
allowing them to instantly compensate when eviluser was denied sudo.
Monitoring for multiple concurrent sessions from the same account or
same source IP is a useful detection signal.

**5 — The 06:33 Gap Is Unresolved**
The first root session at 06:33:32 predates the detected brute force.
Until this is explained, the full initial access vector is unknown.
Log analysis before 06:33 is required to close this gap.

---

## 🔧 Remediation & Recovery

| Priority | Action |
|---|---|
| 🔴 Critical | Isolate ip-10-0-0-100 from the network immediately |
| 🔴 Critical | Delete eviluser account — `userdel -r eviluser` |
| 🔴 Critical | Remove eviluser from /etc/sudoers |
| 🔴 Critical | Reset root password |
| 🔴 Critical | Block 206.189.7.182 and 178.17.58.173 at firewall |
| 🔴 Critical | Investigate 10.0.0.11 — source of lateral movement |
| 🔴 Critical | Restore /var/ossec/etc/rules/local_rules.xml from backup |
| 🟠 High | Disable root SSH login — set PermitRootLogin no |
| 🟠 High | Implement SSH key-based authentication only |
| 🟠 High | Review /etc/sudoers for any unauthorized entries |
| 🟠 High | Check all other Linux hosts for eviluser account |
| 🟡 Medium | Implement fail2ban with aggressive thresholds |
| 🟡 Medium | Alert on any modification to /var/ossec/etc/rules/ |
| 🟡 Medium | Alert on useradd and usermod commands |
| 🟡 Medium | Investigate activity before 06:33:32 |
| 🟢 Low | Implement SSH port change or port knocking |
| 🟢 Low | Deploy MFA for all SSH access |

---

## ✅ Conclusion

```
Verdict:     TRUE POSITIVE ✅
Attacker:    206.189.7.182 / 178.17.58.173
Target:      ip-10-0-0-100 (Linux)
Duration:    06:33 → 07:58 (active for ~85 minutes)
Access:      root via SSH brute force
Impact:      Full root compromise
             Wazuh detection rules tampered
             Backdoor account created with sudo rights
             Lateral movement from 10.0.0.11
             EDR stopped the attacker at 07:58
```

The attacker was methodical — they paced their brute force to avoid
detection, rotated IPs when blocked, immediately targeted monitoring
after getting in, created a backdoor account, escalated its privileges
in two different ways, and used an internal machine for lateral movement.

Every step was captured in the logs. Every command was documented.
Every action mapped to a MITRE technique.

> *Root SSH exposed to the internet.*
> *One weak password.*
> *85 minutes of active compromise.*
> *The logs caught everything the attacker tried to hide.*

---

## 📚 References

| Resource | Link |
|---|---|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| Linux PAM Documentation | [linux-pam.org](http://www.linux-pam.org) |
| OpenSSH Security | [openssh.com](https://www.openssh.com) |
| Wazuh Documentation | [documentation.wazuh.com](https://documentation.wazuh.com) |

---
