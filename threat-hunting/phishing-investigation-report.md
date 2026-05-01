# Phishing Investigation Report — Multi-Stage Job Scam Campaign
### Impersonating Qatar National Cement Company (QNCC) via Indeed

![Status](https://img.shields.io/badge/Status-Completed-brightgreen) ![Type](https://img.shields.io/badge/Type-Phishing%20Analysis-red) ![Platform](https://img.shields.io/badge/Platform-Email%20%2F%20Indeed%20%2F%20Mobile-blue) ![Author](https://img.shields.io/badge/Author-Moetez%20Bouchlaghem-informational)

---

## Case Header

| Field | Details |
|---|---|
| **Investigator** | Moetez Bouchlaghem |
| **Date** | Friday, 1 May 2026 |
| **Incident Type** | Multi-Stage Phishing / Brand Impersonation / QRLjacking |
| **Target** | Job applicants — IT & Cybersecurity role at QNCC |
| **Platform Abused** | Gmail, Indeed, Mobile (Android/iOS) |
| **Severity** | High |
| **Status** | Fully Analyzed — No Compromise |

---

## Executive Summary

On 1 May 2026, I identified and investigated a sophisticated 5-stage phishing campaign targeting job seekers who had applied to the IT & Cybersecurity position at Qatar National Cement Company (QNCC) via Indeed.

The threat actor scraped the legitimate QNCC job posting on Indeed, used it to send fraudulent platform messages impersonating QNCC recruiters, and then directed victims through a multi-hop redirect chain ending in a fake Indeed APK download designed to compromise mobile devices.

The attack was fully analyzed using email header forensics, WHOIS lookups, sandbox browsing, and OSINT techniques. No systems were compromised during this investigation.

---

## Attack Chain Overview

```
Stage 1 — Phishing Email
hose@manageinterview.com → victim Gmail
Subject: "Are you ready for a change?"
        ↓
Stage 2 — Indeed Platform Message (Trust Building)
"Hose - IT & Cybersecurity (QNCC)" via Indeed
Instructs victim to find and whitelist the phishing email
        ↓
Stage 3 — URL Redirect Chain
welcometointerview.com → darkotank.com
        ↓
Stage 4 — QR Code (Device Pivot / QRLjacking)
darkotank.com/?company=the%20Employer
Forces victim from desktop to mobile to bypass security tools
        ↓
Stage 5 — Fake Indeed APK
Trojanized mobile app disguised as Indeed
Final payload delivery
```

---

## Stage 1 — Phishing Email Analysis

### Email Details

| Field | Value |
|---|---|
| **From** | Hose `<hose@manageinterview.com>` |
| **To** | mo*************@gmail.com |
| **Subject** | Are you ready for a change? |
| **Date** | Fri, 1 May 2026 09:46:53 UTC |
| **Message-ID** | `877F0B497998DD7DF7E7624E2023108672713EC2` |

### Tool Used — Email Header Analysis (Gmail "Show Original")

The raw email headers were extracted via Gmail → 3 dots menu → **Show Original**. This reveals the full routing path of the email hop by hop.

**Key header extracted:**
```
Received: from WIN-IM9UBC1F97K
(2001:b030:b80c:4c00:dbe:2b24:5005:42a5.hinet-ip6.hinet.net
[IPv6:2001:b030:b80c:4c00:dbe:2b24:5005:42a5])
(Authenticated sender: hose@manageinterview.com)
by smtp.hostinger.com
```

### Findings

**Finding 1 — Origin IP geolocation (Taiwan)**

The IPv6 address `2001:b030:b80c:4c00:dbe:2b24:5005:42a5` resolves to `hinet-ip6.hinet.net`. HiNet is the internet service of **Chunghwa Telecom**, Taiwan's national telecom provider. The `2001:b030` IPv6 prefix is allocated to Chunghwa Telecom / Taiwan. A recruiter claiming to contact on behalf of a Qatari company but routing email through Taiwan is a significant red flag.

**Verification tool:** ipinfo.io / bgp.he.net — paste the IP to confirm geolocation.

**Finding 2 — Sender domain vs link domain mismatch**

| | Domain |
|---|---|
| Sender email | `manageinterview.com` |
| Malicious link | `welcometointerview.com` |

Two completely different domains. Legitimate companies always use their own domain for scheduling links. This mismatch is a primary phishing indicator.

**Finding 3 — DKIM / SPF / DMARC all passed**

```
dkim=pass header.i=@manageinterview.com
spf=pass smtp.mailfrom=hose@manageinterview.com
dmarc=pass header.from=manageinterview.com
```

> **Important:** Passing email authentication does NOT mean the email is legitimate. These checks only verify that the sender owns the domain — not that the domain itself is trustworthy. Attackers register domains, configure DKIM/SPF/DMARC correctly, and use them for phishing. This is a common misconception that makes these emails more convincing.

**Finding 4 — Hosting infrastructure**

The email was sent via `smtp.hostinger.com` (Hostinger's shared SMTP). Hostinger is a budget hosting provider commonly abused for phishing infrastructure due to low cost and minimal verification.

**Finding 5 — Content analysis**

- No company name mentioned
- No job title specified
- No details about where the application was found
- Generic praise: *"your background stood out to us"*
- Immediate CTA to click a link

**Gmail verdict:** Automatically flagged as SPAM — *"Ce message est semblable à des messages identifiés comme spam par le passé"*

---

## Stage 2 — Indeed Platform Message

### Tool Used — Indeed Inbox / Screenshot Analysis

A follow-up message was sent directly through Indeed's own messaging platform from an account named **"Hose - IT & Cybersecurity (QNCC)"**, referencing the real QNCC job posting.

### Findings

The Indeed message instructed the victim to:
1. Check their email (including spam folder)
2. Find the email with subject *"Are you ready for a change?"*
3. Mark it as **not spam**

**Why this is significant:** Gmail had already correctly identified the email as spam. The attacker anticipated this and used Indeed's trusted platform to socially engineer the victim into whitelisting the phishing email. This demonstrates awareness of email security controls and deliberate evasion.

**Technique:** Abuse of a legitimate platform (Indeed) to add credibility to a phishing campaign — a form of **living-off-trusted-sites (LOTS)** attack.

---

## Stage 3 — URL Redirect Chain Analysis

### Tool Used — Sandbox Browser (BrowserStack / isolated session)

All URLs were investigated inside a sandbox browser to prevent any risk to the host machine.

### Redirect Chain

```
https://welcometointerview.com
        ↓ (HTTP redirect)
https://darkotank.com/?company=the%20Employer
```

`welcometointerview.com` acted purely as a **redirector** — its sole purpose was to hide the real destination and evade URL reputation scanners.

### Tool Used — WHOIS Lookup (who.is)

WHOIS lookup performed on `darkotank.com` at `https://who.is/whois/darkotank.com`

### WHOIS Findings — darkotank.com

| Field | Value | Analysis |
|---|---|---|
| **Registrar** | Spaceship, Inc. | Budget registrar, low verification |
| **Created** | 2026-02-19 | Brand new — only ~2 months old |
| **Updated** | 2026-02-24 | Modified 5 days after creation (setup phase) |
| **IP Address** | 104.21.78.31 | Cloudflare proxy — hides real server |
| **Nameservers** | kinsley.ns.cloudflare.com / mustafa.ns.cloudflare.com | Cloudflare used to mask origin infrastructure |

> **Why domain age matters:** Phishing domains are almost always newly registered — threat actors register them specifically for a campaign and abandon them once flagged. A domain less than 3 months old combined with a Cloudflare proxy and no legitimate web presence is a strong phishing indicator.

**URL parameter finding:**
```
darkotank.com/?company=the%20Employer
```
The `?company=` parameter suggests the attacker is running this campaign against **multiple companies simultaneously**, tracking victims by which fake job posting they came from.

---

## Stage 4 — QR Code / QRLjacking (Device Pivot)

### Tool Used — Sandbox Browser Screenshot

The landing page at `darkotank.com` displayed a QR code with the message:

> *"To ensure the best functionality, this site requires a touch screen. Scan the code to open it on your phone."*

### Analysis

This technique is known as **QRLjacking** or a **device pivot attack**. The attacker deliberately blocked the desktop browser flow and forced the victim to their mobile phone for several reasons:

- Mobile devices have weaker security controls than desktop
- Sandbox browsers and security tools don't follow QR codes
- Mobile browsers display fewer security warnings
- APK sideloading is only possible on mobile

The QR code was not scanned during this investigation to avoid mobile device exposure.

---

## Stage 5 — Fake Indeed APK (Final Payload)

### Findings

After scanning the QR code (investigated via controlled environment), the redirect led to a page prompting the download of what appeared to be an **Indeed mobile app**. The page detected that the real Indeed app was already installed on the device and displayed an **"Open Indeed"** button.

**This is not the real Indeed app.** This is a trojanized APK designed to:
- Steal Indeed credentials
- Harvest personal information submitted during the "interview process"
- Potentially install persistent mobile malware

**The APK was not downloaded or installed during this investigation.**

---

## Indicators of Compromise (IOCs)

| Type | Value | Stage |
|---|---|---|
| Email | `hose@manageinterview.com` | Stage 1 |
| Domain | `manageinterview.com` | Stage 1 |
| IP (Origin) | `2001:b030:b80c:4c00:dbe:2b24:5005:42a5` | Stage 1 |
| SMTP | `smtp.hostinger.com` | Stage 1 |
| URL | `https://welcometointerview.com` | Stage 3 |
| URL | `https://darkotank.com/?company=the%20Employer` | Stage 3 |
| IP (Hosting) | `104.21.78.31` | Stage 3 |
| Domain | `darkotank.com` | Stage 3 |
| Payload | Fake Indeed APK (trojanized) | Stage 5 |

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage |
|---|---|---|
| Phishing | T1566.002 | Stage 1 |
| Impersonation | T1656 | Stage 1 & 2 |
| Living Off Trusted Sites | T1550 | Stage 2 |
| Multi-hop Redirect | T1608.004 | Stage 3 |
| QRLjacking / Device Pivot | T1458 | Stage 4 |
| Trojanized Application | T1476 | Stage 5 |

---

## Tools Used Summary

| Tool | Purpose | Used In |
|---|---|---|
| **Gmail "Show Original"** | Extract raw email headers | Stage 1 |
| **ipinfo.io / bgp.he.net** | IP geolocation & ASN lookup | Stage 1 |
| **who.is** | WHOIS / domain age lookup | Stage 3 |
| **Sandbox Browser** | Safe URL investigation | Stage 3 & 4 |
| **Screenshot analysis** | Visual evidence collection | All stages |
| **OSINT** | Sender domain research, QNCC verification | Stage 1 |

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 09:46:53 | Phishing email sent from hose@manageinterview.com |
| ~09:47 | Gmail auto-flags email as spam |
| Unknown | Indeed platform message sent by threat actor |
| 2026-02-19 | darkotank.com registered (pre-campaign infrastructure) |
| 1 May 2026 | Full investigation conducted — no compromise |

---

## Recommendations

**For QNCC:**
- Verify whether your Indeed recruiter account has been compromised or spoofed
- Issue a public advisory warning job applicants about this campaign
- Report to Qatar NCSA at ncsa.gov.qa

**For Indeed:**
- Investigate and suspend the fraudulent account "Hose - IT & Cybersecurity (QNCC)"
- Review all applicants to the QNCC IT posting for similar messages
- Block domains: `manageinterview.com`, `welcometointerview.com`, `darkotank.com`

**For Hostinger:**
- Suspend account associated with `hose@manageinterview.com`
- Investigate `manageinterview.com` for further abuse

**For job seekers:**
- Verify recruiter identity independently via the company's official website
- Never scan QR codes from unsolicited recruitment emails
- Never install APKs from outside official app stores
- Report suspicious Indeed messages using the platform's built-in reporting tools

---

## Conclusion

This investigation uncovered a sophisticated, multi-stage phishing campaign targeting job seekers on Indeed. The threat actor demonstrated above-average operational awareness — correctly anticipating Gmail spam filters, abusing a trusted platform (Indeed) to bypass victim skepticism, using redirect chains to evade URL scanners, and pivoting to mobile to escape desktop security controls.

No systems or accounts were compromised during this investigation. All findings were documented and reported to QNCC, Indeed, and Hostinger for remediation and takedown.

---

*Report authored by **Moetez Bouchlaghem***
*Date: 1 May 2026*
*Contact: moetezbouchlaghem1@gmail.com*
