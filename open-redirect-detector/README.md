# AI-Assisted Open Redirect Detection Tool

**Week 4 — Cybersecurity Portfolio Project**  
**Author:** Haseeb | IMSciences, Peshawar  
**Context:** Defensive security tooling, tested only against authorized lab environments

---

## What This Tool Does

This is a Python-based vulnerability detection tool that checks whether web application URL parameters are susceptible to **Open Redirect** attacks. It uses a canary domain technique to confirm true redirects, and optionally uses the **Anthropic Claude API** to generate plain-English explanations, severity assessments, and remediation advice for each finding.

All testing is performed exclusively against intentionally vulnerable lab applications. **Never use this tool against any system you do not own or have explicit written permission to test.**

---

## What is Open Redirect?

An Open Redirect vulnerability occurs when a web application accepts a user-controlled URL parameter and redirects the browser to it without validating the destination.

**Root cause (code-level):**
```python
# VULNERABLE — no validation
destination = request.args.get("url")
return redirect(destination)   # Blindly follows whatever the user says
```

**Real-world impact:**
- **Phishing:** Attacker crafts `https://trusted-bank.com/login?next=https://evil.com`. The victim sees the trusted domain in the URL and clicks it, landing on a fake page.
- **OAuth token theft:** `redirect_uri` manipulation in OAuth flows can send access tokens to attacker-controlled servers.
- **Malware delivery:** Redirect chains can bypass URL reputation filters.
- **SSRF stepping stone:** In some server-side contexts, open redirects assist in Server-Side Request Forgery.

**CVSS Base Score (typical):** 6.1 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

---

## Project Structure

```
open-redirect-detector/
├── main.py              # CLI entry point — run this
├── config.py            # All payloads, parameters, and constants
├── detector.py          # Core HTTP probing and detection logic
├── ai_analyzer.py       # Claude API integration for AI-assisted analysis
├── report_generator.py  # JSON + text report generation
├── test_server.py       # Intentionally vulnerable Flask server (local lab)
├── requirements.txt     # Python dependencies
├── reports/             # Generated reports (gitignored for sensitive data)
└── README.md            # This file
```

---

## Setup

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/open-redirect-detector.git
cd open-redirect-detector
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Set up your lab target (choose one)

**Option A — Local test server (fastest, no extra install):**
```bash
python test_server.py
# Vulnerable endpoint: http://localhost:5000/redirect/vulnerable
# Safe endpoint:       http://localhost:5000/redirect/safe
```

**Option B — OWASP Juice Shop (Docker):**
```bash
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop
# Target: http://localhost:3000/redirect
```

**Option C — DVWA (Docker):**
```bash
docker pull vulnerables/web-dvwa
docker run --rm -p 8080:80 vulnerables/web-dvwa
```

### 4. (Optional) Set Anthropic API key for AI analysis
```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Linux / macOS
set ANTHROPIC_API_KEY=sk-ant-...        # Windows
```

---

## Usage

### Basic scan
```bash
python main.py -t http://localhost:5000/redirect/vulnerable
```

### Multiple targets
```bash
python main.py -t http://localhost:5000/redirect/vulnerable http://localhost:3000/redirect
```

### With AI-assisted analysis
```bash
python main.py -t http://localhost:5000/redirect/vulnerable --ai-analysis
```

### Verbose output + custom report prefix
```bash
python main.py -t http://localhost:5000/redirect/vulnerable -v -o reports/week4_scan
```

### Targets from a file
```bash
# targets.txt — one URL per line
python main.py --target-file targets.txt --ai-analysis
```

### Test false-positive handling (safe endpoint should produce no findings)
```bash
python main.py -t http://localhost:5000/redirect/safe
```

---

## How Detection Works

```
For each target URL:
  For each redirect parameter (url, next, redirect, to, ...):
    For each payload (standard → encoded → evasive):
      1. Send GET request with ?param=https://open-redirect-canary.invalid
      2. Inspect response WITHOUT following redirects
      3. Check if HTTP status is 3xx AND:
           (a) Location header contains canary domain, OR
           (b) HTML body has meta-refresh to canary, OR
           (c) JavaScript redirect to canary in page source
      4. If confirmed → record finding, stop testing this param, move on
      5. Assign severity by payload tier (standard=HIGH, evasive=MEDIUM)
```

**Why `.invalid`?** The `.invalid` TLD is officially reserved by RFC 2606 and will never resolve in DNS. This makes it a safe canary — there is no risk of accidentally connecting to a real server during testing.

---

## Detection Payload Tiers

| Tier | Example | Severity if Hit |
|------|---------|----------------|
| 1 — Standard | `https://canary.invalid` | HIGH |
| 2 — Protocol-relative | `//canary.invalid` | MEDIUM |
| 3 — Evasive | `HtTpS://canary.invalid`, `%2F%2Fcanary.invalid` | MEDIUM |

---

## Sample Output

**Console (vulnerable target):**
```
  [SCAN] http://localhost:5000/redirect/vulnerable
         20 params × 9 payloads = up to 180 probes

    [!] VULNERABLE  param='url'  payload='https://open-redirect-canary.invalid'
        type=location_header  severity=HIGH
    [!] VULNERABLE  param='redirect'  payload='https://open-redirect-canary.invalid'
        type=location_header  severity=HIGH

  [DONE] http://localhost:5000/redirect/vulnerable
         Vulnerable parameters found: 2
```

**Text report (finding section):**
```
  FINDING #1
  Severity      : HIGH  (7.0 – 8.9)
  URL Tested    : http://localhost:5000/redirect/vulnerable?url=https://open-redirect-canary.invalid
  Parameter     : ?url
  Payload       : https://open-redirect-canary.invalid
  Server Status : HTTP 302
  Location Hdr  : https://open-redirect-canary.invalid
  Detection     : location_header

  Evidence:
    HTTP 302 redirect with Location: https://open-redirect-canary.invalid
    — server redirected to canary domain.

  [AI-ASSISTED] AI-ASSISTED INTERPRETATION — Generated by Claude...

  Explanation (AI):
    The application redirects users to any URL provided in the 'url'
    parameter without checking if that URL is safe. An attacker can
    exploit this to send victims to a malicious site using a trusted URL.

  Remediation Steps (AI):
    Step 1: Validate the destination URL server-side against an explicit allowlist...
    Step 2: If redirecting to the same application, use relative paths only...
    Step 3: Reject any destination whose hostname is not in the approved list...
```

---

## False Positive / False Negative Handling

**False positives (safe page incorrectly flagged):**
- The tool requires the canary domain to appear in the `Location` header or body
- A 302 to `/login` or `https://your-own-app.com` is NOT flagged
- Test with the `/redirect/safe` endpoint to confirm zero false positives

**False negatives (missed vulnerabilities):**
- POST-based redirects are not tested
- JavaScript-heavy SPAs may redirect after page load (outside this tool's scope)
- Authenticated endpoints require manual testing with a session cookie
- WAF-blocked requests may suppress findings

---

## Tool Limitations

1. Does not follow multi-hop redirect chains
2. Does not execute JavaScript — SPA redirects may be missed
3. Tests GET parameters only (not POST body or JSON)
4. Does not handle endpoints requiring authentication
5. A WAF or rate limiter may block test requests, producing false negatives
6. AI analysis output is an interpretation aid, not a definitive verdict

---

## AI-Assisted Analysis Disclaimer

All sections labelled `[AI-ASSISTED]` in the report are generated by the Anthropic Claude API. They represent an automated interpretation of scan results and should be reviewed by a qualified analyst before being included in any formal security report. Claude is used here to:
- Translate raw findings into plain English
- Suggest CVSS-based severity
- Propose remediation steps
- Generate secure code patterns

AI analysis is an aid to understanding, not a substitute for manual verification.

---

## Authorization Statement

All testing in this project was conducted exclusively against intentionally vulnerable lab applications operated in an isolated local environment:
- `test_server.py` — locally operated, intentionally vulnerable Flask app
- OWASP Juice Shop — locally operated via Docker
- No production, third-party, or unauthorized systems were tested at any point.

---

## Skills Demonstrated

- Python scripting (`requests`, `argparse`, `re`, `json`)
- HTTP protocol understanding (status codes, headers, redirect mechanics)
- Vulnerability detection logic design
- False positive / false negative analysis
- API integration (Anthropic Claude)
- Report generation
- Security documentation

---

## References

- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-project-top-ten/)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [RFC 2606: Reserved Top Level DNS Names](https://www.rfc-editor.org/rfc/rfc2606)
- [PortSwigger: Open Redirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)

---

*Week 4 of a structured cybersecurity learning portfolio. Built with Python, tested on authorized lab environments.*
