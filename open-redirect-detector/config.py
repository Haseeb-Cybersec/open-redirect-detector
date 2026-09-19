"""
config.py — Configuration constants for the Open Redirect Detection Tool
=========================================================================
Week 4 - Cybersecurity Portfolio | Author: Haseeb | IMSciences, Peshawar

Modify CANARY_DOMAIN, REDIRECT_PAYLOADS, and REDIRECT_PARAMS here.
All other modules import from this file — single source of truth.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  CANARY DOMAIN
# ─────────────────────────────────────────────────────────────────────────────
# The .invalid TLD is officially reserved (RFC 2606) and will NEVER resolve
# in DNS. This makes it a safe, non-requestable canary: if a server returns
# a redirect pointing here, it proves it blindly accepted our injected URL.
CANARY_DOMAIN = "open-redirect-canary.invalid"
CANARY_BASE    = f"https://{CANARY_DOMAIN}"

# ─────────────────────────────────────────────────────────────────────────────
#  REDIRECT PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────
# Ordered: obvious → encoded → evasive. All point to CANARY_DOMAIN.
# The detection engine stops at the first confirmed hit per parameter.
REDIRECT_PAYLOADS = [
    # --- Tier 1: Standard ---
    f"https://{CANARY_DOMAIN}",
    f"http://{CANARY_DOMAIN}",
    # --- Tier 2: Protocol-relative ---
    f"//{CANARY_DOMAIN}",
    f"////{CANARY_DOMAIN}",
    # --- Tier 3: Evasion ---
    f"HtTpS://{CANARY_DOMAIN}",           # Case variation
    f"https%3A%2F%2F{CANARY_DOMAIN}",     # URL-encoded colon+slashes
    f"https://{CANARY_DOMAIN}%0d%0a",     # CRLF suffix
    f" https://{CANARY_DOMAIN}",           # Leading whitespace
    f"https://{CANARY_DOMAIN}/path?ref=lab",  # With path
]

# ─────────────────────────────────────────────────────────────────────────────
#  PARAMETER NAMES
# ─────────────────────────────────────────────────────────────────────────────
# Common URL parameters that web apps use to control redirect destination.
REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnUrl", "return_url",
    "goto", "dest", "to", "target", "callback", "return_to",
    "link", "forward", "redir", "destination", "ref",
    "redirectUrl", "nextUrl", "go", "jump", "continue",
    "redirect_uri", "after_login_url", "success_url"
]

# ─────────────────────────────────────────────────────────────────────────────
#  HTTP REDIRECT STATUS CODES
# ─────────────────────────────────────────────────────────────────────────────
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

# ─────────────────────────────────────────────────────────────────────────────
#  REQUEST SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10   # seconds per request
USER_AGENT      = "OpenRedirectDetector/1.0 (Authorized-Lab-Testing-Only)"

# ─────────────────────────────────────────────────────────────────────────────
#  SEVERITY SCALE  (CVSS-inspired, simplified for this tool)
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY = {
    "HIGH": {
        "label":       "HIGH",
        "cvss_range":  "7.0 – 8.9",
        "description": (
            "Direct open redirect — no bypass required. "
            "An attacker can craft a convincing phishing URL using the "
            "trusted domain (e.g. https://trusted-app.com/redirect?to=evil.com). "
            "High risk of credential theft, OAuth token hijacking, or malware delivery."
        ),
    },
    "MEDIUM": {
        "label":       "MEDIUM",
        "cvss_range":  "4.0 – 6.9",
        "description": (
            "Open redirect exploitable with minor evasion technique "
            "(encoded payload, protocol-relative URL, or case variation). "
            "Slightly higher barrier but still exploitable by a motivated attacker."
        ),
    },
    "LOW": {
        "label":       "LOW",
        "cvss_range":  "0.1 – 3.9",
        "description": (
            "Suspected redirect behavior requiring further manual investigation. "
            "May be a partial redirect or false positive."
        ),
    },
    "INFO": {
        "label":       "INFO",
        "cvss_range":  "N/A",
        "description": "No vulnerability confirmed. Informational entry only.",
    },
}
