"""
detector.py — Core detection engine for Open Redirect vulnerabilities
======================================================================
Week 4 - Cybersecurity Portfolio | Author: Haseeb | IMSciences, Peshawar

AUTHORIZED LAB USE ONLY.
This module sends crafted HTTP requests to check whether a URL parameter
allows arbitrary external redirects. Only use against intentionally
vulnerable applications you own or have written permission to test.

Detection approach:
  1. Inject a canary domain (open-redirect-canary.invalid) as the redirect value.
  2. Inspect the response: status code, Location header, and HTML body.
  3. Confirm redirect points to the canary — not just any 3xx response.
  4. If confirmed, classify by payload tier and assign severity.
"""

import re
import requests
from urllib.parse import urlencode, urlparse
from config import (
    CANARY_DOMAIN,
    REDIRECT_PAYLOADS,
    REDIRECT_PARAMS,
    REDIRECT_STATUS_CODES,
    REQUEST_TIMEOUT,
    USER_AGENT,
    SEVERITY,
)


# ─────────────────────────────────────────────────────────────────────────────
#  SINGLE-REQUEST PROBE
# ─────────────────────────────────────────────────────────────────────────────

def probe(base_url: str, param: str, payload: str, session: requests.Session) -> dict:
    """
    Send one detection request and return a structured result dict.

    Args:
        base_url : The base URL of the target endpoint.
        param    : The URL parameter name to inject into.
        payload  : The redirect payload (points to canary domain).
        session  : A shared requests.Session (for connection pooling).

    Returns:
        A dict describing what happened: URL, status, location header, verdict.
    """
    test_url = f"{base_url}?{param}={payload}"

    result = {
        # ── Identifiers ──────────────────────────────────────────────────────
        "base_url":       base_url,
        "test_url":       test_url,
        "param":          param,
        "payload":        payload,
        # ── Raw Response ─────────────────────────────────────────────────────
        "status_code":    None,
        "location":       None,
        "body_snippet":   "",
        # ── Verdict ──────────────────────────────────────────────────────────
        "vulnerable":     False,
        "detection_type": None,   # "location_header" | "meta_refresh" | "js_redirect"
        "payload_tier":   None,   # 1 = standard, 2 = protocol-relative, 3 = evasive
        "severity":       "INFO",
        "evidence":       "",
        # ── Errors ───────────────────────────────────────────────────────────
        "error":          None,
    }

    headers = {"User-Agent": USER_AGENT}

    try:
        response = session.get(
            test_url,
            allow_redirects=False,   # Inspect the redirect, don't follow it
            timeout=REQUEST_TIMEOUT,
            headers=headers,
        )

        result["status_code"] = response.status_code
        result["location"]    = response.headers.get("Location", "")
        result["body_snippet"] = response.text[:800] if response.text else ""

        # ── Detection Method 1: Location Header ───────────────────────────────
        if (response.status_code in REDIRECT_STATUS_CODES
                and CANARY_DOMAIN in result["location"]):
            result["vulnerable"]     = True
            result["detection_type"] = "location_header"
            result["evidence"] = (
                f"HTTP {response.status_code} redirect with "
                f"Location: {result['location']} "
                f"— server redirected to canary domain."
            )

        # ── Detection Method 2: Meta-Refresh in HTML Body ─────────────────────
        if not result["vulnerable"] and response.text:
            meta_pattern = re.compile(
                r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*'
                + re.escape(CANARY_DOMAIN),
                re.IGNORECASE
            )
            if meta_pattern.search(response.text):
                result["vulnerable"]     = True
                result["detection_type"] = "meta_refresh"
                result["evidence"] = (
                    "Meta-refresh redirect to canary domain found in HTML body. "
                    "This bypasses header-level redirect detection."
                )

        # ── Detection Method 3: JavaScript Redirect ───────────────────────────
        if not result["vulnerable"] and response.text:
            js_patterns = [
                r'window\.location\s*=',
                r'window\.location\.href\s*=',
                r'window\.location\.replace\s*\(',
                r'document\.location\s*=',
            ]
            for pattern in js_patterns:
                if (re.search(pattern, response.text, re.IGNORECASE)
                        and CANARY_DOMAIN in response.text):
                    result["vulnerable"]     = True
                    result["detection_type"] = "js_redirect"
                    result["evidence"] = (
                        f"JavaScript redirect ({pattern.split(chr(92))[1]}) "
                        "to canary domain detected in page source."
                    )
                    break

        # ── Non-vulnerable summary ────────────────────────────────────────────
        if not result["vulnerable"]:
            loc_display = result["location"] or "none"
            result["evidence"] = (
                f"No open redirect. Status: {response.status_code}. "
                f"Location: {loc_display}."
            )

    except requests.exceptions.ConnectionError as e:
        result["error"]    = "connection_error"
        result["evidence"] = f"Could not connect to {base_url}: {e}"
    except requests.exceptions.Timeout:
        result["error"]    = "timeout"
        result["evidence"] = f"Request timed out after {REQUEST_TIMEOUT}s."
    except Exception as e:
        result["error"]    = "unexpected"
        result["evidence"] = f"Unexpected error: {e}"

    # ── Severity & Payload Tier ───────────────────────────────────────────────
    if result["vulnerable"]:
        result["payload_tier"] = _classify_payload_tier(payload)
        result["severity"]     = _assign_severity(
            result["payload_tier"], result["detection_type"]
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  TARGET SCANNER  (iterates params × payloads)
# ─────────────────────────────────────────────────────────────────────────────

def scan_target(base_url: str, session: requests.Session, verbose: bool = False) -> list:
    """
    Probe a single target URL with every parameter/payload combination.
    Stops testing a parameter as soon as a vulnerability is confirmed.

    Returns a deduplicated list of result dicts — one per (url, param) pair,
    with the first confirmed hit (or last safe result) per combination.
    """
    print(f"\n  [SCAN] {base_url}")
    print(f"         {len(REDIRECT_PARAMS)} params × {len(REDIRECT_PAYLOADS)} payloads "
          f"= up to {len(REDIRECT_PARAMS) * len(REDIRECT_PAYLOADS)} probes")

    results         = []
    vulnerable_params = set()

    for param in REDIRECT_PARAMS:
        last_result = None

        for payload in REDIRECT_PAYLOADS:
            result = probe(base_url, param, payload, session)
            last_result = result

            if verbose:
                icon = "VULN" if result["vulnerable"] else "safe"
                print(
                    f"    [{icon}] ?{param}={payload[:40]!r:40}  "
                    f"→ HTTP {result['status_code']}"
                )

            if result["vulnerable"]:
                vulnerable_params.add(param)
                results.append(result)

                # Print inline finding summary
                print(
                    f"    [!] VULNERABLE  param={param!r}  "
                    f"payload={payload!r}  "
                    f"type={result['detection_type']}  "
                    f"severity={result['severity']}"
                )
                break  # One confirmed hit per param is enough

        # If no payload triggered a hit, record the last (safe) probe
        if param not in vulnerable_params and last_result:
            results.append(last_result)

    vuln_count = sum(1 for r in results if r["vulnerable"])
    print(f"\n  [DONE] {base_url}")
    print(f"         Vulnerable parameters found: {vuln_count}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _classify_payload_tier(payload: str) -> int:
    """
    Classify a payload into a tier based on evasion complexity.
      Tier 1 = Standard HTTPS/HTTP (most obvious)
      Tier 2 = Protocol-relative or path manipulation
      Tier 3 = Encoding, case variation, or other evasion
    """
    payload_lower = payload.lower().strip()

    if payload_lower.startswith("https://") or payload_lower.startswith("http://"):
        return 1
    if payload.startswith("//") or payload.startswith("////"):
        return 2
    return 3  # Encoded, case-varied, whitespace, etc.


def _assign_severity(tier: int, detection_type: str) -> str:
    """
    Map payload tier + detection type to a severity label.
    Tier 1 via Location header = HIGH (no bypass needed).
    Tier 2/3 or alternate detection methods = MEDIUM.
    """
    if tier == 1 and detection_type == "location_header":
        return "HIGH"
    if tier == 2 or detection_type in ("meta_refresh",):
        return "MEDIUM"
    return "MEDIUM"   # JS redirect or Tier 3 = MEDIUM by default
