"""
report_generator.py — Generates JSON and plain-text reports from scan findings
===============================================================================
Week 4 - Cybersecurity Portfolio | Author: Haseeb | IMSciences, Peshawar

Outputs two files per run:
  <prefix>.json  — Full machine-readable report with all raw data
  <prefix>.txt   — Human-readable professional security report

Report structure:
  Header → Executive Summary → Findings → Limitations → Authorization Note
"""

import json
import os
from datetime import datetime, timezone
from config import SEVERITY


# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

TOOL_NAME    = "Open Redirect Detector"
TOOL_VERSION = "1.0.0"
AUTHOR       = "Haseeb — IMSciences, Peshawar"

SEPARATOR    = "=" * 72
MINI_SEP     = "-" * 72

TOOL_LIMITATIONS = [
    "Does NOT follow multi-hop redirect chains — only the first redirect is inspected.",
    "JavaScript-based redirects in Single-Page Applications (SPAs) may be missed; "
    "the tool reads the initial HTML but does not execute JavaScript.",
    "POST-based redirects are not tested — only GET parameters.",
    "Authenticated endpoints (login-required) are skipped unless a session cookie is provided.",
    "WAF or rate-limiting on the target may produce false negatives by blocking test requests.",
    "Encoded or obfuscated payloads beyond the built-in set may bypass detection.",
    "This tool confirms redirect behavior against a canary domain; it does NOT "
    "verify the full exploitability of each finding (e.g., whether a victim user "
    "would click the crafted link).",
    "Results should always be manually verified before inclusion in a security report.",
]


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _count_by_severity(findings: list) -> dict:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SAFE": 0}
    for f in findings:
        if f.get("vulnerable"):
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        else:
            counts["SAFE"] += 1
    return counts


def _wrap(text: str, width: int = 70, indent: int = 0) -> str:
    """Naive word-wrap for fixed-width text output."""
    prefix = " " * indent
    words  = text.split()
    lines, line = [], []
    current = 0
    for word in words:
        if current + len(word) + 1 > width and line:
            lines.append(prefix + " ".join(line))
            line, current = [word], len(word)
        else:
            line.append(word)
            current += len(word) + 1
    if line:
        lines.append(prefix + " ".join(line))
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  JSON REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _write_json(findings: list, prefix: str) -> str:
    path = f"{prefix}.json"

    report = {
        "tool":        TOOL_NAME,
        "version":     TOOL_VERSION,
        "author":      AUTHOR,
        "generated":   _timestamp(),
        "summary":     _count_by_severity(findings),
        "findings":    findings,
        "limitations": TOOL_LIMITATIONS,
        "authorization_note": (
            "All tests were conducted exclusively against intentionally "
            "vulnerable lab applications (OWASP Juice Shop / DVWA / WebGoat "
            "or a custom local test server) operated in an authorized, "
            "isolated environment. No production or third-party systems were tested."
        ),
    }

    os.makedirs(os.path.dirname(prefix) if os.path.dirname(prefix) else ".", exist_ok=True)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return path


# ─────────────────────────────────────────────────────────────────────────────
#  TEXT REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _write_txt(findings: list, prefix: str) -> str:
    path   = f"{prefix}.txt"
    counts = _count_by_severity(findings)
    vuln   = [f for f in findings if f.get("vulnerable")]

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        SEPARATOR,
        f"  {TOOL_NAME.upper()}  v{TOOL_VERSION}",
        f"  Author   : {AUTHOR}",
        f"  Generated: {_timestamp()}",
        SEPARATOR,
        "",
        "  SCOPE & AUTHORIZATION",
        MINI_SEP,
        _wrap(
            "This assessment was conducted exclusively against intentionally "
            "vulnerable lab applications (OWASP Juice Shop, DVWA, WebGoat, or "
            "a locally operated test server). No production systems, third-party "
            "services, or unauthorized targets were tested.",
            indent=2
        ),
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += [
        "  EXECUTIVE SUMMARY",
        MINI_SEP,
        f"  Total probes analyzed : {len(findings)}",
        f"  Vulnerable findings   : {len(vuln)}",
        f"    HIGH                : {counts['HIGH']}",
        f"    MEDIUM              : {counts['MEDIUM']}",
        f"    LOW                 : {counts['LOW']}",
        f"  Safe (no redirect)    : {counts['SAFE']}",
        "",
    ]

    if not vuln:
        lines += [
            "  RESULT: No open redirect vulnerabilities detected.",
            "  Recommendation: Manually verify with Burp Suite to rule out",
            "  false negatives (e.g. JS-based or POST-based redirects).",
            "",
        ]

    # ── Findings ──────────────────────────────────────────────────────────────
    lines += ["  FINDINGS", MINI_SEP]

    if not vuln:
        lines.append("  None — all tested parameters returned non-redirect responses.")
    else:
        for idx, f in enumerate(vuln, start=1):
            ai  = f.get("ai_analysis", {})
            sev = f.get("severity", "INFO")

            lines += [
                "",
                f"  FINDING #{idx}",
                f"  Severity      : {sev}  ({SEVERITY[sev]['cvss_range']})",
                f"  URL Tested    : {f['test_url']}",
                f"  Parameter     : ?{f['param']}",
                f"  Payload       : {f['payload']}",
                f"  Server Status : HTTP {f['status_code']}",
                f"  Location Hdr  : {f.get('location', 'N/A')}",
                f"  Detection     : {f.get('detection_type', 'N/A')}",
                "",
                "  Evidence:",
                _wrap(f.get("evidence", "N/A"), indent=4),
                "",
            ]

            # AI section
            if ai.get("enabled"):
                lines += [
                    f"  [AI-ASSISTED] {ai.get('disclaimer', '')}",
                    "",
                    "  Explanation (AI):",
                    _wrap(ai.get("plain_english_explanation", "N/A"), indent=4),
                    "",
                    "  Attack Scenario (AI):",
                    _wrap(ai.get("attack_scenario", "N/A"), indent=4),
                    "",
                    f"  AI Severity    : {ai.get('severity_label', 'N/A')}",
                    f"  CVSS Estimate  : {ai.get('cvss_estimate', 'N/A')}",
                    "",
                    "  Severity Reasoning (AI):",
                    _wrap(ai.get("severity_reasoning", "N/A"), indent=4),
                    "",
                    "  Remediation Steps (AI):",
                ]
                for step in ai.get("remediation_steps", []):
                    lines.append(_wrap(step, indent=4))
                lines.append("")

                if ai.get("code_example"):
                    lines += [
                        "  Secure Code Pattern (AI):",
                        "",
                    ]
                    for code_line in ai["code_example"].split("\n"):
                        lines.append(f"    {code_line}")
                    lines.append("")

                if ai.get("false_positive_notes"):
                    lines += [
                        "  False Positive Notes (AI):",
                        _wrap(ai["false_positive_notes"], indent=4),
                        "",
                    ]
            else:
                note = ai.get("note") or ai.get("error", "AI analysis not available.")
                lines += [
                    f"  [AI-ASSISTED] Not available — {note}",
                    "",
                    "  Recommended Remediation (Manual):",
                    _wrap(SEVERITY[sev]["description"], indent=4),
                    _wrap(
                        "  Validate redirect targets against an explicit server-side allowlist. "
                        "Never trust user-supplied URLs directly. If redirecting to external "
                        "sites is not a business requirement, remove the feature entirely.",
                        indent=4
                    ),
                    "",
                ]

            lines.append(MINI_SEP)

    # ── Safe findings summary ─────────────────────────────────────────────────
    safe = [f for f in findings if not f.get("vulnerable")]
    if safe:
        lines += [
            "",
            "  SAFE PROBES (no redirect detected)",
            MINI_SEP,
        ]
        params_tested = sorted(set(f["param"] for f in safe))
        lines.append(f"  Parameters tested without result: {', '.join(params_tested)}")
        lines.append("")

    # ── Limitations ───────────────────────────────────────────────────────────
    lines += [
        "  TOOL LIMITATIONS",
        MINI_SEP,
    ]
    for i, lim in enumerate(TOOL_LIMITATIONS, start=1):
        lines.append(_wrap(f"{i}. {lim}", indent=2))
    lines += ["", SEPARATOR, "  END OF REPORT", SEPARATOR]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return path


# ─────────────────────────────────────────────────────────────────────────────
#  PUBLIC ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(findings: list, prefix: str = "reports/scan_report") -> dict:
    """
    Write both JSON and text reports for a completed scan.

    Args:
        findings : List of enriched result dicts (from detector + ai_analyzer).
        prefix   : File path prefix (directory + base name, no extension).

    Returns:
        dict with 'json_path' and 'txt_path' keys.
    """
    # Ensure output directory exists
    out_dir = os.path.dirname(prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    json_path = _write_json(findings, prefix)
    txt_path  = _write_txt(findings, prefix)

    return {"json_path": json_path, "txt_path": txt_path}
