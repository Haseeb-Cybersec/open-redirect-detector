#!/usr/bin/env python3
"""
main.py — CLI entry point for the AI-Assisted Open Redirect Detection Tool
===========================================================================
Week 4 - Cybersecurity Portfolio | Author: Haseeb | IMSciences, Peshawar

Usage examples:
  # Basic scan — one target
  python main.py -t http://localhost:3000/redirect

  # Multiple targets with verbose output
  python main.py -t http://localhost:3000/redirect http://localhost:8080/go -v

  # Enable AI-assisted analysis (requires ANTHROPIC_API_KEY env var)
  python main.py -t http://localhost:3000/redirect --ai-analysis

  # Full run: verbose + AI + custom output prefix
  python main.py -t http://localhost:3000/redirect --ai-analysis -v -o reports/juiceshop_scan

  # Read targets from a file (one URL per line)
  python main.py --target-file targets.txt --ai-analysis

AUTHORIZED USE ONLY — Juice Shop / DVWA / WebGoat / your own lab only.
"""

import argparse
import sys
import os
from datetime import datetime

import requests

from detector        import scan_target
from ai_analyzer     import analyze_with_ai
from report_generator import generate_report


# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ╔═══════════════════════════════════════════════════════════╗
  ║   AI-ASSISTED OPEN REDIRECT DETECTION TOOL  v1.0.0       ║
  ║   Week 4 Cybersecurity Portfolio — Haseeb, IMSciences    ║
  ╠═══════════════════════════════════════════════════════════╣
  ║   AUTHORIZED LAB USE ONLY (Juice Shop / DVWA / WebGoat)  ║
  ╚═══════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="AI-Assisted Open Redirect Detector — authorized lab use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Targets (mutually exclusive: -t or --target-file)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--targets",
        nargs="+",
        metavar="URL",
        help="One or more authorized target base URLs to scan.",
    )
    target_group.add_argument(
        "--target-file",
        metavar="FILE",
        help="Path to a text file containing one target URL per line.",
    )

    # Options
    parser.add_argument(
        "--ai-analysis", "-a",
        action="store_true",
        help="Enable AI-assisted analysis via the Claude API (requires ANTHROPIC_API_KEY).",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        metavar="PREFIX",
        help="Output file prefix (e.g. reports/my_scan). Default: reports/scan_<timestamp>.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print every probe result, not just confirmed vulnerabilities.",
    )
    parser.add_argument(
        "--skip-confirm",
        action="store_true",
        help="Skip the authorization confirmation prompt (use in CI/CD or scripts).",
    )

    return parser


# ─────────────────────────────────────────────────────────────────────────────
#  AUTHORIZATION GATE
# ─────────────────────────────────────────────────────────────────────────────

def authorization_gate(targets: list, skip: bool = False) -> bool:
    """
    Print a clear authorization reminder and require explicit confirmation.
    Returns True if the user confirms, False if they decline.
    """
    print("\n" + "=" * 60)
    print("  AUTHORIZATION CHECK")
    print("=" * 60)
    print("\n  You are about to scan the following targets:\n")
    for t in targets:
        print(f"    {t}")
    print(
        "\n  By proceeding, you confirm that:\n"
        "    1. Every URL above belongs to an intentionally vulnerable\n"
        "       lab application (Juice Shop / DVWA / WebGoat / your own).\n"
        "    2. You have explicit authorization to test these systems.\n"
        "    3. No production, third-party, or unauthorized systems will\n"
        "       be tested in this session.\n"
    )

    if skip:
        print("  [--skip-confirm active] Proceeding without prompt.\n")
        return True

    answer = input("  Type  YES, I CONFIRM  to proceed: ").strip()
    if answer == "YES, I CONFIRM":
        print("  Authorization confirmed. Starting scan...\n")
        return True

    print("  Authorization not confirmed. Exiting safely.")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    # ── Resolve targets ───────────────────────────────────────────────────────
    if args.targets:
        targets = args.targets
    else:
        try:
            with open(args.target_file, encoding="utf-8") as fh:
                targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[ERROR] Target file not found: {args.target_file}")
            return 1

    if not targets:
        print("[ERROR] No targets provided. Use -t or --target-file.")
        return 1

    # ── Authorization check ───────────────────────────────────────────────────
    if not authorization_gate(targets, skip=args.skip_confirm):
        return 0

    # ── Output prefix ─────────────────────────────────────────────────────────
    if args.output:
        out_prefix = args.output
    else:
        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_prefix = os.path.join("reports", f"scan_{ts}")

    # ── Run scans ─────────────────────────────────────────────────────────────
    session      = requests.Session()
    all_findings = []

    print(f"  Targets to scan : {len(targets)}")
    print(f"  AI analysis     : {'ENABLED' if args.ai_analysis else 'disabled'}")
    print(f"  Output prefix   : {out_prefix}")
    print()

    for target in targets:
        results = scan_target(target, session, verbose=args.verbose)
        all_findings.extend(results)

    # ── AI analysis ───────────────────────────────────────────────────────────
    if args.ai_analysis:
        all_findings = analyze_with_ai(all_findings)
    else:
        for f in all_findings:
            f.setdefault("ai_analysis", {
                "enabled": False,
                "note": "AI analysis not requested. Re-run with --ai-analysis to enable."
            })

    # ── Generate reports ──────────────────────────────────────────────────────
    paths = generate_report(all_findings, prefix=out_prefix)

    vuln_count = sum(1 for f in all_findings if f.get("vulnerable"))
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    print("\n" + "=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print(f"  Vulnerable findings : {vuln_count}  ({high_count} HIGH)")
    print(f"  JSON report         : {paths['json_path']}")
    print(f"  Text report         : {paths['txt_path']}")

    if vuln_count:
        print(
            "\n  [!] Review the text report and verify findings manually\n"
            "      before including them in any formal security report.\n"
        )

    return 0 if vuln_count == 0 else 2   # exit 2 = vulnerabilities found


if __name__ == "__main__":
    sys.exit(main())
