"""
test_server.py — Intentionally Vulnerable Test Server (LOCAL LAB USE ONLY)
===========================================================================
Week 4 - Cybersecurity Portfolio | Author: Haseeb | IMSciences, Peshawar

PURPOSE:
  This server is intentionally vulnerable to Open Redirect.
  It provides two endpoints for testing the detector:

    /redirect/vulnerable  — VULNERABLE: redirects to any URL supplied
    /redirect/safe        — SAFE (patched): validates against an allowlist

  Use this when you don't have Juice Shop/DVWA/WebGoat available.

INSTALL:
  pip install flask

RUN:
  python test_server.py

THEN SCAN:
  python main.py -t http://localhost:5000/redirect/vulnerable
  python main.py -t http://localhost:5000/redirect/safe

THIS FILE IS A LAB TOOL. NEVER DEPLOY ON A REAL SERVER.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
try:
    from flask import Flask, request, redirect, render_template_string
except ImportError:
    print("[ERROR] Flask is not installed. Run: pip install flask")
    raise SystemExit(1)

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  ALLOWLIST  (used only by the safe endpoint)
# ─────────────────────────────────────────────────────────────────────────────
ALLOWED_HOSTS = {"example.com", "myapp.local", "localhost"}

# ─────────────────────────────────────────────────────────────────────────────
#  HOMEPAGE
# ─────────────────────────────────────────────────────────────────────────────

HOME_HTML = """
<!doctype html>
<html>
<head><title>NGO Demo App — Lab Environment</title></head>
<body>
<h2>🌍 Green Future NGO — Demo Application</h2>
<p><strong>LAB ENVIRONMENT ONLY — Intentionally Vulnerable for Security Training</strong></p>
<hr>
<h3>Test Endpoints</h3>
<ul>
  <li>
    <a href="/redirect/vulnerable?url=https://example.com">
      /redirect/vulnerable?url=... (VULNERABLE)
    </a><br>
    Directly redirects to any URL provided — no validation.
  </li>
  <li>
    <a href="/redirect/safe?url=https://example.com">
      /redirect/safe?url=... (SAFE / PATCHED)
    </a><br>
    Validates redirect target against an allowlist before redirecting.
  </li>
</ul>
<hr>
<p>Use this server as a target for the Open Redirect Detector (Week 4 project).</p>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_HTML)


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABLE ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/redirect/vulnerable")
def redirect_vulnerable():
    """
    INTENTIONALLY VULNERABLE — Open Redirect
    ─────────────────────────────────────────
    Root cause: The application takes a user-supplied URL and immediately
    redirects to it with HTTP 302, with ZERO validation.

    Any of these parameters trigger the redirect:
      ?url=...  ?redirect=...  ?to=...  ?next=...  (etc.)

    Real-world equivalent: A login page that redirects to a 'returnUrl'
    parameter after authentication — but forgets to validate the target.
    """
    # Try common parameter names
    param_names = [
        "url", "redirect", "next", "return", "returnUrl",
        "goto", "dest", "to", "target", "callback"
    ]

    destination = None
    used_param  = None

    for name in param_names:
        val = request.args.get(name)
        if val:
            destination = val
            used_param  = name
            break

    if not destination:
        return (
            "<h3>Missing redirect parameter</h3>"
            "<p>Try: <code>?url=https://example.com</code></p>",
            400
        )

    # VULNERABILITY: no validation — redirect to whatever the user says
    app.logger.warning(f"[VULN] Open redirect triggered: ?{used_param}={destination}")
    return redirect(destination, code=302)


# ─────────────────────────────────────────────────────────────────────────────
#  SAFE / PATCHED ENDPOINT
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/redirect/safe")
def redirect_safe():
    """
    PATCHED / SAFE — Allowlist-based redirect validation
    ─────────────────────────────────────────────────────
    The fix: parse the destination URL and check its hostname against
    an explicit server-side allowlist. Reject anything not on the list.

    This endpoint should produce FALSE NEGATIVES in the detector,
    confirming the tool's false-positive suppression works correctly.
    """
    from urllib.parse import urlparse

    destination = request.args.get("url") or request.args.get("redirect")

    if not destination:
        return (
            "<h3>Missing redirect parameter</h3>"
            "<p>Try: <code>?url=https://example.com</code></p>",
            400
        )

    # SECURE: parse and validate the hostname before redirecting
    try:
        parsed = urlparse(destination)
        host   = parsed.hostname or ""
    except Exception:
        host = ""

    if host not in ALLOWED_HOSTS:
        app.logger.info(f"[SAFE] Redirect blocked — host not in allowlist: {host!r}")
        return (
            f"<h3>Redirect Blocked</h3>"
            f"<p>Destination <code>{destination}</code> is not in the allowed list.</p>"
            f"<p>Allowed: {', '.join(sorted(ALLOWED_HOSTS))}</p>",
            403,
        )

    app.logger.info(f"[SAFE] Redirect allowed: {destination}")
    return redirect(destination, code=302)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════════════════╗")
    print("  ║  NGO Demo Test Server — INTENTIONALLY VULNERABLE    ║")
    print("  ║  LOCAL LAB USE ONLY — DO NOT EXPOSE EXTERNALLY      ║")
    print("  ╚══════════════════════════════════════════════════════╝\n")
    print("  Vulnerable endpoint : http://localhost:5000/redirect/vulnerable")
    print("  Safe endpoint       : http://localhost:5000/redirect/safe\n")
    print("  Run detector with:")
    print("    python main.py -t http://localhost:5000/redirect/vulnerable")
    print("    python main.py -t http://localhost:5000/redirect/safe\n")

    app.run(host="127.0.0.1", port=5000, debug=True)
