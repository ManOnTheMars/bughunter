"""Non-intrusive web security posture scanner.

Makes ordinary HTTP(S) requests to a target URL — exactly what a browser does —
and inspects what the server volunteers: response headers, cookies, TLS, and a
small slice of the body. From that it reports common misconfigurations (missing
security headers, insecure cookies, info disclosure, no HTTPS, permissive CORS).

It does NOT send attack payloads, fuzz parameters, brute-force, or attempt any
exploitation. It only reads. Even so: **only scan sites you own or are explicitly
authorized to test.**

Findings reuse the shared `Finding` model (category "Security", file = the URL,
line = 0) so the CLI/UI/report code is shared with the code scanner.
"""
import asyncio
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .analyzer import _build_result
from .provider import complete_findings
from .schemas import Finding, ScanResult

USER_AGENT = "BugHunter/1.0 (+security-posture-scan; non-intrusive)"

# Security response headers we expect on a hardened site.
_SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS header", "Medium",
        "Without Strict-Transport-Security a browser can be downgraded to HTTP "
        "(SSL-strip / MITM).",
        "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`."),
    "content-security-policy": ("Missing Content-Security-Policy", "Medium",
        "No CSP means injected scripts run unrestricted — the main defence-in-depth "
        "against XSS is absent.",
        "Define a CSP, e.g. `default-src 'self'; script-src 'self'`. Start in report-only mode."),
    "x-content-type-options": ("Missing X-Content-Type-Options", "Low",
        "Browsers may MIME-sniff responses, enabling some content-type confusion attacks.",
        "Send `X-Content-Type-Options: nosniff`."),
    "referrer-policy": ("Missing Referrer-Policy", "Low",
        "Full URLs (possibly with tokens) may leak to third parties via the Referer header.",
        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."),
    "permissions-policy": ("Missing Permissions-Policy", "Low",
        "Powerful browser features (camera, geolocation…) are not restricted.",
        "Send a `Permissions-Policy` disabling features you don't use, e.g. `geolocation=(), camera=()`."),
}


def _normalize(url: str) -> str:
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


async def _tls_not_after(host: str, port: int = 443) -> datetime | None:
    """Best-effort fetch of the TLS cert's notAfter (None if unavailable)."""
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=8
        )
    except Exception:
        return None
    try:
        cert = writer.get_extra_info("ssl_object").getpeercert()
        return datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def collect_web_evidence(url: str) -> dict:
    """Fetch the URL (following redirects) and return raw, non-intrusive evidence."""
    url = _normalize(url)
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=15.0,
        headers={"User-Agent": USER_AGENT}, verify=True,
    ) as client:
        resp = await client.get(url)

    final = str(resp.url)
    parsed = urlparse(final)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = [
        {"name": c.name, "secure": c.secure,
         "httponly": "httponly" in (c._rest or {}) if hasattr(c, "_rest") else False,
         "samesite": (c._rest or {}).get("samesite") if hasattr(c, "_rest") else None}
        for c in resp.cookies.jar
    ]
    tls_not_after = None
    if parsed.scheme == "https":
        tls_not_after = await _tls_not_after(parsed.hostname, parsed.port or 443)

    return {
        "requested": url,
        "final_url": final,
        "scheme": parsed.scheme,
        "status": resp.status_code,
        "headers": headers,
        "set_cookie": resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [],
        "cookies": cookies,
        "tls_not_after": tls_not_after.isoformat() if tls_not_after else None,
        "body_snippet": resp.text[:2000],
    }


def _rule_findings(ev: dict) -> list[Finding]:
    url = ev["final_url"]
    h = ev["headers"]
    out: list[Finding] = []

    def add(sev, title, desc, rec, conf="High"):
        out.append(Finding(file=url, category="Security", severity=sev,
                           title=title, line=0, description=desc,
                           recommendation=rec, confidence=conf))

    # HTTPS / transport
    if ev["scheme"] != "https":
        add("High", "Site served over plain HTTP",
            "Traffic is unencrypted and can be read or modified in transit.",
            "Serve the site over HTTPS and redirect all HTTP traffic to it.")

    # Missing security headers
    for key, (title, sev, desc, rec) in _SECURITY_HEADERS.items():
        if key == "strict-transport-security" and ev["scheme"] != "https":
            continue  # HSTS only meaningful over HTTPS
        if key not in h:
            add(sev, title, desc, rec)

    # Clickjacking: needs X-Frame-Options OR CSP frame-ancestors
    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        add("Medium", "No clickjacking protection",
            "Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed.",
            "Send `X-Frame-Options: DENY` or a CSP `frame-ancestors 'none'`.")

    # Info disclosure via banners
    for banner in ("server", "x-powered-by", "x-aspnet-version"):
        if banner in h and h[banner].strip():
            add("Low", f"Server banner exposed ({banner})",
                f"`{banner}: {h[banner]}` reveals the tech stack/version, aiding targeted attacks.",
                f"Remove or genericise the `{banner}` header.", conf="Medium")

    # Permissive CORS
    acao = h.get("access-control-allow-origin", "")
    if acao == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        add("High", "Unsafe CORS configuration",
            "`Access-Control-Allow-Origin: *` together with credentials lets any origin "
            "read authenticated responses.",
            "Reflect a specific allow-listed origin instead of `*` when credentials are allowed.")

    # Cookie flags
    for c in ev["cookies"]:
        problems = []
        if not c["secure"]:
            problems.append("no Secure")
        if not c["httponly"]:
            problems.append("no HttpOnly")
        if not c["samesite"]:
            problems.append("no SameSite")
        if problems:
            add("Medium", f"Insecure cookie: {c['name']}",
                f"Cookie `{c['name']}` is missing flags ({', '.join(problems)}), exposing it "
                "to theft (XSS) or CSRF.",
                "Set Secure, HttpOnly, and SameSite=Lax/Strict on session cookies.",
                conf="Medium")

    # TLS expiry
    if ev["tls_not_after"]:
        exp = datetime.fromisoformat(ev["tls_not_after"])
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            add("High", "TLS certificate expired",
                f"The certificate expired {-days} day(s) ago.", "Renew the TLS certificate.")
        elif days < 21:
            add("Medium", "TLS certificate expiring soon",
                f"The certificate expires in {days} day(s).",
                "Renew/automate renewal (e.g. ACME) before expiry.", conf="Medium")

    return out


_AI_SYSTEM = """You are a web security reviewer. You are given non-intrusive
evidence collected from a single HTTP response (headers, cookies, a body
snippet). Report only real, defensible security issues an attacker could use —
no speculation, no findings already implied by simple header presence. Examples:
dangerous inline secrets/API keys in the body, debug/stack traces, source maps
or admin paths referenced in HTML, mixed content, dangerous CSP directives
('unsafe-inline'/'unsafe-eval' or wildcards). If nothing further, return an
empty findings array. category MUST be "Security"; line 0; be concrete."""


async def _ai_findings(ev: dict, url: str) -> list[Finding]:
    import json
    user = (
        f"Target: {url}\nStatus: {ev['status']}\n\nResponse headers:\n"
        + "\n".join(f"{k}: {v}" for k, v in ev["headers"].items())
        + f"\n\nBody snippet (first 2KB):\n{ev['body_snippet']}"
    )
    text = await complete_findings(_AI_SYSTEM, user)
    raw = json.loads(text)["findings"]
    return [Finding(file=url, **item) for item in raw]


async def scan_web(url: str, ai: bool = False) -> ScanResult:
    """Scan a single URL's security posture. Set ai=True for LLM enrichment."""
    ev = await collect_web_evidence(url)
    findings = _rule_findings(ev)
    if ai:
        try:
            findings += await _ai_findings(ev, ev["final_url"])
        except Exception:
            pass  # AI enrichment is best-effort; rules are the source of truth
    return _build_result(findings, ev["final_url"], files_scanned=1, files_skipped=0)
