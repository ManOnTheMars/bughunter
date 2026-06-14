"""TCP port / service scanner for authorized host reconnaissance.

Performs a standard TCP connect scan (the same thing `nmap -sT` does) over a set
of common ports, grabs any banner the service volunteers, and reports exposed or
risky services. It does NOT exploit, brute-force, or send service-specific attack
payloads — it connects, optionally reads a banner, and disconnects.

AUTHORIZATION: scanning hosts you do not own or have written permission to test
is illegal in most jurisdictions. This module therefore only scans loopback and
RFC-1918 private addresses by default; any public target requires an explicit
`authorized=True` acknowledgement from the caller.

Findings reuse the shared `Finding` model (category "Security", file = host:port).
"""
import asyncio
import ipaddress
import socket

from .analyzer import _build_result
from .schemas import Finding, ScanResult

# port -> (service, severity-if-exposed, note)
_PORT_RISK = {
    21:    ("FTP", "Medium", "Cleartext file transfer; credentials sniffable. Prefer SFTP/FTPS."),
    23:    ("Telnet", "High", "Cleartext remote shell — credentials and sessions are exposed. Use SSH."),
    25:    ("SMTP", "Low", "Mail server exposed; ensure it is not an open relay."),
    110:   ("POP3", "Medium", "Cleartext mail retrieval. Use POP3S/IMAPS."),
    135:   ("MSRPC", "High", "Windows RPC exposed; common lateral-movement surface. Firewall it."),
    139:   ("NetBIOS", "High", "Legacy SMB/NetBIOS exposed. Block at the perimeter."),
    143:   ("IMAP", "Medium", "Cleartext mail retrieval. Use IMAPS."),
    445:   ("SMB", "High", "SMB exposed to the network — a major ransomware/worm vector. Restrict it."),
    1433:  ("MSSQL", "High", "Database port reachable; never expose DBs to untrusted networks."),
    1521:  ("Oracle DB", "High", "Database port reachable; never expose DBs to untrusted networks."),
    3306:  ("MySQL", "High", "Database port reachable; bind to localhost or firewall it."),
    3389:  ("RDP", "High", "Remote Desktop exposed — heavily brute-forced. Use VPN/NLA, restrict source IPs."),
    5432:  ("PostgreSQL", "High", "Database port reachable; bind to localhost or firewall it."),
    5900:  ("VNC", "High", "Remote desktop, often weak/no auth. Tunnel over SSH/VPN."),
    6379:  ("Redis", "High", "Redis is often unauthenticated; exposure leads to RCE/data theft. Bind to localhost."),
    9200:  ("Elasticsearch", "High", "Often unauthenticated; exposure leaks/destroys data. Restrict access."),
    11211: ("Memcached", "High", "Unauthenticated and a DDoS amplification vector. Bind to localhost."),
    27017: ("MongoDB", "High", "Historically unauthenticated; exposure leaks data. Bind to localhost / enable auth."),
    2375:  ("Docker API", "Critical", "Unauthenticated Docker daemon = full host RCE. Never expose; use TLS sockets."),
    22:    ("SSH", "Low", "SSH exposed. Ensure key-only auth, no root login, and fail2ban/rate limiting."),
    80:    ("HTTP", "Low", "Plain HTTP service. Redirect to HTTPS."),
    443:   ("HTTPS", "Low", "HTTPS service present (informational)."),
    8080:  ("HTTP-alt", "Low", "Alternate HTTP port; often a dev/admin server — confirm it should be public."),
    8443:  ("HTTPS-alt", "Low", "Alternate HTTPS port; confirm it should be public."),
}

DEFAULT_PORTS = sorted(_PORT_RISK.keys())


def _is_private(host: str) -> bool:
    """True for loopback / RFC-1918 / link-local hosts (safe to scan unprompted)."""
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (ValueError, OSError):
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


async def _probe(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    """Connect to host:port; return (port, open?, banner)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return port, False, ""
    banner = ""
    try:
        data = await asyncio.wait_for(reader.read(128), timeout=1.5)
        banner = data.decode("latin-1", "replace").strip()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return port, True, banner


async def scan_host(
    host: str,
    ports: list[int] | None = None,
    authorized: bool = False,
    timeout: float = 2.0,
    concurrency: int = 100,
) -> ScanResult:
    """Connect-scan `host` over `ports`. Public targets require authorized=True."""
    host = host.strip()
    if not host:
        raise ValueError("Host is required.")
    if not _is_private(host) and not authorized:
        raise PermissionError(
            f"'{host}' is not a private/loopback address. Scanning a host you do "
            "not own or have written permission to test is illegal. Re-run with "
            "explicit authorization (CLI: --authorized; API: authorized=true) only "
            "if you are authorized to test this target."
        )

    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)

    async def run(p):
        async with sem:
            return await _probe(host, p, timeout)

    results = await asyncio.gather(*(run(p) for p in ports))

    findings: list[Finding] = []
    for port, is_open, banner in sorted(results):
        if not is_open:
            continue
        service, sev, note = _PORT_RISK.get(port, ("Unknown", "Low", "Open port — confirm it should be reachable."))
        desc = f"Port {port}/tcp ({service}) is open."
        if banner:
            desc += f" Banner: {banner[:120]}"
        findings.append(Finding(
            file=f"{host}:{port}", category="Security", severity=sev,
            title=f"{service} open on port {port}", line=0,
            description=desc, recommendation=note, confidence="High",
        ))

    return _build_result(findings, host, files_scanned=len(ports), files_skipped=0)
