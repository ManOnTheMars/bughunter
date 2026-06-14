"""Network host discovery + light OS fingerprinting for authorized LANs.

Sweeps a CIDR range (e.g. 192.168.1.0/24), finds live hosts with a TCP connect
probe, port/service-scans each one, and makes a best-effort OS guess from the
service banners and the ICMP TTL. This is the same kind of work `nmap -sn` /
`nmap -O` does — standard reconnaissance, NOT exploitation. No raw sockets and
no admin/root are required (TTL comes from the system `ping`), so it stays
cross-platform and unprivileged.

The OS guess is a HEURISTIC, not definitive: banners can be spoofed and TTLs are
only a rough family signal. Treat it as a hint.

AUTHORIZATION: sweeping a network you do not own or have written permission to
scan is illegal in most jurisdictions. Only private/loopback ranges are swept by
default; a public range requires an explicit ``authorized=True`` acknowledgement.
"""
import asyncio
import ipaddress
import platform
import re

from .analyzer import _build_result
from .hostscan import DEFAULT_PORTS, _PORT_RISK, _probe
from .schemas import Finding, ScanResult

# Fast liveness probes — if any connects (open) or is refused (host up, port
# closed), the host is alive. Kept small so discovery over a /24 stays quick.
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 139, 8080, 21, 25, 3306]
MAX_HOSTS = 1024  # refuse absurdly large sweeps

_OS_BANNER_HINTS = [
    (re.compile(r"ubuntu", re.I), "Linux (Ubuntu)"),
    (re.compile(r"debian", re.I), "Linux (Debian)"),
    (re.compile(r"centos|red ?hat|rhel", re.I), "Linux (RHEL/CentOS)"),
    (re.compile(r"raspbian", re.I), "Linux (Raspbian)"),
    (re.compile(r"openssh.*linux|\blinux\b", re.I), "Linux"),
    (re.compile(r"microsoft|win(dows|32|64)|iis", re.I), "Windows"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
    (re.compile(r"mikrotik|routeros|cisco|dd-wrt", re.I), "Network device"),
]


def _expand(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.num_addresses <= 2:  # /31, /32 or single host
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


def _is_private_net(cidr: str) -> bool:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=False).is_private
    except ValueError:
        return False


def _os_from_banner(banner: str) -> str | None:
    for rx, label in _OS_BANNER_HINTS:
        if rx.search(banner):
            return label
    return None


def _os_from_ttl(ttl: int) -> str:
    # Common initial TTLs: 64 = Linux/Unix/macOS, 128 = Windows, 255 = network gear.
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network device / other"


async def _ping_ttl(host: str) -> int | None:
    """Return the ICMP TTL via the system ping (None if unreachable)."""
    win = platform.system() == "Windows"
    args = (["ping", "-n", "1", "-w", "1000", host] if win
            else ["ping", "-c", "1", "-W", "1", host])
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
    except (OSError, asyncio.TimeoutError):
        return None
    m = re.search(r"ttl[=\s:]*(\d+)", out.decode("latin-1", "replace"), re.I)
    return int(m.group(1)) if m else None


async def _host_alive(host: str, timeout: float) -> bool:
    """A host is alive if any discovery port is open OR actively refuses."""
    async def one(p):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=timeout)
            w.close()
            return True            # open → up
        except ConnectionRefusedError:
            return True            # refused → host is up, port closed
        except (OSError, asyncio.TimeoutError):
            return False
    return any(await asyncio.gather(*(one(p) for p in DISCOVERY_PORTS)))


async def _scan_one_host(host: str, ports: list[int], timeout: float, sem):
    async with sem:
        if not await _host_alive(host, timeout):
            return None
        results = await asyncio.gather(*(_probe(host, p, timeout) for p in ports))
        ttl = await _ping_ttl(host)

    open_ports = [(p, b) for p, is_open, b in results if is_open]
    banners = " ".join(b for _, b in open_ports if b)
    os_guess = _os_from_banner(banners)
    os_conf = "Medium" if os_guess else "Low"
    if not os_guess and ttl is not None:
        os_guess = _os_from_ttl(ttl)
    os_guess = os_guess or "Unknown"

    findings: list[Finding] = []
    detail = f"Host {host} is up — {len(open_ports)} open port(s). OS guess: {os_guess}"
    if ttl is not None:
        detail += f" (TTL {ttl})"
    findings.append(Finding(
        file=host, category="Security", severity="Low",
        title=f"Live host: {host} [{os_guess}]", line=0,
        description=detail,
        recommendation="Confirm this host should be reachable; inventory it. OS guess is heuristic.",
        confidence=os_conf,
    ))
    for port, banner in open_ports:
        service, sev, note = _PORT_RISK.get(port, ("Unknown", "Low", "Open port — confirm it should be reachable."))
        desc = f"Port {port}/tcp ({service}) open on {host}."
        if banner:
            desc += f" Banner: {banner[:100]}"
        findings.append(Finding(
            file=f"{host}:{port}", category="Security", severity=sev,
            title=f"{service} open on {host}:{port}", line=0,
            description=desc, recommendation=note, confidence="High",
        ))
    return findings


async def scan_network(
    cidr: str,
    authorized: bool = False,
    full_ports: bool | None = None,
    timeout: float = 1.5,
    concurrency: int = 64,
) -> ScanResult:
    """Discover live hosts in `cidr`, scan ports/OS. Public ranges need authorized=True."""
    cidr = cidr.strip()
    if not _is_private_net(cidr) and not authorized:
        raise PermissionError(
            f"'{cidr}' is not a private network. Sweeping a network you do not own "
            "or have written permission to scan is illegal. Re-run with explicit "
            "authorization (CLI: --authorized; API: authorized=true) only if you are "
            "authorized to test this range."
        )
    hosts = _expand(cidr)
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"Range too large ({len(hosts)} hosts > {MAX_HOSTS}). Use a smaller CIDR.")

    ports = DEFAULT_PORTS if (full_ports or full_ports is None) else DISCOVERY_PORTS
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(_scan_one_host(h, ports, timeout, sem) for h in hosts))

    findings: list[Finding] = []
    live = 0
    for r in results:
        if r:
            live += 1
            findings.extend(r)
    # files_scanned repurposed as hosts probed; live count in the host findings.
    return _build_result(findings, f"{cidr} ({live} live)", files_scanned=len(hosts), files_skipped=0)
