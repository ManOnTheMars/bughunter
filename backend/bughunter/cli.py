"""Command-line bug hunter:  python -m bughunter.cli scan <path> [options]"""
import argparse
import asyncio
import json
import os
import sys

from .analyzer import scan_path
from .hostscan import scan_host
from .netscan import scan_network
from .provider import PROVIDER
from .schemas import ScanResult
from .webscan import scan_web

# ANSI colors (cross-platform enough for modern terminals / Windows Terminal).
_C = {
    "Critical": "\033[97;41m", "High": "\033[91m", "Medium": "\033[93m",
    "Low": "\033[96m", "dim": "\033[90m", "bold": "\033[1m",
    "Security": "\033[95m", "Logic": "\033[94m", "reset": "\033[0m",
}


def _c(key: str, text: str) -> str:
    return f"{_C[key]}{text}{_C['reset']}"


def _print_report(result: ScanResult) -> None:
    s = result.summary
    print()
    print(_c("bold", f"  Bug Hunter — {s.root}"))
    print(_c("dim", f"  {s.files_scanned} files scanned · {s.files_skipped} skipped · "
                    f"{s.total_findings} findings"))
    sev = s.by_severity
    print("  " + " · ".join(
        _c(k, f"{k}: {sev[k]}") for k in ("Critical", "High", "Medium", "Low")
    ))
    print()

    if not result.findings:
        print(_c("Low", "  ✓ No issues found."))
        print()
        return

    current_file = None
    for f in result.findings:
        if f.file != current_file:
            current_file = f.file
            print(_c("bold", f"  {f.file}"))
        loc = f"L{f.line}" if f.line else "file"
        tag = _c(f.severity, f" {f.severity.upper()} ")
        cat = _c(f.category, f.category)
        print(f"    {tag} {cat} {_c('dim', loc)}  {_c('bold', f.title)} "
              f"{_c('dim', '(' + f.confidence + ' confidence)')}")
        print(f"      {f.description}")
        print(f"      {_c('Low', '→ ' + f.recommendation)}")
        print()


def _needs_key() -> bool:
    return PROVIDER == "anthropic" and not os.getenv("ANTHROPIC_API_KEY")


def _no_key_msg() -> None:
    print(_c("High", "ANTHROPIC_API_KEY is not set. Add it to backend/.env, "
                     "or set PROVIDER=ollama to use a local model."),
          file=sys.stderr)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bughunter", description="Claude-powered bug & security hunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Scan a local folder or file for code bugs")
    sc.add_argument("path", help="Folder or file to scan")
    sc.add_argument("--security-only", action="store_true", help="Only security vulnerabilities")
    sc.add_argument("--logic-only", action="store_true", help="Only logic/correctness bugs")
    sc.add_argument("--max-files", type=int, default=None, help="Cap number of files analysed")
    sc.add_argument("--verify", action="store_true", help="Second pass to drop false positives")
    sc.add_argument("--json", dest="json_out", metavar="FILE", help="Also write findings as JSON")

    wc = sub.add_parser("web", help="Non-intrusive web security posture scan of a URL")
    wc.add_argument("url", help="Target URL (e.g. https://example.com) — authorized targets only")
    wc.add_argument("--ai", action="store_true", help="Add LLM enrichment of the response")
    wc.add_argument("--cookie", help="Cookie header for an authenticated scan, e.g. \"session=abc\"")
    wc.add_argument("--header", action="append", default=[], metavar="K:V",
                    help="Extra request header (repeatable), e.g. \"Authorization: Bearer ...\"")
    wc.add_argument("--basic", metavar="USER:PASS", help="HTTP Basic auth credentials")
    wc.add_argument("--json", dest="json_out", metavar="FILE", help="Also write findings as JSON")

    nc = sub.add_parser("net", help="Discover live hosts in a network + OS guess (authorized only)")
    nc.add_argument("cidr", help="CIDR range, e.g. 192.168.1.0/24. Public ranges require --authorized")
    nc.add_argument("--authorized", action="store_true",
                    help="Confirm you are authorized to scan a non-private range")
    nc.add_argument("--quick", action="store_true", help="Probe only common ports (faster)")
    nc.add_argument("--json", dest="json_out", metavar="FILE", help="Also write findings as JSON")

    hc = sub.add_parser("host", help="TCP port/service scan of a host (authorized targets only)")
    hc.add_argument("host", help="Host or IP. Public targets require --authorized")
    hc.add_argument("--ports", help="Comma-separated ports (default: common ports)")
    hc.add_argument("--authorized", action="store_true",
                    help="Confirm you are authorized to scan a non-private target")
    hc.add_argument("--json", dest="json_out", metavar="FILE", help="Also write findings as JSON")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "scan":
            if _needs_key():
                _no_key_msg()
                return 2
            categories = (["Security"] if args.security_only
                          else ["Logic"] if args.logic_only else None)

            def progress(rel, done, total=None, found=0, error=None):
                if error:
                    print(_c("dim", f"  ! {rel}: {error}"), file=sys.stderr)
                elif done:
                    note = _c("High", f" {found} found") if found else ""
                    print(_c("dim", f"  [{done}/{total}] {rel}{note}"), file=sys.stderr)

            result = asyncio.run(scan_path(args.path, categories, args.max_files, progress, args.verify))

        elif args.cmd == "web":
            if args.ai and _needs_key():
                _no_key_msg()
                return 2
            headers = {}
            for h in args.header:
                if ":" in h:
                    k, _, v = h.partition(":")
                    headers[k.strip()] = v.strip()
            print(_c("dim", f"  Scanning {args.url} …"), file=sys.stderr)
            result = asyncio.run(scan_web(
                args.url, ai=args.ai, headers=headers or None,
                cookie=args.cookie, basic=args.basic,
            ))

        elif args.cmd == "net":
            print(_c("dim", f"  Sweeping {args.cidr} …"), file=sys.stderr)
            result = asyncio.run(scan_network(
                args.cidr, authorized=args.authorized, full_ports=not args.quick,
            ))

        elif args.cmd == "host":
            ports = None
            if args.ports:
                ports = [int(p) for p in args.ports.split(",") if p.strip()]
            print(_c("dim", f"  Scanning {args.host} …"), file=sys.stderr)
            result = asyncio.run(scan_host(args.host, ports, authorized=args.authorized))
        else:
            parser.error("unknown command")
    except FileNotFoundError as e:
        print(_c("High", str(e)), file=sys.stderr)
        return 1
    except PermissionError as e:  # host scan authorization gate
        print(_c("Critical", f"  {e}"), file=sys.stderr)
        return 2
    except Exception as e:
        print(_c("High", f"  Scan failed: {e}"), file=sys.stderr)
        return 1

    _print_report(result)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(result.model_dump(), fh, indent=2, ensure_ascii=False)
        print(_c("dim", f"  JSON written to {args.json_out}"))

    # Non-zero exit if Critical/High found — useful in CI / pre-commit.
    return 1 if (result.summary.by_severity["Critical"] or result.summary.by_severity["High"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
