"""Command-line bug hunter:  python -m bughunter.cli scan <path> [options]"""
import argparse
import asyncio
import json
import os
import sys

from .analyzer import scan_path
from .provider import PROVIDER
from .schemas import ScanResult

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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bughunter", description="Claude-powered bug & security hunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Scan a local folder or file")
    sc.add_argument("path", help="Folder or file to scan")
    sc.add_argument("--security-only", action="store_true", help="Only security vulnerabilities")
    sc.add_argument("--logic-only", action="store_true", help="Only logic/correctness bugs")
    sc.add_argument("--max-files", type=int, default=None, help="Cap number of files analysed")
    sc.add_argument("--json", dest="json_out", metavar="FILE", help="Also write findings as JSON")

    args = parser.parse_args(argv)

    if PROVIDER == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print(_c("High", "ANTHROPIC_API_KEY is not set. Add it to backend/.env, "
                         "or set PROVIDER=ollama to use a local model."),
              file=sys.stderr)
        return 2

    categories = None
    if args.security_only:
        categories = ["Security"]
    elif args.logic_only:
        categories = ["Logic"]

    def progress(rel, done, total=None, found=0, error=None):
        if error:
            print(_c("dim", f"  ! {rel}: {error}"), file=sys.stderr)
        elif done:
            bar = f"[{done}/{total}]"
            note = _c("High", f" {found} found") if found else ""
            print(_c("dim", f"  {bar} {rel}{note}"), file=sys.stderr)

    try:
        result = asyncio.run(scan_path(args.path, categories, args.max_files, progress))
    except FileNotFoundError as e:
        print(_c("High", str(e)), file=sys.stderr)
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
