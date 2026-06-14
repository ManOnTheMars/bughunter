"""Send source files to an LLM and collect structured bug findings.

Uses schema-enforced JSON so no markdown-fence parsing or retry-on-bad-JSON is
ever needed. The actual model — Anthropic Claude (cloud) or Ollama (local) — is
selected by the PROVIDER env var; see provider.py.
"""
import asyncio
import json
import os

from .provider import complete_findings
from .schemas import Finding, ScanResult, ScanSummary, SEVERITY_ORDER
from .scanner import collect_files, CollectedFile

MAX_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))

SYSTEM_PROMPT = """You are an elite code auditor combining two specialties:
a security researcher (OWASP, CWE) and a senior engineer hunting correctness bugs.

For each file you receive, find REAL defects — not style nits. Two categories:

- "Security": injection (SQL/command/path), XSS, SSRF, hardcoded secrets/keys,
  weak crypto, missing authz/authn, unsafe deserialization, IDOR, open redirects,
  CSRF, sensitive data exposure, unsafe eval, ReDoS.
- "Logic": null/undefined deref, off-by-one, wrong operator, unhandled errors,
  race conditions, resource leaks, incorrect async/await, type confusion,
  bad edge-case handling, infinite loops, incorrect comparisons.

Rules:
- Report only defects you are reasonably confident are real. No false positives
  for the sake of volume. If a file is clean, return an empty findings array.
- Cite the exact 1-based line number (use 0 only for genuinely file-level issues).
- Severity reflects real-world impact: Critical = exploitable/data loss,
  High = serious bug, Medium = should fix, Low = minor.
- Each finding needs a concrete, actionable recommendation."""

USER_TEMPLATE = """File: {path}
Language: {lang}

Analyze this file for security vulnerabilities and logic bugs. Line numbers are
shown on the left as "N| ".

```
{numbered}
```"""

_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript (React)",
    ".ts": "TypeScript", ".tsx": "TypeScript (React)", ".go": "Go",
    ".rs": "Rust", ".java": "Java", ".rb": "Ruby", ".php": "PHP",
    ".cs": "C#", ".c": "C", ".cpp": "C++", ".sql": "SQL", ".sh": "Shell",
}


def _number(text: str) -> str:
    return "\n".join(f"{i}| {line}" for i, line in enumerate(text.splitlines(), 1))


async def analyze_file(cf: CollectedFile, categories: list[str]) -> list[Finding]:
    focus = (
        "Focus ONLY on security vulnerabilities."
        if categories == ["Security"]
        else "Focus ONLY on logic/correctness bugs."
        if categories == ["Logic"]
        else "Report both security and logic defects."
    )
    user_msg = USER_TEMPLATE.format(
        path=cf.rel,
        lang=_LANG.get(cf.path.suffix.lower(), cf.path.suffix.lstrip(".")),
        numbered=_number(cf.text),
    )
    text = await complete_findings(SYSTEM_PROMPT + "\n\n" + focus, user_msg)
    raw = json.loads(text)["findings"]
    return [Finding(file=cf.rel, **item) for item in raw]


def _build_result(
    findings: list[Finding], root: str, files_scanned: int, files_skipped: int
) -> ScanResult:
    """Sort findings and assemble the summary + result (shared by both paths)."""
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))

    by_sev = {s: 0 for s in ("Critical", "High", "Medium", "Low")}
    by_cat = {c: 0 for c in ("Security", "Logic")}
    for f in findings:
        by_sev[f.severity] += 1
        by_cat[f.category] += 1

    summary = ScanSummary(
        root=str(root),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        total_findings=len(findings),
        by_severity=by_sev,
        by_category=by_cat,
    )
    return ScanResult(summary=summary, findings=findings)


async def scan_path(
    root: str,
    categories: list[str] | None = None,
    max_files: int | None = None,
    progress=None,
) -> ScanResult:
    categories = categories or ["Security", "Logic"]
    files, skipped = collect_files(root, max_files)

    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    findings: list[Finding] = []
    done = 0

    async def run(cf: CollectedFile):
        nonlocal done
        async with sem:
            try:
                result = await analyze_file(cf, categories)
            except Exception as e:  # one bad file shouldn't kill the scan
                result = []
                if progress:
                    progress(cf.rel, None, error=str(e))
            findings.extend(result)
            done += 1
            if progress:
                progress(cf.rel, done, total=len(files), found=len(result))

    await asyncio.gather(*(run(cf) for cf in files))
    return _build_result(findings, root, len(files), skipped)


async def scan_stream(
    root: str,
    categories: list[str] | None = None,
    max_files: int | None = None,
    is_disconnected=None,
):
    """Async generator yielding scan events as they happen.

    Events (dicts): "meta" (once, up front), "finding" (per finding as it
    completes), "progress" (per file), and "done" (once, with the final summary).
    Files run concurrently under a semaphore; results are consumed via a queue so
    findings stream out the moment each file finishes. If ``is_disconnected()``
    becomes true, remaining work is cancelled — useful for a client "Stop".
    """
    categories = categories or ["Security", "Logic"]
    files, skipped = collect_files(root, max_files)
    yield {"type": "meta", "root": str(root), "total": len(files), "files_skipped": skipped}

    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    queue: asyncio.Queue = asyncio.Queue()

    async def run(cf: CollectedFile):
        async with sem:
            try:
                result = await analyze_file(cf, categories)
                await queue.put((cf.rel, result, None))
            except asyncio.CancelledError:
                raise
            except Exception as e:  # one bad file shouldn't kill the scan
                await queue.put((cf.rel, [], str(e)))

    tasks = [asyncio.create_task(run(cf)) for cf in files]
    findings: list[Finding] = []
    done = 0
    try:
        for _ in range(len(files)):
            rel, result, err = await queue.get()
            done += 1
            for f in result:
                findings.append(f)
                yield {"type": "finding", "finding": f.model_dump()}
            yield {
                "type": "progress",
                "done": done, "total": len(files),
                "file": rel, "found": len(result), "error": err,
            }
            if is_disconnected is not None and await is_disconnected():
                break
    finally:
        for t in tasks:
            t.cancel()

    result = _build_result(findings, root, len(files), skipped)
    yield {
        "type": "done",
        "summary": result.summary.model_dump(),
        "findings": [f.model_dump() for f in result.findings],
    }
