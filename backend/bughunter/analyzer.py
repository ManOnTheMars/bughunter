"""Send source files to an LLM and collect structured bug findings.

Uses schema-enforced JSON so no markdown-fence parsing or retry-on-bad-JSON is
ever needed. The actual model — Anthropic Claude (cloud) or Ollama (local) — is
selected by the PROVIDER env var; see provider.py.
"""
import asyncio
import json

from .provider import complete_findings
from .schemas import Finding, ScanResult, ScanSummary, SEVERITY_ORDER
from .scanner import collect_files, CollectedFile

MAX_CONCURRENCY = 5

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

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))

    by_sev = {s: 0 for s in ("Critical", "High", "Medium", "Low")}
    by_cat = {c: 0 for c in ("Security", "Logic")}
    for f in findings:
        by_sev[f.severity] += 1
        by_cat[f.category] += 1

    summary = ScanSummary(
        root=str(root),
        files_scanned=len(files),
        files_skipped=skipped,
        total_findings=len(findings),
        by_severity=by_sev,
        by_category=by_cat,
    )
    return ScanResult(summary=summary, findings=findings)
