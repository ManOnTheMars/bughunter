# Bug Hunter

Claude-powered bug & security vulnerability hunter for local codebases. Point it at a
folder or file and Claude Opus reports **security vulnerabilities** (injection, XSS,
hardcoded secrets, weak crypto, missing authz…) and **logic bugs** (null deref, race
conditions, off-by-one, bad edge cases…) with severity, line numbers, and concrete fixes.

Two interfaces share one engine:
- **CLI** — fast, scriptable, CI/pre-commit friendly
- **Web dashboard** — React + FastAPI, findings grouped by severity

```
local folder ─▶ scanner (collect source files) ─▶ Claude Opus (structured JSON) ─▶ findings
```

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
copy .env.example .env      # then add your ANTHROPIC_API_KEY
```

### CLI

```bash
cd backend
python -m bughunter.cli scan ../some-project
python -m bughunter.cli scan ./app --security-only --max-files 30
python -m bughunter.cli scan ./src --json findings.json
```

Exit code is non-zero when any **Critical** or **High** finding exists — drop it into a
pre-commit hook or CI step.

### Web dashboard

```bash
# terminal 1 — backend
cd backend
python -m uvicorn bughunter.server:app --port 8000

# terminal 2 — frontend
cd frontend
npm install
npm run dev        # http://localhost:5173  (proxies /api -> :8000)
```

Enter a local path in the dashboard, pick a mode (All / Security / Logic), and scan.
Results **stream in live** (per-file progress bar + findings as they're found); a
**Stop** button cancels mid-scan and keeps partial results. Finished scans are kept
in a **history** row (client-side `localStorage`) so you can switch between them, and
findings can be filtered by severity. The header shows the active provider/model.

## How it works

- `bughunter/scanner.py` walks the path, collects source files (skips `node_modules`,
  `.git`, build dirs, binaries, files > 80 KB or > 1500 lines).
- `bughunter/analyzer.py` sends each file to `claude-opus-4-8` with **schema-enforced
  JSON output** (`output_config.format`) and adaptive thinking, over AsyncAnthropic
  streaming — so responses are always valid JSON. Files are analysed concurrently
  (`SCAN_CONCURRENCY`, default 5). `scan_stream` yields per-file events for the live UI.
- Findings are sorted by severity and aggregated into a summary.

## Notes

- Requires an Anthropic API key. Each file is one Opus request — use `--max-files` to
  bound cost on large repos.
- Analysis is per-file, so cross-file/architectural issues are out of scope for now.
