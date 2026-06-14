# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Bug Hunter — Claude-powered scanner that finds security vulnerabilities and logic bugs
in local codebases. CLI + web dashboard over a shared analysis engine.

## Architecture

```
backend/bughunter/
  scanner.py    # collect source files from a local path (ignores, size limits)
  analyzer.py   # scan_path (one-shot ScanResult) + scan_stream (async event generator);
                #   per-file analysis → Finding[], concurrent (SCAN_CONCURRENCY, default 5);
                #   optional verify pass drops false positives (SCAN_VERIFY / verify=True)
  webscan.py    # non-intrusive web posture scan (headers/cookies/TLS/info) → Finding[];
                #   rule-based + optional LLM enrichment; optional authenticated scan
                #   (cookie/header/basic, or browser= to reuse a local browser session
                #   via browser_cookie3). NO attack payloads.
  hostscan.py   # TCP connect port/service scan → Finding[]; authorization gate
                #   (private/loopback only unless authorized=True). NO exploitation.
  netscan.py    # CIDR host discovery + port scan + OS guess (banner + ping TTL
                #   heuristic, no raw sockets/admin) → Finding[]; same auth gate.
  uploads.py    # safe .zip extraction for POST /scan/upload — zip-slip + zip-bomb
                #   guards, size/entry caps; only deletes paths under UPLOAD_ROOT.
  provider.py   # LLM backend switch: Anthropic (cloud) | Ollama (local)
  schemas.py    # Finding/ScanResult models + the JSON schema the model is bound to
  cli.py        # `python -m bughunter.cli {scan|web|host} <target>` — colored report
  server.py     # FastAPI: POST /scan, GET /scan/stream (SSE), POST /scan/upload (.zip),
                #   POST /web, POST /host, POST /net, GET /health
frontend/       # React + Vite + Tailwind dashboard (proxies /api -> :8000)
                #   Code/Web/Host/Network scan tabs (+ .zip upload), live progress,
                #   severity filter, history tab (type filter + scan diff)
```

## Providers (provider.py)

The analysis backend is chosen by the `PROVIDER` env var. Both paths return a
JSON string constrained to `FINDINGS_SCHEMA`, so `analyzer.py` never parses
markdown fences or repairs JSON.

- `PROVIDER=anthropic` (cloud) — `claude-opus-4-8`, adaptive thinking
  (`thinking={"type":"adaptive"}`), structured output via
  `output_config={"format":{"type":"json_schema","schema": FINDINGS_SCHEMA}}`,
  `AsyncAnthropic` + `messages.stream(...).get_final_message()`. Needs `ANTHROPIC_API_KEY`.
- `PROVIDER=ollama` (local, free) — POST to `OLLAMA_HOST/api/chat` with the same
  schema passed as Ollama's `format` (grammar-constrained decoding → valid JSON).
  Default model `qwen2.5-coder:14b`. No API key; requires `ollama serve` + the model pulled.

Do not regress: schema objects use `additionalProperties:false` + explicit `required`;
the Anthropic client is **lazy** (only instantiated when PROVIDER=anthropic) so the
server/CLI import cleanly in Ollama mode without a key. One file = one request;
concurrency bounded by a semaphore in `analyzer.py`.

Safety (web/host/net scans are dual-use — keep these guarantees):
- `webscan.py` is **non-intrusive**: it only reads what a normal HTTP GET returns
  (headers/cookies/TLS/body), including in authenticated mode (it just sends the
  supplied cookie/header/credentials like a browser). No payloads, fuzzing,
  brute-force, or exploitation.
- `hostscan.py` / `netscan.py` do standard TCP **connect** scans only (plus the
  system `ping` for TTL in netscan — no raw sockets, no admin, no exploitation).
  The authorization gate (`_is_private` / `authorized=True`) must stay on both:
  public targets require explicit acknowledgement. CLI surfaces it as
  `--authorized`; API as `authorized:true` (403 otherwise). netscan also caps the
  sweep at MAX_HOSTS. Do not weaken these into auto-allow.

## Stack

| Layer | Tech |
|-------|------|
| Backend | Python, FastAPI, anthropic, pydantic |
| Frontend | React, Vite, Tailwind, lucide-react |

## UI

Dark mode, Inter (UI) + JetBrains Mono (paths/numbers). Severity palette:
Critical = rose, High = orange, Medium = amber, Low = sky. Keep findings keyed by the
exact English severity/category strings (the UI styles by them).

## Dev

```bash
# CLI
cd backend && python -m bughunter.cli scan <path>
# Server
cd backend && python -m uvicorn bughunter.server:app --port 8000
# Frontend
cd frontend && npm install && npm run dev
```
