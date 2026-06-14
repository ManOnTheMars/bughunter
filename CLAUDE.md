# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Bug Hunter — Claude-powered scanner that finds security vulnerabilities and logic bugs
in local codebases. CLI + web dashboard over a shared analysis engine.

## Architecture

```
backend/bughunter/
  scanner.py    # collect source files from a local path (ignores, size limits)
  analyzer.py   # per-file analysis → structured Finding[] (concurrent)
  provider.py   # LLM backend switch: Anthropic (cloud) | Ollama (local)
  schemas.py    # Finding/ScanResult models + the JSON schema the model is bound to
  cli.py        # `python -m bughunter.cli scan <path>` — colored terminal report
  server.py     # FastAPI: POST /scan -> ScanResult
frontend/       # React + Vite + Tailwind dashboard (proxies /api -> :8000)
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
