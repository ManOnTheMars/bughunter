# Design: Live progress, scan history & UI polish

Date: 2026-06-14
Status: Approved

## Goal

Add (as enhancements, not rewrites) to BugHunter:
1. **Live progress** — stream per-file progress and findings to the UI during a
   scan instead of blocking until the whole scan completes.
2. **Concurrency control** — make scan concurrency configurable.
3. **Multiple scans** — keep recent scans in the UI and switch between them.
4. **UI polish** — progress bar, severity filtering, animations, accurate model label.

## Key constraint (honesty)

With a single local Ollama model on one GPU, concurrent requests are serialized
by Ollama — raising concurrency does NOT give linear speedup locally (and may
OOM). Real concurrency benefit is for cloud Anthropic. The biggest local UX win
is **live progress**, so the long scan feels responsive. Concurrency is exposed
as config, with a documented default and an `OLLAMA_NUM_PARALLEL` note.

## Backend

### `analyzer.py`
- Extract `_build_result(findings, root, files_scanned, files_skipped) -> ScanResult`
  and reuse it in `scan_path` (no behavior change).
- `MAX_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))`.
- New async generator `scan_stream(root, categories, max_files, is_disconnected=None)`
  yielding dict events:
  - `{"type":"meta","root","total","files_skipped"}`
  - `{"type":"finding","finding":{...}}` (per finding, as it completes)
  - `{"type":"progress","done","total","file","found","error"}` (per file)
  - `{"type":"done","summary":{...},"findings":[...]}`
  Files run under a semaphore; results consumed via an `asyncio.Queue`. If
  `is_disconnected()` returns true, cancel remaining tasks and stop.
- `scan_path` (sync-return) kept unchanged for the CLI and `POST /scan`.

### `server.py`
- New `GET /scan/stream` (query params `path`, `mode`, `max_files`) returning a
  `StreamingResponse(media_type="text/event-stream")`. Each event serialized as
  `event: <type>\ndata: <json>\n\n`. Passes `request.is_disconnected` for cancel.
  Errors emitted as an `error` event. Headers: `Cache-Control: no-cache`,
  `X-Accel-Buffering: no`.
- `POST /scan` and `GET /health` unchanged.

## Frontend (`App.jsx`, `index.css`)

- Scan via `EventSource('/api/scan/stream?' + URLSearchParams)`. Named-event
  listeners (`meta`/`finding`/`progress`/`done`/`error`) update state live:
  progress bar (done/total %), current file, live-updating stat cards, and
  findings appended as they arrive.
- **Stop** button closes the EventSource (and the backend detects disconnect).
- **Scan history**: persist finished scans to `localStorage` (`bughunter.scans`,
  cap ~20) as `{id, path, mode, ts, result}`. A tab/dropdown row switches between
  past scans (read-only view) and a "new scan" slot.
- **Severity filter chips** on the results list (All / Critical / High / Medium / Low).
- **Model label**: fetch `/api/health` on mount; header + loading text show the
  real provider/model (e.g. `Ollama · qwen2.5-coder:14b` or `Claude Opus`) instead
  of the hardcoded "Claude Opus".
- Polish: progress-bar component, fade/slide on new findings, hover/spacing tidy.
  Reuse existing tokens (`card`, `input`, `btn-primary`, `num`, severity colors).

## Out of scope (YAGNI)
- No backend persistence/DB for history (client `localStorage` only).
- No auth/users. No WebSocket. No backend job registry.

## Config (`.env` / `.env.example`)
- `SCAN_CONCURRENCY=5` (new).
- Note: for faster local parallelism set Ollama's `OLLAMA_NUM_PARALLEL` (server-side),
  but VRAM-bound; keep concurrency modest locally.
