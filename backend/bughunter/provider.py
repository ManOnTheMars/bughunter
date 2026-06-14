"""LLM provider abstraction: Anthropic (cloud) or Ollama (local).

Selected via the PROVIDER env var (default "anthropic"). Both paths return a
JSON *string* constrained to FINDINGS_SCHEMA, so analyzer.py never has to parse
markdown fences or repair JSON regardless of which backend is active.

  PROVIDER=anthropic   ANTHROPIC_API_KEY=sk-ant-...   [ANTHROPIC_MODEL=...]
  PROVIDER=ollama      [OLLAMA_HOST=http://localhost:11434] [OLLAMA_MODEL=...]
"""
import os

import httpx
from dotenv import load_dotenv

from .schemas import FINDINGS_SCHEMA

load_dotenv()

PROVIDER = os.getenv("PROVIDER", "anthropic").lower()

# --- Anthropic (cloud) ---
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8")

# --- Ollama (local) ---
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")
# Context window for the local model. Source files are capped at ~80KB / 1500
# lines by the scanner, so 16K tokens comfortably holds file + prompt + output.
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "16384"))

_anthropic_client = None


def label() -> str:
    """Human-readable name of the active model (for logs / health)."""
    return f"ollama:{OLLAMA_MODEL}" if PROVIDER == "ollama" else ANTHROPIC_MODEL


def _get_anthropic():
    global _anthropic_client
    if _anthropic_client is None:
        import anthropic

        key = os.getenv("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Add it to backend/.env, or set "
                "PROVIDER=ollama to use a local model."
            )
        _anthropic_client = anthropic.AsyncAnthropic(api_key=key)
    return _anthropic_client


async def complete_findings(system: str, user: str) -> str:
    """Return a JSON string matching FINDINGS_SCHEMA from the active provider."""
    if PROVIDER == "ollama":
        return await _complete_ollama(system, user)
    return await _complete_anthropic(system, user)


async def _complete_anthropic(system: str, user: str) -> str:
    client = _get_anthropic()
    async with client.messages.stream(
        model=ANTHROPIC_MODEL,
        max_tokens=4096,
        thinking={"type": "adaptive"},
        system=system,
        messages=[{"role": "user", "content": user}],
        output_config={"format": {"type": "json_schema", "schema": FINDINGS_SCHEMA}},
    ) as stream:
        message = await stream.get_final_message()
    return next(b.text for b in message.content if b.type == "text")


async def _complete_ollama(system: str, user: str) -> str:
    """Ollama native /api/chat with schema-constrained `format` → JSON string.

    Ollama applies grammar-constrained decoding from the JSON schema, so the
    returned content is always valid JSON matching FINDINGS_SCHEMA.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "format": FINDINGS_SCHEMA,
        "options": {"temperature": 0, "num_ctx": OLLAMA_NUM_CTX},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    async with httpx.AsyncClient(timeout=httpx.Timeout(600.0)) as http:
        try:
            resp = await http.post(f"{OLLAMA_HOST}/api/chat", json=payload)
        except httpx.ConnectError as e:
            raise RuntimeError(
                f"Cannot reach Ollama at {OLLAMA_HOST}. Is it running "
                f"(`ollama serve`) and is the model pulled (`ollama pull {OLLAMA_MODEL}`)?"
            ) from e
        if resp.status_code == 404:
            raise RuntimeError(
                f"Ollama model '{OLLAMA_MODEL}' not found. Pull it with: "
                f"ollama pull {OLLAMA_MODEL}"
            )
        resp.raise_for_status()
        data = resp.json()
    return data["message"]["content"]
