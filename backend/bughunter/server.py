"""FastAPI backend for the Bug Hunter web dashboard."""
import json
import logging

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .analyzer import scan_path, scan_stream
from .provider import PROVIDER, label
from .schemas import ScanResult

logger = logging.getLogger(__name__)

app = FastAPI(title="Bug Hunter API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _categories(mode: str) -> list[str]:
    return (
        ["Security"] if mode == "security"
        else ["Logic"] if mode == "logic"
        else ["Security", "Logic"]
    )


class ScanRequest(BaseModel):
    path: str = Field(min_length=1)
    mode: str = Field(default="all")  # all | security | logic
    max_files: int | None = Field(default=40, ge=1, le=500)


@app.get("/health")
def health():
    return {"status": "ok", "provider": PROVIDER, "model": label()}


@app.post("/scan", response_model=ScanResult)
async def scan(body: ScanRequest):
    try:
        return await scan_path(body.path, _categories(body.mode), body.max_files)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/scan/stream")
async def scan_stream_endpoint(
    request: Request,
    path: str = Query(min_length=1),
    mode: str = Query("all"),
    max_files: int | None = Query(40, ge=1, le=500),
):
    """Server-Sent Events: streams meta/finding/progress/done as the scan runs.

    Consumed by the UI via EventSource. Closing the connection (client "Stop")
    triggers request.is_disconnected(), which cancels remaining files.
    """
    async def events():
        try:
            async for ev in scan_stream(
                path, _categories(mode), max_files,
                is_disconnected=request.is_disconnected,
            ):
                yield f"event: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
        except FileNotFoundError as e:
            yield f"event: error\ndata: {json.dumps({'detail': str(e)})}\n\n"
        except Exception as e:
            logger.exception("Stream scan failed")
            yield f"event: error\ndata: {json.dumps({'detail': str(e)})}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
