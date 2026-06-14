"""FastAPI backend for the Bug Hunter web dashboard."""
import json
import logging

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .analyzer import scan_path, scan_stream
from .hostscan import scan_host
from .netscan import scan_network
from .provider import PROVIDER, label
from .schemas import ScanResult
from .uploads import MAX_ZIP_BYTES, cleanup_upload, extract_zip
from .webscan import scan_web

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
    verify: bool = Field(default=False)


class WebScanRequest(BaseModel):
    url: str = Field(min_length=1)
    ai: bool = Field(default=False)
    cookie: str | None = Field(default=None)
    headers: dict[str, str] | None = Field(default=None)
    basic: str | None = Field(default=None)
    browser: str | None = Field(default=None)


class HostScanRequest(BaseModel):
    host: str = Field(min_length=1)
    ports: list[int] | None = Field(default=None)
    authorized: bool = Field(default=False)


class NetScanRequest(BaseModel):
    cidr: str = Field(min_length=1)
    authorized: bool = Field(default=False)
    quick: bool = Field(default=False)


@app.get("/health")
def health():
    return {"status": "ok", "provider": PROVIDER, "model": label()}


@app.post("/scan", response_model=ScanResult)
async def scan(body: ScanRequest):
    try:
        return await scan_path(body.path, _categories(body.mode), body.max_files, verify=body.verify)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/scan/upload", response_model=ScanResult)
async def scan_upload(
    file: UploadFile = File(...),
    mode: str = Query("all"),
    max_files: int | None = Query(80, ge=1, le=500),
    verify: bool = Query(False),
):
    """Scan an uploaded source-code .zip. Extracted to a temp dir, scanned, deleted."""
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip archive.")
    data = await file.read(MAX_ZIP_BYTES + 1)
    if len(data) > MAX_ZIP_BYTES:
        raise HTTPException(status_code=413, detail=f"Zip too large (> {MAX_ZIP_BYTES // 1024 // 1024} MB).")
    try:
        root, _ = extract_zip(data, file.filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        result = await scan_path(root, _categories(mode), max_files, verify=verify)
    except Exception as e:
        logger.exception("Upload scan failed")
        raise HTTPException(status_code=502, detail=str(e))
    finally:
        cleanup_upload(root)
    result.summary.root = file.filename  # friendly label instead of the temp path
    return result


@app.post("/web", response_model=ScanResult)
async def web(body: WebScanRequest):
    """Non-intrusive web security posture scan. Authorized targets only."""
    try:
        return await scan_web(
            body.url, ai=body.ai, headers=body.headers,
            cookie=body.cookie, basic=body.basic, browser=body.browser,
        )
    except Exception as e:
        logger.exception("Web scan failed")
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/net", response_model=ScanResult)
async def net(body: NetScanRequest):
    """Discover live hosts in a CIDR + OS guess. Public ranges require authorized=true."""
    try:
        return await scan_network(body.cidr, authorized=body.authorized, full_ports=not body.quick)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Net scan failed")
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/host", response_model=ScanResult)
async def host(body: HostScanRequest):
    """TCP port/service scan. Public targets require authorized=true."""
    try:
        return await scan_host(body.host, body.ports, authorized=body.authorized)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        logger.exception("Host scan failed")
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
