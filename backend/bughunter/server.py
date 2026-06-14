"""FastAPI backend for the Bug Hunter web dashboard."""
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .analyzer import scan_path
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


class ScanRequest(BaseModel):
    path: str = Field(min_length=1)
    mode: str = Field(default="all")  # all | security | logic
    max_files: int | None = Field(default=40, ge=1, le=500)


@app.get("/health")
def health():
    return {"status": "ok", "provider": PROVIDER, "model": label()}


@app.post("/scan", response_model=ScanResult)
async def scan(body: ScanRequest):
    categories = (
        ["Security"] if body.mode == "security"
        else ["Logic"] if body.mode == "logic"
        else ["Security", "Logic"]
    )
    try:
        return await scan_path(body.path, categories, body.max_files)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(status_code=502, detail=str(e))
