"""Safe handling of uploaded source archives (.zip) for scanning.

Extracts an uploaded zip into a managed temp directory with guards against
zip-slip (path traversal via crafted entry names) and zip bombs (entry count
and total uncompressed size). The extracted tree is scanned like any local
path, then deleted. Only paths under UPLOAD_ROOT are ever removed.
"""
import io
import os
import shutil
import tempfile
import uuid
import zipfile

UPLOAD_ROOT = os.path.join(tempfile.gettempdir(), "bughunter_uploads")
MAX_ZIP_BYTES = 60 * 1024 * 1024        # 60 MB compressed upload
MAX_UNCOMPRESSED = 400 * 1024 * 1024    # 400 MB total uncompressed (zip-bomb guard)
MAX_ENTRIES = 8000                      # too-many-files guard


def _is_within(base: str, target: str) -> bool:
    base, target = os.path.abspath(base), os.path.abspath(target)
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:  # different drives on Windows, etc.
        return False


def extract_zip(data: bytes, original_name: str = "upload.zip") -> tuple[str, int]:
    """Extract zip bytes into a fresh dir under UPLOAD_ROOT. Returns (dir, file_count)."""
    if len(data) > MAX_ZIP_BYTES:
        raise ValueError(f"Zip too large ({len(data) // 1024 // 1024} MB > {MAX_ZIP_BYTES // 1024 // 1024} MB).")
    os.makedirs(UPLOAD_ROOT, exist_ok=True)
    dest = os.path.join(UPLOAD_ROOT, uuid.uuid4().hex)
    os.makedirs(dest, exist_ok=True)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ValueError(f"Zip has too many entries ({len(infos)} > {MAX_ENTRIES}).")
            if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
                raise ValueError("Uncompressed contents exceed the size limit (possible zip bomb).")
            count = 0
            for info in infos:
                target = os.path.join(dest, info.filename)
                if not _is_within(dest, target):
                    raise ValueError(f"Unsafe path in zip (path traversal): {info.filename}")
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
                count += 1
    except zipfile.BadZipFile as e:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError("Not a valid .zip archive.") from e
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return dest, count


def is_managed_upload(path: str) -> bool:
    """True only for paths inside UPLOAD_ROOT (safe to delete)."""
    return _is_within(UPLOAD_ROOT, path) and os.path.abspath(path) != os.path.abspath(UPLOAD_ROOT)


def cleanup_upload(path: str) -> None:
    """Delete an extracted upload dir (no-op for any path outside UPLOAD_ROOT)."""
    if is_managed_upload(path):
        shutil.rmtree(path, ignore_errors=True)
