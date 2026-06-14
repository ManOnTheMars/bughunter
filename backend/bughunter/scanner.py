"""Collect analysable source files from a local path."""
from pathlib import Path

# Extensions worth sending to the model.
SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".rb", ".php", ".cs",
    ".c", ".h", ".cpp", ".hpp", ".cc",
    ".swift", ".scala", ".sh", ".bash", ".sql",
    ".vue", ".svelte",
}

# Directories never worth scanning.
IGNORE_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "dist", "build", "out", ".next", ".nuxt", ".vite", "coverage",
    "vendor", "target", "bin", "obj", ".idea", ".vscode", "site-packages",
}

MAX_BYTES = 80_000   # skip very large files (cost / context)
MAX_LINES = 1500


class CollectedFile:
    __slots__ = ("path", "rel", "text", "lines")

    def __init__(self, path: Path, rel: str, text: str):
        self.path = path
        self.rel = rel
        self.text = text
        self.lines = text.count("\n") + 1


def collect_files(root: str, max_files: int | None = None) -> tuple[list[CollectedFile], int]:
    """Return (files_to_analyse, skipped_count). Raises if root is invalid."""
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    collected: list[CollectedFile] = []
    skipped = 0

    if root_path.is_file():
        candidates = [root_path]
        base = root_path.parent
    else:
        candidates = []
        base = root_path
        for p in sorted(root_path.rglob("*")):
            if p.is_dir():
                continue
            if any(part in IGNORE_DIRS for part in p.parts):
                continue
            candidates.append(p)

    for p in candidates:
        if p.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                skipped += 1
                continue
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            skipped += 1
            continue
        if not text.strip():
            continue
        if text.count("\n") + 1 > MAX_LINES:
            skipped += 1
            continue
        rel = str(p.relative_to(base)) if p != base else p.name
        collected.append(CollectedFile(p, rel, text))

    if max_files is not None:
        if len(collected) > max_files:
            skipped += len(collected) - max_files
            collected = collected[:max_files]

    return collected, skipped
