"""Resolve the project root and explicitly reused local caches; entry points keep outputs in the project build tree."""

import os
from pathlib import Path

# Owned source root, independent of the caller's working directory.
ROOT = Path(__file__).resolve().parents[1]
# Only an explicit override reuses another cache; build artifacts still belong to the project entry point.
CACHE = Path(os.environ.get("ASTRA_CACHE_ROOT", ROOT / "build")).expanduser().resolve()


def isolate(path: Path) -> None:
    """Keep cached Go sources outside parent-module discovery, preserving an existing regular marker."""
    path.mkdir(parents=True, exist_ok=True)
    marker = path / "go.mod"
    try:
        with marker.open("x", encoding="utf-8") as stream:
            stream.write("// Build caches are independent of the project's Go modules.\nmodule astra.local/build\n")
    except FileExistsError:
        if marker.is_symlink() or not marker.is_file():
            raise OSError(f"Cache module boundary is not a regular file: {marker}")
