"""
Anti-Skid :: Integrity Engine
Performs the pre-flight hash audit, comparing current file state against
the gold-standard manifest.
"""

import hashlib
import json
import os
import sys
import time
from typing import Tuple, List, Dict

from .manifest import load_manifest, MANIFEST_FILENAME

CHUNK_SIZE = 8192

# ---------------------------------------------------------------------------
# Audit result data-class (lightweight tuple-based)
# ---------------------------------------------------------------------------

AuditResult = Dict
"""
An audit result is a dict:
{
    "passed": bool,
    "elapsed_ms": float,
    "total_files": int,
    "matched": int,
    "mismatches": [
        {"path": str, "expected": str, "actual": str},
        ...
    ],
    "missing": [str, ...],
    "new_files": [str, ...],
    "error": str | None,
}
"""

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _hash_file(filepath: str) -> str:
    """SHA-256 of a single file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError) as exc:
        return f"ERROR:{exc}"


def _normalise_path(p: str) -> str:
    """Normalise path separators to forward-slash for comparison."""
    return p.replace("\\", "/")


def verify_integrity(
    manifest_path: str = None,
    project_root: str = None,
) -> AuditResult:
    """
    Re-hash every file enumerated in the manifest and compare digests.

    Parameters
    ----------
    manifest_path : str or None
        Path to manifest.json.  If None, looks for MANIFEST_FILENAME in
        *project_root* (or cwd if *project_root* is also None).
    project_root : str or None
        Root directory of the project.  Defaults to the directory
        containing the manifest.

    Returns
    -------
    AuditResult
    """
    t0 = time.perf_counter()

    # --- Resolve manifest ---------------------------------------------------
    if manifest_path is None:
        if project_root is None:
            project_root = os.getcwd()
        manifest_path = os.path.join(project_root, MANIFEST_FILENAME)

    manifest_path = os.path.abspath(manifest_path)

    if project_root is None:
        project_root = os.path.dirname(manifest_path)
    else:
        project_root = os.path.abspath(project_root)

    # --- Load baseline ------------------------------------------------------
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "passed": False,
            "elapsed_ms": elapsed,
            "total_files": 0,
            "matched": 0,
            "mismatches": [],
            "missing": [],
            "new_files": [],
            "error": f"Manifest load failed: {exc}",
        }

    baseline: Dict[str, str] = manifest.get("files", {})
    mismatches: List[dict] = []
    missing: List[str] = []
    matched = 0

    # --- Check every file in the baseline -----------------------------------
    for rel_path, expected_hash in sorted(baseline.items()):
        abs_path = os.path.join(project_root, _normalise_path(rel_path))

        if not os.path.isfile(abs_path):
            missing.append(_normalise_path(rel_path))
            continue

        actual_hash = _hash_file(abs_path)

        if actual_hash != expected_hash:
            mismatches.append({
                "path": _normalise_path(rel_path),
                "expected": expected_hash,
                "actual": actual_hash,
            })
        else:
            matched += 1

    # --- Scan for new files not in the baseline -----------------------------
    new_files: List[str] = []
    extensions = tuple(manifest.get("extensions", (".py", ".pyw", ".pyc")))
    exclude_dirs = set(manifest.get("excluded_directories", ("__pycache__", ".git")))
    # Also skip the manifest itself
    manifest_file_rel = os.path.relpath(manifest_path, project_root)
    manifest_file_rel = _normalise_path(manifest_file_rel)

    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            if fname.endswith(extensions):
                abs_path = os.path.join(dirpath, fname)
                rel_path = _normalise_path(os.path.relpath(abs_path, project_root))
                if rel_path == manifest_file_rel:
                    continue
                if rel_path not in baseline:
                    new_files.append(rel_path)

    total = len(baseline)
    passed = len(mismatches) == 0 and len(missing) == 0
    elapsed = (time.perf_counter() - t0) * 1000

    return {
        "passed": passed,
        "elapsed_ms": round(elapsed, 2),
        "total_files": total,
        "matched": matched,
        "mismatches": mismatches,
        "missing": missing,
        "new_files": new_files,
        "error": None,
    }