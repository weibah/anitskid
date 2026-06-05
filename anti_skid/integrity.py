# compares current file hashes against manifest.json
# if anything looks sus it reports back

import hashlib
import os
import time

from .manifest import load_manifest, MANIFEST_FILENAME

CHUNK_SIZE = 8192


def _hash_file(filepath: str) -> str:
    # sha256 a single file
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as e:
        return f"DEAD:{e}"


def _fix_path(p: str) -> str:
    # make sure slashes are forward for comparison
    return p.replace("\\", "/")


def verify_integrity(manifest_path: str = None, project_root: str = None) -> dict:
    # rehashes everything and compares to the baseline
    # returns a dict with all the info about whats broken
    t0 = time.perf_counter()

    # figure out paths
    if manifest_path is None:
        if project_root is None:
            project_root = os.getcwd()
        manifest_path = os.path.join(project_root, MANIFEST_FILENAME)

    manifest_path = os.path.abspath(manifest_path)

    if project_root is None:
        project_root = os.path.dirname(manifest_path)
    else:
        project_root = os.path.abspath(project_root)

    # load the baseline
    try:
        manifest = load_manifest(manifest_path)
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return {
            "passed": False,
            "elapsed_ms": elapsed,
            "total_files": 0,
            "matched": 0,
            "mismatches": [],
            "missing": [],
            "new_files": [],
            "error": f"couldnt load manifest: {e}",
        }

    baseline = manifest.get("files", {})
    mismatches = []
    missing = []
    matched = 0

    # check every file thats supposed to exist
    for rel_path, expected_hash in sorted(baseline.items()):
        abs_path = os.path.join(project_root, _fix_path(rel_path))

        if not os.path.isfile(abs_path):
            missing.append(_fix_path(rel_path))
            continue

        actual_hash = _hash_file(abs_path)

        if actual_hash != expected_hash:
            mismatches.append({
                "path": _fix_path(rel_path),
                "expected": expected_hash,
                "actual": actual_hash,
            })
        else:
            matched += 1

    # look for new files that arent in the manifest
    new_files = []
    extensions = tuple(manifest.get("extensions", (".py", ".pyw", ".pyc")))
    exclude_dirs = set(manifest.get("excluded_directories", ("__pycache__", ".git")))
    manifest_rel = _fix_path(os.path.relpath(manifest_path, project_root))

    for dirpath, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fname in filenames:
            if fname.endswith(extensions):
                abs_path = os.path.join(dirpath, fname)
                rel_path = _fix_path(os.path.relpath(abs_path, project_root))
                if rel_path == manifest_rel:
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