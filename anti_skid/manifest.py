"""
Anti-Skid :: Manifest Generator & Loader
Handles creation of the cryptographic baseline (manifest.json) and loading it.
"""

import hashlib
import json
import os
import sys

MANIFEST_FILENAME = "manifest.json"
CHUNK_SIZE = 8192


def _sha256_of_file(filepath: str) -> str:
    """Return the SHA-256 hex digest of *filepath*."""
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


def _collect_files(root_dir: str, extensions: tuple, exclude_dirs: tuple) -> dict:
    """
    Walk *root_dir*, collecting relative file paths that match *extensions*
    and are not inside any directory listed in *exclude_dirs*.
    Returns {relative_path: absolute_path}.
    """
    files_map = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Remove excluded directories in-place so os.walk doesn't descend
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

        for fname in filenames:
            if fname.endswith(extensions):
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root_dir)
                # Use forward slashes for cross-platform manifest consistency
                rel_path = rel_path.replace(os.sep, "/")
                files_map[rel_path] = abs_path
    return files_map


def generate_manifest(
    root_dir: str,
    output_path: str = None,
    extensions: tuple = (".py", ".pyw", ".pyc", ".pyd", ".so", ".dll"),
    exclude_dirs: tuple = (
        "__pycache__", ".git", ".svn", ".hg",
        "node_modules", "venv", ".venv", "env",
        "build", "dist", ".tox", ".eggs", "*.egg-info",
    ),
) -> str:
    """
    Walk *root_dir*, hash every qualifying file, and write a manifest.json.

    Parameters
    ----------
    root_dir : str
        The project root to protect.
    output_path : str or None
        Where to write the manifest.  Defaults to *root_dir*/manifest.json.
    extensions : tuple
        File extensions to include in the integrity baseline.
    exclude_dirs : tuple
        Directory names to skip entirely.

    Returns
    -------
    str : absolute path to the written manifest.
    """
    if output_path is None:
        output_path = os.path.join(root_dir, MANIFEST_FILENAME)

    files_map = _collect_files(root_dir, extensions, exclude_dirs)

    manifest = {
        "version": "1.0.0",
        "generated_by": "anti_skid",
        "root": os.path.abspath(root_dir).replace(os.sep, "/"),
        "extensions": list(extensions),
        "excluded_directories": list(exclude_dirs),
        "files": {},
    }

    for rel_path, abs_path in sorted(files_map.items()):
        manifest["files"][rel_path] = _sha256_of_file(abs_path)

    # Exclude the manifest itself from the file list (avoid infinite recursion)
    manifest_rel = os.path.relpath(output_path, root_dir).replace(os.sep, "/")
    manifest["files"].pop(manifest_rel, None)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    print(f"[Anti-Skid] Manifest generated → {output_path}  "
          f"({len(manifest['files'])} files)")
    return os.path.abspath(output_path)


def load_manifest(manifest_path: str) -> dict:
    """Load and return a manifest dict from *manifest_path*."""
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)

    required = {"version", "root", "files"}
    missing = required - set(manifest.keys())
    if missing:
        raise ValueError(f"Manifest is missing required keys: {missing}")

    return manifest