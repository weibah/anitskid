# hashes ur whole project and makes manifest.json
# that file is the "gold standard" baseline or whatever

import hashlib
import json
import os

MANIFEST_FILENAME = "manifest.json"
CHUNK_SIZE = 8192


def _hash_file(filepath: str) -> str:
    # sha256 go brr
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


def _grab_files(root_dir: str, exts: tuple, skip_dirs: tuple) -> dict:
    # walks the project, grabs files matching exts, skips annoying dirs
    stuff = {}
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # don't go into skipped dirs
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        for fname in filenames:
            if fname.endswith(exts):
                abs_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(abs_path, root_dir).replace(os.sep, "/")
                stuff[rel_path] = abs_path
    return stuff


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
    # runs through the project and makes manifest.json
    if output_path is None:
        output_path = os.path.join(root_dir, MANIFEST_FILENAME)

    files = _grab_files(root_dir, extensions, exclude_dirs)

    manifest = {
        "version": "1.0.0",
        "generated_by": "anti_skid",
        "root": os.path.abspath(root_dir).replace(os.sep, "/"),
        "extensions": list(extensions),
        "excluded_directories": list(exclude_dirs),
        "files": {},
    }

    for rel_path, abs_path in sorted(files.items()):
        manifest["files"][rel_path] = _hash_file(abs_path)

    # dont hash the manifest itself dumbass
    manifest_rel = os.path.relpath(output_path, root_dir).replace(os.sep, "/")
    manifest["files"].pop(manifest_rel, None)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[anti-skid] manifest made -> {output_path} ({len(manifest['files'])} files)")
    return os.path.abspath(output_path)


def load_manifest(manifest_path: str) -> dict:
    # loads manifest.json into a dict
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"no manifest at {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    needed = {"version", "root", "files"}
    missing = needed - set(manifest.keys())
    if missing:
        raise ValueError(f"manifest is cooked, missing: {missing}")

    return manifest