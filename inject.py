# anti-skid injector
# takes a folder or a .py file and auto-installs anti-skid into it
# copies the module, injects the import, and generates manifest.json
# usage: python inject.py "C:\path\to\ur\project"
#      or just run it and itll ask u

import os
import sys
import shutil

# where anti-skid itself lives (the package folder)
_OUR_DIR = os.path.dirname(os.path.abspath(__file__))
_ANTI_SKID_SRC = os.path.join(_OUR_DIR, "anti_skid")


def _find_py_files(target_dir: str) -> list:
    # finds all .py and .pyw files in a folder (top level only, not subdirs)
    py_files = []
    try:
        for f in os.listdir(target_dir):
            full = os.path.join(target_dir, f)
            if os.path.isfile(full) and f.lower().endswith((".py", ".pyw")):
                py_files.append(full)
    except:
        pass
    return py_files


def _find_main_file(target_dir: str) -> str:
    # tries to figure out which file is the entry point
    # priority: main.py > app.py > __init__.py > first .py file > first .pyw file

    candidates = [
        os.path.join(target_dir, "main.py"),
        os.path.join(target_dir, "main.pyw"),
        os.path.join(target_dir, "app.py"),
        os.path.join(target_dir, "app.pyw"),
        os.path.join(target_dir, "__init__.py"),
    ]

    for c in candidates:
        if os.path.isfile(c):
            return c

    # fallback: first .py or .pyw file in the directory
    py_files = _find_py_files(target_dir)
    if py_files:
        return py_files[0]

    return None


def _inject_import(filepath: str) -> bool:
    # slaps "import anti_skid" at the top of a .py file if its not already there
    if not os.path.isfile(filepath):
        return False

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    # dont double inject
    if "import anti_skid" in content:
        print(f"  [skip] already has import in {os.path.basename(filepath)}")
        return False

    # insert at the very top, before anything else
    # but after shebang if there is one
    lines = content.splitlines(True) if content else []
    new_lines = []

    inserted = False
    for i, line in enumerate(lines):
        # keep shebangs and encoding declarations at the very top
        if not inserted:
            stripped = line.strip()
            if stripped.startswith("#!") or stripped.startswith("# -*-") or stripped.startswith("# coding"):
                new_lines.append(line)
                continue
            # insert our import right here
            new_lines.append("import anti_skid\n")
            inserted = True
        new_lines.append(line)

    # if the file was empty or only had shebangs
    if not inserted:
        new_lines.append("import anti_skid\n")

    with open(filepath, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    return True


def _copy_anti_skid(target_dir: str) -> str:
    # copies the anti_skid folder into the target project
    dest = os.path.join(target_dir, "anti_skid")

    # remove old one if it exists
    if os.path.exists(dest):
        print(f"  [warn] anti_skid already exists in target, removing...")
        shutil.rmtree(dest, ignore_errors=True)

    shutil.copytree(_ANTI_SKID_SRC, dest)
    print(f"  [ok] copied anti_skid to {dest}")
    return dest


def _generate_manifest_in(target_dir: str):
    # generates manifest.json for the target project
    import subprocess

    env = os.environ.copy()
    env["ANTI_SKID_DISABLE"] = "1"

    code = f"""
import sys
sys.path.insert(0, {repr(target_dir)})
import os
os.chdir({repr(target_dir)})
from anti_skid.manifest import generate_manifest
generate_manifest({repr(target_dir)})
"""
    try:
        r = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=30,
            env=env, cwd=target_dir
        )
        if r.stdout:
            print(f"  {r.stdout.strip()}")
        if r.stderr and "disabled" not in r.stderr.lower():
            print(f"  [warn] {r.stderr.strip()}")
        return r.returncode == 0
    except Exception as e:
        print(f"  [err] manifest generation failed: {e}")
        return False


def inject(target_path: str) -> bool:
    # main function: does the whole injection process

    # figure out if its a file or directory
    if os.path.isfile(target_path):
        target_dir = os.path.dirname(os.path.abspath(target_path))
        main_file = os.path.abspath(target_path)
    elif os.path.isdir(target_path):
        target_dir = os.path.abspath(target_path)
        main_file = _find_main_file(target_dir)
    else:
        print(f"[err] not a file or directory: {target_path}")
        return False

    print(f"\n--- anti-skid injector ---")
    print(f"target: {target_dir}")

    # step 1: copy the module
    print(f"\n[1] copying anti_skid module...")
    _copy_anti_skid(target_dir)

    # step 2: inject import into main file
    print(f"\n[2] injecting import...")
    if main_file:
        injected = _inject_import(main_file)
        if injected:
            print(f"  [ok] injected 'import anti_skid' into {os.path.basename(main_file)}")
    else:
        print(f"  [warn] no .py file found to inject into. u gotta add 'import anti_skid' manually")

    # also inject into init.py if it exists and isnt the main file
    init_py = os.path.join(target_dir, "__init__.py")
    if os.path.isfile(init_py) and init_py != main_file:
        _inject_import(init_py)

    # step 3: generate manifest
    print(f"\n[3] generating manifest.json...")
    _generate_manifest_in(target_dir)

    # step 4: inform
    manifest_path = os.path.join(target_dir, "manifest.json")
    print(f"\n--- done ---")
    print(f"anti-skid is now injected into: {target_dir}")
    print(f"manifest: {manifest_path}")
    print(f"\nmake sure to set ur webhook if u want breach alerts:")
    print(f"  set ANTI_SKID_WEBHOOK=https://discord.com/api/webhooks/...")
    print(f"")

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = input("path to project or .py file: ").strip().strip('"')

    if not path:
        print("bro u gotta give me a path")
        sys.exit(1)

    if not os.path.exists(path):
        print(f"that dont exist: {path}")
        sys.exit(1)

    ok = inject(path)
    sys.exit(0 if ok else 1)