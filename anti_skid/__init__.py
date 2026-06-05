# just import this at the top of ur main file and it does the rest
# if some skid touched ur code it nukes the process and dms u lmao
# 
# env vars:
#   ANTI_SKID_WEBHOOK  -> ur discord webhook link
#   ANTI_SKID_MANIFEST -> path to manifest.json if its not in the project root
#   ANTI_SKID_DISABLE  -> set to 1 to skip the check (why would u do this)

import os
import sys
import threading

_MANIFEST_FILE = "manifest.json"
_started = False
_lock = threading.Lock()


def _find_manifest() -> str:
    """find manifest.json by checking multiple places"""

    # 1) explicit env var
    env_path = os.environ.get("ANTI_SKID_MANIFEST")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2) walk UP from cwd looking for manifest.json
    cwd = os.getcwd()
    for _ in range(10):
        candidate = os.path.join(cwd, _MANIFEST_FILE)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(cwd)
        if parent == cwd:  # hit root
            break
        cwd = parent

    # 3) check relative to the location of THIS file (the anti_skid package dir)
    our_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(our_dir, _MANIFEST_FILE)
    if os.path.isfile(candidate):
        return candidate

    # 4) walk DOWN from the anti_skid package dir (it might be one dir above)
    parent_of_us = os.path.dirname(our_dir)
    candidate = os.path.join(parent_of_us, _MANIFEST_FILE)
    if os.path.isfile(candidate):
        return candidate

    # 5) walk UP from the anti_skid dir
    search = parent_of_us
    for _ in range(5):
        candidate = os.path.join(search, _MANIFEST_FILE)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(search)
        if parent == search:
            break
        search = parent

    # 6) this is where the calling script wants us to look, even if it doesnt exist yet
    #    (manifest generation will create it later)
    #    use whatever we found from the frame, falling back to cwd
    try:
        import inspect
        frame = inspect.currentframe()
        # walk up past our own frames looking for the first non-anti_skid caller
        f = frame.f_back if frame else None
        while f:
            mod = f.f_globals.get("__name__", "")
            fname = f.f_globals.get("__file__", "")
            # skip frames from inside the anti_skid package or stdlib
            if "anti_skid" not in fname and "importlib" not in fname:
                if fname:
                    root = os.path.dirname(os.path.abspath(fname))
                    candidate = os.path.join(root, _MANIFEST_FILE)
                    # return the path even if it doesnt exist - the caller might be
                    # generating the manifest for the first time
                    return candidate
            f = f.f_back
    except:
        pass

    # 7) ultimate fallback: cwd
    return os.path.join(os.getcwd(), _MANIFEST_FILE)


def _do_check():
    global _started

    with _lock:
        if _started:
            return
        _started = True

    # skip if disabled (debug only fr)
    if os.environ.get("ANTI_SKID_DISABLE") == "1":
        print("[anti-skid] disabled lol")
        return

    from .integrity import verify_integrity
    from .telemetry import report_breach

    manifest_path = _find_manifest()

    # run it
    audit = verify_integrity(manifest_path=manifest_path)

    if audit.get("error"):
        print(f"[anti-skid] audit broke: {audit['error']}", file=sys.stderr)
        sys.exit(1)

    if audit["passed"]:
        print(f"[anti-skid] clean {audit['matched']}/{audit['total_files']} files ({audit['elapsed_ms']:.1f}ms)")
        return

    # someone touched ur shit
    print(f"[anti-skid] BREACH DETECTED !!\n"
          f"  mismatches: {len(audit['mismatches'])}\n"
          f"  missing: {len(audit['missing'])}\n"
          f"  new files: {len(audit['new_files'])}",
          file=sys.stderr)

    webhook = os.environ.get("ANTI_SKID_WEBHOOK")
    report_breach(webhook, audit)

    print("[anti-skid] killing process cuz ur code got skidded", file=sys.stderr)
    sys.exit(1)

# run on import
_do_check()
