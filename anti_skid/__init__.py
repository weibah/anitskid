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

_started = False
_lock = threading.Lock()

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

    # find manifest.json
    manifest_path = os.environ.get("ANTI_SKID_MANIFEST")
    if not manifest_path:
        # try to find it relative to whoever imported us
        try:
            import inspect
            frame = inspect.currentframe()
            outer = frame.f_back.f_back if frame and frame.f_back else None
            if outer and outer.f_globals.get("__file__"):
                root = os.path.dirname(os.path.abspath(outer.f_globals["__file__"]))
            else:
                root = os.getcwd()
        except:
            root = os.getcwd()
        manifest_path = os.path.join(root, "manifest.json")

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