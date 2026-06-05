"""
Anti-Skid :: High-Security Integrity Framework
================================================

Import this module at the top of your project's entry point to enable
automatic pre-flight integrity verification.

Usage::

    # In your main.py or __init__.py
    import anti_skid  # noqa: F401  <- triggers the pre-flight check

    # Your application logic starts below...
    def main():
        ...

Environment Variables
---------------------
ANTI_SKID_WEBHOOK : str
    Discord webhook URL for breach telemetry delivery.
ANTI_SKID_MANIFEST : str
    Path to manifest.json (default: <project_root>/manifest.json).
ANTI_SKID_DISABLE : str
    Set to '1' to bypass the integrity check (USE WITH CAUTION).
"""

import os
import sys
import threading

# ---------------------------------------------------------------------------
# Deferred imports so the package can always be imported (even partially)
# ---------------------------------------------------------------------------

_initialised = False
_lock = threading.Lock()


def _preflight() -> None:
    """
    Run the integrity verification as a mandatory pre-flight check.
    On failure, fires telemetry and terminates the process.
    """
    global _initialised

    with _lock:
        if _initialised:
            return
        _initialised = True

    # --- Honour disable flag (debugging / development only) -----------------
    if os.environ.get("ANTI_SKID_DISABLE") == "1":
        print("[Anti-Skid] DISABLED via ANTI_SKID_DISABLE env var.")
        return

    # Lazily import internal modules (keeps __init__.py light) ---------------
    from .integrity import verify_integrity
    from .telemetry import report_breach

    # Resolve manifest path
    manifest_path = os.environ.get("ANTI_SKID_MANIFEST")
    if not manifest_path:
        # Walk up from the calling frame's file location to find manifest.json
        try:
            import inspect
            caller_frame = inspect.currentframe()
            # Go up two frames: _preflight -> __init__ module level -> caller
            outer = caller_frame.f_back.f_back if caller_frame and caller_frame.f_back else None
            if outer and outer.f_globals.get("__file__"):
                project_root = os.path.dirname(os.path.abspath(outer.f_globals["__file__"]))
            else:
                project_root = os.getcwd()
        except Exception:
            project_root = os.getcwd()
        manifest_path = os.path.join(project_root, "manifest.json")

    # --- Run the audit ------------------------------------------------------
    audit = verify_integrity(manifest_path=manifest_path)

    if audit.get("error"):
        print(f"[Anti-Skid] AUDIT ERROR: {audit['error']}", file=sys.stderr)
        sys.exit(1)

    if audit["passed"]:
        print(
            f"[Anti-Skid] Integrity check PASSED "
            f"({audit['matched']}/{audit['total_files']} files, "
            f"{audit['elapsed_ms']:.1f} ms)"
        )
        return

    # --- BREACH DETECTED ----------------------------------------------------
    print(
        f"[Anti-Skid] !!! INTEGRITY BREACH DETECTED !!!\n"
        f"  Mismatches: {len(audit['mismatches'])}\n"
        f"  Missing   : {len(audit['missing'])}\n"
        f"  New files : {len(audit['new_files'])}\n",
        file=sys.stderr,
    )

    # Fire telemetry (non-blocking)
    webhook_url = os.environ.get("ANTI_SKID_WEBHOOK")
    report_breach(webhook_url, audit)

    # Termination
    print("[Anti-Skid] Terminating process to prevent unauthorized execution.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Trigger the pre-flight check at import time
# ---------------------------------------------------------------------------
_preflight()