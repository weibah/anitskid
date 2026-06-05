"""
Anti-Skid :: Environment Diagnostics Module
Collects host metadata, network status, and container/VM indicators.
"""

import os
import socket
import platform
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# IP / Host metadata
# ---------------------------------------------------------------------------

def _get_public_ip(timeout: float = 4.0) -> str:
    """Retrieve the public-facing IP address via ipify."""
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode("utf-8").strip()
    except Exception:
        return "UNAVAILABLE"


def _get_local_ip() -> str:
    """Best-effort local network IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_host_info() -> dict:
    """Return a dict with basic host identification."""
    return {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME")
                     or os.environ.get("USER")
                     or "UNKNOWN",
        "local_ip": _get_local_ip(),
        "public_ip": _get_public_ip(),
        "platform": platform.platform(),
        "python_version": sys.version,
    }


# ---------------------------------------------------------------------------
# Port scanning (common ports)
# ---------------------------------------------------------------------------

_COMMON_PORTS = [
    (22, "SSH"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (27017, "MongoDB"),
    (5000, "Flask/Dev"),
    (3000, "Node/Dev"),
    (5900, "VNC"),
    (25565, "Minecraft"),
]


def _scan_port(host: str, port: int) -> tuple:
    """Attempt a TCP connect to *host:port*.  Returns (port, label, open)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.6)
    result = s.connect_ex((host, port))
    s.close()
    return port, result == 0


def get_port_status(host: str = "127.0.0.1") -> dict:
    """Scan a subset of common ports on *host* and return status map."""
    status = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_scan_port, host, port): (port, label)
                   for port, label in _COMMON_PORTS}
        for future in as_completed(futures):
            port, label = futures[future]
            try:
                p, is_open = future.result()
                status[f"{port}/{label}"] = "OPEN" if is_open else "closed"
            except Exception:
                status[f"{port}/{label}"] = "error"
    return status


# ---------------------------------------------------------------------------
# Discord / container / VM detection
# ---------------------------------------------------------------------------

def _process_exists(proc_name: str) -> bool:
    """Cross-platform process-exists check via tasklist / ps."""
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["tasklist", "/FI", f"IMAGENAME eq {proc_name}"],
                shell=False,
                timeout=5,
            )
            return proc_name.encode().lower() in out.lower()
        else:
            out = subprocess.check_output(["pgrep", "-f", proc_name], timeout=5)
            return bool(out.strip())
    except Exception:
        return False


def detect_discord() -> bool:
    """Return True if a Discord desktop client process is active."""
    discords = ["Discord.exe", "discord", "DiscordCanary.exe", "DiscordPTB.exe"]
    for name in discords:
        if _process_exists(name):
            return True
    return False


def detect_container_or_vm() -> dict:
    """Lightweight heuristics for container / VM environments."""
    clues = {}

    # Docker /.dockerenv
    clues["docker_env_file"] = os.path.exists("/.dockerenv")

    # cgroup inspection (Linux only – harmless elsewhere)
    try:
        with open("/proc/1/cgroup", "r") as f:
            cgroup = f.read().lower()
        clues["docker_cgroup"] = "docker" in cgroup or "kubepods" in cgroup
    except Exception:
        clues["docker_cgroup"] = False

    # Generic VM hints
    vm_indicators = {
        "vbox": False,
        "vmware": False,
        "qemu": False,
    }
    if sys.platform == "win32":
        try:
            system_info = subprocess.check_output(
                ["systeminfo"], shell=False, timeout=10
            ).decode("utf-8", errors="replace").lower()
            vm_indicators["vbox"] = "virtualbox" in system_info
            vm_indicators["vmware"] = "vmware" in system_info
            vm_indicators["qemu"] = "qemu" in system_info
        except Exception:
            pass
    else:
        try:
            dmesg = subprocess.check_output(["dmesg"], timeout=5).decode(
                "utf-8", errors="replace"
            ).lower()
            vm_indicators["vbox"] = "vbox" in dmesg
            vm_indicators["vmware"] = "vmware" in dmesg
            vm_indicators["qemu"] = "qemu" in dmesg
        except Exception:
            pass

    clues.update(vm_indicators)
    return clues


# ---------------------------------------------------------------------------
# Aggregate report
# ---------------------------------------------------------------------------

def collect_environment_report() -> dict:
    """Gather all environment diagnostics into a single report dict."""
    report = {"host": get_host_info()}

    # Ports – do not block the pre-flight check for long
    try:
        report["ports"] = get_port_status()
    except Exception:
        report["ports"] = {"error": "scan-failed"}

    try:
        report["discord_process"] = detect_discord()
    except Exception:
        report["discord_process"] = "error"

    try:
        report["container_vm"] = detect_container_or_vm()
    except Exception:
        report["container_vm"] = {"error": "detection-failed"}

    return report