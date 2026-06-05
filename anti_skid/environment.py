# sniffs the host for info so u know whos stealing ur stuff
# ip, ports, discord process, vm detection etc

import os
import socket
import platform
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------- ip stuff ---------------

def _pub_ip(timeout: float = 4.0) -> str:
    # grabs ur public ip from ipify
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode("utf-8").strip()
    except:
        return "DEAD"


def _local_ip() -> str:
    # best effort local ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def grab_host() -> dict:
    # who are u
    return {
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or "???",
        "local_ip": _local_ip(),
        "public_ip": _pub_ip(),
        "platform": platform.platform(),
        "python_version": sys.version,
    }


# --------------- port scan ---------------

_ports_to_check = [
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


def _poke_port(host: str, port: int):
    # tries to connect to a port, returns if its open
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.6)
    ok = s.connect_ex((host, port))
    s.close()
    return port, ok == 0


def scan_ports(host: str = "127.0.0.1") -> dict:
    # scans common ports on localhost
    res = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_poke_port, host, p): (p, lbl) for p, lbl in _ports_to_check}
        for f in as_completed(futures):
            port, label = futures[f]
            try:
                _, is_open = f.result()
                res[f"{port}/{label}"] = "OPEN" if is_open else "closed"
            except:
                res[f"{port}/{label}"] = "err"
    return res


# --------------- process / vm checks ---------------

def _proc_running(name: str) -> bool:
    # checks if a process is running (windows uses tasklist, linux uses pgrep)
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(
                ["tasklist", "/FI", f"IMAGENAME eq {name}"], shell=False, timeout=5
            )
            return name.encode().lower() in out.lower()
        else:
            out = subprocess.check_output(["pgrep", "-f", name], timeout=5)
            return bool(out.strip())
    except:
        return False


def discord_check() -> bool:
    # is discord open
    names = ["Discord.exe", "discord", "DiscordCanary.exe", "DiscordPTB.exe"]
    for n in names:
        if _proc_running(n):
            return True
    return False


def vmcheck() -> dict:
    # tries to figure out if ur in a vm or container or whatever
    clues = {}

    clues["docker_env_file"] = os.path.exists("/.dockerenv")

    try:
        with open("/proc/1/cgroup", "r") as f:
            cg = f.read().lower()
        clues["docker_cgroup"] = "docker" in cg or "kubepods" in cg
    except:
        clues["docker_cgroup"] = False

    vms = {"vbox": False, "vmware": False, "qemu": False}
    if sys.platform == "win32":
        try:
            si = subprocess.check_output(["systeminfo"], shell=False, timeout=10)
            si = si.decode("utf-8", errors="replace").lower()
            vms["vbox"] = "virtualbox" in si
            vms["vmware"] = "vmware" in si
            vms["qemu"] = "qemu" in si
        except:
            pass
    else:
        try:
            d = subprocess.check_output(["dmesg"], timeout=5).decode("utf-8", errors="replace").lower()
            vms["vbox"] = "vbox" in d
            vms["vmware"] = "vmware" in d
            vms["qemu"] = "qemu" in d
        except:
            pass

    clues.update(vms)
    return clues


# --------------- all together ---------------

def sniff_everything() -> dict:
    # one call to grab everything at once
    report = {"host": grab_host()}

    try:
        report["ports"] = scan_ports()
    except:
        report["ports"] = {"error": "scan died"}

    try:
        report["discord_process"] = discord_check()
    except:
        report["discord_process"] = "err"

    try:
        report["container_vm"] = vmcheck()
    except:
        report["container_vm"] = {"error": "vm check died"}

    return report