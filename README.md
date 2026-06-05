# Anti-Skid

> **High-Security Integrity Framework** — Your code, defended.

Anti-Skid is a lightweight, dependency-free Python framework that acts as an automated "digital sentry" for your proprietary source code. It embeds a cryptographic verification layer directly into your project's execution pipeline. If anyone modifies your source code, the system triggers a defensive protocol: it terminates the application and sends you a detailed diagnostic report via Discord.

---

## 🔐 How It Works

### 1. Baseline Generation
A one-time process hashes every file in your project using **SHA-256** and writes the fingerprints to an immutable `manifest.json` — the "gold standard" baseline.

### 2. Pre-Flight Check
Every time your program starts, Anti-Skid silently re-hashes the codebase and compares each digest against the baseline. This happens in milliseconds.

### 3. Breach Detection
If even a **single bit** has been altered — a renamed variable, an injected backdoor, a modified function — the check fails.

### 4. Telemetry & Termination
A structured diagnostic report is built and sent to your private Discord webhook (asynchronously). The process then terminates with exit code 1, preventing unauthorized execution.

---

## 📦 The Breach Telemetry Bundle

When a breach is detected, the report sent to your Discord includes:

| Section | Content |
|---------|---------|
| **File Integrity Audit** | Which files were modified, expected vs. actual hashes |
| **Host Diagnostics** | Public IP, local IP, hostname, username, platform |
| **Environment Markers** | Discord process detection, Docker/container detection, VM detection (VirtualBox, VMware, QEMU) |
| **Port Status** | Active port scan of common services on localhost |

---

## 🚀 Quick Start

### Installation

```bash
# Clone into your project
git clone https://github.com/weibah/anti-skid.git
cd anti-skid

# Or install as a package
pip install -e .
```

### Step 1 — Generate Your Baseline

```bash
# From the CLI
anti-skid-gen /path/to/your/project

# Or programmatically
python -c "from anti_skid.manifest import generate_manifest; generate_manifest('.')"
```

This creates `manifest.json` in your project root.

### Step 2 — Add the Pre-Flight Check

In your project's main entry point (e.g., `main.py` or `__init__.py`), add at the very top:

```python
import anti_skid  # ← MUST be the first import in your project

# Your application logic goes here...
def main():
    print("All clear. Running normally.")
```

### Step 3 — Configure Your Webhook (Optional)

Set the environment variable for breach notifications:

```bash
# Windows
set ANTI_SKID_WEBHOOK=https://discord.com/api/webhooks/...

# Linux / macOS
export ANTI_SKID_WEBHOOK=https://discord.com/api/webhooks/...
```

If no webhook is configured, the breach report will be printed to stderr instead.

### Step 4 — Deploy

Ship your project with `manifest.json` included. Anti-Skid does the rest.

---

## 🧰 Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `ANTI_SKID_WEBHOOK` | Discord webhook URL for breach telemetry | *(none — prints to stderr)* |
| `ANTI_SKID_MANIFEST` | Custom path to `manifest.json` | `<project_root>/manifest.json` |
| `ANTI_SKID_DISABLE` | Set to `1` to bypass integrity check *(dev only!)* | *(enabled)* |

---

## 🔒 Security Recommendations

- **Bytecode Obfuscation**: Compile the Anti-Skid package into `.pyc` files or use tools like [PyArmor](https://pyarmor.readthedocs.io/) to protect the verification logic from reverse-engineering.
- **Immutable Manifest**: Consider distributing `manifest.json` with read-only permissions or as a compiled resource.
- **Webhook Rotation**: Use a dedicated Discord webhook and rotate it periodically to prevent abuse.
- **Entry-Point Enforcement**: Place `import anti_skid` as the absolute first line of your entry point — before any other imports — to ensure the check runs before any application logic.

---

## 📁 Project Structure

```
anti_skid/
├── anti_skid/
│   ├── __init__.py      # Pre-flight check — runs on import
│   ├── manifest.py      # Baseline generation & loading
│   ├── integrity.py     # SHA-256 audit engine
│   ├── telemetry.py     # Discord webhook reporter
│   ├── environment.py   # Host/network/container diagnostics
│   └── cli.py           # CLI entry point (anti-skid-gen)
├── setup.py
├── requirements.txt
├── .gitignore
├── README.md
└── manifest.json         # ← Your gold-standard baseline
```

---

## ⚙️ Requirements

- **Python 3.8+**
- **Zero external dependencies** — uses only the Python standard library.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

Anti-Skid is an integrity verification tool designed to help you detect unauthorized modifications to your source code. It does not replace proper code signing, access controls, or legal protections. Use it as one layer in a comprehensive security strategy.

---

*Anti-Skid — Your digital sentry, always watching.*