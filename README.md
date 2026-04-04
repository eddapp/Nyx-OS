# 🌑 Nyx OS

<p align="center">
  <img src="assets/nyx-banner.png" width="720"/>
</p>

<p align="center">
  <strong>Privacy • Autonomy • Control</strong><br/>
  <em>Arch-based OS with a compiled Rust control layer — no shell script soup.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-purple" />
  <img src="https://img.shields.io/badge/core-rust-orange" />
  <img src="https://img.shields.io/badge/base-arch-blue" />
  <img src="https://img.shields.io/badge/security-enforced-critical" />
</p>

---

## 🧠 What is Nyx OS?

Nyx OS is a **privacy-first Arch-based operating system** built around a **centralized, compiled control layer**.

> No implicit networking. No uncontrolled processes. No script glue.

---

## 🏗️ Architecture

```text
ArchISO
  → Minimal Arch Base
    → Firewall (deny-all)
      → Nyx Control Layer (Rust)
        → Network Stack (Tor/VPN/DNS)
          → Verification Layer
            → User Environment
```

---

## ⚙️ Core Components

| Component | Description |
|----------|------------|
| 🧩 nyx-core | Shared types, structured JSON output, logging |
| 🌐 nyx-route | Network routing control |
| 🛰️ nyx-dns | DNS enforcement + leak prevention |
| 🕸️ nyx-tor | Tor lifecycle + routing |
| 🚨 nyx-health | Kill switch + panic system |
| 🧪 nyx-integrity | System verification |
| 🧹 nyx-wipe | Anti-forensics + secure deletion |

---

## 🔐 Philosophy

- ❌ No shell script glue
- 🧱 Everything critical is compiled
- 🔒 Networking is **blocked by default**
- 🧠 Control is explicit, not assumed

---

## 🚀 Bootstrap

```bash
git clone https://github.com/Nyx OS/core
cd core
./bootstrap.sh
```

---

## 📁 Project Layout

```text
core/        → Rust control layer
iso/         → ArchISO build system
dashboard/   → Tauri UI
docs/        → Architecture + specs
```

---

## 📸 Preview

> Add screenshots here

---

## ⚠️ Status

🚧 Alpha — not production ready.

---

## 🤝 Contributing

Coming soon.

---

## 📜 License

MIT
