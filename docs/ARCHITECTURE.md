# 🏗️ Architecture

NyxArch enforces a strict layered design:

1. Firewall (deny-all baseline)
2. Nyx control layer (Rust binaries)
3. Network stack (Tor / VPN / DNS)
4. Verification layer
5. User environment

---

## 🔐 Security Model

- No outbound traffic before policy
- All routing enforced centrally
- Verification at boot

---

## 🧠 Design Goal

A system where **security precedes usability**.
