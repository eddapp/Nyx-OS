<p align="center">
  <img src="assets/nyx-banner.png" width="720" alt="NyxOS — privacy-first Arch-based OS" />
</p>

# NyxOS

### A hardened, privacy-focused Linux operating system built on Arch Linux.

**NyxOS** is an Arch Linux–based operating system designed around privacy, security, network isolation, system integrity, and user control.

NyxOS brings together secure networking, VPN and Tor routing, DNS protection, firewall enforcement, anti-forensics, system integrity, diagnostics, and a unified security control plane into a cohesive desktop operating system.

The goal is simple:

> **Privacy and security should be properties of the operating system—not a collection of applications the user has to manually configure.**

---

## Project Status

> **NyxOS is currently under active development.**

The project is being engineered as a complete operating system rather than a desktop theme or collection of shell scripts.

Core architecture, security boundaries, networking, desktop integration, and the Arch-based build system are being developed incrementally.

Features documented below represent the intended NyxOS platform architecture and feature-parity targets.

---

# What is NyxOS?

NyxOS is an **Arch-based privacy and security operating system** designed to provide a hardened environment for everyday computing, security research, privacy-sensitive workloads, and anonymous networking.

The system is built around several principles:

* Privacy by default
* Security by default
* Fail-closed networking
* Minimal trust
* Least privilege
* Defense in depth
* Verifiable system state
* User-controlled routing
* No security theater
* No false security indicators
* Open and auditable architecture

NyxOS is intended to make advanced privacy and security controls accessible without requiring the user to manually assemble and maintain an entire security stack.

---

# Design Philosophy

## Security is a system property

NyxOS does not treat security as a single application.

The operating system is designed as a collection of cooperating security layers:

```text
                    ┌──────────────────────┐
                    │      NyxOS User      │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   NyxOS Dashboard    │
                    │      / Tauri UI      │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Nyx Control Plane   │
                    │        Rust           │
                    └──────────┬───────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
   ┌──────▼──────┐      ┌──────▼──────┐      ┌─────▼───────┐
   │   Network   │      │   Privacy   │      │   Security  │
   │   Control   │      │   Services  │      │   Services  │
   └──────┬──────┘      └──────┬──────┘      └─────┬───────┘
          │                    │                    │
   ┌──────▼────────────────────▼────────────────────▼───────┐
   │                  Linux / Arch Base                     │
   │              Kernel • systemd • nftables               │
   └─────────────────────────────────────────────────────────┘
```

The graphical interface is not the security mechanism.

The **Nyx Rust control plane** is responsible for enforcing and verifying security state.

---

# Core Components

NyxOS is being organized into dedicated system components rather than one monolithic application.

### `nyx-core`

The central Rust system layer.

Responsibilities include:

* system state
* configuration
* service orchestration
* policy evaluation
* privileged operations
* IPC
* security state
* subsystem coordination

---

### `nyx-route`

Secure network routing and policy enforcement.

Responsibilities include:

* route management
* interface management
* routing policies
* VPN routing
* Tor routing
* network state verification
* fail-closed behavior

---

### `nyx-firewall`

The NyxOS firewall and network enforcement layer.

Built around Linux's native firewall infrastructure.

Responsibilities include:

* default-deny policies
* kill switch enforcement
* interface policies
* VPN-only routing
* Tor-only routing
* leak prevention
* emergency network isolation

---

### `nyx-vpn`

Unified VPN management.

Designed to support multiple VPN technologies where appropriate, including:

* WireGuard
* OpenVPN
* additional compatible transports

NyxOS should verify that the VPN is actually functioning rather than simply displaying a connected status.

---

### `nyx-tor`

Tor integration and routing management.

Capabilities include:

* Tor lifecycle management
* Tor routing
* bridge configuration
* bridge transports
* connection verification
* routing status
* failure handling

Where appropriate, NyxOS can support transports such as:

* obfs4
* other Tor-supported transports

---

### `nyx-dns`

Secure DNS management.

Responsibilities include:

* DNS configuration
* DNS routing
* leak prevention
* resolver health
* DNS state verification
* integration with VPN/Tor policies

---

### `nyx-health`

System and security health monitoring.

Monitors:

* network state
* VPN state
* Tor state
* DNS state
* firewall state
* system services
* storage
* resource health
* security subsystem health

---

### `nyx-integrity`

System integrity subsystem.

Designed to provide visibility into:

* critical system files
* configuration integrity
* service state
* package state
* boot integrity
* security configuration

---

### `nyx-wipe`

Privacy and anti-forensics tooling.

Potential capabilities include:

* secure cleanup workflows
* temporary-data cleanup
* cache cleanup
* privacy-oriented data removal
* storage sanitization workflows where technically appropriate

All destructive operations must be explicit, auditable, and protected against accidental execution.

---

### `nyx-security`

Central security subsystem.

Responsible for coordinating:

* hardening
* security policies
* MAC policies
* sandboxing
* privilege boundaries
* security checks
* threat-state reporting

---

### `nyx-diagnostics`

Diagnostics and troubleshooting.

Provides:

* network diagnostics
* service diagnostics
* system reports
* configuration validation
* security-state reports
* log collection
* failure analysis

---

# Nyx Shield

**Nyx Shield** is the system-wide security enforcement concept.

The objective is to ensure that privacy-sensitive traffic does not silently bypass the user's selected protection path.

For example:

```text
User
 │
 ▼
NyxOS
 │
 ├── Firewall
 │
 ├── VPN
 │
 ├── Tor
 │
 └── DNS
      │
      ▼
   Internet
```

If a required security path fails, NyxOS should transition into a defined safe state rather than silently routing traffic around the protection mechanism.

The exact policy depends on the user's selected networking mode.

Possible modes include:

```text
DIRECT
VPN
TOR
VPN → TOR
TOR → VPN
ISOLATED
```

---

# Security Center

NyxOS will provide a centralized **Security Center** through the desktop environment.

The Security Center is intended to expose the actual operating-system security state.

Example:

```text
NYXOS SECURITY CENTER

System
  ● Integrity        Verified
  ● Firewall         Active
  ● Security Policy  Enforced

Network
  ● Interface        Connected
  ● VPN              Connected
  ● DNS              Protected
  ● IPv6             Protected

Privacy
  ● Tor              Active
  ● Routing          Tor
  ● Leak Detection   Passed

System Health
  ● CPU              Normal
  ● Memory           Normal
  ● Storage          Normal
```

The UI must never claim that a security control is active merely because a configuration file exists or a process is running.

**NyxOS verifies behavior.**

---

# Desktop Environment

The initial desktop environment is intended to provide a familiar Linux desktop while integrating NyxOS security functionality directly into the operating system.

The desktop architecture is centered around:

* XFCE
* Tauri
* Rust
* native Linux services
* D-Bus/IPC
* Nyx Control Plane

The goal is to avoid creating a security-critical application where the graphical interface itself becomes the authority.

Instead:

```text
Tauri UI
   │
   ▼
Nyx Control Plane
   │
   ├── Firewall
   ├── VPN
   ├── Tor
   ├── DNS
   ├── Routing
   ├── Security
   └── Diagnostics
```

---

# Privacy Features

NyxOS is intended to provide a comprehensive privacy toolkit.

Planned capabilities include:

### Network Privacy

* VPN routing
* Tor routing
* DNS protection
* DNS leak prevention
* IPv6 leak prevention
* firewall enforcement
* routing verification
* connection monitoring

### Identity & Metadata Protection

* privacy-oriented browser configuration
* metadata-aware workflows
* temporary environments
* privacy-focused system defaults

### Anti-Forensics

* secure cleanup
* temporary-data management
* privacy-oriented wipe tools
* live-session workflows

### System Security

* hardened services
* least privilege
* AppArmor
* sandboxing
* system integrity monitoring
* secure defaults
* attack-surface reduction

---

# Security Architecture

NyxOS follows a defense-in-depth model.

```text
┌────────────────────────────────────────────┐
│                 Applications               │
├────────────────────────────────────────────┤
│              Desktop / Tauri               │
├────────────────────────────────────────────┤
│             Nyx Control Plane              │
├────────────────────────────────────────────┤
│       Security / Privacy Services          │
├────────────────────────────────────────────┤
│ Firewall │ VPN │ Tor │ DNS │ Routing       │
├────────────────────────────────────────────┤
│        AppArmor / Sandboxing / MAC          │
├────────────────────────────────────────────┤
│               Linux Kernel                 │
├────────────────────────────────────────────┤
│                Arch Linux                  │
└────────────────────────────────────────────┘
```

Security-critical decisions should be:

* deterministic
* auditable
* testable
* fail-safe
* independent of the graphical interface

---

# Intelligence Layer

NyxOS may include an optional intelligence layer for security analysis and system assistance.

Potential applications include:

* anomaly detection
* system behavior analysis
* network analysis
* security event correlation
* diagnostics
* configuration assistance
* threat intelligence
* system recommendations

However:

> **AI does not become the security authority.**

Security policy remains deterministic and explicitly enforced by the operating system.

An intelligence system may recommend an action, but the Nyx security architecture decides whether that action is permitted.

---

# Security Modes

NyxOS is designed around explicit operating modes.

Example architecture:

```text
┌─────────────────────┐
│    NyxOS Modes      │
├─────────────────────┤
│ Normal              │
│ VPN                 │
│ Tor                 │
│ VPN → Tor           │
│ Tor → VPN           │
│ Isolated            │
│ Live                │
│ Recovery            │
└─────────────────────┘
```

Each mode defines:

* routing policy
* firewall policy
* DNS policy
* privacy services
* permitted interfaces
* failure behavior
* verification requirements

---

# Live Environment

NyxOS is intended to support a bootable live environment for privacy-sensitive sessions and recovery operations.

The live environment should provide:

* ephemeral sessions
* network protection
* security tools
* diagnostics
* recovery tools
* system inspection
* privacy workflows

The live environment is part of the operating-system architecture rather than simply an ISO installer.

---

# Security Operations Center

NyxOS will provide an integrated **Security Operations Center (SOC)** interface.

The SOC is intended to provide visibility into:

* network connections
* firewall events
* VPN state
* Tor state
* DNS activity
* system events
* service health
* security alerts
* integrity events
* diagnostics

The SOC should emphasize evidence and system state rather than presenting opaque security scores.

---

# Application Ecosystem

NyxOS is intended to provide a complete privacy/security-oriented application environment.

Application categories include:

* secure browsers
* networking tools
* VPN tools
* Tor tools
* DNS tools
* encryption utilities
* password/security tools
* OSINT utilities
* forensic utilities
* system administration tools
* diagnostics
* development tools
* privacy utilities

Applications should be integrated into the NyxOS security model where appropriate.

---

# Arch Linux

NyxOS uses **Arch Linux as its underlying distribution architecture**.

Arch provides:

* rolling packages
* modern Linux infrastructure
* extensive package availability
* flexible system construction
* strong developer ecosystem
* transparent package management
* access to the Arch User Repository ecosystem

NyxOS adds its own:

* security architecture
* control plane
* privacy services
* networking policy
* desktop integration
* build system
* tooling
* workflows
* security verification

---

# Build System

NyxOS will provide an automated Arch-based build pipeline.

The build system is intended to produce:

```text
NyxOS
 ├── ISO
 ├── Live Environment
 ├── Installer
 ├── Packages
 ├── Development Images
 └── Recovery Environment
```

The long-term goal is a reproducible and verifiable build process.

Build requirements include:

* deterministic configuration
* package verification
* signed artifacts
* reproducible builds where practical
* automated testing
* ISO validation
* boot testing

---

# Server / Headless Edition

NyxOS is not limited to desktop systems.

A headless/server configuration is planned for systems that require NyxOS security and networking infrastructure without the full graphical environment.

Potential uses include:

* secure gateways
* privacy routers
* VPN gateways
* Tor gateways
* security appliances
* hardened servers
* research systems

The same underlying Rust control-plane architecture should support both desktop and headless deployments where practical.

---

# Security Verification

NyxOS treats verification as a first-class feature.

Examples:

```text
VPN PROCESS RUNNING
        ≠
VPN TRAFFIC VERIFIED
```

```text
TOR PROCESS RUNNING
        ≠
TRAFFIC VERIFIED THROUGH TOR
```

```text
FIREWALL CONFIGURED
        ≠
FIREWALL EFFECTIVELY BLOCKING TRAFFIC
```

NyxOS therefore aims to verify actual system behavior.

Testing will include:

* firewall bypass tests
* VPN disconnect tests
* DNS leak tests
* IPv6 leak tests
* Tor routing tests
* interface failure tests
* service failure tests
* privilege-boundary tests
* boot tests
* recovery tests
* package integrity tests

---

# Threat Model

NyxOS is designed to reduce exposure to threats such as:

* network surveillance
* DNS leakage
* accidental traffic exposure
* malicious network environments
* compromised applications
* unauthorized privilege escalation
* configuration mistakes
* system tampering
* metadata leakage

NyxOS **does not guarantee anonymity or protection against every attacker**.

Security depends on:

* hardware
* firmware
* kernel integrity
* physical access
* applications
* user behavior
* network infrastructure
* third-party services
* configuration

NyxOS therefore focuses on measurable protections rather than absolute security claims.

---

# Project Architecture

The project is broadly organized around:

```text
NyxOS
│
├── Core
│   ├── nyx-core
│   ├── nyx-security
│   ├── nyx-health
│   └── nyx-integrity
│
├── Network
│   ├── nyx-route
│   ├── nyx-firewall
│   ├── nyx-vpn
│   ├── nyx-tor
│   └── nyx-dns
│
├── Privacy
│   ├── nyx-wipe
│   └── privacy workflows
│
├── Diagnostics
│   └── nyx-diagnostics
│
├── Desktop
│   ├── Tauri
│   ├── Security Center
│   ├── SOC
│   └── XFCE integration
│
├── Build
│   ├── ArchISO
│   ├── packages
│   └── CI/CD
│
└── Documentation
    ├── architecture
    ├── security model
    ├── threat model
    └── development
```

The exact repository layout may evolve during development.

---

# Development Principles

NyxOS development follows several rules.

### 1. Security before convenience

A feature that weakens the security model requires explicit architectural justification.

### 2. Fail closed

Security-sensitive failures should default to the safest defined state.

### 3. Verify, don't assume

System state must be measured rather than inferred from process existence or configuration.

### 4. Least privilege

Privileged operations should be isolated and minimized.

### 5. No security theater

The UI must not display a green light simply because a service is running.

### 6. Explicit trust boundaries

Every component should have a defined:

* privilege level
* trust level
* communication boundary
* data boundary
* failure behavior

### 7. Rust for the control plane

Security-critical orchestration and system services should favor memory-safe Rust implementations where appropriate.

### 8. Linux-native security primitives

NyxOS should use mature Linux security mechanisms rather than reinventing them unnecessarily.

### 9. Test the failure state

Every security mechanism must be tested when it:

* disconnects
* crashes
* loses connectivity
* receives invalid configuration
* loses its dependency
* is restarted
* is upgraded

---

# Relationship to Kodachi OS

NyxOS takes inspiration from the **privacy/security operating-system model pioneered by Kodachi OS**, particularly its approach of integrating VPN, Tor, DNS protection, firewall controls, privacy tooling, security monitoring, and a unified desktop experience.

NyxOS is being developed as an **independent Arch Linux implementation**.

The Kodachi project is used as a reference for understanding desired capabilities and workflows.

NyxOS does not assume that Kodachi source code, proprietary assets, branding, or implementation-specific components can simply be copied into this project.

Third-party components incorporated into NyxOS must be evaluated under their respective licenses.

---

# Roadmap

## Phase 1 — Foundation

* [ ] Arch-based NyxOS build
* [ ] Bootable ISO
* [ ] Base system
* [ ] Rust control plane
* [ ] Security architecture
* [ ] Firewall foundation
* [ ] Network policy
* [ ] DNS subsystem
* [ ] System health
* [ ] Integrity subsystem

## Phase 2 — Network Privacy

* [ ] VPN manager
* [ ] WireGuard integration
* [ ] OpenVPN integration
* [ ] Nyx Shield
* [ ] DNS leak protection
* [ ] IPv6 protection
* [ ] Network verification
* [ ] Tor integration

## Phase 3 — Desktop

* [ ] XFCE integration
* [ ] Tauri dashboard
* [ ] Security Center
* [ ] Network Center
* [ ] VPN controls
* [ ] Tor controls
* [ ] DNS controls
* [ ] System health dashboard

## Phase 4 — Advanced Privacy

* [ ] Tor bridges
* [ ] Advanced VPN transports
* [ ] Anti-forensics tooling
* [ ] Secure cleanup
* [ ] Privacy workflows
* [ ] Desktop integrations
* [ ] Live environment

## Phase 5 — Security Operations

* [ ] SOC
* [ ] Security event monitoring
* [ ] Diagnostics
* [ ] Integrity monitoring
* [ ] Threat analysis
* [ ] Security reporting

## Phase 6 — Intelligence

* [ ] Local security analytics
* [ ] Anomaly detection
* [ ] Threat intelligence
* [ ] Intelligent diagnostics
* [ ] Optional AI assistance

## Phase 7 — Platform

* [ ] Server edition
* [ ] Recovery environment
* [ ] Reproducible builds
* [ ] Signed releases
* [ ] Automated security testing
* [ ] Hardware compatibility expansion

---

# Contributing

NyxOS welcomes contributors interested in:

* Linux systems engineering
* Rust
* cybersecurity
* network security
* privacy engineering
* Arch Linux
* desktop Linux
* Tauri
* kernel/security research
* testing
* documentation

Before contributing security-sensitive code, contributors should understand the relevant NyxOS architecture and threat model.

Security-sensitive changes should include appropriate tests and documentation.

---

# Security Issues

Do not publicly disclose an unpatched security vulnerability in an issue.

Security vulnerabilities should be reported through the project's designated security-reporting process.

Include:

* affected component
* reproduction steps
* impact
* relevant logs
* affected versions
* proposed mitigation, if known

---

# Disclaimer

NyxOS is security and privacy software.

No operating system can guarantee complete anonymity, privacy, or protection against every threat.

NyxOS should be evaluated according to its actual implementation, configuration, and threat model.

Security features are subject to change while the project is under development.

---

# License

NyxOS licensing information will be provided here as the project reaches its release/licensing milestone.

Individual third-party components may be distributed under their own licenses.

---

# Links

* **NyxOS:** https://github.com/eddapp/Nyx-OS
* **Kodachi OS:** https://github.com/WMAL/kodachios

---

<p align="center">
  <img src="assets/nyx-logo.png" width="220" alt="NyxOS logo" />
</p>

## NyxOS

**Privacy by architecture.
Security by design.
Control by default.**
