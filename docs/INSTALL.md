# Building and installing NyxOS

## 1. Build the ISO (on an Arch machine)

```
cd iso
./build.sh                  # desktop ISO (XFCE + LightDM)
./build.sh --profile server # headless ISO
```

Run as your normal user with sudo rights. The script builds every Nyx crate into an Arch package, builds the AUR-only packages (Zen browser, oniux, session-desktop), signs everything with a build-signing key it generates on first run, then calls `mkarchiso`. Output lands in `iso/out/`:

- `nyxos-<date>-x86_64.iso`
- `<iso>.manifest` and `.manifest.asc` (signed: ISO hash, git commit, canary hash)
- `CANARY.md`, `CANARY.md.asc`, `nyxos-build-signing-key.asc`

Before `mkarchiso` runs, the build also stages three things into the image that are gitignored build products: the signed `[nyxos]` package repo at `/opt/nyxos/repo`, a `nyxos` pacman keyring under `/usr/share/pacman/keyrings/`, and a copy of the curated package list for the installer.

## 2. Boot the live medium

Write the ISO to a USB stick (`dd`, Ventoy, etc.) and boot it. The boot menu offers five tiers: Live, Persistent, Encrypted Persistence, Forensics (RAM-only, no automount of internal disks), and Full Hardening.

The desktop ISO logs the live user in automatically:

| | |
|---|---|
| user | `nyx` |
| password | `nyxos` (only needed to unlock the screen) |
| sudo | passwordless for the live session only |
| root | locked |

The server ISO logs `nyx` in on tty1 instead. On first boot `pacman-init.service` initialises the pacman keyring and trusts the Arch, BlackArch and NyxOS keys, so `pacman` and the installer can verify every package, including the ones on the medium.

## 3. Install to disk

Open **Install NyxOS** from the application menu (System category), or run:

```
sudo nyx-install
```

`nyx-install` wraps Arch's own `archinstall`. It generates a configuration that pre-fills everything that defines NyxOS and then opens archinstall's normal menu:

Pre-filled by NyxOS:
- the full curated package set (the ISO's own list minus live-only packages), resolved from the on-medium `[nyxos]` repo plus the Arch and BlackArch mirrors
- Xfce4 desktop with the LightDM GTK greeter, NetworkManager, PipeWire, the `linux` kernel
- the services to enable: nftables, dnscrypt-proxy, apparmor, NetworkManager and the eight Nyx daemons
- a post-install step (below)

You set in the menu:
- **Disk configuration** (partition layout; optional LUKS encryption)
- **Bootloader** (systemd-boot on UEFI, GRUB on BIOS)
- **Authentication** (root password and/or a user in `wheel`)
- hostname, timezone, locale, mirror region

Choose *Install*. When the base install finishes, archinstall runs `nyxos-postinstall.sh` inside the new system. It:

1. copies the NyxOS configuration the live medium carries (nftables, Tor, DNSCrypt, NetworkManager DNS, the dashboard polkit rule, the Zen AppArmor profile, os-release) and points resolv.conf at dnscrypt-proxy;
2. copies `/opt/nyxos/repo` and the `nyxos` keyring onto the disk, makes sure `[nyxos]` and `[blackarch]` are in pacman.conf, and populates the keyring;
3. adds `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to the installed bootloader's kernel command line (systemd-boot entries or GRUB) so AppArmor enforces;
4. creates the `autologin` group LightDM's PAM stack expects.

It deliberately does not carry over the live medium's passwordless sudo, autologin, or live accounts. An installed NyxOS uses the accounts and password-prompting sudo you configured in archinstall.

Reboot, log in through LightDM, and open **NyxOS Control** from the menu.

## What is and is not verified

- The build pipeline, signing, keyring format, repo staging and installer config generation have been exercised on a build host.
- An end-to-end build followed by an install in a VM has **not** yet been run from this tree. Do that before calling a release usable.
