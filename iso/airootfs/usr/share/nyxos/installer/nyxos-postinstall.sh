#!/usr/bin/env bash
# nyxos-postinstall.sh — run by archinstall as a custom command INSIDE the
# freshly installed system (arch-chroot). Registered by nyx-install.
#
# arch-chroot bind-mounts the live system's /run into the chroot, and
# archiso keeps the live root image mounted at /run/archiso/airootfs, so
# every file the live medium carries is readable here at $LIVE/... — that
# is how this script copies NyxOS's configuration and its on-medium
# package repo without any of it having to be packaged first.
set -euo pipefail
LIVE=/run/archiso/airootfs
log() { echo "nyxos-postinstall: $*"; }
[[ -d "$LIVE/etc" ]] || { echo "nyxos-postinstall: $LIVE not visible — not running under archinstall on the NyxOS medium?" >&2; exit 1; }

# 1. NyxOS configuration the live medium carries. These overwrite the
#    packages' stock copies exactly as mkarchiso does for the live image.
#    Deliberately NOT copied: sudoers.d/10-nyxos-live (live-only passwordless
#    sudo), lightdm autologin, the live passwd/shadow/group files, archiso's
#    mkinitcpio hooks, the forensics udev rule, hostname, pacman.conf
#    (archinstall already copied the live one, see step 2).
for rel in \
    etc/nftables.conf \
    etc/tor/torrc \
    etc/dnscrypt-proxy/dnscrypt-proxy.toml \
    etc/NetworkManager/conf.d/dns.conf \
    etc/polkit-1/rules.d/90-nyx-dashboard.rules \
    etc/apparmor.d/usr.bin.zen-browser \
    etc/os-release
do
    if [[ -f "$LIVE/$rel" ]]; then
        install -D -m 644 -- "$LIVE/$rel" "/$rel"
        log "installed /$rel"
    else
        log "warning: $LIVE/$rel missing on the medium, skipped"
    fi
done
chmod 600 /etc/nftables.conf
# resolv.conf must point at dnscrypt-proxy on loopback; NetworkManager is
# told dns=none above so it never rewrites this.
rm -f /etc/resolv.conf
printf 'nameserver 127.0.0.1\noptions edns0\n' > /etc/resolv.conf

# 2. The signed [nyxos] package repo and its keyring, so `pacman -Syu`
#    keeps working for Nyx packages after reboot. archinstall copied the
#    live /etc/pacman.conf (which already carries the [nyxos] block) into
#    this system; make sure of it anyway.
if [[ -d "$LIVE/opt/nyxos/repo" ]]; then
    mkdir -p /opt/nyxos
    rm -rf /opt/nyxos/repo
    cp -a -- "$LIVE/opt/nyxos/repo" /opt/nyxos/repo
    log "copied [nyxos] repo to /opt/nyxos/repo"
fi
if ! grep -q '^\[nyxos\]' /etc/pacman.conf; then
    printf '\n[nyxos]\nSigLevel = Required TrustedOnly\nServer = file:///opt/nyxos/repo\n' >> /etc/pacman.conf
    log "added [nyxos] to /etc/pacman.conf"
fi
if ! grep -q '^\[blackarch\]' /etc/pacman.conf; then
    printf '\n[blackarch]\nSigLevel = Required DatabaseOptional\nServer = https://ca.mirrors.cicku.me/blackarch/$repo/os/$arch\nServer = https://mirror.cyberbits.eu/blackarch/$repo/os/$arch\nServer = https://blackarch.org/blackarch/$repo/os/$arch\n' >> /etc/pacman.conf
    log "added [blackarch] to /etc/pacman.conf"
fi
mkdir -p /usr/share/pacman/keyrings
cp -f -- "$LIVE"/usr/share/pacman/keyrings/nyxos* /usr/share/pacman/keyrings/ 2>/dev/null || log "warning: no nyxos keyring on the medium"
mkdir -p /usr/share/nyxos
cp -a -- "$LIVE/usr/share/nyxos/." /usr/share/nyxos/
[[ -d /etc/pacman.d/gnupg ]] || pacman-key --init
pacman-key --populate archlinux blackarch nyxos || log "warning: pacman-key --populate reported a problem"

# 3. AppArmor needs to be in the kernel's LSM list, exactly as every NyxOS
#    boot entry passes it. archinstall does not expose kernel parameters,
#    so patch whichever bootloader it installed.
LSM='lsm=landlock,lockdown,yama,integrity,apparmor,bpf'
if compgen -G '/boot/loader/entries/*.conf' >/dev/null; then
    for entry in /boot/loader/entries/*.conf; do
        grep -q "$LSM" "$entry" || sed -i "s|^options |options $LSM |" "$entry"
    done
    log "added $LSM to systemd-boot entries"
elif [[ -f /etc/default/grub ]]; then
    grep -q "$LSM" /etc/default/grub || \
        sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=\"|GRUB_CMDLINE_LINUX_DEFAULT=\"$LSM |" /etc/default/grub
    grub-mkconfig -o /boot/grub/grub.cfg
    log "added $LSM to GRUB and regenerated grub.cfg"
else
    log "warning: unrecognised bootloader — add '$LSM' to the kernel command line by hand or AppArmor will not enforce"
fi

# 4. LightDM's autologin PAM stack references this group; create it so an
#    owner who later enables autologin only has to join it.
getent group autologin >/dev/null || groupadd -r autologin

log "done"
