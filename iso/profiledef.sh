#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="nyxos"
iso_label="NYXOS_$(date +%Y%m)"
iso_publisher="NyxOS <https://nyxos.org>"
iso_application="NyxOS Live/Install Medium"
iso_version="$(date +%Y.%m.%d)"
install_dir="nyxos"
buildmodes=('iso')
bootmodes=(
  'bios.syslinux.mbr'
  'bios.syslinux.eltorito'
  'uefi-x64.systemd-boot.esp'
  'uefi-x64.systemd-boot.eltorito'
)
arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'zstd' '-Xcompression-level' '19')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--long' '-19')

file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/etc/gshadow"]="0:0:400"
  ["/etc/sudoers.d/10-nyxos-live"]="0:0:440"
  ["/root"]="0:0:750"
  ["/usr/local/bin/nyx-install"]="0:0:755"
  ["/usr/share/nyxos/installer/nyxos-postinstall.sh"]="0:0:755"
  ["/etc/nftables.conf"]="0:0:600"
  ["/etc/dnscrypt-proxy/dnscrypt-proxy.toml"]="0:0:644"
  ["/etc/tor/torrc"]="0:0:644"
)
