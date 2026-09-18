# NyxOS "workbench" sandbox image — the ONLY container image nyx-isolation's
# Podman runtime ever runs (see ../src/containers.rs). Not a general-purpose
# base image: built once via ./build-workbench.sh, which also pins its
# resulting digest into /etc/nyx/workbench-image.json for nyx-isolation to
# verify, by digest, before every single container launch. A local image
# that no longer matches that pinned digest is refused, not trusted.
#
# Base: the official minimal Arch Linux image. It already ships close to
# nothing beyond a package database and bash — everything this workbench
# actually needs for "a sandboxed shell to poke around in something
# untrusted" is added explicitly below, not inherited for free.
FROM docker.io/library/archlinux:base

RUN pacman -Syu --noconfirm --needed \
        bash coreutils grep sed gawk less which diffutils findutils \
        file tar gzip nano \
    && pacman -Scc --noconfirm \
    && rm -rf /var/cache/pacman/pkg/* /var/lib/pacman/sync/*

COPY entrypoint.sh /usr/local/bin/nyx-workbench-entrypoint
RUN chmod 0755 /usr/local/bin/nyx-workbench-entrypoint

WORKDIR /root

# Exec form deliberately: the entrypoint script itself becomes PID 1 inside
# the container rather than being wrapped by another shell, so the SIGTERM
# trap it installs (see entrypoint.sh) is the one PID 1 actually receives.
ENTRYPOINT ["/usr/local/bin/nyx-workbench-entrypoint"]
CMD ["shell"]
