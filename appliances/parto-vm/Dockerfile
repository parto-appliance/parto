# Build tools run natively on either Linux architecture. Guest architecture is explicit.
FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    debootstrap ca-certificates curl gnupg qemu-utils qemu-user-static \
    qemu-system-x86 qemu-system-arm qemu-efi-aarch64 seabios ovmf parted dosfstools e2fsprogs util-linux \
    python3 xz-utils libxml2-utils && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/bash"]
