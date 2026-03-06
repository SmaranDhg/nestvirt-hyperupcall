#!/usr/bin/env bash
# scripts/launch_l1.sh — Launch the L1 VM using hyperturtle-qemu.
#
# Customise the variables below or override them as environment variables:
#   DISK_IMG=~/my-l1.qcow2 MEM=64G ./scripts/launch_l1.sh
#
# Prerequisites:
#   - hyperturtle-linux kernel installed and booted (uname -r should show it)
#   - hyperturtle-qemu built (./setup.sh qemu)
#   - A disk image with Ubuntu 20.04 + hyperturtle-linux kernel inside L1
#   - A tap interface created:
#       sudo ip tuntap add tap0 mode tap
#       sudo ip link set tap0 up
#       sudo ip addr add 10.0.0.1/24 dev tap0  # optional, for SSH into L1

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ─── Configuration ────────────────────────────────────────────────────────────
DISK_IMG="${DISK_IMG:-$HOME/l1.qcow2}"
QEMU="${QEMU:-$REPO_ROOT/hyperturtle-qemu/src/build/qemu-system-x86_64}"
CPUS="${CPUS:-12}"
MEM="${MEM:-32G}"
SSH_PORT="${SSH_PORT:-2222}"       # host port forwarded to L1's SSH (22)
TAP_IFACE="${TAP_IFACE:-tap0}"     # tap interface for L1's experiment network
MAC="${MAC:-52:54:00:12:34:56}"
EXTRA_ARGS="${EXTRA_ARGS:-}"        # append any extra QEMU flags here

# ─── Sanity checks ────────────────────────────────────────────────────────────
if [[ ! -x "$QEMU" ]]; then
    echo "QEMU binary not found at: $QEMU"
    echo "Run ./setup.sh qemu  (or set QEMU=/path/to/qemu-system-x86_64)"
    exit 1
fi

if [[ ! -f "$DISK_IMG" ]]; then
    echo "Disk image not found: $DISK_IMG"
    echo "Create one with:"
    echo "  qemu-img create -f qcow2 $DISK_IMG 60G"
    echo "  # then install Ubuntu 20.04 into it and install the hyperturtle kernel"
    exit 1
fi

# ─── Launch ───────────────────────────────────────────────────────────────────
echo "[launch_l1] Starting L1 VM: ${CPUS} vCPUs, ${MEM} RAM, disk=${DISK_IMG}"
echo "[launch_l1] SSH forwarded: localhost:${SSH_PORT} → L1:22"
echo "[launch_l1] Press Ctrl-A X to exit QEMU console"

exec "$QEMU" \
    -enable-kvm \
    -cpu host,+vmx \
    -smp "$CPUS" \
    -m "$MEM" \
    \
    -drive file="$DISK_IMG",if=virtio,cache=none,aio=native \
    \
    -netdev user,id=mgmt0,hostfwd=tcp::"$SSH_PORT"-:22 \
    -device virtio-net-pci,netdev=mgmt0,mac="$MAC" \
    \
    -netdev tap,id=expnet,ifname="$TAP_IFACE",script=no,downscript=no \
    -device virtio-net-pci,netdev=expnet \
    \
    -object memory-backend-memfd,id=hp0,size=8M,share=on \
    -object memory-backend-memfd,id=hp1,size=8M,share=on \
    -object memory-backend-memfd,id=hp2,size=8M,share=on \
    -object memory-backend-memfd,id=hp3,size=8M,share=on \
    -object memory-backend-memfd,id=hp4,size=8M,share=on \
    \
    -device ivshmem-plain,bus=pcie.0,memdev=hp0,id=bpf_map_dev0 \
    -device ivshmem-plain,bus=pcie.0,memdev=hp1,id=bpf_map_dev1 \
    -device ivshmem-plain,bus=pcie.0,memdev=hp2,id=bpf_map_dev2 \
    -device ivshmem-plain,bus=pcie.0,memdev=hp3,id=bpf_map_dev3 \
    -device ivshmem-plain,bus=pcie.0,memdev=hp4,id=bpf_map_dev4 \
    \
    -nographic \
    -serial mon:stdio \
    $EXTRA_ARGS
