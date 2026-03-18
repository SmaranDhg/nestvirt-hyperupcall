#!/usr/bin/env bash
# setup.sh — Build hyperturtle-linux kernel, libbpf, and hyperturtle-qemu
# from scratch on Ubuntu 20.04.  Run as a normal user with sudo access.
#
# Usage:
#   ./setup.sh          # full build (kernel + libbpf + QEMU)
#   ./setup.sh kernel   # kernel only
#   ./setup.sh qemu     # QEMU only (assumes kernel/libbpf already built)
#
# After the script finishes, reboot into the new kernel and start L1:
#   sudo reboot
#   ./scripts/launch_l1.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LINUX_SRC="$REPO_ROOT/hyperturtle-linux/src"
QEMU_SRC="$REPO_ROOT/hyperturtle-qemu/src"
QEMU_BUILD="$QEMU_SRC/build"

STEP=${1:-all}

log()  { echo "[setup] $*"; }
die()  { echo "[setup] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" &>/dev/null || die "'$1' not found — run: ./setup.sh deps"; }

# ─────────────────────────────────────────────────────────────────────────────
# Step 0: system dependencies
# ─────────────────────────────────────────────────────────────────────────────
install_deps() {
    log "Installing build dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        git build-essential libncurses-dev libssl-dev libelf-dev \
        bc flex bison binutils-dev libcap-dev libpci-dev libnuma-dev \
        libbfd-dev pkg-config zlib1g-dev libglib2.0-dev libpixman-1-dev \
        ninja-build python3 python3-pip python3-setuptools \
        libfdt-dev libslirp-dev \
        dwarves \
        curl wget
    log "Dependencies installed."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: initialise git submodules (full kernel + QEMU source trees)
# ─────────────────────────────────────────────────────────────────────────────
init_submodules() {
    log "Initialising submodules (this will download the full kernel and QEMU source — may take a while)..."
    cd "$REPO_ROOT"
    git submodule update --init --recursive --progress \
        hyperturtle-linux/src \
        hyperturtle-qemu/src
    log "Submodules ready."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: overlay our modified files on top of the upstream source trees
# ─────────────────────────────────────────────────────────────────────────────
overlay_files() {
    log "Overlaying modified source files..."

    # Kernel modifications
    cp -v "$REPO_ROOT/hyperturtle-linux/arch/x86/kvm/x86.c" \
          "$LINUX_SRC/arch/x86/kvm/x86.c"
    cp -v "$REPO_ROOT/hyperturtle-linux/arch/x86/kvm/vmx/nested.c" \
          "$LINUX_SRC/arch/x86/kvm/vmx/nested.c"
    cp -v "$REPO_ROOT/hyperturtle-linux/include/linux/kvm_host.h" \
          "$LINUX_SRC/include/linux/kvm_host.h"

    # QEMU modifications
    cp -v "$REPO_ROOT/hyperturtle-qemu/accel/kvm/kvm-all.c" \
          "$QEMU_SRC/accel/kvm/kvm-all.c"

    log "Files overlaid."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: build the Linux kernel
# ─────────────────────────────────────────────────────────────────────────────
build_kernel() {
    log "Configuring kernel (hyperturtle_defconfig + DWARF4)..."
    cd "$LINUX_SRC"

    # Use the known-working CloudLab host config instead of a minimal defconfig
    # so we don't drop the bare-metal storage and network drivers!
    cp /boot/config-$(uname -r) .config
    make olddefconfig

    # Force DWARF4 — newer GCC defaults to DWARFv5 which breaks resolve_btfids
    ./scripts/config --enable  DEBUG_INFO_DWARF4
    ./scripts/config --disable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
    # Disable BTF entirely if DWARF4 still fails
    # ./scripts/config --disable DEBUG_INFO_BTF
    make olddefconfig

    log "Building kernel ($(nproc) threads)..."
    make -j"$(nproc)"

    log "Installing kernel..."
    sudo make install
    sudo make modules_install

    log "Kernel built and installed.  Run 'sudo reboot' to boot into it."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: build libbpf (required by hyperturtle-qemu at link time)
# ─────────────────────────────────────────────────────────────────────────────
build_libbpf() {
    log "Building libbpf..."
    cd "$LINUX_SRC/tools/lib/bpf"
    make -j"$(nproc)"
    sudo make install
    sudo ldconfig
    log "libbpf built and installed."
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: build QEMU (x86_64 softmmu target only)
# ─────────────────────────────────────────────────────────────────────────────
build_qemu() {
    log "Building hyperturtle-qemu..."
    mkdir -p "$QEMU_BUILD"
    cd "$QEMU_BUILD"
    ../configure --target-list=x86_64-softmmu --extra-ldflags="-lbpf"
    make -j"$(nproc)"
    log "QEMU binary: $QEMU_BUILD/qemu-system-x86_64"
    log "Add to PATH or set QEMU env var in scripts/launch_l1.sh."
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
case "$STEP" in
    deps)
        install_deps
        ;;
    submodules)
        init_submodules
        ;;
    overlay)
        overlay_files
        ;;
    kernel)
        overlay_files
        build_kernel
        ;;
    libbpf)
        build_libbpf
        ;;
    qemu)
        overlay_files
        build_qemu
        ;;
    all)
        install_deps
        init_submodules
        overlay_files
        build_kernel
        build_libbpf
        build_qemu
        log ""
        log "═══════════════════════════════════════════════════════"
        log " Build complete."
        log ""
        log " Next steps:"
        log "   1. sudo reboot                     # boot new kernel"
        log "   2. uname -r                        # verify kernel"
        log "   3. ./scripts/launch_l1.sh          # start L1 VM"
        log "   4. (inside L1) ./scripts/build_hyperupcalls.sh"
        log "   5. (inside L2) ./scripts/run_benchmarks.sh"
        log "═══════════════════════════════════════════════════════"
        ;;
    *)
        echo "Usage: $0 [all|deps|submodules|overlay|kernel|libbpf|qemu]"
        exit 1
        ;;
esac
