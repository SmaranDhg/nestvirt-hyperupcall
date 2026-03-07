"""
CloudLab RSpec (geni-lib) for a single bare-metal node with nested KVM enabled.

Usage (CloudLab UI):
  1) Create a new experiment profile, paste this file into the "Profile" editor.
  2) Instantiate.
  3) SSH in, verify nested is enabled, then run repo build steps.
"""

import geni.portal as portal
import geni.rspec.pg as pg


pc = portal.Context()
request = pc.makeRequestRSpec()

# One physical machine (bare metal).
node = request.RawPC("node")

# Ubuntu 20.04 as expected by setup.sh / README.
# This URN typically works across CloudLab sites; if your site differs, update it.
node.disk_image = "urn:publicid:IDN+cloudlab.us+image+emulab-ops//UBUNTU20-64-STD"

# Enable nested virtualization at boot (Intel or AMD).
# Notes:
# - This does NOT reboot into a custom kernel; it only enables kvm_* nested=1.
# - Your repo's ./setup.sh builds a kernel + QEMU and then requires a manual reboot.
startup = r"""sudo bash -lc '
set -euo pipefail

echo \"[cloudlab] Enabling nested KVM (best-effort)\"

if command -v lscpu >/dev/null 2>&1; then
  VENDOR=\"$(lscpu | awk -F: \"/Vendor ID/ {gsub(/^[ \t]+/, \\\"\\\", \\$2); print \\$2; exit}\")\"
else
  VENDOR=\"\"
fi

mkdir -p /etc/modprobe.d

case \"${VENDOR}\" in
  *Intel*|*intel*)
    echo \"options kvm-intel nested=1 ept=1\" > /etc/modprobe.d/kvm-intel.conf
    modprobe -r kvm_intel 2>/dev/null || true
    modprobe -r kvm 2>/dev/null || true
    modprobe kvm
    modprobe kvm_intel nested=1 ept=1 || true
    ;;
  *AMD*|*amd*)
    echo \"options kvm-amd nested=1\" > /etc/modprobe.d/kvm-amd.conf
    modprobe -r kvm_amd 2>/dev/null || true
    modprobe -r kvm 2>/dev/null || true
    modprobe kvm
    modprobe kvm_amd nested=1 || true
    ;;
  *)
    echo \"[cloudlab] WARN: could not detect CPU vendor (lscpu missing or unexpected output)\"
    echo \"[cloudlab]       trying both kvm_intel and kvm_amd\"
    echo \"options kvm-intel nested=1 ept=1\" > /etc/modprobe.d/kvm-intel.conf
    echo \"options kvm-amd nested=1\" > /etc/modprobe.d/kvm-amd.conf
    modprobe kvm || true
    modprobe kvm_intel nested=1 ept=1 || true
    modprobe kvm_amd nested=1 || true
    ;;
esac

echo \"[cloudlab] /dev/kvm:\"
ls -la /dev/kvm || true

if [ -r /sys/module/kvm_intel/parameters/nested ]; then
  echo \"[cloudlab] kvm_intel nested = $(cat /sys/module/kvm_intel/parameters/nested)\"
fi
if [ -r /sys/module/kvm_amd/parameters/nested ]; then
  echo \"[cloudlab] kvm_amd nested = $(cat /sys/module/kvm_amd/parameters/nested)\"
fi

echo \"[cloudlab] Done.\"
'"""

node.addService(pg.Execute(shell="sh", command=startup))

pc.printRequestRSpec(request)

