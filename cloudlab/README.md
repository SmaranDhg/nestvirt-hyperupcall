# CloudLab: single-node nested virtualization profile

This folder contains a **simple one-node CloudLab RSpec** that provisions:

- Ubuntu 20.04 bare-metal node
- KVM nested virtualization enabled (`kvm_intel nested=1` or `kvm_amd nested=1`)

## Use in CloudLab

- Create a new CloudLab profile.
- Paste `cloudlab/profile.py` into the profile editor (geni-lib Python RSpec).
- Instantiate the profile.

## Verify nested virt on the node

After the node boots, SSH in and verify:

```bash
ls -la /dev/kvm
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || true
cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || true
```

Typical values are `Y` (Intel) or `1` (AMD).

## Next steps for this repo

From the repo root (`nestvirt-hyperupcall/`):

```bash
./setup.sh
sudo reboot
./scripts/launch_l1.sh
```

If your CloudLab site uses a different Ubuntu 20.04 image URN, update the
`node.disk_image` value in `cloudlab/profile.py`.

