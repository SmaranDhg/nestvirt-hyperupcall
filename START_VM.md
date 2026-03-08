# Start L1 VM

**Minimal QEMU command** (user-mode net, SSH on 2222, cloud-init via cidata.iso):

```bash
QEMU=~/nestvirt-hyperupcall/hyperturtle-qemu/src/build/qemu-system-x86_64
sudo $QEMU -enable-kvm -cpu host -smp 8 -m 12G \
  -drive file=/data/vm/l1-cloud.qcow2,if=virtio \
  -drive file=/data/vm/cidata.iso,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic
```

**Same with vCPUs pinned to host cores 0–7:**
```bash
sudo taskset -c 0-7 $QEMU -enable-kvm -cpu host -smp 8 -m 12G \
  -drive file=/data/vm/l1-cloud.qcow2,if=virtio \
  -drive file=/data/vm/cidata.iso,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -nographic
```

**SSH into L1:** `ssh -p 2222 ubuntu@localhost`

---

**Pin vCPUs to host CPUs**

- **Whole VM** to cores 0–3: run QEMU under `taskset`:
  ```bash
  sudo taskset -c 0-3 $QEMU -enable-kvm -cpu host -smp 4 -m 12G ...
  ```
- **Per-vCPU** (vCPU0→pCPU0, vCPU1→pCPU1, …): after the VM is up, pin each vCPU thread. For 8 vCPUs (`-smp 8`), use `seq 0 7` and host cores 0–7:
  ```bash
  QEMU_PID=$(pgrep -f qemu-system-x86.*l1-cloud)
  N=8   # match -smp N
  for i in $(seq 0 $((N-1))); do
    TID=$(ps -T -p $QEMU_PID | awk -v i=$i 'NR==2+i {print $2}')
    sudo taskset -cp $i $TID
  done
  ```
  First thread is often the main QEMU process (affinity 0-31); the next N are vCPU threads. Or use **libvirt**: `virsh vcpupin <domain> <vcpunum> <cpulist>`.

---

**Alternative (tap + script):** `./scripts/launch_l1.sh` — see README for DISK_IMG, tap setup.
