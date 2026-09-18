# Running Cerberus inside a disposable VM

This is the boundary that makes Cerberus safe against a kernel-level escape: put
the whole thing inside a throwaway virtual machine, so even a guest-kernel
break-out only destroys the guest, which is deleted the moment it exits.

There are two ways to do it — the built-in launcher (recommended), and the manual
QEMU recipe it automates (for reference / customisation).

## The built-in launcher

```bash
python3 -m cerberus.vm run
```

That single command:

1. downloads a small cloud image once and caches it (never modified);
2. makes a **copy-on-write overlay** so the run is disposable;
3. builds a cloud-init seed (pure-Python ISO — no `genisoimage`/`cloud-localds`
   needed, though it uses them if present) that carries the Cerberus source in
   and **auto-starts the dashboard on boot**;
4. boots QEMU with an **isolated** network — no route to your LAN or the
   internet, only one forwarded port for the dashboard;
5. **deletes the overlay and seed on exit** — nothing the guest did survives.

Then open `http://127.0.0.1:8787` on the host. The code under test now runs two
boundaries deep: Cerberus's sandbox **inside** a disposable VM.

Options:

```bash
python3 -m cerberus.vm run --image fedora        # ubuntu (default) | debian | fedora
python3 -m cerberus.vm run --port 9000           # host port for the dashboard
python3 -m cerberus.vm run --memory 4096 --cpus 4
python3 -m cerberus.vm run --dry-run             # print the QEMU command, don't boot
python3 -m cerberus.vm run --allow-net           # DANGER: give the guest real network
python3 -m cerberus.vm clean                     # remove cached overlays/seeds
python3 -m cerberus.vm clean --images            # also drop downloaded base images
```

Requirements on the host: **`qemu-system-x86_64`** and **`qemu-img`**
(`apt install qemu-system-x86 qemu-utils`, `dnf install @virtualization qemu-img`,
or `pacman -S qemu-full`). KVM (`/dev/kvm`) is used automatically when present;
without it the launcher falls back to slower TCG emulation.

Why this is safe: the guest gets its **own copy** of the source (baked into the
seed, no live host mount), the network uses QEMU user-mode with `restrict=on`
(the guest can't reach your LAN or the internet, only the one forwarded port),
and the disk is a copy-on-write overlay that is deleted on exit.

## The manual QEMU recipe (what the launcher automates)

Useful if you want to customise the VM or understand the moving parts.

```bash
mkdir -p ~/cerberus-vm && cd ~/cerberus-vm
# base image (once)
wget https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img -O base.img
# cloud-init seed
cat > user-data <<'EOF'
#cloud-config
password: cerberus
chpasswd: { expire: false }
ssh_pwauth: true
packages: [python3]
EOF
touch meta-data
cloud-localds seed.img user-data meta-data

# disposable overlay + isolated boot
qemu-img create -f qcow2 -F qcow2 -b base.img overlay.qcow2 16G
qemu-system-x86_64 -enable-kvm -m 2048 -cpu host \
  -drive file=overlay.qcow2,if=virtio \
  -drive file=seed.img,if=virtio \
  -netdev user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:8787-:8787 \
  -device virtio-net,netdev=n0 -display none -serial mon:stdio
rm -f overlay.qcow2      # everything the run touched is gone
```

Inside the guest, copy in the Cerberus source and run
`sudo python3 -m cerberus.web` (or `cerberus.gui`). `restrict=on` is what stops
an escaped payload from reaching your network — keep it.

## Notes

- Snapshot instead of overlay-delete if you want to inspect the aftermath.
- For a lighter boundary, a Firecracker microVM or `runsc` (gVisor) as the
  runtime achieves much of this with less overhead; see `HARDENING.md`.
```
