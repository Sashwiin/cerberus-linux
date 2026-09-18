# Running Cerberus inside a disposable VM

This is the boundary that makes Cerberus safe against a kernel-level escape: put
the whole thing inside a throwaway virtual machine, so even a guest-kernel
break-out only destroys the guest. Do this on the machine you'll run it on — it
needs KVM and a base image, neither of which can be prepared in a generic build
sandbox.

## One-time: a minimal guest image

Use any small cloud image (Fedora Cloud, Ubuntu Cloud, Debian genericcloud).
Example with Ubuntu:

```bash
mkdir -p ~/cerberus-vm && cd ~/cerberus-vm
wget https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img -O base.img
# a cloud-init seed that creates a user and installs python3 + tk
cat > user-data <<'EOF'
#cloud-config
password: cerberus
chpasswd: { expire: false }
ssh_pwauth: true
packages: [python3, python3-tk]
EOF
touch meta-data
cloud-localds seed.img user-data meta-data
```

## Each run: a discardable overlay

The key safety property is that the disk is **copy-on-write and thrown away**, so
nothing the malware does survives:

```bash
cd ~/cerberus-vm
# fresh overlay on top of the immutable base — deleted when the VM exits
qemu-img create -f qcow2 -F qcow2 -b base.img overlay.qcow2 8G

qemu-system-x86_64 \
  -enable-kvm -m 2048 -cpu host \
  -drive file=overlay.qcow2,if=virtio \
  -drive file=seed.img,if=virtio \
  -netdev user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:8787-:8787 \
  -device virtio-net,netdev=n0 \
  -display none -serial mon:stdio

# 'restrict=on' gives the guest NO route to your LAN or the internet, only the
# forwarded dashboard port. When you're done:
rm -f overlay.qcow2      # everything the run touched is gone
```

Inside the guest, copy in the Cerberus source (scp, a 9p share you trust, or bake
it into the image) and run it as usual:

```bash
sudo python3 -m cerberus.web            # or: sudo python3 -m cerberus.gui
```

You reach the dashboard from the host at `http://127.0.0.1:8787`, while the code
under test runs two boundaries deep: Cerberus's sandbox **inside** a disposable
VM. A kernel exploit that breaks Cerberus still lands only in the VM, which you
delete.

## Notes

- `restrict=on` is what stops an escaped payload from reaching your network. Drop
  it only if a test genuinely needs egress, and never onto your real LAN.
- Snapshot instead of overlay-delete if you want to inspect the aftermath:
  `qemu-img snapshot -c clean base.img` once, then `-loadvm clean` per run.
- For a lighter-weight boundary, a Firecracker microVM or `runsc` (gVisor) as the
  runtime achieves much of this with less overhead; see HARDENING.md.
```
