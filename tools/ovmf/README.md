# OVMF — UEFI firmware for QEMU

This directory holds the OVMF firmware binary that QEMU uses to emulate UEFI
for the `run-uefi` recipe. OVMF is the official EDK2 port of UEFI to x86_64
virtual machines.

## Automatic download

```
just fetch-ovmf
```

Pulls `OVMF.fd` (combined code + vars, ~3 MiB) from the
[retrage edk2-nightly mirror](https://retrage.github.io/edk2-nightly/) into
`tools/ovmf/OVMF.fd`. This is the fastest path and what `run-uefi` expects.

## Manual alternatives

If the automatic download fails (firewall, proxy, etc.) or you prefer a
distro-vetted build:

**Ubuntu (WSL or Linux host)**
```
sudo apt install ovmf
cp /usr/share/ovmf/OVMF.fd tools/ovmf/OVMF.fd
```

**Arch**
```
sudo pacman -S edk2-ovmf
cp /usr/share/edk2/x64/OVMF.fd tools/ovmf/OVMF.fd
```

**Fedora**
```
sudo dnf install edk2-ovmf
cp /usr/share/edk2/ovmf/OVMF.fd tools/ovmf/OVMF.fd
```

## Combined vs split firmware

The `run-uefi` recipe uses `-bios tools/ovmf/OVMF.fd` (combined code + vars in
one file). This is simple but UEFI variables (boot entries, Secure Boot state)
do not persist across QEMU runs.

For persistent variables — needed when testing Secure Boot or installing to
the virtual NVMe — use the split layout:

```
tools/ovmf/OVMF_CODE.fd   # read-only firmware code
tools/ovmf/OVMF_VARS.fd   # writable variable store
```

Then invoke QEMU with two pflash drives:

```
-drive if=pflash,format=raw,readonly=on,file=tools/ovmf/OVMF_CODE.fd
-drive if=pflash,format=raw,file=tools/ovmf/OVMF_VARS.fd
```

Download both from
`https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF_{CODE,VARS}.fd`
or extract from the distro packages above (they ship split by default).

## Why OVMF at all

Modern laptops — the HP Pavilion target — only boot UEFI; BIOS/CSM is
frequently disabled in firmware. The existing `just run` uses QEMU's SeaBIOS
which matches sotX's current boot path but is **not** what real hardware will
do. `run-uefi` exercises the same loader (Limine's BOOTX64.EFI) that the
Pavilion will invoke, so regressions show up here first instead of on
hardware.
