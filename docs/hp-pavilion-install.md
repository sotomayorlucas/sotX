# Booting sotX on an HP Pavilion laptop

This is the M4 install walkthrough for the HP Pavilion bringup. Everything
up to this point is validated in QEMU-OVMF; the steps below are what's
needed to get a physical Pavilion to run the same image.

> **Risk warning.** sotX is an experimental research OS. It does not touch
> the existing OS on your NVMe — Phase B (M4+) runs entirely from a USB
> stick with the initramfs in RAM — but you are disabling Secure Boot and
> Fast Boot on a machine you rely on. Have a working Windows recovery USB
> on hand before you start.

## 1. Build the disk image

```
just image                                    # rebuild kernel + initrd + image
cp target/sotx.img target/sotx-pavilion.img   # rename for clarity
```

Output: `target/sotx-pavilion.img` (512 MiB). BIOS path uses
`limine-bios.sys`; UEFI path uses `/EFI/BOOT/BOOTX64.EFI`. Both live inside
the FAT32 partition on the image and are selected automatically by the
firmware.

## 2. Flash the USB stick

A USB ≥ 1 GiB is plenty. Flashing **overwrites the entire stick**.

### Windows

1. Install [Rufus](https://rufus.ie/) (no admin install needed).
2. Open Rufus with the stick inserted.
3. Device: pick the USB stick.
4. Boot selection: `Disk or ISO image` → select `target\sotx-pavilion.img`.
5. Rufus will detect it's a raw image and switch to **DD Image mode** — accept.
6. Partition scheme: leave whatever Rufus picked (both work).
7. Click START → wait for "READY".
8. Eject via the tray icon.

### Linux

```bash
lsblk                         # locate the USB, e.g. /dev/sdc — double-check size
sudo dd if=target/sotx-pavilion.img \
        of=/dev/sdc \
        bs=4M conv=fsync status=progress
sync
```

`dd` gives you no safety net if you pick the wrong block device. Verify
the size in `lsblk` matches the stick.

### macOS

```bash
diskutil list                    # find /dev/diskN for the USB
diskutil unmountDisk /dev/diskN
sudo dd if=target/sotx-pavilion.img \
        of=/dev/rdiskN \
        bs=4m
sudo diskutil eject /dev/diskN
```

## 3. Pavilion UEFI settings

On Pavilion models the firmware setup key is **F10** at power-on (or Esc to
get a menu of keys). You may need to mash it a few times before the HP logo
paints — UEFI + Fast Boot gives you < 2 s.

Navigate (keys vary slightly by Pavilion generation):

| Setting            | Value         | Path (typical)                            |
|--------------------|---------------|-------------------------------------------|
| Secure Boot        | **Disabled**  | Security → Secure Boot Configuration      |
| Fast Boot          | **Disabled**  | System Configuration → Boot Options       |
| Legacy Support     | **Disabled**  | System Configuration → Boot Options       |
| Boot Order         | USB at top    | System Configuration → Boot Options       |

Legacy Support stays off because we *want* UEFI; the Limine BIOS stub is a
fallback for non-UEFI firmwares. Save + Exit (F10) and let the laptop reboot.

## 4. Boot the USB

Insert the flashed stick before power-on. Press **F9** during the HP logo
to open the one-time boot menu. Select:

```
USB Hard Drive - <stick label>       (UEFI)
```

If only a non-UEFI entry appears, Secure Boot or Fast Boot is still on —
go back to step 3.

## 5. What you should see

In order, on the laptop screen:

1. **HP logo** from firmware (< 1 s).
2. **Limine 8.x (x86-64, UEFI)** banner with a 3 s countdown to auto-boot
   the `sotX` entry.
3. **`limine: Loading executable` / `Loading module`** — kernel + initrd
   handoff. Takes a few seconds.
4. **sotX ASCII logo + Tokyo Night progress bar** from the kernel splash.
   _Known caveat_: the kernel-side framebuffer renderer (M1) doesn't
   render under QEMU's caching; real-hardware MTRRs should make it work.
   If the screen stays blank through this stage but the machine doesn't
   hang, it's the same QEMU-only issue — keep waiting for step 5.
5. **LUCAS shell prompt** once init takes over the framebuffer via the
   Wayland compositor (~25-30 s under WHPX; unknown on real silicon).

## 6. When things go wrong

| Symptom                                        | Likely cause                                  | What to try                                         |
|------------------------------------------------|-----------------------------------------------|-----------------------------------------------------|
| HP logo → black screen, no Limine              | Secure Boot still on                          | Re-check step 3; also disable UEFI CSM if present   |
| Limine menu, then black screen forever         | Kernel hung pre-init; FB renderer not visible | Hold power 5 s to force off; next boot, check serial if possible |
| LUCAS logo appears but internal keyboard dead  | xHCI enumeration picked wrong port            | Plug a USB-A keyboard dongle in; log `root-hub scan` will show which port |
| `shutdown` / `poweroff` hangs                  | Pavilion firmware needs AML `_PTS` method     | Hold power 5 s; raise as follow-up (AML interp)     |
| Laptop powers off cleanly but won't boot back  | ESP variables cleared                         | Boot Windows recovery USB, restore EFI entry        |

**Serial-less debugging**: laptops have no physical COM1 port. Everything
the kernel prints to serial is invisible. Options:

- **Framebuffer**: the kernel has a minimal text renderer (M1); if the
  screen keeps updating past Limine, the kernel is progressing.
- **Panic trap**: panics reclaim the framebuffer automatically (M1
  `reclaim_for_panic`), so a register dump should show up even mid-boot.
- **Photograph the screen**: progress bar stage + first error line is
  usually enough to narrow the milestone.

## 7. What's not in this image yet

- **No persistent storage.** Everything lives in the 381 MiB initramfs
  that got loaded into RAM. Reboot = fresh slate. Phase B / MVU adds the
  NVMe + sotFS path.
- **No WiFi or Ethernet.** Network is QEMU SLIRP-only for now. Phase C
  sketches a USB-Ethernet CDC-ECM path and an LKL iwlwifi bringup.
- **`sudo` / multi-user / login.** All one root.

## 8. Recovery

If the Pavilion's UEFI variables get mangled (rare but possible when new
boot entries are added):

1. Boot the Windows 10/11 recovery USB you prepared.
2. *Troubleshoot → Advanced options → Command Prompt*.
3. `bootrec /fixboot`, `bootrec /rebuildbcd` — or use HP's firmware menu
   to restore default settings.

Keep the sotX USB stick and the Windows recovery USB **physically
labeled** so you don't accidentally flash over your recovery.

---

Milestones tracked in `C:\Users\sotom\.claude\plans\elegant-watching-floyd.md`
and `memory/project_hp_pavilion_mvb.md`. Logs from first-boot attempts go
into `docs/pavilion-logs/` (gitignored).
