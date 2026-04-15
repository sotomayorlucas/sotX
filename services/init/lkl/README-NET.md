# LKL Net Backend — Camino B (real NIC via IPC to net-raw)

Status: **Camino B from `docs/phase-5-design.md`** — real external
connectivity when built with `SOTOS_LKL=1` and booted with a second
virtio-net NIC exposed to QEMU.

## Architecture

Mirror of `disk_backend.c` / `blk` service:

```
┌─────────────────────────────────────────────────┐
│ init process                                     │
│                                                  │
│  ┌──────────────┐    IPC     ┌────────────────┐ │
│  │ LKL kernel   │◄───────────┤ net-raw        │ │
│  │ (in-process) │  TX/RX     │ service thread │ │
│  └──────┬───────┘            │ owns 2nd NIC   │ │
│         │                    └────────┬───────┘ │
│         │ lkl_dev_net_ops             │         │
│         ▼                             ▼         │
│  net_backend.c ──────────────► sotos_virtio::  │
│  (this file)                    VirtioNet      │
│                                       │         │
└───────────────────────────────────────┼─────────┘
                                        ▼
                                   QEMU virtio-net #1
                                   (netdev=n1,
                                    mac=52:54:00:AB:CD:EF)

     sotos-net service (separate process) owns NIC #0.
```

## What this provides

- **Real external connectivity** for LKL's TCP/IP stack.
- `connect(10.0.0.x, ...)` traverses: LKL → net_backend.c TX → IPC
  CMD_TX → net-raw handler → VirtioNet::transmit → QEMU NIC #1 → host.
- RX arrives on NIC #1 → VirtioNet::poll_rx → IPC CMD_RX_POLL/WAIT
  → net_backend.c RX → LKL.
- No coordination needed with sotos-net (which owns NIC #0 separately).

## IPC protocol (`net-raw` service)

Defined in `services/init/src/main.rs`:

| Cmd | Name | Args | Reply |
|---|---|---|---|
| 1 | `TX` | `regs[0]=frame_vaddr, regs[1]=len, regs[2]=self_as_cap` | `regs[0]=bytes_sent or -errno` |
| 2 | `RX_POLL` | `regs[0]=dst_vaddr, regs[1]=len, regs[2]=self_as_cap` | `regs[0]=bytes_recvd (0 if none)` |
| 3 | `MAC` | — | `regs[0..5]=MAC bytes` |
| 4 | `RX_WAIT` | `regs[0]=dst_vaddr, regs[1]=len, regs[2]=self_as_cap` | blocks, then `regs[0]=bytes_recvd` |

Frames are raw Ethernet (dst MAC + src MAC + ethertype + payload).
The service strips the virtio-net 10-byte header before returning
RX data, so LKL sees pure L2 frames.

## Build (from WSL)

```bash
# Outside WSL (Windows):
just build-lkl                    # build liblkl.a (once)

# Inside WSL:
cd services/init/lkl
make                              # compile net_backend.c, fuse with lkl → liblkl_fused.a

# Outside WSL:
SOTOS_LKL=1 just run-lkl          # boots with 2 NICs, LKL active
```

### Local `justfile.lkl` update

Because `justfile.lkl` is gitignored (developer-local workflow), each
maintainer must manually add the second `-netdev/-device` pair to
their local `run-lkl` recipe. Change:

```
run-lkl: image-lkl create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -netdev user,id=net1,hostfwd=tcp::12345-:22 \
        -device virtio-net-pci,netdev=net1,disable-modern=on,mac=52:54:00:AB:CD:EF \
        -serial stdio \
        -no-reboot \
        -m 2048M
```

Key adds:
- `-netdev user,id=net1,hostfwd=tcp::12345-:22` — second user-mode
  network with host port 12345 forwarded to LKL port 22. (Pick any
  port for your own tests.)
- `-device virtio-net-pci,netdev=net1,disable-modern=on,mac=52:54:00:AB:CD:EF`
  — second NIC with a deterministic MAC so LKL's IP is stable.

## Expected serial log

On boot (truncated to net-relevant lines):
```
NETRAW-SVC: found second virtio-net at dev 4 IRQ 10
NETRAW-SVC: MAC=52:54:00:ab:cd:ef
NETRAW-SVC: registered as 'net-raw', handler started
[lkl-net-raw] looking up 'net-raw' service...
[lkl-net-raw] net-raw ep=<n>
[lkl-net-raw] self_as=<n>
[lkl-net-raw] mac=52:54:00:ab:cd:ef
[lkl-net-raw] netdev registered, id=0
[lkl-boot] starting kernel (background)...
[lkl-boot] Linux kernel running!
[lkl-net-raw] ifindex=2
[lkl-net-raw] ipv4=10.0.2.15/24
[lkl-net-raw] gw=10.0.2.2
[lkl-net-raw] up — external connectivity via net-raw service
[lkl-boot] ready — forwarding enabled
LKL: forwarding activated
```

## Smoke tests

```bash
# Outside WSL — connect to LKL's port forward (QEMU -hostfwd tcp::12345-:22)
telnet localhost 12345            # fails: nothing listening on :22 inside LKL, but
                                  # packets traverse the stack

# Inside LKL (once we have a userspace binary in initrd):
SOTOS_LKL=1 just run-lkl          # inside: busybox wget http://10.0.2.2:8080/...
python scripts/test_alpine_wget.py  # should now see external HTTP fetch
```

## Graceful degradation modes

| Build / runtime | Effect |
|---|---|
| `SOTOS_LKL=0` (default) | `net-raw` handler idles (never receives IPC). No cost. |
| `SOTOS_LKL=1`, single NIC | `NETRAW-SVC: no second virtio-net (skipping...)` — LKL boots without external net; 127.0.0.1 still works. |
| `SOTOS_LKL=1`, two NICs | Full activation per log above. |
| `SOTOS_LKL=1`, `net-raw` service crashes | `[lkl-net-raw] 'net-raw' not found` — LKL boots without external net. |

## Design decisions

1. **Dedicated second NIC** (not shared with sotos-net) — cleanest.
   No coordination / classifier logic. Both run full TCP/IP stacks
   independently.
2. **Flatten iovec into `tx_staging` / `rx_staging`** — simpler than
   scatter-gather at the IPC boundary. Max frame 1514 bytes fits in
   1 page. Cost: one memcpy per direction, well under QEMU's latency.
3. **Block in `poll()` via CMD_RX_WAIT** (not busy-loop) — the
   handler thread in init does the yielding, our bridge thread sleeps
   inside sys_call. Correctness under SMP.
4. **Self-AS cap read from BootInfo** (0xB00000+312) — same as
   disk_backend.c. No cap fork issues.

## Upgrade paths

1. **IRQ-driven RX** — the handler currently yield-spins in `RX_WAIT`.
   Wire `net.wait_irq()` (already in `VirtioNet`) so the thread
   actually blocks on IRQ until a frame arrives. ~20 LOC.
2. **DHCP instead of static IP** — call `lkl_start_dhcp(ifindex)`
   after `lkl_if_up`. Requires pinning the NIC's MAC to avoid IP
   collisions across boots.
3. **Zero-copy** — map the caller's AS page directly into the TX
   buffer instead of memcpy'ing through `tx_staging`. Depends on
   caller (LKL) aligning frames to page boundaries; current LKL
   passes short iovecs so copy is cheaper anyway.

## Related

- `docs/phase-5-design.md` — full phase 5 architecture
- `services/init/lkl/disk_backend.c` — sibling for block I/O
- `services/init/src/main.rs::start_raw_net_service` — service wiring
- `services/init/src/main.rs::raw_net_handler` — IPC handler loop
- `libs/sotos-virtio/src/net.rs` — `NetVaddrs` + `init_at` + `nth_device`
- `justfile.lkl::run-lkl` — QEMU cmdline with 2 NICs
