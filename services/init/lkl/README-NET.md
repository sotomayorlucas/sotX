# LKL Net Backend — Loopback Scaffold

Status: **Camino A from `docs/phase-5-design.md`** — scaffold only.
External connectivity requires Camino B (real virtio-net driver).

## What this provides

- Registers a `struct lkl_netdev` (ops + MAC) with LKL so the kernel's
  external TCP/IP stack boots correctly.
- Accepts all tx frames (drops them silently, returns iov total as
  "bytes sent").
- Never produces rx frames (blocks in poll until `poll_hup`).
- Brings the interface up with static IPv4 10.0.2.15/24, gw 10.0.2.2.

## What this does NOT provide

- Real external I/O — `connect(10.0.0.1, ...)` will time out.
- DHCP (static IP is hardcoded to match QEMU user-mode defaults).
- MAC spoofing protection — the hardcoded MAC 52:54:00:AB:CD:EF
  must not collide with the sotos-net service's MAC.

## What 127.0.0.1 does

LKL's kernel builds in a separate `lo` loopback device independent of
any registered netdev. Self-directed syscalls (socket+bind+listen+
connect on 127.0.0.1) work end-to-end inside LKL's TCP/IP stack
without touching this backend. That's the point of Camino A: validate
the dispatcher↔LKL wiring without needing a real NIC.

## Build (from WSL)

```bash
# Outside WSL (Windows):
just build-lkl                    # builds liblkl.a (once)

# Inside WSL:
cd services/init/lkl
make                              # compiles all .c including net_backend.c
                                  # and fuses them with liblkl.a into
                                  # liblkl_fused.a

# Then outside WSL (Windows):
SOTOS_LKL=1 just run-lkl          # boots with LKL + our backend
```

## What the serial log should show

```
[lkl-net-loopback] init (scaffold only — no external carrier)
[lkl-net-loopback] rx_notify=<cap>
[lkl-boot] starting kernel (background)...
[lkl-net-loopback] netdev registered, id=0 mac=52:54:00:ab:cd:ef
[lkl-boot] Linux kernel running!
[lkl-net-loopback] ifindex=2
[lkl-net-loopback] ipv4=10.0.2.15/24
[lkl-net-loopback] gw=10.0.2.2
[lkl-net-loopback] up — external traffic dropped, loopback via LKL internal lo
[lkl-boot] populating rootfs...
...
[lkl-boot] ready — forwarding enabled
LKL: forwarding activated
```

Once `LKL: forwarding activated` appears, the phase-3/4/5a routing
plumbing in the init Rust code starts forwarding whitelisted syscalls
to LKL. All stateless arms (uname/getrandom/etc) hit the real Linux
kernel. fd-creating arms (socket/open/epoll_create) allocate real
LKL fds that go into `LKL_FDS`. fd-indexed arms (read/write/close on
those fds) route through.

## Smoke test from LUCAS shell

Once activated, from LUCAS shell:
```
# This works: LKL's internal lo handles 127.0.0.1
busybox nc -l 127.0.0.1 8080 &
busybox echo hi | busybox nc 127.0.0.1 8080

# This fails (correctly): external IPs have no carrier
busybox wget http://10.0.2.2:8080/    # hangs / times out
```

## Upgrade to Camino B (real NIC)

Replace `sotos_net_tx` and `sotos_net_rx` with a real virtio-net driver
that talks to a second QEMU NIC. Steps:

1. `justfile.lkl` — add a second `-netdev user,id=n1 -device virtio-net-pci,netdev=n1,mac=52:54:00:AB:CD:EF`.
2. Inside `net_backend_init`:
   - `sys_port_in32` scan of PCI bus 0 for the second virtio-net (skip the one sotos-net uses).
   - Allocate virtio RX + TX queues (use existing `sotos-virtio` patterns in Rust as reference — port to C).
   - Register an IRQ for the device.
3. `sotos_net_tx`: copy iovec into virtio TX queue descriptor, notify.
4. `sotos_net_rx`: read from virtio RX queue, copy into iovec.
5. `sotos_net_poll`: `sys_wait_irq` on the device's IRQ.

Estimated size: 400-600 LOC. See `libs/sotos-virtio/src/net.rs` for a
Rust reference of the exact same protocol.

## File layout

```
services/init/lkl/
├── net_backend.h     — public interface (3 functions)
├── net_backend.c     — loopback implementation (this scaffold)
├── disk_backend.h    — sibling for block I/O (via blk service IPC)
├── disk_backend.c    — already implemented (Camino A for disk)
├── Makefile          — builds net_backend.o + fuses with liblkl.a
└── lkl_bridge.c      — orchestrates: init → register → start → up
```
