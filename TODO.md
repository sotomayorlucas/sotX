# sotOS — TODO

## Tech Debt (all resolved)
- [x] Fix 31 kernel warnings (dead code, unused imports)
- [x] Separate VMM into its own process (now services/vmm/, own CR3)
- [x] Fix IRQ sharing — up to 4 handlers per IRQ line (virtio-blk + virtio-net on IRQ 11)

## Networking
- [x] IPC channel between net process and init (svc_register/svc_lookup + IPC commands)
- [x] DNS resolver (libs/sotos-net/src/dns.rs — A-record query/parse)
- [x] Socket API for LUCAS shell (`socket()`, `connect()`, `send()`, `recv()`, `close()`)
- [x] DHCP client (Discover/Offer/Request/Ack, falls back to 10.0.2.15)
- [x] `ping` / `wget` as shell commands
- [x] `traceroute` shell command (ICMP with custom TTL, works on local subnet; SLIRP doesn't forward Time Exceeded)
- [x] DNS resolution from shell (resolve/ping/wget accept hostnames via custom syscall 200 → net IPC)

## Filesystem
- [ ] Directory hierarchy (object store is currently flat)
- [ ] CoW snapshots for atomic transactions
- [ ] Large file support (currently limited by data region size)

## Kernel / Architecture
- [x] Real SMP boot — `-smp 4` default on all targets, TSC timeout on AP boot
- [x] Userspace process spawning — InitrdRead/BootInfoWrite syscalls, ELF parser, spawn_process()
- [x] IPC server registry — SvcRegister/SvcLookup syscalls, kernel-side name→endpoint registry
- [x] Dynamic linking / shared libraries — sotos-ld linker, dl_open/dl_sym/dl_close, PIC .so support

## Security
- [x] W^X enforcement (NX bit on non-executable ELF segments, SYS_MAP enforces W→NX)
- [x] Stack guard pages (unmapped page below each process stack)
- [x] ASLR (stack base randomized with RDTSC-seeded xorshift64, 0-64KB jitter)
- [x] Stack canaries (`-Z stack-protector=strong`, fixed sentinel canary, 1800+ check sites per binary)

## Drivers
- [ ] AHCI / NVMe storage
- [ ] USB (HID at minimum)
- [ ] Audio

## Dream Goals
- [ ] Self-hosting (port the Rust compiler)
