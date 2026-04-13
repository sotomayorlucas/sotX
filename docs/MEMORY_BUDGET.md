# sotX Kernel Static Memory Budget

Per-pool inventory of every kernel-resident `static` / `static mut` /
fixed-count array that contributes to the kernel's permanent memory
footprint. All numbers are derived by inspecting `kernel/src/**/*.rs`
at commit `ce4d80b` (sotX branch).

## Methodology

1. Walk every `static` declaration found by
   `^static\s|^pub static\s` in `kernel/src/`.
2. Classify each one by *fixed-size pool* (a `[T; N]` or `struct` with
   inline arrays) versus *heap-backed pool* (a `Pool<T>` / `Vec<T>` /
   `VecDeque<T>` that grows lazily). Heap-backed pools have a near-zero
   permanent footprint at boot — they only consume slab memory once
   populated — so they are listed at the end with their headers' size.
3. For element sizes: when the layout is unambiguous (`#[repr(C)]`,
   plain numeric arrays, atomics) the size is exact. When the type is
   a Rust enum + `Option` + padding, the size is a *conservative
   estimate* and is annotated `~`.
4. Section assignment is based on whether the initializer is non-zero:
   - `static X: T = T::new()` whose `new()` writes only `0` /
     `AtomicU64::new(0)` / `None` / `Mutex::new(0)` → `.bss`
     (kernel image just records "N zero bytes").
   - Anything with non-zero initialization (e.g. `TID_TO_SLOT`'s
     `0xFFFF_FFFF` sentinel) → `.data`.
5. Constants drawn from sources:
   - `MAX_CPUS = 16` — `libs/sotos-common/src/lib.rs:263`
   - `MAX_THREADS = 256` — `kernel/src/sched/mod.rs:343`
   - `MAX_REFCOUNT_FRAMES = 2_097_152` — `kernel/src/mm/mod.rs:41`
   - `DF_STACK_SIZE = 4096 * 5 = 20 480` — `kernel/src/arch/x86_64/gdt.rs:49`
   - `MAX_EP_PER_CORE = 64` — `kernel/src/ipc/endpoint.rs:35`
   - `MAILBOX_SIZE = 32` — `kernel/src/ipc/mailbox.rs:16`
   - `MAX_DEMAND_ENTRIES = 256` — `kernel/src/mm/demand.rs:13`
   - `CACHE_ENTRIES = 64`, `SECTOR_SIZE = 512` — `kernel/src/mm/page_cache.rs:11,14`
   - `MAX_ROUTES = 64` — `kernel/src/ipc/route.rs:24`
   - `MAX_EDGES = 128`, `MAX_NODES = 64` — `kernel/src/ipc/audit.rs:12,14`
   - `MAX_USERS = 32` — `kernel/src/user.rs:16`
   - `MAX_SERVICES = 32`, `MAX_NAME_LEN = 31` — `kernel/src/svc_registry.rs:10,11`
   - `MAX_IRQ = 16`, `MAX_SHARED = 4` — `kernel/src/irq.rs:20,23`

## Inventory — fixed-size statics

### Top contributors (each over 4 KiB)

| Pool | File | Element | Element size | Count | Total bytes | Section |
|------|------|---------|--------------|-------|-------------|---------|
| FRAME_REFCOUNT | kernel/src/mm/mod.rs:42 | `u16` | 2 B | 2 097 152 | 4 194 304 (4 MiB) | .bss |
| PER_CORE_ENDPOINTS | kernel/src/ipc/endpoint.rs:197 | `CoreEndpointPool` (`[Option<Endpoint>;64]`+gens+lock) | ~11 344 B | 16 (MAX_CPUS) | ~181 504 (~177 KiB) | .bss |
| PAGE_FAULT_STACK | kernel/src/arch/x86_64/gdt.rs:55 | `u8` | 1 B | 20 480 | 20 480 (20 KiB) | .bss |
| GP_FAULT_STACK | kernel/src/arch/x86_64/gdt.rs:56 | `u8` | 1 B | 20 480 | 20 480 (20 KiB) | .bss |
| DOUBLE_FAULT_STACK | kernel/src/arch/x86_64/gdt.rs:54 | `u8` | 1 B | 20 480 | 20 480 (20 KiB) | .bss |
| DEMAND_TABLE | kernel/src/mm/demand.rs:121 | `DemandEntry` (`[u64;2]`+flags+bool+`u64`) | ~40 B | 256 | ~10 240 (10 KiB) | .bss |
| PAGE_CACHE | kernel/src/mm/page_cache.rs:97 | `CacheEntry` (4+8+512+1+8+1 → padded) | ~544 B | 64 | ~34 816 (~34 KiB) | .bss |
| THREAD_IPC | kernel/src/sched/mod.rs:369 | `Mutex<ThreadIpcState>` (Message ≈ 80 + role + opt + lock) | ~104 B | 256 | ~26 624 (~26 KiB) | .bss |
| TID_TO_SLOT | kernel/src/sched/mod.rs:376 | `AtomicU32` | 4 B | 256 | 1 024 | **.data** (init = `0xFFFF_FFFF`) |
| PER_CORE_MAILBOXES | kernel/src/ipc/mailbox.rs:69 | `Mailbox` (`[Option<IpcRequest>;32]` + heads + lock) | ~3 360 B | 16 | ~53 760 (~52 KiB) | .bss |

### Smaller statics

| Pool | File | Element | Element size | Count | Total bytes | Section |
|------|------|---------|--------------|-------|-------------|---------|
| TSS_STORAGE | kernel/src/arch/x86_64/gdt.rs:66 | `TaskStateSegment` (`x86_64` crate) | 104 B | 1 | 104 | .bss |
| GDT (Lazy) | kernel/src/arch/x86_64/gdt.rs:86 | `(GlobalDescriptorTable, Selectors)` | ~96 B | 1 | ~96 | .bss |
| IDT (Lazy) | kernel/src/arch/x86_64/idt.rs:71 | `InterruptDescriptorTable` (`x86_64` crate) | 4 096 B | 1 | 4 096 | .bss |
| IRQ_TABLE | kernel/src/irq.rs:51 | `IrqBinding` (`[Option<PoolHandle>;4]`) | 64 B | 16 (MAX_IRQ) | 1 024 | .bss |
| ROUTE_TABLE | kernel/src/ipc/route.rs:109 | `RouteEntry` (`u32+u16+u32+bool` padded) ×64 + count + node | ~1 040 B | 1 | ~1 040 | .bss |
| IPC_GRAPH | kernel/src/ipc/audit.rs:203 | `IpcGraph` (`[Option<Edge>;128]` + nodes + counters) | ~2 144 B | 1 | ~2 144 | .bss |
| PER_CPU_QUEUES | kernel/src/sched/mod.rs:239 | `TicketMutex<CpuQueue>` (4 × VecDeque header + lock) | ~104 B | 16 (MAX_CPUS) | ~1 664 | .bss |
| GLOBAL_READY | kernel/src/sched/mod.rs:247 | `TicketMutex<CpuQueue>` | ~104 B | 1 | ~104 | .bss |
| SCHEDULER | kernel/src/sched/mod.rs:454 | `TicketMutex<Scheduler>` (Pool headers + tid_to_slot[256]) | ~2 104 B | 1 | ~2 104 | .bss |
| HEARTBEATS | kernel/src/watchdog.rs:19 | `AtomicU64` | 8 B | 16 (MAX_CPUS) | 128 | .bss |
| PENDING_COUNT | kernel/src/ipc/mailbox.rs:75 | `AtomicU32` | 4 B | 16 (MAX_CPUS) | 64 | .bss |
| CPU_CACHES | kernel/src/mm/slab.rs:236 | `Mutex<SlabAllocator>` (8 SizeClass + ready + lock) | ~152 B | 16 (MAX_CPUS) | ~2 432 | .bss |
| WX_RELAXED | kernel/src/mm/paging.rs:28 | `AtomicU64` | 8 B | 4 | 32 | .bss |
| USER_TABLE | kernel/src/user.rs:255 | `Mutex<UserTable>` (`[UserAccount;32]` ≈ 166 B + counters) | ~5 336 B | 1 | ~5 336 (~5 KiB) | .bss |
| REGISTRY | kernel/src/svc_registry.rs:92 | `Mutex<Registry>` (`[ServiceEntry;32]` ≈ 36 B each + count) | ~1 160 B | 1 | ~1 160 | .bss |
| FAULT_STATE | kernel/src/fault.rs:67 | `Mutex<FaultState>` (Vec/VecDeque headers only) | ~80 B | 1 | ~80 | .bss |
| __stack_chk_guard | kernel/src/main.rs:48 | `u64` | 8 B | 1 | 8 | **.data** (sentinel `0x00000aff0a0d0000`) |

### Tiny / atomic / scalar statics (each ≤ 16 B)

These are listed for completeness; their combined contribution is well
under 1 KiB.

| Pool | File:Line | Type | Bytes |
|------|-----------|------|-------|
| SERIAL_LOCK | arch/x86_64/serial.rs:9 | `Mutex<()>` | ~4 |
| LAPIC_BASE | arch/x86_64/lapic.rs:9 | `AtomicU64` | 8 |
| CALIBRATED_TICKS | arch/x86_64/lapic.rs:12 | `AtomicU32` | 4 |
| DEBUG_PROFILE_CR3 | arch/x86_64/idt.rs:863 | `AtomicU64` | 8 |
| INITRD_PHYS_BASE | initrd.rs:9 | `AtomicU64` | 8 |
| INITRD_SIZE | initrd.rs:11 | `AtomicU64` | 8 |
| HHDM_OFFSET | mm/mod.rs:20 | `AtomicU64` | 8 |
| PRNG_STATE | mm/mod.rs:80 | `AtomicU64` | 8 |
| BOOT_CR3 | mm/paging.rs:18 | `AtomicU64` | 8 |
| ALLOCATOR (frame) | mm/frame.rs:41 | `Mutex<Option<BitmapAllocator>>` | ~48 |
| ALLOCATOR (slab) | mm/slab.rs:269 | `KernelAllocator` (ZST) | 0 |
| PERCPU_READY | mm/slab.rs:27 | `AtomicBool` | 1 |
| PANICKING | panic.rs:6 | `AtomicBool` | 1 |
| GLOBAL_TICKS | sched/mod.rs:68 | `AtomicU64` | 8 |
| TRACE_LEVEL | trace.rs:10 | `AtomicU8` | 1 |
| TRACE_CATS | trace.rs:13 | `AtomicU16` | 2 |
| APS_READY | main.rs:107 | `AtomicU32` | 4 |
| GUEST_ENTRY | main.rs:110 | `AtomicU64` | 8 |
| Limine request markers (×7) | main.rs:69-104 | request structs | ~32 each, ~224 |
| CAP_TABLE | cap/mod.rs:18 | `Mutex<CapabilityTable>` (Pool headers only) | ~80 |
| CHANNELS | ipc/channel.rs:65 | `TicketMutex<Pool<Channel>>` (header only) | ~80 |
| NOTIFICATIONS | ipc/notify.rs:33 | `TicketMutex<Pool<Notification>>` (header only) | ~80 |

## Heap-backed pools (zero static footprint)

These declarations look like statics but their backing storage is a
`Pool<T>`/`Vec<T>`/`VecDeque<T>` that lives on the kernel slab heap.
At boot they consume only the size of their inline header
(usually three pointers + a length, ~32 bytes each); their real
memory is allocated lazily from `slab.rs` on first insert. They are
*not* counted in the static budget below.

| Pool | File | Backing | Notes |
|------|------|---------|-------|
| `Scheduler.threads` | kernel/src/sched/mod.rs:389 | `Pool<Thread>` | up to 256 threads, sizeof(Thread) ≈ 600 B (~150 KiB max in slab) |
| `Scheduler.domains` | kernel/src/sched/mod.rs:390 | `Pool<SchedDomain>` | each `SchedDomain` ≈ 300 B + suspended `Vec` |
| `CapabilityTable.entries` | kernel/src/cap/table.rs:113 | `Pool<CapEntry>` | grows on demand |
| `CHANNELS` | kernel/src/ipc/channel.rs:65 | `Pool<Channel>` | each `Channel` ≈ 16 × 88 B ≈ 1.4 KiB |
| `NOTIFICATIONS` | kernel/src/ipc/notify.rs:33 | `Pool<Notification>` | small entries |
| `FAULT_STATE.handlers` | kernel/src/fault.rs:44 | `Vec<FaultHandler>` | one per registered AS |
| `FAULT_STATE.cr3_caps` | kernel/src/fault.rs:49 | `Vec<Cr3CapEntry>` | one per registered AS |

## Total static footprint

Summing the *fixed-size* rows above (excluding heap-backed pools):

| Bucket | Bytes | KiB |
|--------|------:|----:|
| FRAME_REFCOUNT | 4 194 304 | 4 096 |
| PER_CORE_ENDPOINTS | ~181 504 | ~177 |
| PER_CORE_MAILBOXES | ~53 760 | ~52 |
| PAGE_CACHE | ~34 816 | ~34 |
| THREAD_IPC | ~26 624 | ~26 |
| Three IST stacks (DOUBLE/PAGE/GP) | 61 440 | 60 |
| DEMAND_TABLE | ~10 240 | ~10 |
| USER_TABLE | ~5 336 | ~5 |
| IDT | 4 096 | 4 |
| SCHEDULER | ~2 104 | ~2 |
| IPC_GRAPH | ~2 144 | ~2 |
| CPU_CACHES | ~2 432 | ~2 |
| PER_CPU_QUEUES + GLOBAL_READY | ~1 768 | ~2 |
| ROUTE_TABLE | ~1 040 | ~1 |
| REGISTRY | ~1 160 | ~1 |
| IRQ_TABLE | 1 024 | 1 |
| TID_TO_SLOT | 1 024 | 1 |
| All small atomics + scalars | ~700 | <1 |

**Sum ≈ 4 585 516 bytes ≈ 4.37 MiB**, of which **4.0 MiB is the
single `FRAME_REFCOUNT` table**. Without the refcount table the
remainder is ~390 KiB.

### Top 5 largest pools

1. `FRAME_REFCOUNT` — 4 MiB (`mm/mod.rs:42`)
2. `PER_CORE_ENDPOINTS` — ~177 KiB (`ipc/endpoint.rs:197`)
3. `PER_CORE_MAILBOXES` — ~52 KiB (`ipc/mailbox.rs:69`)
4. `PAGE_CACHE` — ~34 KiB (`mm/page_cache.rs:97`)
5. `THREAD_IPC` — ~26 KiB (`sched/mod.rs:369`)

## Comments / red flags

- **`FRAME_REFCOUNT` dwarfs everything else.** The comment in
  `kernel/src/mm/mod.rs:39` says "Table size: 1048576 × 2 bytes = 2 MB
  static allocation", but the actual constant
  `MAX_REFCOUNT_FRAMES = 2_097_152` (line 41) makes the real cost
  **4 MiB**. Either the constant or the comment is wrong, and the
  table is sized for 8 GiB of RAM regardless of what QEMU is launched
  with (default `-m 256M` only needs ~128 KiB of refcounts at this
  granularity, ~32× over-provisioned for the typical dev VM and
  ~16× for the documented 512 MiB default).
- Source comment at `kernel/src/mm/mod.rs:39` (corrected in this PR)
  previously said "2 MB static allocation"; the actual cost is 4 MB.
- **Per-core IPC pools scale linearly with `MAX_CPUS = 16`.** The
  endpoint pool (~11 KiB/core) and mailbox (~3.3 KiB/core) together
  consume **~228 KiB** even on a single-CPU boot. If `MAX_CPUS` is
  ever raised to 32 or 64, this becomes a noticeable hot spot.
- **`PAGE_CACHE` is statically sized for 64 sectors of 512 B each
  plus headers.** That is fine for the current LRU prototype but
  cannot grow with disk size; rewriting it as a slab-backed structure
  would let it shrink to a header on small VMs.
- **`THREAD_IPC` and `TID_TO_SLOT` are fixed at `MAX_THREADS = 256`.**
  Together they cost ~28 KiB and bound the thread count even though
  the underlying `Pool<Thread>` is heap-backed.
- **`USER_TABLE` is ~5 KiB despite having a single root user.** The
  `[UserAccount; 32]` array is always materialized; a `Vec<UserAccount>`
  would shrink the boot footprint to a header.
- **`DEMAND_TABLE` (10 KiB), `IPC_GRAPH` (~2 KiB),
  `ROUTE_TABLE` (~1 KiB) and `REGISTRY` (~1 KiB)** are all
  fixed-size search arrays. They are small in absolute terms but
  every lookup is O(N); converting them to heap-backed maps would
  reduce both footprint and worst-case latency.
- **Three IST stacks of 20 KiB each** are statically allocated for
  early boot (`gdt.rs:54-56`); SMP CPUs get their own from the frame
  allocator via `init_percpu()`. The static stacks remain reachable
  but unused after `init_percpu()` runs on the BSP — ~60 KiB of
  permanently dead `.bss`.
- **Build status (verification gap)**: at the inspected commit
  `cargo build --release --package sotos-kernel` fails with
  `E0583` ("file not found for module") for several modules
  (`sched::shm`, `ipc::ipc`, `mm::memory`, `cap::cap`, `irq::irq`,
  `ipc::notify`, `fault::fault`, `sched::domain::domain`,
  `service`, `thread`, `debug`). These are pre-existing breakages
  unrelated to this inventory; the numbers above are derived from
  source inspection only and could not be cross-checked against the
  output of `size target/x86_64-unknown-none/release/sotos-kernel`.
  Once the build is fixed, the numbers in the table above should be
  re-validated against `objdump -h` and `size`.
- All sizes annotated `~` are conservative estimates: they assume
  natural alignment (8-byte for any struct containing a `u64`),
  count `Option<T>` as `T + 8` when `T` has no niche, and add a
  4 B header for `spin::Mutex` / `TicketMutex` wrappers. Real sizes
  may differ by ±10% per row; the totals are accurate to one
  significant figure.
