/*
 * lkl_bridge.c — Fusion point: LKL as backend of LUCAS.
 *
 * Provides two functions callable from Rust via FFI:
 *   lkl_bridge_init()    — boot Linux 6.6 kernel inside init process
 *   lkl_bridge_syscall() — translate x86_64 syscall + guest memory bridge + lkl_syscall()
 *
 * All LKL calls happen in the same address space as init (no IPC).
 *
 * Concurrency model (per docs/lkl-futex-fix-design.md, Solution A):
 *   Previously a single process-wide `bridge_lock` serialized every entry
 *   into this function. That deadlocked FUTEX_WAIT: a waiter held the lock
 *   while blocked inside LKL, so the waker could never acquire it.
 *
 *   Each child pid has exactly one init-side IPC handler thread, so the
 *   static scratch buffers only need per-pid isolation, not a global lock.
 *   `g_scratch[pid - 1]` gives each handler its own buffer and LKL handles
 *   its own internal serialization via `lkl_cpu_get/put`. `bridge_lock` is
 *   therefore removed entirely.
 */

#include <stdint.h>
#include "sotos_syscall.h"
#include "allocator.h"
#include "host_ops.h"
#include "guest_mem.h"
#include "libc_stubs.h"
#include "syscall_xlat.h"
#include "disk_backend.h"
#include "net_backend.h"

#ifdef HAS_LKL
#include <lkl.h>
#include <lkl_host.h>
#include <lkl/asm/host_ops.h>
#else
#include "lkl_stub.h"
#endif

/* Per-pid scratch buffers for guest memory bridge (see file header for
 * the concurrency rationale). MAX_THREADS must match MAX_PROCS in
 * services/init/src/process.rs. */
#define MAX_THREADS 64
struct per_thread_bridge_scratch {
    char path_buf[4096];
    char path_buf2[4096];
    char data_buf[4096];
    char stat_buf[256];
    char sockaddr_buf[128];
};
static struct per_thread_bridge_scratch g_scratch[MAX_THREADS];

static volatile int lkl_ready = 0;

#ifdef HAS_LKL
static struct lkl_host_operations g_host_ops;

/* ── LKL block device callbacks (disk_backend.c provides the actual I/O) ── */

static int sotos_blk_get_capacity(struct lkl_disk disk, unsigned long long *res)
{
    (void)disk;
    uint64_t cap = disk_capacity();
    if (cap == 0) return -1;
    *res = (unsigned long long)cap;
    return 0;
}

static int sotos_blk_request(struct lkl_disk disk, struct lkl_blk_req *req)
{
    (void)disk;

    if (req->type == LKL_DEV_BLK_TYPE_FLUSH ||
        req->type == LKL_DEV_BLK_TYPE_FLUSH_OUT) {
        /* Nothing to flush for IPC-based backend — data is already committed
         * by the blk service after each write. */
        return LKL_DEV_BLK_STATUS_OK;
    }

    unsigned long long sector = req->sector;

    for (int i = 0; i < req->count; i++) {
        void  *data = req->buf[i].iov_base;
        size_t len  = req->buf[i].iov_len;

        if (req->type == LKL_DEV_BLK_TYPE_READ) {
            int ret = disk_read(data, sector * 512, len);
            if (ret < 0) return LKL_DEV_BLK_STATUS_IOERR;
        } else if (req->type == LKL_DEV_BLK_TYPE_WRITE) {
            int ret = disk_write(data, sector * 512, len);
            if (ret < 0) return LKL_DEV_BLK_STATUS_IOERR;
        } else {
            return LKL_DEV_BLK_STATUS_UNSUP;
        }

        /* Advance sector position for the next scatter-gather element. */
        sector += (len + 511) / 512;
    }

    return LKL_DEV_BLK_STATUS_OK;
}

/* Boot thread: runs lkl_start_kernel on a separate sotX thread so init
 * can continue to the shell while the Linux kernel boots in background. */
static void lkl_boot_thread_fn(void *arg)
{
    (void)arg;

    /* Net backend MUST register BEFORE lkl_start_kernel.
     * Verified empirically: post-start triggers `lkl_cpu_put: unbalanced
     * put` inside virtio_dev_setup → Linux kernel BUG. The pre-start
     * path uses the cmdline `virtio_mmio.device=...` mechanism instead
     * of lkl_sys_virtio_mmio_device_add, which avoids the cpu_put issue. */
    net_backend_init();
    int lkl_net_id = net_backend_register();

    serial_puts("[lkl-boot] starting kernel (background)...\n");
    int rc = lkl_start_kernel("mem=64M loglevel=3");
    if (rc < 0) {
        serial_puts("[lkl-boot] lkl_start_kernel FAILED\n");
        sys_thread_exit();
    }
    serial_puts("[lkl-boot] Linux kernel running!\n");

    /* if_up/set_ipv4 require start_kernel (use real syscalls). */
    if (lkl_net_id >= 0) {
        (void)net_backend_up(lkl_net_id);
    }

    /* Smoke test */
    struct { char s[65]; char n[65]; char r[65]; char v[65]; char m[65]; char d[65]; } uts;
    memset(&uts, 0, sizeof(uts));
    long params[6] = {(long)&uts, 0, 0, 0, 0, 0};
    long urc = lkl_syscall(160, params);
    if (urc == 0) {
        serial_puts("[lkl-boot] uname: ");
        serial_puts(uts.s);
        serial_puts(" ");
        serial_puts(uts.r);
        serial_puts("\n");
    }

    /* ── Populate rootramfs (tmpfs already mounted at / by Linux) ── */
    serial_puts("[lkl-boot] populating rootfs...\n");

    /* Create essential directories (mkdirat = generic 34) */
    static const char *dirs[] = {
        "/tmp", "/dev", "/etc", "/proc", "/sys", "/var",
        "/var/tmp", "/root", "/lib", "/bin", "/sbin",
        "/usr", "/usr/lib", "/usr/bin", NULL
    };
    for (int i = 0; dirs[i]; i++) {
        long dp[6] = {-100 /* AT_FDCWD */, (long)dirs[i], 0755, 0, 0, 0};
        lkl_syscall(34 /* mkdirat */, dp);
    }

    /* chdir("/") (generic 49) */
    {
        long cp[6] = {(long)"/", 0, 0, 0, 0, 0};
        lkl_syscall(49 /* chdir */, cp);
    }

    /* Helper: write a small file */
    #define LKL_WRITE_FILE(path, content) do { \
        long _op[6] = {-100, (long)(path), 0102 /* O_WRONLY|O_CREAT */, 0644, 0, 0}; \
        long _fd = lkl_syscall(56 /* openat */, _op); \
        if (_fd >= 0) { \
            long _wp[6] = {_fd, (long)(content), sizeof(content)-1, 0, 0, 0}; \
            lkl_syscall(64 /* write */, _wp); \
            long _cp[6] = {_fd, 0, 0, 0, 0, 0}; \
            lkl_syscall(57 /* close */, _cp); \
        } \
    } while (0)

    LKL_WRITE_FILE("/etc/hostname", "sotos\n");
    LKL_WRITE_FILE("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\n");
    LKL_WRITE_FILE("/etc/group", "root:x:0:\n");
    LKL_WRITE_FILE("/etc/resolv.conf", "nameserver 10.0.2.3\n");

    #undef LKL_WRITE_FILE

    serial_puts("[lkl-boot] rootfs ready\n");

    /* ── Mount real ext4 disk via virtio-blk IPC ── */
    if (disk_init() == 0) {
        serial_puts("[lkl-boot] registering disk with LKL...\n");
        static struct lkl_dev_blk_ops sotos_blk_ops;
        sotos_blk_ops.get_capacity = sotos_blk_get_capacity;
        sotos_blk_ops.request      = sotos_blk_request;

        struct lkl_disk disk;
        memset(&disk, 0, sizeof(disk));
        disk.ops = &sotos_blk_ops;

        int disk_id = lkl_disk_add(&disk);
        if (disk_id < 0) {
            serial_puts("[lkl-boot] lkl_disk_add failed: ");
            serial_put_dec((uint64_t)(-(long)disk_id));
            serial_puts("\n");
        } else {
            serial_puts("[lkl-boot] disk_id=");
            serial_put_dec((uint64_t)disk_id);
            serial_puts(", mounting ext4...\n");

            char mnt_str[64];
            memset(mnt_str, 0, sizeof(mnt_str));
            long mrc = lkl_mount_dev((unsigned int)disk_id, 0, "ext4",
                                     0, NULL, mnt_str, sizeof(mnt_str));
            if (mrc == 0) {
                serial_puts("[lkl-boot] ext4 mounted at: ");
                serial_puts(mnt_str);
                serial_puts("\n");

                /* Bind-mount or symlink /mnt -> mount point for easy access */
                long mp[6] = {-100 /* AT_FDCWD */, (long)"/mnt", 0755, 0, 0, 0};
                lkl_syscall(34 /* mkdirat */, mp);
                /* mount --bind mnt_str /mnt */
                long bp[6] = {(long)mnt_str, (long)"/mnt", 0, 0x1000 /* MS_BIND */, 0, 0};
                long brc = lkl_syscall(40 /* mount */, bp);
                if (brc == 0)
                    serial_puts("[lkl-boot] bind-mounted at /mnt\n");
            } else {
                serial_puts("[lkl-boot] ext4 mount failed (");
                serial_put_dec((uint64_t)(-(long)mrc));
                serial_puts("), trying ext2...\n");

                memset(mnt_str, 0, sizeof(mnt_str));
                mrc = lkl_mount_dev((unsigned int)disk_id, 0, "ext2",
                                    0, NULL, mnt_str, sizeof(mnt_str));
                if (mrc == 0) {
                    serial_puts("[lkl-boot] ext2 mounted at: ");
                    serial_puts(mnt_str);
                    serial_puts("\n");
                } else {
                    serial_puts("[lkl-boot] disk mount failed, continuing without\n");
                }
            }
        }
    }

    lkl_ready = 1;
    serial_puts("[lkl-boot] ready — forwarding enabled\n");
    sys_thread_exit();
}

/* Boot thread entry: naked asm stub for stack alignment + call. */
static volatile uint64_t boot_thread_fn_ptr;
__asm__(
    ".globl lkl_boot_trampoline\n"
    "lkl_boot_trampoline:\n"
    "    and $-16, %rsp\n"
    "    xor %edi, %edi\n"           /* arg = NULL */
    "    movabs $boot_thread_fn_ptr, %rax\n"
    "    movq (%rax), %rax\n"
    "    call *%rax\n"
    "    ud2\n"
);
extern void lkl_boot_trampoline(void);
#endif

/* ---------------------------------------------------------------
 * lkl_bridge_init — called once from Rust main.rs at boot.
 * Returns immediately. LKL boots in background thread.
 * --------------------------------------------------------------- */
int lkl_bridge_init(void)
{
    serial_puts("[lkl-bridge] init arena...\n");
    if (arena_init() < 0) {
        serial_puts("[lkl-bridge] arena_init failed\n");
        return -1;
    }

#ifdef HAS_LKL
    volatile char *p = (volatile char *)&g_host_ops;
    for (unsigned long i = 0; i < sizeof(g_host_ops); i++) p[i] = 0;
    host_ops_init(&g_host_ops);

    /* CRITICAL: tools/lkl/lib/{posix,nt}-host.c defines a GLOBAL
     * `struct lkl_host_operations lkl_host_ops` (NOT a pointer) whose
     * default mem_alloc points to posix_malloc, which calls libc's
     * malloc — unavailable in our freestanding build. virtio_net.c +
     * other tools/lkl code use `lkl_host_ops.X` directly, bypassing
     * lkl_init(). We must memcpy our ops INTO the global so those
     * call sites land on our handlers. lkl_init() then also wires
     * `lkl_ops = &g_host_ops` for the kernel-internal call sites.
     * Discovered when lkl_netdev_add returned -ENOMEM without ever
     * calling our lkl_mem_alloc (allocs counter unchanged). */
    {
        extern struct lkl_host_operations lkl_host_ops;
        const char *src = (const char *)&g_host_ops;
        char *dst = (char *)&lkl_host_ops;
        for (unsigned long i = 0; i < sizeof(g_host_ops); i++) dst[i] = src[i];
    }

    int rc = lkl_init(&g_host_ops);
    if (rc < 0) {
        serial_puts("[lkl-bridge] lkl_init failed\n");
        return rc;
    }
    serial_puts("[lkl-bridge] lkl_init OK, spawning boot thread...\n");

    /* Spawn boot thread: allocate 64KB stack, create thread */
    boot_thread_fn_ptr = (uint64_t)lkl_boot_thread_fn;
    #define LKL_BOOT_STACK_BASE 0x34200000ULL
    #define LKL_BOOT_STACK_PAGES 16
    for (int i = 0; i < LKL_BOOT_STACK_PAGES; i++) {
        uint64_t frame = sys_frame_alloc();
        if ((int64_t)frame < 0) {
            serial_puts("[lkl-bridge] stack frame_alloc failed\n");
            return -12;
        }
        sys_map(LKL_BOOT_STACK_BASE + i * 0x1000, frame, 2 /* MAP_WRITABLE */);
    }
    uint64_t stack_top = LKL_BOOT_STACK_BASE + LKL_BOOT_STACK_PAGES * 0x1000;
    int64_t tid = sys_thread_create(
        (uint64_t)lkl_boot_trampoline, stack_top, 0);
    if (tid < 0) {
        serial_puts("[lkl-bridge] thread_create failed\n");
        return (int)tid;
    }
    serial_puts("[lkl-bridge] boot thread spawned (tid=");
    serial_put_dec((uint64_t)tid);
    serial_puts("), init continues\n");
    return 0;
#else
    serial_puts("[lkl-bridge] stub mode\n");
    return 0;
#endif
}

/* ---------------------------------------------------------------
 * lkl_bridge_syscall — called from child_handler for each forwarded syscall
 *
 * x86_nr:  x86_64 Linux syscall number
 * args:    6 syscall arguments (rdi, rsi, rdx, r10, r8, r9)
 * as_cap:  child address-space cap (for vm_read/vm_write)
 * pid:     child process ID
 *
 * Returns: Linux return value (or -ENOSYS if not ready)
 * --------------------------------------------------------------- */
int64_t lkl_bridge_syscall(uint64_t x86_nr, const uint64_t *args,
                           uint64_t as_cap, uint64_t pid)
{
    if (!lkl_ready) return -38; /* -ENOSYS */

    /* Child pids are allocated in 1..=MAX_THREADS by services/init/src/process.rs.
     * Reject anything out of range rather than silently aliasing slot 0. */
    if (pid == 0 || pid > MAX_THREADS) return -22; /* -EINVAL */
    struct per_thread_bridge_scratch *s = &g_scratch[pid - 1];

#ifdef HAS_LKL
    /* Process expired LKL timers (TCP retransmit, delayed work, etc.) */
    host_ops_tick();

    long lkl_nr = xlat_syscall_x86_to_lkl((long)x86_nr);
    if (lkl_nr < 0) return -38;

    long result;

    switch ((int)x86_nr) {

    /* ── uname(buf) ── */
    case 63: {
        char ub[390]; memset(ub, 0, 390);
        long p[6] = {(long)ub,0,0,0,0,0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[0], ub, 390);
        break;
    }

    /* ── open(path, flags, mode) → openat(AT_FDCWD, ...) ── */
    case 2: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, (long)args[1], (long)args[2], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── openat(dirfd, path, flags, mode) ── */
    case 257: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        long p[6] = {(long)args[0], (long)s->path_buf, (long)args[2], (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── read(fd, buf, count) ── */
    case 0: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], s->data_buf, (size_t)result);
        break;
    }

    /* ── write(fd, buf, count) ── */
    case 1: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        if (as_cap) guest_read(as_cap, args[1], s->data_buf, c);
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── close(fd) ── */
    case 3: {
        long p[6] = {(long)args[0], 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── stat/lstat(path, statbuf) → fstatat ── */
    case 4: case 6: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        memset(s->stat_buf, 0, 256);
        int fl = (x86_nr == 6) ? 0x100 : 0;
        long p[6] = {-100, (long)s->path_buf, (long)s->stat_buf, (long)fl, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[1], s->stat_buf, 144);
        break;
    }

    /* ── fstat(fd, statbuf) ── */
    case 5: {
        memset(s->stat_buf, 0, 256);
        long p[6] = {(long)args[0], (long)s->stat_buf, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[1], s->stat_buf, 144);
        break;
    }

    /* ── fstatat(dirfd, path, statbuf, flags) ── */
    case 262: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        memset(s->stat_buf, 0, 256);
        long p[6] = {(long)args[0], (long)s->path_buf, (long)s->stat_buf, (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[2], s->stat_buf, 144);
        break;
    }

    /* ── lseek(fd, offset, whence) ── */
    case 8: {
        long p[6] = {(long)args[0], (long)args[1], (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── getcwd(buf, size) ── */
    case 79: {
        memset(s->path_buf, 0, 4096);
        size_t sz = (size_t)args[1]; if (sz > 4096) sz = 4096;
        long p[6] = {(long)s->path_buf, (long)sz, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) {
            size_t l = 0; while (l < sz && s->path_buf[l]) l++;
            guest_write(as_cap, args[0], s->path_buf, l + 1);
        }
        break;
    }

    /* ── chdir(path) ── */
    case 80: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {(long)s->path_buf, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── access(path, mode) → faccessat ── */
    case 21: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, (long)args[1], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── mkdir(path, mode) → mkdirat ── */
    case 83: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, (long)args[1], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── unlink(path) → unlinkat ── */
    case 87: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── readlinkat(dirfd, path, buf, bufsiz) ── */
    case 267: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        size_t bsz = (size_t)args[3]; if (bsz > 4096) bsz = 4096;
        long p[6] = {(long)args[0], (long)s->path_buf, (long)s->data_buf, (long)bsz, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[2], s->data_buf, (size_t)result);
        break;
    }

    /* ── getdents64(fd, dirp, count) ── */
    case 217: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], s->data_buf, (size_t)result);
        break;
    }

    /* ── getrandom(buf, count, flags) ── */
    case 318: {
        size_t c = (size_t)args[1]; if (c > 4096) c = 4096;
        long p[6] = {(long)s->data_buf, (long)c, (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[0], s->data_buf, (size_t)result);
        break;
    }

    /* ── sysinfo(struct sysinfo *) — 112 bytes on x86_64 ── */
    case 99: {
        char si[112]; memset(si, 0, 112);
        long p[6] = {(long)si, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[0], si, 112);
        break;
    }

    /* ── gettimeofday(tv, tz) ── */
    case 96: {
        char tv[16]; memset(tv, 0, 16);
        long p[6] = {(long)tv, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[0], tv, 16);
        break;
    }

    /* ── clock_gettime(clockid, tp) ── */
    case 228: {
        char tp[16]; memset(tp, 0, 16);
        long p[6] = {(long)args[0], (long)tp, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[1], tp, 16);
        break;
    }

    /* ── nanosleep(req, rem) ── */
    case 35: {
        char req[16]; memset(req, 0, 16);
        if (as_cap) guest_read(as_cap, args[0], req, 16);
        long p[6] = {(long)req, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ══════════════════════════════════════════════════════════════
     * Tier 1: Pipes & sockets
     * ══════════════════════════════════════════════════════════════ */

    /* ── pipe(int fds[2]) / pipe2(int fds[2], flags) ── */
    case 22: case 293: {
        int kfds[2] = {-1, -1};
        int flags = (x86_nr == 293) ? (int)args[1] : 0;
        long p[6] = {(long)kfds, (long)flags, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap)
            guest_write(as_cap, args[0], kfds, 8);
        break;
    }

    /* ── socketpair(domain, type, protocol, int sv[2]) ── */
    case 53: {
        int ksv[2] = {-1, -1};
        long p[6] = {(long)args[0], (long)args[1], (long)args[2], (long)ksv, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap)
            guest_write(as_cap, args[3], ksv, 8);
        break;
    }

    /* ── connect/bind(fd, sockaddr, addrlen) ── */
    case 42: case 49: {
        size_t addrlen = (size_t)args[2];
        if (addrlen > 128) addrlen = 128;
        memset(s->sockaddr_buf, 0, 128);
        if (as_cap) guest_read(as_cap, args[1], s->sockaddr_buf, addrlen);
        long p[6] = {(long)args[0], (long)s->sockaddr_buf, (long)addrlen, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── accept(fd, addr, addrlen*) / accept4(fd, addr, addrlen*, flags) ── */
    case 43: case 288: {
        memset(s->sockaddr_buf, 0, 128);
        uint32_t klen = 128;
        if (as_cap && args[2]) guest_read(as_cap, args[2], &klen, 4);
        if (klen > 128) klen = 128;
        int flags4 = (x86_nr == 288) ? (int)args[3] : 0;
        long p[6] = {(long)args[0], (long)s->sockaddr_buf, (long)&klen, (long)flags4, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) {
            if (args[1]) guest_write(as_cap, args[1], s->sockaddr_buf, klen);
            if (args[2]) guest_write(as_cap, args[2], &klen, 4);
        }
        break;
    }

    /* ── getsockname/getpeername(fd, addr, addrlen*) ── */
    case 51: case 52: {
        memset(s->sockaddr_buf, 0, 128);
        uint32_t klen = 128;
        if (as_cap && args[2]) guest_read(as_cap, args[2], &klen, 4);
        if (klen > 128) klen = 128;
        long p[6] = {(long)args[0], (long)s->sockaddr_buf, (long)&klen, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) {
            guest_write(as_cap, args[1], s->sockaddr_buf, klen);
            guest_write(as_cap, args[2], &klen, 4);
        }
        break;
    }

    /* ── setsockopt(fd, level, optname, optval, optlen) ── */
    case 54: {
        size_t optlen = (size_t)args[4]; if (optlen > 256) optlen = 256;
        char kopt[256]; memset(kopt, 0, 256);
        if (as_cap && args[3]) guest_read(as_cap, args[3], kopt, optlen);
        long p[6] = {(long)args[0], (long)args[1], (long)args[2],
                     (long)kopt, (long)optlen, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── getsockopt(fd, level, optname, optval, optlen*) ── */
    case 55: {
        uint32_t klen = 0;
        if (as_cap && args[4]) guest_read(as_cap, args[4], &klen, 4);
        if (klen > 256) klen = 256;
        char kopt[256]; memset(kopt, 0, 256);
        long p[6] = {(long)args[0], (long)args[1], (long)args[2],
                     (long)kopt, (long)&klen, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) {
            if (args[3]) guest_write(as_cap, args[3], kopt, klen);
            if (args[4]) guest_write(as_cap, args[4], &klen, 4);
        }
        break;
    }

    /* ── sendto(fd, buf, len, flags, dest_addr, addrlen) ── */
    case 44: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        if (as_cap) guest_read(as_cap, args[1], s->data_buf, c);
        memset(s->sockaddr_buf, 0, 128);
        size_t addrlen = (size_t)args[5]; if (addrlen > 128) addrlen = 128;
        if (as_cap && args[4]) guest_read(as_cap, args[4], s->sockaddr_buf, addrlen);
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, (long)args[3],
                     args[4] ? (long)s->sockaddr_buf : 0, (long)addrlen};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── recvfrom(fd, buf, len, flags, src_addr, addrlen*) ── */
    case 45: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        memset(s->sockaddr_buf, 0, 128);
        uint32_t klen = 128;
        if (as_cap && args[5]) guest_read(as_cap, args[5], &klen, 4);
        if (klen > 128) klen = 128;
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, (long)args[3],
                     args[4] ? (long)s->sockaddr_buf : 0,
                     args[5] ? (long)&klen : 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], s->data_buf, (size_t)result);
        if (result >= 0 && as_cap && args[4])
            guest_write(as_cap, args[4], s->sockaddr_buf, klen);
        if (result >= 0 && as_cap && args[5])
            guest_write(as_cap, args[5], &klen, 4);
        break;
    }

    /* ══════════════════════════════════════════════════════════════
     * Tier 2: Path-bearing syscalls
     * ══════════════════════════════════════════════════════════════ */

    /* ── rename(old, new) → renameat(AT_FDCWD, old, AT_FDCWD, new) ── */
    case 82: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        guest_read_str(as_cap, args[1], s->path_buf2, 4096);
        /* LKL generic renameat = 38 */
        long p[6] = {-100, (long)s->path_buf, -100, (long)s->path_buf2, 0, 0};
        result = lkl_syscall(38, p);
        break;
    }

    /* ── rmdir(path) → unlinkat(AT_FDCWD, path, AT_REMOVEDIR) ── */
    case 84: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, 0x200 /* AT_REMOVEDIR */, 0, 0, 0};
        result = lkl_syscall(35 /* unlinkat */, p);
        break;
    }

    /* ── chmod(path, mode) → fchmodat(AT_FDCWD, path, mode, 0) ── */
    case 90: {
        guest_read_str(as_cap, args[0], s->path_buf, 4096);
        long p[6] = {-100, (long)s->path_buf, (long)args[1], 0, 0, 0};
        result = lkl_syscall(53 /* fchmodat */, p);
        break;
    }

    /* ── faccessat(dirfd, path, mode, flags) ── */
    case 269: case 439: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        long p[6] = {(long)args[0], (long)s->path_buf, (long)args[2], (long)args[3], 0, 0};
        result = lkl_syscall(48 /* faccessat */, p);
        break;
    }

    /* ── unlinkat(dirfd, path, flags) ── */
    case 263: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        long p[6] = {(long)args[0], (long)s->path_buf, (long)args[2], 0, 0, 0};
        result = lkl_syscall(35 /* unlinkat */, p);
        break;
    }

    /* ── mkdirat(dirfd, path, mode) ── */
    case 258: {
        guest_read_str(as_cap, args[1], s->path_buf, 4096);
        long p[6] = {(long)args[0], (long)s->path_buf, (long)args[2], 0, 0, 0};
        result = lkl_syscall(34 /* mkdirat */, p);
        break;
    }

    /* ══════════════════════════════════════════════════════════════
     * Tier 3: Scatter/gather I/O
     * ══════════════════════════════════════════════════════════════ */

    /* ── pread64(fd, buf, count, offset) ── */
    case 17: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], s->data_buf, (size_t)result);
        break;
    }

    /* ── pwrite64(fd, buf, count, offset) ── */
    case 18: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        if (as_cap) guest_read(as_cap, args[1], s->data_buf, c);
        long p[6] = {(long)args[0], (long)s->data_buf, (long)c, (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── readv(fd, iov, iovcnt) — decompose to sequential reads ── */
    case 19: {
        int iovcnt = (int)args[2]; if (iovcnt > 16) iovcnt = 16;
        struct { uint64_t base; uint64_t len; } giov[16];
        memset(giov, 0, sizeof(giov));
        if (as_cap) guest_read(as_cap, args[1], giov, iovcnt * 16);
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            size_t c = (size_t)giov[i].len; if (c > 4096) c = 4096;
            /* use read (generic 63) for each iovec */
            long p[6] = {(long)args[0], (long)s->data_buf, (long)c, 0, 0, 0};
            long r = lkl_syscall(63, p);
            if (r > 0) {
                if (as_cap) guest_write(as_cap, giov[i].base, s->data_buf, (size_t)r);
                total += r;
            }
            if (r < (long)c) break;
        }
        result = total;
        break;
    }

    /* ── writev(fd, iov, iovcnt) — decompose to sequential writes ── */
    case 20: {
        int iovcnt = (int)args[2]; if (iovcnt > 16) iovcnt = 16;
        struct { uint64_t base; uint64_t len; } giov[16];
        memset(giov, 0, sizeof(giov));
        if (as_cap) guest_read(as_cap, args[1], giov, iovcnt * 16);
        long total = 0;
        for (int i = 0; i < iovcnt; i++) {
            size_t c = (size_t)giov[i].len; if (c > 4096) c = 4096;
            if (as_cap) guest_read(as_cap, giov[i].base, s->data_buf, c);
            /* use write (generic 64) for each iovec */
            long p[6] = {(long)args[0], (long)s->data_buf, (long)c, 0, 0, 0};
            long r = lkl_syscall(64, p);
            if (r > 0) total += r;
            if (r < (long)c) break;
        }
        result = total;
        break;
    }

    /* ══════════════════════════════════════════════════════════════
     * Tier 4: Poll / epoll
     * ══════════════════════════════════════════════════════════════ */

    /* ── poll(pollfd*, nfds, timeout_ms) ── */
    case 7: {
        int nfds = (int)args[1]; if (nfds > 64) nfds = 64;
        char kpoll[512]; memset(kpoll, 0, 512); /* 64 * 8 = 512 */
        if (as_cap) guest_read(as_cap, args[0], kpoll, nfds * 8);
        long p[6] = {(long)kpoll, (long)nfds, (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) guest_write(as_cap, args[0], kpoll, nfds * 8);
        break;
    }

    /* ── epoll_ctl(epfd, op, fd, event*) ── */
    case 233: {
        char ev[16]; memset(ev, 0, 16);
        if (as_cap && args[3]) guest_read(as_cap, args[3], ev, 12);
        long p[6] = {(long)args[0], (long)args[1], (long)args[2],
                     args[3] ? (long)ev : 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── epoll_wait/epoll_pwait(epfd, events, maxevents, timeout, ...) ── */
    case 232: case 281: {
        int maxev = (int)args[2]; if (maxev > 32) maxev = 32;
        char kevs[384]; memset(kevs, 0, 384); /* 32 * 12 */
        long p[6] = {(long)args[0], (long)kevs, (long)maxev,
                     (long)args[3], 0, 8};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap)
            guest_write(as_cap, args[1], kevs, (size_t)result * 12);
        break;
    }

    /* ── sendmsg(fd, msghdr*, flags) — flatten nested pointers ── */
    case 46: {
        /* struct msghdr { name, namelen, iov, iovlen, control, controllen, flags }
         * We only handle the iovec data, ignoring control messages and name. */
        char mhdr[56]; memset(mhdr, 0, 56);
        if (as_cap) guest_read(as_cap, args[1], mhdr, 56);
        uint64_t iov_ptr = *(uint64_t *)(mhdr + 16);  /* msg_iov */
        uint64_t iov_len = *(uint64_t *)(mhdr + 24);  /* msg_iovlen */
        if (iov_len > 8) iov_len = 8;
        /* Read iovec array from guest */
        struct { uint64_t base; uint64_t len; } giov[8];
        memset(giov, 0, sizeof(giov));
        if (as_cap && iov_ptr) guest_read(as_cap, iov_ptr, giov, iov_len * 16);
        /* Flatten all iovecs into s->data_buf */
        size_t total = 0;
        for (uint64_t i = 0; i < iov_len && total < 4096; i++) {
            size_t c = (size_t)giov[i].len;
            if (c > 4096 - total) c = 4096 - total;
            if (as_cap && giov[i].base)
                guest_read(as_cap, giov[i].base, s->data_buf + total, c);
            total += c;
        }
        /* Build kernel iovec pointing to contiguous buffer */
        struct { void *base; uint64_t len; } kiov;
        kiov.base = s->data_buf; kiov.len = total;
        /* Build kernel msghdr */
        char kmhdr[56]; memset(kmhdr, 0, 56);
        /* Copy name if present */
        uint64_t name_ptr = *(uint64_t *)(mhdr + 0);
        uint32_t name_len = *(uint32_t *)(mhdr + 8);
        if (name_ptr && name_len > 0 && name_len <= 128) {
            memset(s->sockaddr_buf, 0, 128);
            if (as_cap) guest_read(as_cap, name_ptr, s->sockaddr_buf, name_len);
            *(uint64_t *)(kmhdr + 0) = (uint64_t)s->sockaddr_buf;
            *(uint32_t *)(kmhdr + 8) = name_len;
        }
        *(uint64_t *)(kmhdr + 16) = (uint64_t)&kiov;
        *(uint64_t *)(kmhdr + 24) = 1;
        long p[6] = {(long)args[0], (long)kmhdr, (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── recvmsg(fd, msghdr*, flags) ── */
    case 47: {
        char mhdr[56]; memset(mhdr, 0, 56);
        if (as_cap) guest_read(as_cap, args[1], mhdr, 56);
        uint64_t iov_ptr = *(uint64_t *)(mhdr + 16);
        uint64_t iov_len = *(uint64_t *)(mhdr + 24);
        if (iov_len > 8) iov_len = 8;
        struct { uint64_t base; uint64_t len; } giov[8];
        memset(giov, 0, sizeof(giov));
        if (as_cap && iov_ptr) guest_read(as_cap, iov_ptr, giov, iov_len * 16);
        /* Single kernel iovec for receive */
        struct { void *base; uint64_t len; } kiov;
        size_t total_cap = 0;
        for (uint64_t i = 0; i < iov_len; i++) total_cap += giov[i].len;
        if (total_cap > 4096) total_cap = 4096;
        kiov.base = s->data_buf; kiov.len = total_cap;
        /* Kernel msghdr */
        char kmhdr[56]; memset(kmhdr, 0, 56);
        memset(s->sockaddr_buf, 0, 128);
        *(uint64_t *)(kmhdr + 0) = (uint64_t)s->sockaddr_buf;
        *(uint32_t *)(kmhdr + 8) = 128;
        *(uint64_t *)(kmhdr + 16) = (uint64_t)&kiov;
        *(uint64_t *)(kmhdr + 24) = 1;
        long p[6] = {(long)args[0], (long)kmhdr, (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        /* Scatter received data back into guest iovecs */
        if (result > 0 && as_cap) {
            size_t off = 0;
            for (uint64_t i = 0; i < iov_len && off < (size_t)result; i++) {
                size_t c = (size_t)giov[i].len;
                if (c > (size_t)result - off) c = (size_t)result - off;
                guest_write(as_cap, giov[i].base, s->data_buf + off, c);
                off += c;
            }
            /* Write back msg_name and msg_namelen */
            uint64_t guest_name = *(uint64_t *)(mhdr + 0);
            uint32_t ret_namelen = *(uint32_t *)(kmhdr + 8);
            if (guest_name && ret_namelen > 0) {
                if (ret_namelen > 128) ret_namelen = 128;
                guest_write(as_cap, guest_name, s->sockaddr_buf, ret_namelen);
            }
            /* Write back msg_namelen + msg_flags to guest msghdr */
            *(uint32_t *)(mhdr + 8) = ret_namelen;
            *(uint32_t *)(mhdr + 48) = *(uint32_t *)(kmhdr + 48);
            guest_write(as_cap, args[1], mhdr, 56);
        }
        break;
    }

    /* ── select(nfds, readfds, writefds, exceptfds, timeout) ── */
    case 23: {
        int nfds = (int)args[0]; if (nfds > 1024) nfds = 1024;
        size_t fdset_bytes = ((size_t)nfds + 63) / 64 * 8;
        if (fdset_bytes > 128) fdset_bytes = 128;
        char kr[128], kw[128], ke[128];
        memset(kr, 0, 128); memset(kw, 0, 128); memset(ke, 0, 128);
        if (as_cap && args[1]) guest_read(as_cap, args[1], kr, fdset_bytes);
        if (as_cap && args[2]) guest_read(as_cap, args[2], kw, fdset_bytes);
        if (as_cap && args[3]) guest_read(as_cap, args[3], ke, fdset_bytes);
        char tv[16]; memset(tv, 0, 16);
        if (as_cap && args[4]) guest_read(as_cap, args[4], tv, 16);
        long p[6] = {(long)nfds, args[1] ? (long)kr : 0, args[2] ? (long)kw : 0,
                     args[3] ? (long)ke : 0, args[4] ? (long)tv : 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) {
            if (args[1]) guest_write(as_cap, args[1], kr, fdset_bytes);
            if (args[2]) guest_write(as_cap, args[2], kw, fdset_bytes);
            if (args[3]) guest_write(as_cap, args[3], ke, fdset_bytes);
        }
        break;
    }

    /* ── pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask) ── */
    case 270: {
        int nfds = (int)args[0]; if (nfds > 1024) nfds = 1024;
        size_t fdset_bytes = ((size_t)nfds + 63) / 64 * 8;
        if (fdset_bytes > 128) fdset_bytes = 128;
        char kr[128], kw[128], ke[128];
        memset(kr, 0, 128); memset(kw, 0, 128); memset(ke, 0, 128);
        if (as_cap && args[1]) guest_read(as_cap, args[1], kr, fdset_bytes);
        if (as_cap && args[2]) guest_read(as_cap, args[2], kw, fdset_bytes);
        if (as_cap && args[3]) guest_read(as_cap, args[3], ke, fdset_bytes);
        char ts[16]; memset(ts, 0, 16);
        if (as_cap && args[4]) guest_read(as_cap, args[4], ts, 16);
        long p[6] = {(long)nfds, args[1] ? (long)kr : 0, args[2] ? (long)kw : 0,
                     args[3] ? (long)ke : 0, args[4] ? (long)ts : 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) {
            if (args[1]) guest_write(as_cap, args[1], kr, fdset_bytes);
            if (args[2]) guest_write(as_cap, args[2], kw, fdset_bytes);
            if (args[3]) guest_write(as_cap, args[3], ke, fdset_bytes);
        }
        break;
    }

    /* ── ppoll(fds, nfds, timeout_ts, sigmask, sigsetsize) ── */
    case 271: {
        int nfds = (int)args[1]; if (nfds > 64) nfds = 64;
        char kpoll[512]; memset(kpoll, 0, 512);
        if (as_cap) guest_read(as_cap, args[0], kpoll, nfds * 8);
        char ts[16]; memset(ts, 0, 16);
        if (as_cap && args[2]) guest_read(as_cap, args[2], ts, 16);
        long p[6] = {(long)kpoll, (long)nfds,
                     args[2] ? (long)ts : 0, 0, 8, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) guest_write(as_cap, args[0], kpoll, nfds * 8);
        break;
    }

    /* ══════════════════════════════════════════════════════════════
     * Tier 5: Misc
     * ══════════════════════════════════════════════════════════════ */

    /* ── clock_getres(clockid, res) ── */
    case 229: {
        char res[16]; memset(res, 0, 16);
        long p[6] = {(long)args[0], (long)res, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap && args[1])
            guest_write(as_cap, args[1], res, 16);
        break;
    }

    /* ── clock_nanosleep(clockid, flags, req, rem) ── */
    case 230: {
        char req[16]; memset(req, 0, 16);
        char rem[16]; memset(rem, 0, 16);
        if (as_cap) guest_read(as_cap, args[2], req, 16);
        long p[6] = {(long)args[0], (long)args[1], (long)req,
                     args[3] ? (long)rem : 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result != 0 && as_cap && args[3])
            guest_write(as_cap, args[3], rem, 16);
        break;
    }

    /* ── memfd_create(name, flags) ── */
    case 319: {
        guest_read_str(as_cap, args[0], s->path_buf, 256);
        long p[6] = {(long)s->path_buf, (long)args[1], 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── futex(uaddr, op, val, timeout, uaddr2, val3) ── */
    case 202: {
        /* Read the futex word from guest memory */
        uint32_t fval = 0;
        if (as_cap) guest_read(as_cap, args[0], &fval, 4);
        /* Put it at a known kernel address */
        static uint32_t kfutex;
        kfutex = fval;
        long p[6] = {(long)&kfutex, (long)args[1], (long)args[2],
                     (long)args[3], (long)args[4], (long)args[5]};
        result = lkl_syscall(lkl_nr, p);
        /* Write back (FUTEX_WAKE modifies the word) */
        if (as_cap) guest_write(as_cap, args[0], &kfutex, 4);
        break;
    }

    /* ── fcntl(fd, cmd, arg) — most commands are no-pointer ── */
    case 72: {
        long p[6] = {(long)args[0], (long)args[1], (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── ioctl(fd, cmd, arg) — common no-pointer ioctls passthrough ── */
    case 16: {
        long p[6] = {(long)args[0], (long)args[1], (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── Generic: no-pointer syscalls (passthrough) ── */
    default: {
        long p[6] = {(long)args[0], (long)args[1], (long)args[2],
                     (long)args[3], (long)args[4], (long)args[5]};
        result = lkl_syscall(lkl_nr, p);
        break;
    }
    }

    return (int64_t)result;
#else
    (void)args; (void)as_cap; (void)s;
    return -38;
#endif
}

/* ---------------------------------------------------------------
 * lkl_bridge_ready — check if LKL is initialized
 * --------------------------------------------------------------- */
int lkl_bridge_ready(void)
{
    return lkl_ready;
}
