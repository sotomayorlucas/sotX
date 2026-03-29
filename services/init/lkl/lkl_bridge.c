/*
 * lkl_bridge.c — Fusion point: LKL as backend of LUCAS.
 *
 * Provides two functions callable from Rust via FFI:
 *   lkl_bridge_init()    — boot Linux 6.6 kernel inside init process
 *   lkl_bridge_syscall() — translate x86_64 syscall + guest memory bridge + lkl_syscall()
 *
 * All LKL calls happen in the same address space as init (no IPC).
 */

#include <stdint.h>
#include "sotos_syscall.h"
#include "allocator.h"
#include "host_ops.h"
#include "guest_mem.h"
#include "libc_stubs.h"
#include "syscall_xlat.h"

#ifdef HAS_LKL
#include <lkl.h>
#include <lkl/asm/host_ops.h>
#else
#include "lkl_stub.h"
#endif

/* Static scratch buffers for guest memory bridge. */
static char g_path_buf[4096];
static char g_data_buf[4096];
static char g_stat_buf[256];

static int lkl_ready = 0;

/* ---------------------------------------------------------------
 * lkl_bridge_init — called once from Rust main.rs at boot
 * --------------------------------------------------------------- */
int lkl_bridge_init(void)
{
    serial_puts("[lkl-bridge] init arena...\n");
    if (arena_init() < 0) {
        serial_puts("[lkl-bridge] arena_init failed\n");
        return -1;
    }

#ifdef HAS_LKL
    static struct lkl_host_operations host_ops;
    volatile char *p = (volatile char *)&host_ops;
    for (unsigned long i = 0; i < sizeof(host_ops); i++) p[i] = 0;
    host_ops_init(&host_ops);

    serial_puts("[lkl-bridge] starting Linux kernel...\n");
    int rc = lkl_init(&host_ops);
    if (rc < 0) {
        serial_puts("[lkl-bridge] lkl_init failed\n");
        return rc;
    }

    rc = lkl_start_kernel("mem=64M loglevel=3");
    if (rc < 0) {
        serial_puts("[lkl-bridge] lkl_start_kernel failed\n");
        return rc;
    }
    serial_puts("[lkl-bridge] Linux kernel running\n");

    /* Smoke test */
    struct { char s[65]; char n[65]; char r[65]; char v[65]; char m[65]; char d[65]; } uts;
    memset(&uts, 0, sizeof(uts));
    long params[6] = {(long)&uts, 0, 0, 0, 0, 0};
    long urc = lkl_syscall(160 /* __lkl__NR_uname */, params);
    if (urc == 0) {
        serial_puts("[lkl-bridge] uname: ");
        serial_puts(uts.s);
        serial_puts(" ");
        serial_puts(uts.r);
        serial_puts("\n");
    }

    lkl_ready = 1;
#else
    serial_puts("[lkl-bridge] stub mode (no HAS_LKL)\n");
    lkl_ready = 0;
#endif
    return 0;
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
    (void)pid;
    if (!lkl_ready) return -38; /* -ENOSYS */

#ifdef HAS_LKL
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
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        long p[6] = {-100, (long)g_path_buf, (long)args[1], (long)args[2], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── openat(dirfd, path, flags, mode) ── */
    case 257: {
        guest_read_str(as_cap, args[1], g_path_buf, 4096);
        long p[6] = {(long)args[0], (long)g_path_buf, (long)args[2], (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── read(fd, buf, count) ── */
    case 0: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        long p[6] = {(long)args[0], (long)g_data_buf, (long)c, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], g_data_buf, (size_t)result);
        break;
    }

    /* ── write(fd, buf, count) ── */
    case 1: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        if (as_cap) guest_read(as_cap, args[1], g_data_buf, c);
        long p[6] = {(long)args[0], (long)g_data_buf, (long)c, 0, 0, 0};
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
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        memset(g_stat_buf, 0, 256);
        int fl = (x86_nr == 6) ? 0x100 : 0;
        long p[6] = {-100, (long)g_path_buf, (long)g_stat_buf, (long)fl, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[1], g_stat_buf, 144);
        break;
    }

    /* ── fstat(fd, statbuf) ── */
    case 5: {
        memset(g_stat_buf, 0, 256);
        long p[6] = {(long)args[0], (long)g_stat_buf, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[1], g_stat_buf, 144);
        break;
    }

    /* ── fstatat(dirfd, path, statbuf, flags) ── */
    case 262: {
        guest_read_str(as_cap, args[1], g_path_buf, 4096);
        memset(g_stat_buf, 0, 256);
        long p[6] = {(long)args[0], (long)g_path_buf, (long)g_stat_buf, (long)args[3], 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[2], g_stat_buf, 144);
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
        memset(g_path_buf, 0, 4096);
        size_t sz = (size_t)args[1]; if (sz > 4096) sz = 4096;
        long p[6] = {(long)g_path_buf, (long)sz, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result >= 0 && as_cap) {
            size_t l = 0; while (l < sz && g_path_buf[l]) l++;
            guest_write(as_cap, args[0], g_path_buf, l + 1);
        }
        break;
    }

    /* ── chdir(path) ── */
    case 80: {
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        long p[6] = {(long)g_path_buf, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── access(path, mode) → faccessat ── */
    case 21: {
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        long p[6] = {-100, (long)g_path_buf, (long)args[1], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── mkdir(path, mode) → mkdirat ── */
    case 83: {
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        long p[6] = {-100, (long)g_path_buf, (long)args[1], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── unlink(path) → unlinkat ── */
    case 87: {
        guest_read_str(as_cap, args[0], g_path_buf, 4096);
        long p[6] = {-100, (long)g_path_buf, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        break;
    }

    /* ── readlinkat(dirfd, path, buf, bufsiz) ── */
    case 267: {
        guest_read_str(as_cap, args[1], g_path_buf, 4096);
        size_t bsz = (size_t)args[3]; if (bsz > 4096) bsz = 4096;
        long p[6] = {(long)args[0], (long)g_path_buf, (long)g_data_buf, (long)bsz, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[2], g_data_buf, (size_t)result);
        break;
    }

    /* ── getdents64(fd, dirp, count) ── */
    case 217: {
        size_t c = (size_t)args[2]; if (c > 4096) c = 4096;
        long p[6] = {(long)args[0], (long)g_data_buf, (long)c, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[1], g_data_buf, (size_t)result);
        break;
    }

    /* ── getrandom(buf, count, flags) ── */
    case 318: {
        size_t c = (size_t)args[1]; if (c > 4096) c = 4096;
        long p[6] = {(long)g_data_buf, (long)c, (long)args[2], 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result > 0 && as_cap) guest_write(as_cap, args[0], g_data_buf, (size_t)result);
        break;
    }

    /* ── sysinfo(struct sysinfo *) ── */
    case 99: {
        char si[128]; memset(si, 0, 128);
        long p[6] = {(long)si, 0, 0, 0, 0, 0};
        result = lkl_syscall(lkl_nr, p);
        if (result == 0 && as_cap) guest_write(as_cap, args[0], si, 128);
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
    (void)args; (void)as_cap;
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
