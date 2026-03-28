/*
 * main.c -- LKL server service entry point.
 *
 * Runs as a freestanding sotOS userspace service:
 *   1. Reads BootInfo at 0xB00000 for root capabilities
 *   2. Creates an IPC endpoint and registers as "lkl" service
 *   3. Initialises the arena allocator (128 MiB)
 *   4. Initialises LKL host ops and starts the Linux kernel (stub)
 *   5. Enters an IPC recv loop, forwarding syscalls to LKL
 */

#include <stdint.h>
#include "sotos_syscall.h"
#include "allocator.h"
#include "host_ops.h"
#include "guest_mem.h"
#include "disk_backend.h"
#ifdef HAS_LKL
#include <lkl.h>
#include <lkl/asm/host_ops.h>
#else
#include "lkl_stub.h"
#endif
#include "libc_stubs.h"
#include "syscall_xlat.h"

/* ---------------------------------------------------------------
 * BootInfo (mirrors sotos-common BootInfo struct)
 * --------------------------------------------------------------- */

#define BOOT_INFO_ADDR  0xB00000ULL
#define BOOT_INFO_MAGIC 0x534F544F53ULL  /* "SOTOS" */
#define BOOT_INFO_MAX_CAPS 32

struct boot_info {
    uint64_t magic;
    uint64_t cap_count;
    uint64_t caps[BOOT_INFO_MAX_CAPS];
    uint64_t guest_entry;
    uint64_t fb_addr;
    uint32_t fb_width;
    uint32_t fb_height;
    uint32_t fb_pitch;
    uint32_t fb_bpp;
    uint64_t stack_top;
    uint64_t self_as_cap;
};

/* ---------------------------------------------------------------
 * IPC dispatch: handle a Linux syscall from a client process
 *
 * msg.tag        = Linux syscall number
 * msg.regs[0..5] = syscall arguments
 * msg.regs[6]    = client pid
 * msg.regs[7]    = client AS cap (for vm_read/vm_write)
 *
 * Returns the result in a reply message.
 * --------------------------------------------------------------- */

static void handle_syscall(uint64_t ep_cap, struct ipc_msg *msg)
{
    uint64_t nr      = msg->tag;
    uint64_t as_cap  = msg->regs[7];
    struct ipc_msg reply;

    memset(&reply, 0, sizeof(reply));

#ifdef HAS_LKL
    /* Translate x86_64 syscall number to LKL generic number. */
    long lkl_nr = xlat_syscall_x86_to_lkl((long)nr);
    if (lkl_nr < 0) {
        reply.regs[0] = (uint64_t)(int64_t)(-38); /* -ENOSYS */
    } else {
        /* Per-syscall guest memory bridge:
         * Buffer syscalls need data copied between child AS and lkl-server. */
        long result;
        switch ((int)nr) {
        case 63: { /* SYS_UNAME: uname(struct utsname *buf) */
            /* struct utsname = 6 * 65 = 390 bytes */
            char local_buf[390];
            memset(local_buf, 0, sizeof(local_buf));
            long p[6] = {(long)local_buf, 0, 0, 0, 0, 0};
            result = lkl_syscall(lkl_nr, p);
            if (result == 0 && as_cap != 0) {
                /* Copy result to child's address space. */
                guest_write(as_cap, msg->regs[0], local_buf, 390);
            }
            break;
        }
        default: {
            /* Generic: pass args directly (no buffer handling).
             * Only works for syscalls without pointer arguments. */
            long p[6] = {
                (long)msg->regs[0], (long)msg->regs[1],
                (long)msg->regs[2], (long)msg->regs[3],
                (long)msg->regs[4], (long)msg->regs[5]
            };
            result = lkl_syscall(lkl_nr, p);
            break;
        }
        }
        reply.regs[0] = (uint64_t)result;
    }
    reply.tag = 0;
#else
    /* Stub mode: return -ENOSYS for all syscalls. */
    (void)as_cap;
    reply.tag     = 0;
    reply.regs[0] = (uint64_t)(int64_t)(-38);  /* -ENOSYS */

    /* Log the first few unknown syscalls for debugging. */
    serial_puts("[lkl] stub syscall ");
    serial_put_dec(nr);
    serial_puts(" -> -ENOSYS\n");
#endif

    sys_send(ep_cap, &reply);
}

/* ---------------------------------------------------------------
 * _start -- freestanding entry point
 * --------------------------------------------------------------- */

/* Real entry: align stack to 16 bytes (x86_64 ABI requires it for SSE). */
__asm__(
    ".globl _start\n"
    "_start:\n"
    "    and $-16, %rsp\n"
    "    call _start_c\n"
    "    ud2\n"
);

void __attribute__((noreturn)) _start_c(void)
{
    /* Set FS_BASE for main thread identity (used by thread_self). */
    static uint64_t main_tid_sentinel = 0xCAFE0001ULL;
    sys_set_fs_base((uint64_t)&main_tid_sentinel);

    serial_puts("[lkl-server] starting\n");

    /* 1. Read BootInfo. */
    volatile struct boot_info *bi =
        (volatile struct boot_info *)BOOT_INFO_ADDR;

    if (bi->magic != BOOT_INFO_MAGIC) {
        serial_puts("[lkl-server] ERROR: bad BootInfo magic\n");
        sys_thread_exit();
    }

    serial_puts("[lkl-server] BootInfo OK, caps=");
    serial_put_dec(bi->cap_count);
    serial_puts("\n");

    /* 2. Create endpoint and register as "lkl" service. */
    int64_t ep = sys_endpoint_create();
    if (ep < 0) {
        serial_puts("[lkl-server] ERROR: endpoint_create failed\n");
        sys_thread_exit();
    }

    static const char svc_name[] = "lkl";
    int64_t reg = sys_svc_register(svc_name, 3, (uint64_t)ep);
    if (reg < 0) {
        serial_puts("[lkl-server] WARNING: svc_register failed (");
        serial_put_dec((uint64_t)(-reg));
        serial_puts(")\n");
        /* Continue anyway -- clients can use direct cap grant. */
    } else {
        serial_puts("[lkl-server] registered as 'lkl' service\n");
    }

    /* 3. Initialise arena allocator (128 MiB at 0x7A000000). */
    serial_puts("[lkl-server] init arena (128 MiB)...\n");
    int arena_rc = arena_init();
    if (arena_rc < 0) {
        serial_puts("[lkl-server] ERROR: arena_init failed (");
        serial_put_dec((uint64_t)(-arena_rc));
        serial_puts(")\n");
        sys_thread_exit();
    }
    serial_puts("[lkl-server] arena ready\n");

    /* 4. Initialise LKL host operations. */
    static struct lkl_host_operations host_ops;
    /* Zero with volatile write to prevent optimizer reordering. */
    volatile char *p = (volatile char *)&host_ops;
    for (unsigned long i = 0; i < sizeof(host_ops); i++)
        p[i] = 0;
    host_ops_init(&host_ops);

    /* 5. Start LKL kernel. */
    serial_puts("[lkl-server] starting LKL kernel...\n");
#ifdef HAS_LKL
    serial_puts("[lkl-server] host_ops at ");
    serial_put_hex((uint64_t)&host_ops);
    serial_puts(" print=");
    serial_put_hex((uint64_t)host_ops.print);
    serial_puts("\n");
    serial_puts("[lkl-server] jmp_set=");
    serial_put_hex((uint64_t)host_ops.jmp_buf_set);
    serial_puts(" jmp_ljmp=");
    serial_put_hex((uint64_t)host_ops.jmp_buf_longjmp);
    serial_puts(" memcpy=");
    serial_put_hex((uint64_t)host_ops.memcpy);
    serial_puts("\n");
    serial_puts("[lkl-server] calling lkl_init...\n");
    int init_rc = lkl_init(&host_ops);
    if (init_rc < 0) {
        serial_puts("[lkl-server] ERROR: lkl_init failed (");
        serial_put_dec((uint64_t)(-(int64_t)init_rc));
        serial_puts(")\n");
        sys_thread_exit();
    }
    serial_puts("[lkl-server] lkl_init OK\n");

    int boot_rc = lkl_start_kernel("mem=64M loglevel=8");
    if (boot_rc < 0) {
        serial_puts("[lkl-server] ERROR: lkl_start_kernel failed (");
        serial_put_dec((uint64_t)(-(int64_t)boot_rc));
        serial_puts(")\n");
        sys_thread_exit();
    }
    serial_puts("[lkl-server] LKL kernel started (real Linux)\n");

    /* Quick smoke test: call lkl_sys_uname */
    {
        struct { char s[65]; char n[65]; char r[65]; char v[65]; char m[65]; char d[65]; } uts;
        memset(&uts, 0, sizeof(uts));
        long params[6] = {(long)&uts, 0, 0, 0, 0, 0};
        long rc = lkl_syscall(160 /* __lkl__NR_uname */, params);
        serial_puts("[lkl-server] uname rc=");
        serial_put_dec((uint64_t)(rc < 0 ? -rc : rc));
        if (rc == 0) {
            serial_puts(" sysname=");
            serial_puts(uts.s);
            serial_puts(" release=");
            serial_puts(uts.r);
        }
        serial_puts("\n");
    }
#else
    /* Stub mode */
    (void)host_ops;
    serial_puts("[lkl-server] LKL kernel started (stub)\n");
#endif

    /* 6. Initialise disk backend (stub for phase 1). */
    disk_init();

    /* 7. Enter IPC recv loop. */
    serial_puts("[lkl-server] entering IPC loop on ep=");
    serial_put_dec((uint64_t)ep);
    serial_puts("\n");

    for (;;) {
        struct ipc_msg msg;
        int64_t r = sys_recv((uint64_t)ep, &msg);
        if (r < 0) {
            /* recv error -- yield and retry. */
            sys_yield();
            continue;
        }

        handle_syscall((uint64_t)ep, &msg);

        /* Process pending timers. */
        host_ops_tick();
    }
}
