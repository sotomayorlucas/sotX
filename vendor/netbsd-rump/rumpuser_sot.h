/*
 * rumpuser_sot.h -- SOT hypervisor adaptation layer for NetBSD rump kernel.
 *
 * Defines the internal structures used by rumpuser_sot.c to implement the
 * rumpuser(3) interface on top of SOT exokernel primitives.
 *
 * The rump kernel calls ~30 hypercall functions (threads, mutexes, rwlocks,
 * condition variables, memory, block I/O, clock, random, params).  This
 * header declares the backing structures; the upstream rumpuser.h declares
 * the public API signatures.
 */

#ifndef RUMPUSER_SOT_H
#define RUMPUSER_SOT_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------
 * SOT syscall numbers (from kernel/src/syscall/mod.rs)
 * --------------------------------------------------------------- */

/* Core kernel primitives */
#define SYS_YIELD              0
#define SYS_SEND               1
#define SYS_RECV               2
#define SYS_CALL               3
#define SYS_ENDPOINT_CREATE   10
#define SYS_FRAME_ALLOC       20
#define SYS_FRAME_FREE        21
#define SYS_MAP               22
#define SYS_UNMAP             23
#define SYS_UNMAP_FREE        24
#define SYS_THREAD_CREATE     40
#define SYS_THREAD_EXIT       42
#define SYS_NOTIFY_CREATE     70
#define SYS_NOTIFY_WAIT       71
#define SYS_NOTIFY_SIGNAL     72
#define SYS_SVC_LOOKUP       131
#define SYS_SET_FS_BASE      160
#define SYS_GET_FS_BASE      161
#define SYS_DEBUG_PRINT      255

/* SOT exokernel extensions (300-310) */
#define SYS_SO_CREATE        300
#define SYS_SO_INVOKE        301
#define SYS_SO_GRANT         302
#define SYS_SO_REVOKE        303
#define SYS_SO_OBSERVE       304
#define SYS_SOT_DOMAIN_CREATE 305
#define SYS_SOT_DOMAIN_ENTER 306
#define SYS_SOT_CHANNEL_CREATE 307
#define SYS_TX_BEGIN         308
#define SYS_TX_COMMIT        309
#define SYS_TX_ABORT         310

/* ---------------------------------------------------------------
 * SO type tags for rump object types
 * --------------------------------------------------------------- */
#define SO_TYPE_MUTEX        0x0100
#define SO_TYPE_RWLOCK       0x0101
#define SO_TYPE_CV           0x0102
#define SO_TYPE_THREAD       0x0103
#define SO_TYPE_BIO_REQ      0x0104

/* SO method IDs for so_invoke */
#define SO_MTD_MUTEX_LOCK    1
#define SO_MTD_MUTEX_UNLOCK  2
#define SO_MTD_MUTEX_TRYLOCK 3
#define SO_MTD_RW_RLOCK      4
#define SO_MTD_RW_WLOCK      5
#define SO_MTD_RW_UNLOCK     6
#define SO_MTD_RW_TRYRLOCK   7
#define SO_MTD_RW_TRYWLOCK   8
#define SO_MTD_CV_WAIT       9
#define SO_MTD_CV_SIGNAL    10
#define SO_MTD_CV_BROADCAST 11

/* ---------------------------------------------------------------
 * Page flags (from kernel's paging module)
 * --------------------------------------------------------------- */
#define MAP_WRITABLE         (1ULL << 1)
#define MAP_NO_EXECUTE       (1ULL << 63)
#define MAP_RW_NX            (MAP_WRITABLE | MAP_NO_EXECUTE)

/* ---------------------------------------------------------------
 * Rump mutex flags (from rumpuser.h)
 * --------------------------------------------------------------- */
#define RUMPUSER_MTX_SPIN    0x01
#define RUMPUSER_MTX_KMUTEX  0x02

/* ---------------------------------------------------------------
 * Arena allocator configuration
 * --------------------------------------------------------------- */
#define RUMP_ARENA_BASE      0x40000000ULL  /* 1 GiB mark */
#define RUMP_ARENA_SIZE      (64ULL * 1024 * 1024)  /* 64 MiB */
#define PAGE_SIZE            4096ULL

/* ---------------------------------------------------------------
 * Internal structure definitions
 *
 * These are the opaque types that rumpuser.h forward-declares.
 * Each backs a rump synchronization or threading primitive with
 * SOT spinlocks + notification objects.
 * --------------------------------------------------------------- */

struct lwp;  /* Forward declaration (rump kernel LWP) */

/*
 * Mutex: spinlock-based with optional rump-kernel schedule/unschedule
 * wrapping.  SPIN mutexes never call hyp_schedule/unschedule (they are
 * held with interrupts disabled in the rump kernel).
 */
struct rumpuser_mtx {
    volatile int     locked;      /* 0 = free, 1 = held */
    int              flags;       /* RUMPUSER_MTX_SPIN | RUMPUSER_MTX_KMUTEX */
    struct lwp      *owner;       /* current holder (for rumpuser_mutex_owner) */
    uint64_t         notify_cap;  /* SOT notification for blocking waiters */
};

/*
 * Read-write lock: readers-count + writer flag + notification.
 * Writers starve readers (simple priority scheme).
 */
struct rumpuser_rw {
    volatile int     readers;     /* count of active readers */
    volatile int     writer;      /* 1 if a writer holds the lock */
    struct lwp      *write_owner; /* writer identity */
    uint64_t         notify_cap;  /* SOT notification for wake */
};

/*
 * Condition variable: waiter counter + notification.
 * cv_wait releases the associated mutex, blocks, re-acquires on wake.
 */
struct rumpuser_cv {
    volatile int     waiters;     /* number of threads in cv_wait */
    uint64_t         notify_cap;  /* SOT notification for signal/broadcast */
    volatile int     generation;  /* bumped on signal, to avoid lost wakes */
};

/*
 * Thread cookie: returned from rumpuser_thread_create, used by
 * rumpuser_thread_join to wait for completion.
 */
#define RUMP_MAX_THREADS 128
#define RUMP_THREAD_STACK_SIZE (64 * 1024)  /* 64 KiB per thread stack */

struct rump_thread_cookie {
    int              slot;        /* offset  0: index in global thread table */
    uint64_t         thread_cap;  /* offset  8: SOT thread capability */
    volatile int     finished;    /* offset 16: set to 1 when thread exits */
    uint64_t         notify_cap;  /* offset 24: joinable threads signal on exit */
    void           *(*entry)(void *); /* offset 32: thread function */
    void            *arg;         /* offset 40: argument to entry */
    int              joinable;    /* offset 48: whether joinable */
    uint64_t         td_ptr;      /* offset 56: pointer to rump_thread_data */
    char             name[32];    /* offset 64: debug name */
};

/* ---------------------------------------------------------------
 * IPC message structure (must match sotos_syscall.h)
 * --------------------------------------------------------------- */
struct ipc_msg {
    uint64_t tag;
    uint64_t regs[8];
};

/* ---------------------------------------------------------------
 * Inline syscall helpers
 * --------------------------------------------------------------- */

static inline uint64_t sot_syscall0(uint64_t nr)
{
    uint64_t ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r11", "memory");
    return ret;
}

static inline uint64_t sot_syscall1(uint64_t nr, uint64_t a1)
{
    uint64_t ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1)
        : "rcx", "r11", "memory");
    return ret;
}

static inline uint64_t sot_syscall2(uint64_t nr, uint64_t a1, uint64_t a2)
{
    uint64_t ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory");
    return ret;
}

static inline uint64_t sot_syscall3(uint64_t nr, uint64_t a1, uint64_t a2,
                                    uint64_t a3)
{
    uint64_t ret;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory");
    return ret;
}

static inline uint64_t sot_syscall4(uint64_t nr, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4)
{
    uint64_t ret;
    register uint64_t r8 __asm__("r8") = a4;
    __asm__ volatile ("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r8)
        : "rcx", "r11", "memory");
    return ret;
}

/* ---------------------------------------------------------------
 * High-level SOT wrappers
 * --------------------------------------------------------------- */

static inline void sot_yield(void)
{
    sot_syscall0(SYS_YIELD);
}

static inline int64_t sot_frame_alloc(void)
{
    return (int64_t)sot_syscall0(SYS_FRAME_ALLOC);
}

static inline int64_t sot_map(uint64_t vaddr, uint64_t frame_cap, uint64_t flags)
{
    return (int64_t)sot_syscall3(SYS_MAP, vaddr, frame_cap, flags);
}

static inline int64_t sot_unmap_free(uint64_t vaddr)
{
    return (int64_t)sot_syscall1(SYS_UNMAP_FREE, vaddr);
}

static inline int64_t sot_thread_create(uint64_t rip, uint64_t rsp, uint64_t arg)
{
    return (int64_t)sot_syscall3(SYS_THREAD_CREATE, rip, rsp, arg);
}

static inline void __attribute__((noreturn)) sot_thread_exit(void)
{
    sot_syscall0(SYS_THREAD_EXIT);
    __builtin_unreachable();
}

static inline int64_t sot_notify_create(void)
{
    return (int64_t)sot_syscall0(SYS_NOTIFY_CREATE);
}

static inline void sot_notify_wait(uint64_t cap)
{
    sot_syscall1(SYS_NOTIFY_WAIT, cap);
}

static inline void sot_notify_signal(uint64_t cap)
{
    sot_syscall1(SYS_NOTIFY_SIGNAL, cap);
}

static inline void sot_set_fs_base(uint64_t addr)
{
    sot_syscall1(SYS_SET_FS_BASE, addr);
}

static inline uint64_t sot_get_fs_base(void)
{
    return sot_syscall0(SYS_GET_FS_BASE);
}

static inline void sot_debug_putchar(uint8_t ch)
{
    sot_syscall1(SYS_DEBUG_PRINT, (uint64_t)ch);
}

static inline int64_t sot_svc_lookup(const char *name, uint64_t len)
{
    return (int64_t)sot_syscall2(SYS_SVC_LOOKUP, (uint64_t)name, len);
}

/* ---------------------------------------------------------------
 * Serial output helpers
 * --------------------------------------------------------------- */

static inline void sot_serial_puts(const char *s)
{
    while (*s)
        sot_debug_putchar((uint8_t)*s++);
}

static inline void sot_serial_hex(uint64_t val)
{
    static const char hex[] = "0123456789abcdef";
    sot_serial_puts("0x");
    for (int i = 60; i >= 0; i -= 4)
        sot_debug_putchar((uint8_t)hex[(val >> i) & 0xF]);
}

static inline void sot_serial_dec(int64_t val)
{
    if (val < 0) {
        sot_debug_putchar('-');
        val = -val;
    }
    if (val == 0) {
        sot_debug_putchar('0');
        return;
    }
    char buf[20];
    int n = 0;
    while (val > 0) {
        buf[n++] = '0' + (char)(val % 10);
        val /= 10;
    }
    for (int i = n - 1; i >= 0; i--)
        sot_debug_putchar((uint8_t)buf[i]);
}

/* ---------------------------------------------------------------
 * Arena allocator interface (internal to rumpuser_sot.c)
 * --------------------------------------------------------------- */

int   rump_arena_init(void);
void *rump_arena_alloc(unsigned long size);
void  rump_arena_free(void *ptr, unsigned long size);
unsigned long rump_arena_used(void);

#endif /* RUMPUSER_SOT_H */
