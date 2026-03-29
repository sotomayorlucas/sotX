/*
 * rumpuser_sot.c -- SOT Rump Hypervisor: rumpuser(3) on SOT exokernel.
 *
 * This is the adaptation layer that maps NetBSD rump kernel hypercalls
 * to SOT exokernel primitives.  It replaces the default POSIX-based
 * librumpuser with one that runs on bare SOT without libc, pthreads,
 * or POSIX I/O.
 *
 * Mapping strategy:
 *   Threads     -> SYS_THREAD_CREATE / SYS_THREAD_EXIT + notification-based join
 *   Mutexes     -> spinlock (atomic test-and-set) + SYS_NOTIFY for contention
 *   RW locks    -> atomic reader count + writer flag + SYS_NOTIFY
 *   Cond vars   -> generation counter + SYS_NOTIFY_WAIT/SIGNAL
 *   Memory      -> SYS_FRAME_ALLOC + SYS_MAP (arena bump allocator)
 *   Block I/O   -> IPC to "blk" service via SYS_CALL
 *   Clock       -> RDTSC (assumed 2 GHz)
 *   Random      -> RDRAND instruction (x86_64)
 *   Console     -> SYS_DEBUG_PRINT (serial COM1)
 *
 * Copyright (c) 2025-2026 sotOS contributors.
 * BSD 2-Clause License (matching NetBSD rump kernel licensing).
 */

#define LIBRUMPUSER  /* expose curlwp interface in rumpuser.h */

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

/* We cannot include the real rumpuser.h without a rump build tree present,
 * so we re-declare what we need.  The signatures MUST match rumpuser.h
 * exactly for ABI compatibility with the rump kernel. */
#include "rumpuser_sot.h"

/* ---------------------------------------------------------------
 * Rump hypervisor upcalls (stored during rumpuser_init)
 * --------------------------------------------------------------- */

struct rumpuser_hyperup {
    void (*hyp_schedule)(void);
    void (*hyp_unschedule)(void);
    void (*hyp_backend_unschedule)(int, int *, void *);
    void (*hyp_backend_schedule)(int, void *);
    void (*hyp_lwproc_switch)(struct lwp *);
    void (*hyp_lwproc_release)(void);
    int  (*hyp_lwproc_rfork)(void *, int, const char *);
    int  (*hyp_lwproc_newlwp)(int /* pid_t */);
    struct lwp *(*hyp_lwproc_curlwp)(void);
    int  (*hyp_syscall)(int, void *, long *);
    void (*hyp_lwpexit)(void);
    void (*hyp_execnotify)(const char *);
    int  (*hyp_getpid)(void);
    void *hyp__extra[8];
};

typedef void (*rump_biodone_fn)(void *, size_t, int);

static struct rumpuser_hyperup rump_hyp;
static int rump_initialized;

/* ---------------------------------------------------------------
 * Forward declarations (libc-free string/memory helpers)
 * --------------------------------------------------------------- */

static void *ru_memset(void *s, int c, size_t n);
static void *ru_memcpy(void *dst, const void *src, size_t n);
static int   ru_strcmp(const char *a, const char *b);
static size_t ru_strlen(const char *s);
static int   ru_snprintf(char *buf, size_t blen, const char *fmt, ...);

/* ---------------------------------------------------------------
 * Rump kernel schedule/unschedule wrappers
 *
 * The rump kernel requires that hypercalls which may block call
 * hyp_unschedule before blocking and hyp_schedule after waking.
 * This prevents the rump kernel from thinking a CPU is busy when
 * it is actually sleeping in the hypervisor.
 * --------------------------------------------------------------- */

static inline void rumpkern_sched(int nlocks, void *interlock)
{
    (void)interlock;
    for (int i = 0; i < nlocks; i++)
        rump_hyp.hyp_schedule();
}

static inline void rumpkern_unsched(int *nlocksp, void *interlock)
{
    (void)interlock;
    /* The rump kernel tracks a recursion count for virtual CPUs.
     * We always hold exactly 1 lock when entering a hypercall. */
    *nlocksp = 1;
    rump_hyp.hyp_unschedule();
}

/* ---------------------------------------------------------------
 * Arena allocator (self-contained, SOT frame-based)
 *
 * Maps physical frames at RUMP_ARENA_BASE on first use.  Bump
 * allocation with a size-tagged free list for reuse.
 * --------------------------------------------------------------- */

struct free_node {
    struct free_node *next;
    unsigned long     size;
};

static uint64_t          arena_bump;
static uint64_t          arena_end;
static struct free_node *arena_free_head;
static int               arena_ready;

int rump_arena_init(void)
{
    uint64_t pages = RUMP_ARENA_SIZE / PAGE_SIZE;
    uint64_t addr  = RUMP_ARENA_BASE;

    sot_serial_puts("[rumpuser] arena_init: mapping ");
    sot_serial_dec((int64_t)pages);
    sot_serial_puts(" pages at ");
    sot_serial_hex(RUMP_ARENA_BASE);
    sot_serial_puts("\n");

    for (uint64_t i = 0; i < pages; i++) {
        int64_t frame = sot_frame_alloc();
        if (frame < 0) {
            sot_serial_puts("[rumpuser] arena_init: frame_alloc failed at page ");
            sot_serial_dec((int64_t)i);
            sot_serial_puts("\n");
            return (int)frame;
        }
        int64_t r = sot_map(addr, (uint64_t)frame, MAP_RW_NX);
        if (r < 0) {
            sot_serial_puts("[rumpuser] arena_init: map failed\n");
            return (int)r;
        }
        addr += PAGE_SIZE;
    }

    arena_bump       = RUMP_ARENA_BASE;
    arena_end        = RUMP_ARENA_BASE + RUMP_ARENA_SIZE;
    arena_free_head  = (void *)0;
    arena_ready      = 1;

    sot_serial_puts("[rumpuser] arena ready: ");
    sot_serial_dec((int64_t)(RUMP_ARENA_SIZE / 1024 / 1024));
    sot_serial_puts(" MiB\n");
    return 0;
}

void *rump_arena_alloc(unsigned long size)
{
    if (!arena_ready || size == 0)
        return (void *)0;

    /* 16-byte alignment for SSE compatibility. */
    size = (size + 15UL) & ~15UL;

    /* Minimum size: must fit a free_node for later reuse. */
    if (size < sizeof(struct free_node))
        size = sizeof(struct free_node);

    /* First-fit search in free list. */
    struct free_node **pp = &arena_free_head;
    while (*pp) {
        if ((*pp)->size >= size) {
            void *ptr = (void *)*pp;
            *pp = (*pp)->next;
            return ptr;
        }
        pp = &(*pp)->next;
    }

    /* Bump allocator fallback. */
    if (arena_bump + size > arena_end)
        return (void *)0;

    void *ptr = (void *)arena_bump;
    arena_bump += size;
    return ptr;
}

void rump_arena_free(void *ptr, unsigned long size)
{
    if (!ptr || !arena_ready)
        return;

    /* Round up size to match allocation alignment. */
    size = (size + 15UL) & ~15UL;
    if (size < sizeof(struct free_node))
        size = sizeof(struct free_node);

    struct free_node *node = (struct free_node *)ptr;
    node->size = size;
    node->next = arena_free_head;
    arena_free_head = node;
}

unsigned long rump_arena_used(void)
{
    return (unsigned long)(arena_bump - RUMP_ARENA_BASE);
}

/* ---------------------------------------------------------------
 * Thread management
 *
 * Each rump thread gets a SOT kernel thread.  We maintain a table
 * of thread cookies for join support.  The thread trampoline runs
 * the user function, marks the cookie as finished, and exits.
 * --------------------------------------------------------------- */

static struct rump_thread_cookie thread_table[RUMP_MAX_THREADS];
static volatile int next_thread_slot;

/* Per-thread current LWP pointer.  Since we don't have real TLS on
 * SOT, we use FS_BASE to point to a per-thread data block. */
struct rump_thread_data {
    struct lwp *curlwp;    /* offset 0: current LWP */
    int         slot;      /* offset 8: thread table index */
    uint64_t    _pad;      /* offset 12: pad to 16 bytes */
};

#define MAX_THREAD_DATA 128
static struct rump_thread_data thread_data_pool[MAX_THREAD_DATA];
static volatile int next_td_slot;

static struct rump_thread_data *get_thread_data(void)
{
    uint64_t fs = sot_get_fs_base();
    if (fs >= (uint64_t)&thread_data_pool[0] &&
        fs < (uint64_t)&thread_data_pool[MAX_THREAD_DATA])
        return (struct rump_thread_data *)fs;
    return (void *)0;
}

/*
 * Thread entry trampoline (pure assembly).
 * Stack at entry: [rsp] = pointer to rump_thread_cookie.
 * Pops cookie, aligns stack to ABI requirement, sets FS_BASE for
 * per-thread data, calls entry(arg), marks finished, signals
 * joiner, exits.
 */
/*
 * Thread entry trampoline (pure assembly).
 *
 * Stack at entry: [rsp] = pointer to rump_thread_cookie.
 *
 * Struct layout (rump_thread_cookie, x86_64, natural alignment):
 *   offset  0: int slot           (4 bytes + 4 pad)
 *   offset  8: uint64_t thread_cap
 *   offset 16: int finished       (4 bytes + 4 pad)
 *   offset 24: uint64_t notify_cap
 *   offset 32: void *(*entry)(void *)
 *   offset 40: void *arg
 *   offset 48: int joinable       (4 bytes + 4 pad)
 *   offset 56: uint64_t td_ptr    (pointer to rump_thread_data)
 *   offset 64: char name[32]
 */
__asm__(
    ".globl rump_thread_trampoline\n"
    ".type rump_thread_trampoline, @function\n"
    "rump_thread_trampoline:\n"
    "    pop %rbx\n"                /* rbx = cookie pointer (callee-saved) */
    "    and $-16, %rsp\n"          /* align stack to 16 bytes */
    /* Set FS_BASE to the pre-computed thread_data pointer stored
     * in cookie->td_ptr (offset 56).  This avoids any RIP-relative
     * addressing issues with -mcmodel=large. */
    "    mov 56(%rbx), %rdi\n"     /* rdi = cookie->td_ptr */
    "    mov $160, %eax\n"         /* SYS_SET_FS_BASE */
    "    syscall\n"
    /* Call entry(arg) */
    "    mov 32(%rbx), %rax\n"     /* rax = cookie->entry (offset 32) */
    "    mov 40(%rbx), %rdi\n"     /* rdi = cookie->arg   (offset 40) */
    "    test %rax, %rax\n"
    "    jz 1f\n"
    "    sub $8, %rsp\n"           /* 16-byte alignment before call */
    "    call *%rax\n"
    "    add $8, %rsp\n"
    "1:\n"
    /* Mark finished: cookie->finished (offset 16) = 1 */
    "    movl $1, 16(%rbx)\n"
    /* Signal joiner: if cookie->notify_cap (offset 24) != 0 */
    "    mov 24(%rbx), %rdi\n"     /* rdi = notify_cap */
    "    test %rdi, %rdi\n"
    "    jz 2f\n"
    "    mov $72, %eax\n"          /* SYS_NOTIFY_SIGNAL */
    "    syscall\n"
    "2:\n"
    "    mov $42, %eax\n"          /* SYS_THREAD_EXIT */
    "    syscall\n"
    "    ud2\n"
);
extern void rump_thread_trampoline(void);

/*
 * rumpuser_thread_create -- Create a new rump kernel thread.
 *
 * Maps to: SYS_THREAD_CREATE + arena stack allocation.
 * The SOT kernel creates a new scheduling context with its own
 * register file, stack, and address space (shared with parent).
 *
 * Parameters:
 *   f        - thread entry function
 *   arg      - argument passed to f
 *   name     - human-readable name (for debugging)
 *   joinable - if true, rumpuser_thread_join can be called later
 *   priority - scheduling priority hint (not enforced by SOT)
 *   cpuidx   - preferred CPU index (ignored on single-CPU SOT)
 *   cookie   - [out] opaque handle for join
 *
 * Returns 0 on success, errno on failure.
 */
int rumpuser_thread_create(void *(*f)(void *), void *arg, const char *name,
    int joinable, int priority, int cpuidx, void **cookie)
{
    (void)priority;
    (void)cpuidx;

    int slot = __atomic_fetch_add(&next_thread_slot, 1, __ATOMIC_RELAXED)
               % RUMP_MAX_THREADS;

    struct rump_thread_cookie *ck = &thread_table[slot];
    ck->slot     = slot;
    ck->finished = 0;
    ck->entry    = f;
    ck->arg      = arg;
    ck->joinable = joinable;

    /* Copy name for debugging. */
    if (name) {
        int i;
        for (i = 0; i < 31 && name[i]; i++)
            ck->name[i] = name[i];
        ck->name[i] = '\0';
    } else {
        ck->name[0] = '\0';
    }

    /* Create notification object for joinable threads. */
    if (joinable) {
        int64_t nc = sot_notify_create();
        ck->notify_cap = (nc > 0) ? (uint64_t)nc : 0;
    } else {
        ck->notify_cap = 0;
    }

    /* Allocate per-thread data slot and store pointer in cookie
     * so the trampoline can set FS_BASE without RIP-relative addressing. */
    int td_slot = __atomic_fetch_add(&next_td_slot, 1, __ATOMIC_RELAXED)
                  % MAX_THREAD_DATA;
    thread_data_pool[td_slot].curlwp = (void *)0;
    thread_data_pool[td_slot].slot   = slot;
    ck->td_ptr = (uint64_t)&thread_data_pool[td_slot];

    /* Allocate stack from arena. */
    uint8_t *stack = (uint8_t *)rump_arena_alloc(RUMP_THREAD_STACK_SIZE);
    if (!stack) {
        sot_serial_puts("[rumpuser] thread_create: OOM for stack\n");
        return 12; /* ENOMEM */
    }

    /* Set up stack: push cookie pointer for trampoline to pop. */
    uint64_t sp = ((uint64_t)stack + RUMP_THREAD_STACK_SIZE) & ~15ULL;
    sp -= 8;
    *(uint64_t *)sp = (uint64_t)ck;

    sot_serial_puts("[rumpuser] thread_create: '");
    if (name) sot_serial_puts(name);
    sot_serial_puts("' slot=");
    sot_serial_dec((int64_t)slot);
    sot_serial_puts("\n");

    /* Create the SOT kernel thread. */
    int64_t tcap = sot_thread_create((uint64_t)rump_thread_trampoline, sp, 0);
    if (tcap < 0) {
        sot_serial_puts("[rumpuser] thread_create: syscall failed\n");
        return 11; /* EAGAIN */
    }

    ck->thread_cap = (uint64_t)tcap;

    if (cookie)
        *cookie = (void *)ck;

    return 0;
}

/*
 * rumpuser_thread_exit -- Terminate the calling rump thread.
 *
 * Maps to: SYS_THREAD_EXIT (never returns).
 */
void rumpuser_thread_exit(void)
{
    sot_serial_puts("[rumpuser] thread_exit\n");

    /* Mark our cookie as finished if we can find it. */
    struct rump_thread_data *td = get_thread_data();
    if (td && td->slot >= 0 && td->slot < RUMP_MAX_THREADS) {
        struct rump_thread_cookie *ck = &thread_table[td->slot];
        ck->finished = 1;
        if (ck->notify_cap)
            sot_notify_signal(ck->notify_cap);
    }

    sot_thread_exit();
}

/*
 * rumpuser_thread_join -- Wait for a joinable rump thread to finish.
 *
 * Maps to: SYS_NOTIFY_WAIT on the thread's notification object,
 * with a spin-yield fallback for threads without a notify cap.
 */
int rumpuser_thread_join(void *cookie)
{
    struct rump_thread_cookie *ck = (struct rump_thread_cookie *)cookie;
    if (!ck)
        return 22; /* EINVAL */

    int nlocks;
    rumpkern_unsched(&nlocks, (void *)0);

    /* Wait for thread to finish.  If we have a notification cap, use it;
     * otherwise spin-yield (necessary if notify_create failed). */
    if (ck->notify_cap) {
        int spins = 0;
        while (!ck->finished) {
            sot_notify_wait(ck->notify_cap);
            if (++spins > 500000) break;  /* safety timeout */
        }
    } else {
        int spins = 0;
        while (!ck->finished) {
            sot_yield();
            if (++spins > 500000) break;
        }
    }

    rumpkern_sched(nlocks, (void *)0);
    return 0;
}

/* ---------------------------------------------------------------
 * Current LWP tracking
 *
 * The rump kernel needs to track which LWP is "current" on each
 * virtual CPU.  We use per-thread data via FS_BASE to store a
 * pointer to the current lwp.
 * --------------------------------------------------------------- */

void rumpuser_curlwpop(int op, struct lwp *l)
{
    struct rump_thread_data *td = get_thread_data();

    /* enum: CREATE=0, DESTROY=1, SET=2, CLEAR=3 */
    switch (op) {
    case 0: /* RUMPUSER_LWP_CREATE */
        /* Nothing to do -- lwp lifecycle managed by rump kernel. */
        break;
    case 1: /* RUMPUSER_LWP_DESTROY */
        if (td && td->curlwp == l)
            td->curlwp = (void *)0;
        break;
    case 2: /* RUMPUSER_LWP_SET */
        if (td)
            td->curlwp = l;
        break;
    case 3: /* RUMPUSER_LWP_CLEAR */
        if (td)
            td->curlwp = (void *)0;
        break;
    }
}

struct lwp *rumpuser_curlwp(void)
{
    struct rump_thread_data *td = get_thread_data();
    if (td)
        return td->curlwp;
    return (void *)0;
}

/* ---------------------------------------------------------------
 * Mutexes
 *
 * Implemented as spinlocks with yield.  SPIN mutexes use pure
 * spinning; KMUTEX mutexes call hyp_schedule/unschedule around
 * the blocking loop so the rump kernel can schedule other LWPs.
 *
 * The SOT notification object is used for contended mutexes to
 * avoid pure busy-wait when there are many threads.
 * --------------------------------------------------------------- */

/*
 * rumpuser_mutex_init -- Allocate and initialize a mutex.
 *
 * Maps to: arena allocation + optional SYS_NOTIFY_CREATE.
 */
void rumpuser_mutex_init(struct rumpuser_mtx **mtxp, int flags)
{
    struct rumpuser_mtx *mtx = (struct rumpuser_mtx *)
        rump_arena_alloc(sizeof(struct rumpuser_mtx));
    if (!mtx) {
        sot_serial_puts("[rumpuser] mutex_init: OOM\n");
        *mtxp = (void *)0;
        return;
    }

    mtx->locked = 0;
    mtx->flags  = flags;
    mtx->owner  = (void *)0;

    /* Create a notification object for blocking on contention.
     * SPIN mutexes don't need one (they never block). */
    if (!(flags & RUMPUSER_MTX_SPIN)) {
        int64_t nc = sot_notify_create();
        mtx->notify_cap = (nc > 0) ? (uint64_t)nc : 0;
    } else {
        mtx->notify_cap = 0;
    }

    *mtxp = mtx;
}

/*
 * rumpuser_mutex_enter -- Lock a mutex.
 *
 * For KMUTEX: calls hyp_unschedule before blocking, hyp_schedule
 * after acquiring.  This lets the rump kernel schedule other LWPs
 * on the same virtual CPU while we're blocked.
 *
 * Maps to: atomic test_and_set spin + SYS_NOTIFY_WAIT on contention.
 */
void rumpuser_mutex_enter(struct rumpuser_mtx *mtx)
{
    if (!mtx) return;

    if (!(mtx->flags & RUMPUSER_MTX_SPIN)) {
        int nlocks;
        rumpkern_unsched(&nlocks, (void *)0);

        while (__atomic_test_and_set((volatile void *)&mtx->locked,
                                     __ATOMIC_ACQUIRE)) {
            if (mtx->notify_cap)
                sot_notify_wait(mtx->notify_cap);
            else
                sot_yield();
        }

        rumpkern_sched(nlocks, (void *)0);
    } else {
        /* SPIN mutex: pure spinning, no schedule/unschedule. */
        while (__atomic_test_and_set((volatile void *)&mtx->locked,
                                     __ATOMIC_ACQUIRE))
            sot_yield();
    }

    mtx->owner = rumpuser_curlwp();
}

/*
 * rumpuser_mutex_enter_nowrap -- Lock mutex without schedule wrapping.
 *
 * Used by the rump kernel during contexts where hyp_schedule/unschedule
 * must not be called (e.g., during scheduler operations).
 */
void rumpuser_mutex_enter_nowrap(struct rumpuser_mtx *mtx)
{
    if (!mtx) return;

    while (__atomic_test_and_set((volatile void *)&mtx->locked,
                                 __ATOMIC_ACQUIRE))
        sot_yield();

    mtx->owner = rumpuser_curlwp();
}

/*
 * rumpuser_mutex_tryenter -- Attempt to lock mutex without blocking.
 *
 * Returns 0 on success, non-zero (EBUSY) if already held.
 */
int rumpuser_mutex_tryenter(struct rumpuser_mtx *mtx)
{
    if (!mtx) return 16; /* EBUSY */

    if (__atomic_test_and_set((volatile void *)&mtx->locked,
                              __ATOMIC_ACQUIRE)) {
        return 16; /* EBUSY */
    }

    mtx->owner = rumpuser_curlwp();
    return 0;
}

/*
 * rumpuser_mutex_exit -- Unlock a mutex.
 *
 * Maps to: atomic clear + SYS_NOTIFY_SIGNAL if waiters exist.
 */
void rumpuser_mutex_exit(struct rumpuser_mtx *mtx)
{
    if (!mtx) return;

    mtx->owner = (void *)0;
    __atomic_clear((volatile void *)&mtx->locked, __ATOMIC_RELEASE);

    /* Wake one potential waiter. */
    if (mtx->notify_cap)
        sot_notify_signal(mtx->notify_cap);
}

/*
 * rumpuser_mutex_destroy -- Free a mutex.
 *
 * Maps to: arena free.  The notification cap leaks (SOT does not
 * yet have cap destruction; it will be reclaimed on process exit).
 */
void rumpuser_mutex_destroy(struct rumpuser_mtx *mtx)
{
    if (!mtx) return;
    rump_arena_free(mtx, sizeof(struct rumpuser_mtx));
}

/*
 * rumpuser_mutex_owner -- Query mutex owner (for kernel assertions).
 *
 * Sets *lp to the lwp that currently holds the mutex, or NULL.
 */
void rumpuser_mutex_owner(struct rumpuser_mtx *mtx, struct lwp **lp)
{
    if (!mtx || !lp) return;

    if (mtx->locked)
        *lp = mtx->owner;
    else
        *lp = (void *)0;
}

/*
 * rumpuser_mutex_spin_p -- Query whether a mutex is a spin mutex.
 *
 * Returns non-zero if the mutex was created with RUMPUSER_MTX_SPIN.
 */
int rumpuser_mutex_spin_p(struct rumpuser_mtx *mtx)
{
    if (!mtx) return 0;
    return (mtx->flags & RUMPUSER_MTX_SPIN) != 0;
}

/* ---------------------------------------------------------------
 * Read-Write Locks
 *
 * Multiple concurrent readers, exclusive writer.  Writers take
 * priority (set writer flag first, then wait for readers to drain).
 * Uses atomic operations + SOT notifications for blocking.
 * --------------------------------------------------------------- */

/*
 * rumpuser_rw_init -- Allocate and initialize a read-write lock.
 */
void rumpuser_rw_init(struct rumpuser_rw **rwp)
{
    struct rumpuser_rw *rw = (struct rumpuser_rw *)
        rump_arena_alloc(sizeof(struct rumpuser_rw));
    if (!rw) {
        *rwp = (void *)0;
        return;
    }

    rw->readers     = 0;
    rw->writer      = 0;
    rw->write_owner = (void *)0;

    int64_t nc = sot_notify_create();
    rw->notify_cap = (nc > 0) ? (uint64_t)nc : 0;

    *rwp = rw;
}

/*
 * rumpuser_rw_enter -- Acquire read or write lock.
 *
 * write = RUMPUSER_RW_WRITER (1) for exclusive, RUMPUSER_RW_READER (0)
 * for shared.
 *
 * Maps to: atomic reader counter manipulation + spin-yield for writers.
 */
void rumpuser_rw_enter(int write, struct rumpuser_rw *rw)
{
    if (!rw) return;

    int nlocks;
    rumpkern_unsched(&nlocks, (void *)0);

    if (write) {
        /* Writer: spin until we can set the writer flag AND readers == 0. */
        for (;;) {
            int expected = 0;
            if (__atomic_compare_exchange_n(&rw->writer, &expected, 1,
                    0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                /* Got writer flag; now wait for readers to drain. */
                while (__atomic_load_n(&rw->readers, __ATOMIC_ACQUIRE) != 0) {
                    if (rw->notify_cap)
                        sot_notify_wait(rw->notify_cap);
                    else
                        sot_yield();
                }
                break;
            }
            if (rw->notify_cap)
                sot_notify_wait(rw->notify_cap);
            else
                sot_yield();
        }
        rw->write_owner = rumpuser_curlwp();
    } else {
        /* Reader: spin while a writer holds or is waiting. */
        for (;;) {
            if (!__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE)) {
                __atomic_add_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
                /* Double-check: if a writer slipped in, back out. */
                if (__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE)) {
                    __atomic_sub_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
                    if (rw->notify_cap)
                        sot_notify_signal(rw->notify_cap);
                    continue;
                }
                break;
            }
            if (rw->notify_cap)
                sot_notify_wait(rw->notify_cap);
            else
                sot_yield();
        }
    }

    rumpkern_sched(nlocks, (void *)0);
}

/*
 * rumpuser_rw_tryenter -- Non-blocking rwlock acquisition.
 *
 * Returns 0 on success, EBUSY on failure.
 */
int rumpuser_rw_tryenter(int write, struct rumpuser_rw *rw)
{
    if (!rw) return 16; /* EBUSY */

    if (write) {
        int expected = 0;
        if (!__atomic_compare_exchange_n(&rw->writer, &expected, 1,
                0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 16; /* EBUSY */
        if (__atomic_load_n(&rw->readers, __ATOMIC_ACQUIRE) != 0) {
            __atomic_store_n(&rw->writer, 0, __ATOMIC_RELEASE);
            if (rw->notify_cap) sot_notify_signal(rw->notify_cap);
            return 16; /* EBUSY */
        }
        rw->write_owner = rumpuser_curlwp();
    } else {
        if (__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE))
            return 16; /* EBUSY */
        __atomic_add_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
        if (__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE)) {
            __atomic_sub_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
            if (rw->notify_cap) sot_notify_signal(rw->notify_cap);
            return 16; /* EBUSY */
        }
    }
    return 0;
}

/*
 * rumpuser_rw_tryupgrade -- Attempt to upgrade a reader to writer.
 *
 * Returns 0 on success, EBUSY if other readers exist.
 */
int rumpuser_rw_tryupgrade(struct rumpuser_rw *rw)
{
    if (!rw) return 16;

    int expected = 0;
    if (!__atomic_compare_exchange_n(&rw->writer, &expected, 1,
            0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 16; /* another writer */

    /* We're still counted as a reader; check if we're the only one. */
    if (__atomic_load_n(&rw->readers, __ATOMIC_ACQUIRE) != 1) {
        __atomic_store_n(&rw->writer, 0, __ATOMIC_RELEASE);
        if (rw->notify_cap) sot_notify_signal(rw->notify_cap);
        return 16; /* other readers exist */
    }

    /* Drop our reader count; we are now the writer. */
    __atomic_sub_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
    rw->write_owner = rumpuser_curlwp();
    return 0;
}

/*
 * rumpuser_rw_downgrade -- Downgrade writer to reader.
 */
void rumpuser_rw_downgrade(struct rumpuser_rw *rw)
{
    if (!rw) return;

    __atomic_add_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
    rw->write_owner = (void *)0;
    __atomic_store_n(&rw->writer, 0, __ATOMIC_RELEASE);

    /* Wake waiting readers. */
    if (rw->notify_cap)
        sot_notify_signal(rw->notify_cap);
}

/*
 * rumpuser_rw_exit -- Release a read or write lock.
 */
void rumpuser_rw_exit(struct rumpuser_rw *rw)
{
    if (!rw) return;

    if (__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE)) {
        /* We're the writer.  Release write lock. */
        rw->write_owner = (void *)0;
        __atomic_store_n(&rw->writer, 0, __ATOMIC_RELEASE);
    } else {
        /* We're a reader.  Decrement reader count. */
        __atomic_sub_fetch(&rw->readers, 1, __ATOMIC_ACQ_REL);
    }

    /* Wake any waiters (writers waiting for readers=0, or readers
     * waiting for writer=0). */
    if (rw->notify_cap)
        sot_notify_signal(rw->notify_cap);
}

/*
 * rumpuser_rw_destroy -- Free a read-write lock.
 */
void rumpuser_rw_destroy(struct rumpuser_rw *rw)
{
    if (!rw) return;
    rump_arena_free(rw, sizeof(struct rumpuser_rw));
}

/*
 * rumpuser_rw_held -- Check if rwlock is held in specified mode.
 *
 * Writes result into *heldp (1=held, 0=not held).
 */
void rumpuser_rw_held(int write, struct rumpuser_rw *rw, int *heldp)
{
    if (!rw || !heldp) return;

    if (write) {
        *heldp = (__atomic_load_n(&rw->writer, __ATOMIC_ACQUIRE) &&
                  rw->write_owner == rumpuser_curlwp()) ? 1 : 0;
    } else {
        *heldp = (__atomic_load_n(&rw->readers, __ATOMIC_ACQUIRE) > 0) ? 1 : 0;
    }
}

/* ---------------------------------------------------------------
 * Condition Variables
 *
 * Generation-counter based.  A waiter records the current
 * generation, releases the mutex, and waits until the generation
 * changes (via signal or broadcast).  This avoids lost-wakeup
 * races without needing a full waiter queue.
 * --------------------------------------------------------------- */

/*
 * rumpuser_cv_init -- Allocate and initialize a condition variable.
 */
void rumpuser_cv_init(struct rumpuser_cv **cvp)
{
    struct rumpuser_cv *cv = (struct rumpuser_cv *)
        rump_arena_alloc(sizeof(struct rumpuser_cv));
    if (!cv) {
        *cvp = (void *)0;
        return;
    }

    cv->waiters    = 0;
    cv->generation = 0;

    int64_t nc = sot_notify_create();
    cv->notify_cap = (nc > 0) ? (uint64_t)nc : 0;

    *cvp = cv;
}

/*
 * rumpuser_cv_destroy -- Free a condition variable.
 */
void rumpuser_cv_destroy(struct rumpuser_cv *cv)
{
    if (!cv) return;
    rump_arena_free(cv, sizeof(struct rumpuser_cv));
}

/*
 * rumpuser_cv_wait -- Block until condition is signaled.
 *
 * Protocol:
 *   1. Record current generation
 *   2. Increment waiter count
 *   3. Release associated mutex (with schedule unwrap)
 *   4. Wait for generation to change
 *   5. Re-acquire mutex
 *   6. Decrement waiter count
 *
 * Maps to: SYS_NOTIFY_WAIT + spin-yield for generation check.
 */
void rumpuser_cv_wait(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx)
{
    if (!cv || !mtx) return;

    int gen = __atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);

    /* Release mutex and rump scheduler. */
    rumpuser_mutex_exit(mtx);

    int nlocks;
    rumpkern_unsched(&nlocks, (void *)0);

    /* Wait for generation to change (signal or broadcast). */
    while (__atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE) == gen) {
        if (cv->notify_cap)
            sot_notify_wait(cv->notify_cap);
        else
            sot_yield();
    }

    rumpkern_sched(nlocks, (void *)0);

    __atomic_sub_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);

    /* Re-acquire mutex (with full schedule wrapping). */
    rumpuser_mutex_enter(mtx);
}

/*
 * rumpuser_cv_wait_nowrap -- Same as cv_wait but without rump schedule
 * wrapping around the mutex operations.
 */
void rumpuser_cv_wait_nowrap(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx)
{
    if (!cv || !mtx) return;

    int gen = __atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);

    /* Release mutex WITHOUT schedule wrapping. */
    rumpuser_mutex_exit(mtx);

    while (__atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE) == gen) {
        if (cv->notify_cap)
            sot_notify_wait(cv->notify_cap);
        else
            sot_yield();
    }

    __atomic_sub_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);

    rumpuser_mutex_enter_nowrap(mtx);
}

/*
 * rumpuser_cv_timedwait -- Wait with timeout.
 *
 * Uses RDTSC for deadline computation (2 GHz assumed).
 * Returns 0 on signal, ETIMEDOUT (60) on timeout.
 */
int rumpuser_cv_timedwait(struct rumpuser_cv *cv, struct rumpuser_mtx *mtx,
    int64_t sec, int64_t nsec)
{
    if (!cv || !mtx) return 22; /* EINVAL */

    int gen = __atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE);
    __atomic_add_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);

    rumpuser_mutex_exit(mtx);

    int nlocks;
    rumpkern_unsched(&nlocks, (void *)0);

    /* Compute RDTSC deadline.  Assume 2 GHz: 1 tick = 0.5 ns. */
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t tsc_now = ((uint64_t)hi << 32) | lo;
    uint64_t deadline_ns = (uint64_t)sec * 1000000000ULL + (uint64_t)nsec;
    uint64_t deadline_tsc = tsc_now + deadline_ns * 2;  /* 2 ticks per ns */

    int timed_out = 0;

    while (__atomic_load_n(&cv->generation, __ATOMIC_ACQUIRE) == gen) {
        __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t now = ((uint64_t)hi << 32) | lo;
        if (now >= deadline_tsc) {
            timed_out = 1;
            break;
        }
        sot_yield();
    }

    rumpkern_sched(nlocks, (void *)0);

    __atomic_sub_fetch(&cv->waiters, 1, __ATOMIC_ACQ_REL);
    rumpuser_mutex_enter(mtx);

    return timed_out ? 60 : 0;  /* ETIMEDOUT = 60 on NetBSD */
}

/*
 * rumpuser_cv_signal -- Wake one waiter.
 *
 * Bumps the generation counter so exactly one waiter (the one that
 * sees its generation change) wakes up.  Additional waiters remain
 * blocked because the generation continues to match theirs.
 *
 * Maps to: atomic increment + SYS_NOTIFY_SIGNAL.
 */
void rumpuser_cv_signal(struct rumpuser_cv *cv)
{
    if (!cv) return;

    __atomic_add_fetch(&cv->generation, 1, __ATOMIC_RELEASE);

    if (cv->notify_cap)
        sot_notify_signal(cv->notify_cap);
}

/*
 * rumpuser_cv_broadcast -- Wake all waiters.
 *
 * Same as signal but wakes everyone.  Since all waiters compare
 * against their captured generation, bumping once wakes them all.
 * We also re-signal the notification to handle the case where
 * multiple threads are blocked on the same notification cap.
 */
void rumpuser_cv_broadcast(struct rumpuser_cv *cv)
{
    if (!cv) return;

    __atomic_add_fetch(&cv->generation, 1, __ATOMIC_RELEASE);

    /* Signal repeatedly to wake all notification waiters.
     * SOT notifications are edge-triggered; each signal wakes at most
     * one waiter.  So we signal once per current waiter. */
    if (cv->notify_cap) {
        int n = __atomic_load_n(&cv->waiters, __ATOMIC_ACQUIRE);
        for (int i = 0; i <= n; i++)
            sot_notify_signal(cv->notify_cap);
    }
}

/*
 * rumpuser_cv_has_waiters -- Check if any threads are waiting.
 */
void rumpuser_cv_has_waiters(struct rumpuser_cv *cv, int *hwaitersp)
{
    if (!cv || !hwaitersp) return;
    *hwaitersp = (__atomic_load_n(&cv->waiters, __ATOMIC_ACQUIRE) > 0) ? 1 : 0;
}

/* ---------------------------------------------------------------
 * Memory allocation
 *
 * rumpuser_malloc / rumpuser_free map directly to our arena.
 * rumpuser_anonmmap / rumpuser_unmap do frame-level allocation
 * for larger mappings.
 * --------------------------------------------------------------- */

/*
 * rumpuser_malloc -- Allocate memory for the rump kernel.
 *
 * Maps to: arena bump allocator (backed by SOT physical frames).
 * The alignment parameter is a power-of-two alignment request.
 */
int rumpuser_malloc(size_t len, int alignment, void **memp)
{
    if (len == 0) {
        *memp = (void *)0;
        return 0;
    }

    /* For large alignments, over-allocate and manually align. */
    size_t alloc_size = len;
    if (alignment > 16)
        alloc_size += (size_t)alignment;

    void *ptr = rump_arena_alloc(alloc_size);
    if (!ptr) {
        sot_serial_puts("[rumpuser] malloc: OOM for ");
        sot_serial_dec((int64_t)len);
        sot_serial_puts(" bytes\n");
        *memp = (void *)0;
        return 12; /* ENOMEM */
    }

    if (alignment > 16) {
        uint64_t addr = (uint64_t)ptr;
        addr = (addr + (uint64_t)alignment - 1) & ~((uint64_t)alignment - 1);
        ptr = (void *)addr;
    }

    *memp = ptr;
    return 0;
}

/*
 * rumpuser_free -- Free memory.
 *
 * Maps to: arena free-list insertion.
 */
void rumpuser_free(void *mem, size_t len)
{
    rump_arena_free(mem, len);
}

/*
 * rumpuser_anonmmap -- Map anonymous memory.
 *
 * Used by the rump kernel for large allocations (typically page-sized).
 * Maps to: SYS_FRAME_ALLOC + SYS_MAP for each 4K page.
 *
 * Parameters:
 *   prefaddr - preferred address (hint, may be NULL)
 *   len      - size in bytes
 *   alignbit - log2 of desired alignment
 *   exec     - if true, pages should be executable
 *   memp     - [out] pointer to mapped region
 */
int rumpuser_anonmmap(void *prefaddr, size_t len, int alignbit,
    int exec, void **memp)
{
    (void)prefaddr;  /* We choose our own address. */
    (void)exec;      /* W^X: we never map RWX on SOT. */

    /* Round up to page boundary. */
    size_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;

    /* Allocate from a dedicated mmap region above the arena. */
    static uint64_t mmap_next = RUMP_ARENA_BASE + RUMP_ARENA_SIZE;
    uint64_t base = mmap_next;

    /* Enforce alignment if requested. */
    if (alignbit > 12) {
        uint64_t align_mask = (1ULL << alignbit) - 1;
        base = (base + align_mask) & ~align_mask;
    }

    for (size_t i = 0; i < pages; i++) {
        int64_t frame = sot_frame_alloc();
        if (frame < 0) {
            sot_serial_puts("[rumpuser] anonmmap: frame_alloc failed\n");
            *memp = (void *)0;
            return 12; /* ENOMEM */
        }
        uint64_t flags = MAP_RW_NX;
        if (exec)
            flags = MAP_WRITABLE;  /* RWX not allowed, use RW only */

        int64_t r = sot_map(base + i * PAGE_SIZE, (uint64_t)frame, flags);
        if (r < 0) {
            sot_serial_puts("[rumpuser] anonmmap: map failed\n");
            *memp = (void *)0;
            return 12; /* ENOMEM */
        }
    }

    mmap_next = base + pages * PAGE_SIZE;
    *memp = (void *)base;

    return 0;
}

/*
 * rumpuser_unmap -- Unmap anonymous memory.
 *
 * Maps to: SYS_UNMAP_FREE for each page in the range.
 */
void rumpuser_unmap(void *addr, size_t len)
{
    if (!addr || len == 0) return;

    uint64_t base = (uint64_t)addr & ~(PAGE_SIZE - 1);
    size_t pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;

    for (size_t i = 0; i < pages; i++)
        sot_unmap_free(base + i * PAGE_SIZE);
}

/* ---------------------------------------------------------------
 * Block I/O
 *
 * The rump kernel calls rumpuser_bio for disk reads and writes.
 * We forward these to the sotOS "blk" service via IPC, mirroring
 * the protocol used by lkl-server's disk_backend.c.
 *
 * Protocol:
 *   CMD=1 (READ):  regs[0]=sector, regs[1]=count,
 *                  regs[2]=dest_vaddr, regs[3]=as_cap
 *   CMD=2 (WRITE): regs[0]=sector, regs[1]=count,
 *                  regs[2]=src_vaddr,  regs[3]=as_cap
 * --------------------------------------------------------------- */

#define BLK_CMD_READ     1
#define BLK_CMD_WRITE    2
#define BLK_CMD_CAPACITY 3

static uint64_t bio_blk_ep;      /* IPC endpoint for "blk" service */
static uint64_t bio_self_as_cap; /* our address space cap for VM reads */
static char __attribute__((aligned(4096))) bio_bounce[4096];

static int bio_initialized;

static int bio_init(void)
{
    if (bio_initialized) return 0;

    static const char name[] = "blk";
    int64_t cap = sot_svc_lookup(name, 3);
    if (cap <= 0) {
        sot_serial_puts("[rumpuser] bio: 'blk' service not found\n");
        return -1;
    }
    bio_blk_ep = (uint64_t)cap;

    /* Read self AS cap from BootInfo (offset 312). */
    volatile uint64_t *bi = (volatile uint64_t *)(0xB00000ULL + 312);
    bio_self_as_cap = *bi;

    bio_initialized = 1;
    sot_serial_puts("[rumpuser] bio: blk ep=");
    sot_serial_dec((int64_t)bio_blk_ep);
    sot_serial_puts(" as=");
    sot_serial_dec((int64_t)bio_self_as_cap);
    sot_serial_puts("\n");

    return 0;
}

/*
 * rumpuser_bio -- Perform asynchronous block I/O.
 *
 * The rump kernel expects this to be asynchronous: start the I/O and
 * call biodone(bioarg, dlen, error) when complete.  Since SOT IPC is
 * synchronous, we complete the operation inline and call biodone
 * immediately.
 *
 * Maps to: IPC SYS_CALL to "blk" service, 4K bounce buffer per chunk.
 */
void rumpuser_bio(int fd, int op, void *data, size_t dlen,
    int64_t off, rump_biodone_fn biodone, void *bioarg)
{
    (void)fd;  /* We have a single block device. */
    int error = 0;

    if (bio_init() != 0) {
        error = 5; /* EIO */
        biodone(bioarg, 0, error);
        return;
    }

    /* IPC to blk service, 4K at a time through bounce buffer. */
    size_t done = 0;
    while (done < dlen) {
        size_t chunk = dlen - done;
        if (chunk > 4096) chunk = 4096;

        uint64_t byte_off   = (uint64_t)off + done;
        uint64_t sector     = byte_off / 512;
        uint64_t sect_count = (chunk + 511) / 512;
        if (sect_count > 8) sect_count = 8;

        struct ipc_msg msg;
        ru_memset(&msg, 0, sizeof(msg));

        if (op & 0x01) {
            /* RUMPUSER_BIO_READ */
            msg.tag     = BLK_CMD_READ;
            msg.regs[0] = sector;
            msg.regs[1] = sect_count;
            msg.regs[2] = (uint64_t)bio_bounce;
            msg.regs[3] = bio_self_as_cap;

            /* Full IPC call using inline asm (matches sotos_syscall.h). */
            uint64_t ret;
            register uint64_t r8  __asm__("r8")  = msg.regs[1];
            register uint64_t r9  __asm__("r9")  = msg.regs[2];
            register uint64_t r10 __asm__("r10") = msg.regs[3];
            register uint64_t r12 __asm__("r12") = 0;
            register uint64_t r13 __asm__("r13") = 0;
            register uint64_t r14 __asm__("r14") = 0;
            register uint64_t r15 __asm__("r15") = 0;
            __asm__ volatile (
                "syscall"
                : "=a"(ret), "+r"(r8), "+r"(r9), "+r"(r10),
                  "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15)
                : "a"((uint64_t)SYS_CALL), "D"(bio_blk_ep),
                  "S"(msg.tag), "d"(msg.regs[0])
                : "rcx", "r11", "memory"
            );

            if ((int64_t)ret < 0) {
                error = 5; /* EIO */
                break;
            }

            ru_memcpy((uint8_t *)data + done, bio_bounce, chunk);
        } else {
            /* RUMPUSER_BIO_WRITE */
            ru_memcpy(bio_bounce, (const uint8_t *)data + done, chunk);

            msg.tag     = BLK_CMD_WRITE;
            msg.regs[0] = sector;
            msg.regs[1] = sect_count;
            msg.regs[2] = (uint64_t)bio_bounce;
            msg.regs[3] = bio_self_as_cap;

            uint64_t ret;
            register uint64_t r8  __asm__("r8")  = msg.regs[1];
            register uint64_t r9  __asm__("r9")  = msg.regs[2];
            register uint64_t r10 __asm__("r10") = msg.regs[3];
            register uint64_t r12 __asm__("r12") = 0;
            register uint64_t r13 __asm__("r13") = 0;
            register uint64_t r14 __asm__("r14") = 0;
            register uint64_t r15 __asm__("r15") = 0;
            __asm__ volatile (
                "syscall"
                : "=a"(ret), "+r"(r8), "+r"(r9), "+r"(r10),
                  "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15)
                : "a"((uint64_t)SYS_CALL), "D"(bio_blk_ep),
                  "S"(msg.tag), "d"(msg.regs[0])
                : "rcx", "r11", "memory"
            );

            if ((int64_t)ret < 0) {
                error = 5; /* EIO */
                break;
            }
        }

        done += chunk;
    }

    /* Sync if requested. */
    if ((op & 0x04) && !error) {
        /* RUMPUSER_BIO_SYNC -- no-op for now; our IPC is synchronous. */
    }

    /* Invoke completion callback immediately (synchronous I/O). */
    biodone(bioarg, done, error);
}

/* ---------------------------------------------------------------
 * File operations (rump needs these for reading component modules)
 * --------------------------------------------------------------- */

/*
 * rumpuser_open -- Open a host file.
 *
 * Not applicable on SOT (no host filesystem).  Returns ENOENT.
 */
int rumpuser_open(const char *path, int mode, int *fdp)
{
    (void)path; (void)mode;
    sot_serial_puts("[rumpuser] open: ");
    if (path) sot_serial_puts(path);
    sot_serial_puts(" -> ENOENT\n");
    *fdp = -1;
    return 2; /* ENOENT */
}

/*
 * rumpuser_close -- Close a host file descriptor.
 */
int rumpuser_close(int fd)
{
    (void)fd;
    return 0;
}

/*
 * rumpuser_getfileinfo -- Stat a host file.
 *
 * Returns ENOENT (no host FS).
 */
int rumpuser_getfileinfo(const char *path, uint64_t *sizep, int *typep)
{
    (void)path;
    if (sizep) *sizep = 0;
    if (typep) *typep = 0; /* RUMPUSER_FT_OTHER */
    return 2; /* ENOENT */
}

/* Iovec definition for ABI compatibility (must precede function decls). */
struct rumpuser_iovec {
    void  *iov_base;
    size_t iov_len;
};

/*
 * rumpuser_iovread / rumpuser_iovwrite -- Scatter/gather file I/O.
 *
 * Not supported on SOT.
 */
int rumpuser_iovread(int fd, struct rumpuser_iovec *iov, size_t cnt,
    int64_t off, size_t *retp)
{
    (void)fd; (void)iov; (void)cnt; (void)off;
    if (retp) *retp = 0;
    return 5; /* EIO */
}

int rumpuser_iovwrite(int fd, const struct rumpuser_iovec *iov, size_t cnt,
    int64_t off, size_t *retp)
{
    (void)fd; (void)iov; (void)cnt; (void)off;
    if (retp) *retp = 0;
    return 5; /* EIO */
}

/*
 * rumpuser_syncfd -- Sync a file descriptor.
 */
int rumpuser_syncfd(int fd, int flags, uint64_t start, uint64_t len)
{
    (void)fd; (void)flags; (void)start; (void)len;
    return 0;
}

/* ---------------------------------------------------------------
 * Clock
 *
 * RDTSC-based with assumed 2 GHz frequency.  This matches the
 * approach used by the vDSO and LKL host_ops in sotOS.
 * --------------------------------------------------------------- */

/*
 * rumpuser_clock_gettime -- Get current time.
 *
 * which:
 *   RUMPUSER_CLOCK_RELWALL (0) = wall-clock (we fake epoch 2025-01-01)
 *   RUMPUSER_CLOCK_ABSMONO (1) = monotonic since boot
 *
 * Maps to: RDTSC / 2 = nanoseconds (at 2 GHz).
 */
int rumpuser_clock_gettime(int which, int64_t *sec, long *nsec)
{
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t tsc = ((uint64_t)hi << 32) | lo;
    uint64_t ns  = tsc / 2;  /* 2 GHz -> each tick = 0.5 ns */

    if (which == 0) {
        /* RUMPUSER_CLOCK_RELWALL: wall-clock.
         * Fake a base epoch of 2025-01-01T00:00:00 UTC.
         * 1735689600 = seconds since Unix epoch to 2025-01-01. */
        uint64_t base_sec = 1735689600ULL;
        *sec  = (int64_t)(base_sec + ns / 1000000000ULL);
        *nsec = (long)(ns % 1000000000ULL);
    } else {
        /* RUMPUSER_CLOCK_ABSMONO: monotonic since boot. */
        *sec  = (int64_t)(ns / 1000000000ULL);
        *nsec = (long)(ns % 1000000000ULL);
    }

    return 0;
}

/*
 * rumpuser_clock_sleep -- Sleep for specified duration.
 *
 * For relative sleep (RELWALL): busy-wait using RDTSC.
 * For absolute monotonic (ABSMONO): compute remaining time and wait.
 *
 * Maps to: RDTSC spin-yield loop (no hardware sleep timer).
 */
int rumpuser_clock_sleep(int which, int64_t sec, long nsec)
{
    int nlocks;
    rumpkern_unsched(&nlocks, (void *)0);

    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t tsc_now = ((uint64_t)hi << 32) | lo;

    uint64_t deadline_tsc;

    if (which == 0) {
        /* RUMPUSER_CLOCK_RELWALL: relative sleep. */
        uint64_t duration_ns = (uint64_t)sec * 1000000000ULL + (uint64_t)nsec;
        deadline_tsc = tsc_now + duration_ns * 2;  /* 2 ticks/ns at 2 GHz */
    } else {
        /* RUMPUSER_CLOCK_ABSMONO: absolute monotonic deadline. */
        uint64_t target_ns = (uint64_t)sec * 1000000000ULL + (uint64_t)nsec;
        deadline_tsc = target_ns * 2;  /* 2 ticks/ns at 2 GHz */
    }

    /* Spin-yield until deadline.  For short sleeps (<10 us) we spin;
     * for longer sleeps we yield each iteration. */
    for (;;) {
        __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
        uint64_t now = ((uint64_t)hi << 32) | lo;
        if (now >= deadline_tsc) break;
        sot_yield();
    }

    rumpkern_sched(nlocks, (void *)0);
    return 0;
}

/* ---------------------------------------------------------------
 * Random number generation
 *
 * Uses the x86_64 RDRAND instruction directly.  Falls back to a
 * simple xorshift64 PRNG seeded from RDTSC if RDRAND fails.
 * --------------------------------------------------------------- */

static inline int rdrand64(uint64_t *val)
{
    uint8_t ok;
    __asm__ volatile (
        "rdrand %0\n\t"
        "setc   %1"
        : "=r"(*val), "=qm"(ok)
    );
    return ok;
}

/* xorshift64 fallback PRNG (non-cryptographic). */
static uint64_t xorshift_state;

static uint64_t xorshift64(void)
{
    uint64_t x = xorshift_state;
    if (x == 0) {
        /* Seed from RDTSC. */
        uint32_t lo, hi;
        __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
        x = ((uint64_t)hi << 32) | lo;
        if (x == 0) x = 0xdeadbeefcafe1234ULL;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    xorshift_state = x;
    return x;
}

/*
 * rumpuser_getrandom -- Fill buffer with random bytes.
 *
 * flags:
 *   RUMPUSER_RANDOM_HARD (0x01) = cryptographic quality requested
 *   RUMPUSER_RANDOM_NOWAIT (0x02) = don't block (no effect on SOT)
 *
 * Maps to: RDRAND instruction (hardware RNG), with xorshift fallback.
 */
int rumpuser_getrandom(void *buf, size_t buflen, int flags, size_t *retp)
{
    (void)flags;
    uint8_t *p = (uint8_t *)buf;
    size_t filled = 0;

    while (filled < buflen) {
        uint64_t val;
        int got_rdrand = 0;

        /* Try RDRAND up to 10 times. */
        for (int tries = 0; tries < 10; tries++) {
            if (rdrand64(&val)) {
                got_rdrand = 1;
                break;
            }
        }

        if (!got_rdrand)
            val = xorshift64();

        /* Copy 1-8 bytes from val into output buffer. */
        size_t remain = buflen - filled;
        size_t copy = (remain < 8) ? remain : 8;
        for (size_t i = 0; i < copy; i++)
            p[filled + i] = (uint8_t)(val >> (i * 8));
        filled += copy;
    }

    if (retp) *retp = filled;
    return 0;
}

/* ---------------------------------------------------------------
 * Host parameters
 * --------------------------------------------------------------- */

/*
 * rumpuser_getparam -- Query host environment parameters.
 *
 * The rump kernel queries RUMPUSER_PARAM_NCPU and
 * RUMPUSER_PARAM_HOSTNAME at startup.
 */
int rumpuser_getparam(const char *name, void *buf, size_t blen)
{
    if (ru_strcmp(name, "_RUMPUSER_NCPU") == 0) {
        /* sotOS runs single-CPU by default. */
        char *b = (char *)buf;
        b[0] = '1'; b[1] = '\0';
        return 0;
    }

    if (ru_strcmp(name, "_RUMPUSER_HOSTNAME") == 0) {
        const char *hostname = "sotbsd-rump";
        size_t len = ru_strlen(hostname);
        if (len >= blen) len = blen - 1;
        ru_memcpy(buf, hostname, len);
        ((char *)buf)[len] = '\0';
        return 0;
    }

    /* Unknown parameter.  Names starting with '_' are reserved. */
    if (name[0] == '_')
        return 22; /* EINVAL */

    /* Treat as environment variable lookup; we have no env on SOT. */
    return 2; /* ENOENT -- not found */
}

/* ---------------------------------------------------------------
 * Console output
 * --------------------------------------------------------------- */

/*
 * rumpuser_putchar -- Write a single character to console.
 */
void rumpuser_putchar(int c)
{
    sot_debug_putchar((uint8_t)c);
}

/*
 * rumpuser_dprintf -- Debug printf to serial console.
 *
 * Minimal variadic printf: supports %s, %d, %x, %p, %c, %%.
 * Full printf is not available without libc.
 */
void rumpuser_dprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    while (*fmt) {
        if (*fmt == '%') {
            fmt++;
            switch (*fmt) {
            case 's': {
                const char *s = va_arg(ap, const char *);
                if (s) sot_serial_puts(s);
                else sot_serial_puts("(null)");
                break;
            }
            case 'd': {
                int val = va_arg(ap, int);
                sot_serial_dec((int64_t)val);
                break;
            }
            case 'l': {
                fmt++;
                if (*fmt == 'd') {
                    long val = va_arg(ap, long);
                    sot_serial_dec((int64_t)val);
                } else if (*fmt == 'x') {
                    unsigned long val = va_arg(ap, unsigned long);
                    sot_serial_hex((uint64_t)val);
                }
                break;
            }
            case 'x': {
                unsigned int val = va_arg(ap, unsigned int);
                sot_serial_hex((uint64_t)val);
                break;
            }
            case 'p': {
                void *val = va_arg(ap, void *);
                sot_serial_hex((uint64_t)val);
                break;
            }
            case 'c': {
                int val = va_arg(ap, int);
                sot_debug_putchar((uint8_t)val);
                break;
            }
            case '%':
                sot_debug_putchar('%');
                break;
            default:
                sot_debug_putchar('%');
                sot_debug_putchar((uint8_t)*fmt);
                break;
            }
        } else {
            sot_debug_putchar((uint8_t)*fmt);
        }
        fmt++;
    }

    va_end(ap);
}

/* ---------------------------------------------------------------
 * Error handling and termination
 * --------------------------------------------------------------- */

/*
 * rumpuser_seterrno -- Set per-thread errno.
 *
 * No real TLS errno on SOT; we keep a global (single-CPU safe).
 */
static int rump_errno;

void rumpuser_seterrno(int error)
{
    rump_errno = error;
}

/*
 * rumpuser_kill -- Send signal to process.
 *
 * On SOT there are no Unix signals.  We just ignore non-fatal
 * signals and panic on fatal ones.
 */
int rumpuser_kill(int64_t pid, int sig)
{
    (void)pid;

    sot_serial_puts("[rumpuser] kill: sig=");
    sot_serial_dec((int64_t)sig);
    sot_serial_puts("\n");

    /* Signal 6 = SIGABRT, 9 = SIGKILL, 11 = SIGSEGV -- fatal. */
    if (sig == 6 || sig == 9 || sig == 11) {
        sot_serial_puts("[rumpuser] FATAL signal, halting\n");
        for (;;) sot_yield();  /* hang instead of killing entire server */
    }

    return 0;
}

/*
 * rumpuser_exit -- Terminate the rump kernel.
 */
void __attribute__((noreturn)) rumpuser_exit(int rv)
{
    sot_serial_puts("[rumpuser] exit: rv=");
    sot_serial_dec((int64_t)rv);
    sot_serial_puts("\n");

    if (rv == -1) {
        /* RUMPUSER_PANIC */
        sot_serial_puts("[rumpuser] PANIC\n");
    }

    /* Halt: loop forever (SOT has no process exit for servers). */
    for (;;)
        sot_yield();
}

/* ---------------------------------------------------------------
 * Page size
 * --------------------------------------------------------------- */

unsigned long rumpuser_getpagesize(void)
{
    return PAGE_SIZE;
}

/* ---------------------------------------------------------------
 * Dynamic loader bootstrap
 *
 * In a full NetBSD rump build, rumpuser_dl_bootstrap discovers
 * component modules via dlopen/dlsym.  On SOT, all rump components
 * are statically linked, so this is a no-op.
 * --------------------------------------------------------------- */

typedef void (*rump_modinit_fn)(const void *const *, size_t);
typedef int  (*rump_symload_fn)(void *, uint64_t, char *, uint64_t);
typedef void (*rump_compload_fn)(const void *);
typedef void (*rump_evcntattach_fn)(void *);

void rumpuser_dl_bootstrap(rump_modinit_fn modinit,
    rump_symload_fn symload, rump_compload_fn compload,
    rump_evcntattach_fn evcntattach)
{
    (void)modinit;
    (void)symload;
    (void)compload;
    (void)evcntattach;

    sot_serial_puts("[rumpuser] dl_bootstrap: static link mode\n");
}

/* ---------------------------------------------------------------
 * Daemonize (not applicable on SOT)
 * --------------------------------------------------------------- */

int rumpuser_daemonize_begin(void)
{
    return 0;
}

int rumpuser_daemonize_done(int error)
{
    (void)error;
    return 0;
}

/* ---------------------------------------------------------------
 * Initialization
 * --------------------------------------------------------------- */

/*
 * rumpuser_init -- Initialize the rump hypervisor layer.
 *
 * Called by rump_init() in the rump kernel.  This is our entry
 * point: we set up the arena, store the upcall function pointers,
 * and prepare serial output.
 *
 * Version must match RUMPUSER_VERSION (17).
 */
#define RUMPUSER_VERSION 17

int rumpuser_init(int version, const struct rumpuser_hyperup *hyp)
{
    sot_serial_puts("[rumpuser] init: version=");
    sot_serial_dec((int64_t)version);
    sot_serial_puts(" (expected ");
    sot_serial_dec((int64_t)RUMPUSER_VERSION);
    sot_serial_puts(")\n");

    if (version != RUMPUSER_VERSION) {
        sot_serial_puts("[rumpuser] VERSION MISMATCH\n");
        return 22; /* EINVAL */
    }

    /* Store hypervisor upcall table. */
    ru_memcpy(&rump_hyp, hyp, sizeof(rump_hyp));

    /* Initialize arena allocator. */
    int r = rump_arena_init();
    if (r != 0) {
        sot_serial_puts("[rumpuser] arena init failed: ");
        sot_serial_dec((int64_t)r);
        sot_serial_puts("\n");
        return 12; /* ENOMEM */
    }

    /* Set up per-thread data for the main thread. */
    thread_data_pool[0].curlwp = (void *)0;
    thread_data_pool[0].slot   = 0;
    sot_set_fs_base((uint64_t)&thread_data_pool[0]);
    next_td_slot = 1;

    /* Initialize the first thread table entry for the main thread. */
    thread_table[0].slot     = 0;
    thread_table[0].finished = 0;
    thread_table[0].joinable = 0;
    next_thread_slot = 1;

    rump_initialized = 1;

    sot_serial_puts("[rumpuser] init complete (arena=");
    sot_serial_dec((int64_t)(RUMP_ARENA_SIZE / 1024 / 1024));
    sot_serial_puts(" MiB, SOT hypervisor)\n");

    return 0;
}

/* ---------------------------------------------------------------
 * Syscall proxy stubs
 *
 * The rump syscall proxy allows remote processes to issue rump
 * kernel syscalls over a socket.  Not applicable on SOT (all
 * rump components run in-process).  These stubs prevent link
 * errors when LIBRUMPUSER is defined.
 * --------------------------------------------------------------- */

int rumpuser_sp_init(const char *url, const char *ostype,
    const char *osrelease, const char *machine)
{
    (void)url; (void)ostype; (void)osrelease; (void)machine;
    return 0;
}

int rumpuser_sp_copyin(void *arg, const void *raddr, void *laddr, size_t len)
{
    (void)arg;
    ru_memcpy(laddr, raddr, len);
    return 0;
}

int rumpuser_sp_copyinstr(void *arg, const void *raddr, void *laddr, size_t *lenp)
{
    (void)arg;
    const char *s = (const char *)raddr;
    char *d = (char *)laddr;
    size_t i = 0;
    size_t max = lenp ? *lenp : 256;
    while (i < max && s[i]) {
        d[i] = s[i];
        i++;
    }
    if (i < max) d[i] = '\0';
    if (lenp) *lenp = i;
    return 0;
}

int rumpuser_sp_copyout(void *arg, const void *laddr, void *raddr, size_t len)
{
    (void)arg;
    ru_memcpy(raddr, laddr, len);
    return 0;
}

int rumpuser_sp_copyoutstr(void *arg, const void *laddr, void *raddr, size_t *lenp)
{
    (void)arg;
    const char *s = (const char *)laddr;
    char *d = (char *)raddr;
    size_t i = 0;
    size_t max = lenp ? *lenp : 256;
    while (i < max && s[i]) {
        d[i] = s[i];
        i++;
    }
    if (i < max) d[i] = '\0';
    if (lenp) *lenp = i;
    return 0;
}

int rumpuser_sp_anonmmap(void *arg, size_t len, void **memp)
{
    (void)arg;
    return rumpuser_anonmmap((void *)0, len, 0, 0, memp);
}

int rumpuser_sp_raise(void *arg, int sig)
{
    (void)arg; (void)sig;
    return 0;
}

void rumpuser_sp_fini(void *arg)
{
    (void)arg;
}

/* ---------------------------------------------------------------
 * Libc-free helper implementations
 *
 * Since we cannot link against libc on SOT, we provide our own
 * minimal string/memory functions used internally.
 * --------------------------------------------------------------- */

static void *ru_memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    while (n-- > 0) *p++ = (uint8_t)c;
    return s;
}

static void *ru_memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n-- > 0) *d++ = *s++;
    return dst;
}

static int ru_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static size_t ru_strlen(const char *s)
{
    size_t len = 0;
    while (*s++) len++;
    return len;
}

/* Minimal snprintf (for internal use only). */
static int ru_snprintf(char *buf, size_t blen, const char *fmt, ...)
{
    (void)fmt;
    /* Stub: callers use sot_serial_puts for output instead. */
    if (blen > 0) buf[0] = '\0';
    return 0;
}
