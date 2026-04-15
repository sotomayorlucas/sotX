/*
 * host_ops.c -- LKL host operations for sotX (real LKL API).
 *
 * Maps each LKL host callback to sotX kernel primitives.
 * Uses the real struct lkl_host_operations from lkl/asm/host_ops.h.
 */

#include <stdint.h>
#include <stddef.h>
#include "sotos_syscall.h"
#include "allocator.h"
#include "libc_stubs.h"

/* Use real LKL headers when available, stubs otherwise. */
#ifdef HAS_LKL
#include <lkl.h>
#include <lkl/asm/host_ops.h>
#else
#include "lkl_stub.h"
#endif

/* ---------------------------------------------------------------
 * Semaphores (opaque struct allocated from arena)
 * --------------------------------------------------------------- */

struct lkl_sem {
    volatile int64_t count;
    uint64_t         notify_cap;  /* sotX notification for blocking */
};

static struct lkl_sem *lkl_sem_alloc(int count)
{
    struct lkl_sem *s = (struct lkl_sem *)arena_alloc(sizeof(*s));
    if (!s) return NULL;
    s->count = count;
    s->notify_cap = 0;
    int64_t nc = sys_notify_create();
    if (nc > 0) s->notify_cap = (uint64_t)nc;
    return s;
}

static void lkl_sem_free(struct lkl_sem *sem)
{
    (void)sem; /* arena doesn't free individual allocs */
}

static void lkl_sem_up(struct lkl_sem *sem)
{
    __atomic_add_fetch(&sem->count, 1, __ATOMIC_SEQ_CST);
    if (sem->notify_cap)
        sys_notify_signal(sem->notify_cap);
}

static void lkl_sem_down(struct lkl_sem *sem)
{
    for (;;) {
        int64_t c = __atomic_load_n(&sem->count, __ATOMIC_SEQ_CST);
        if (c > 0) {
            if (__atomic_compare_exchange_n(&sem->count, &c, c - 1,
                    0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
                return;
        }
        /* Always yield — notify_wait can deadlock on single-CPU if the
         * signalling thread hasn't been scheduled yet. */
        sys_yield();
    }
}

/* ---------------------------------------------------------------
 * Mutexes (opaque struct)
 * --------------------------------------------------------------- */

struct lkl_mutex {
    volatile int64_t locked;
    int              recursive;
    uint64_t         owner;   /* thread_self of holder */
    int              depth;
};

static struct lkl_mutex *lkl_mutex_alloc(int recursive)
{
    struct lkl_mutex *m = (struct lkl_mutex *)arena_alloc(sizeof(*m));
    if (!m) return NULL;
    m->locked = 0;
    m->recursive = recursive;
    m->owner = 0;
    m->depth = 0;
    return m;
}

static void lkl_mutex_free(struct lkl_mutex *m) { (void)m; }

static unsigned long lkl_thread_self(void);

static void lkl_mutex_lock(struct lkl_mutex *m)
{
    if (m->recursive) {
        unsigned long self = lkl_thread_self();
        if (m->locked && m->owner == self) {
            m->depth++;
            return;
        }
    }
    while (__atomic_test_and_set((volatile void *)&m->locked, __ATOMIC_ACQUIRE))
        sys_yield();
    m->owner = lkl_thread_self();
    m->depth = 1;
}

static void lkl_mutex_unlock(struct lkl_mutex *m)
{
    if (m->recursive && --m->depth > 0)
        return;
    m->owner = 0;
    __atomic_clear((volatile void *)&m->locked, __ATOMIC_RELEASE);
}

/* ---------------------------------------------------------------
 * Threading
 * --------------------------------------------------------------- */

#define MAX_LKL_THREADS 64
#define THREAD_STACK_SIZE 32768  /* 32 KiB */

struct thread_slot {
    uint64_t cap;
    volatile int done;
};
static struct thread_slot thread_table[MAX_LKL_THREADS];
static volatile int next_tid = 1;

struct trampoline_ctx {
    void (*fn)(void *);
    void *arg;
    int   slot;
};

/* Thread entry trampoline in pure asm — avoids GCC prologue alignment issues.
 * Stack at entry: [rsp] = ctx_ptr (struct trampoline_ctx *).
 * Pops ctx, aligns stack, calls ctx->fn(ctx->arg), marks done, exits. */
__asm__(
    ".globl thread_trampoline\n"
    ".type thread_trampoline, @function\n"
    "thread_trampoline:\n"
    "    pop %rbx\n"            /* rbx = ctx pointer */
    "    and $-16, %rsp\n"      /* rsp%16==0 BEFORE call (ABI requirement) */
    /* Set FS_BASE to unique thread ID (slot address in ctx + 0x10) */
    "    lea 0x10(%rbx), %rdi\n" /* rdi = &ctx->slot (unique per-thread addr) */
    "    mov $160, %eax\n"      /* SYS_SET_FS_BASE */
    "    syscall\n"
    /* Call fn(arg) */
    "    test %rbx, %rbx\n"
    "    jz 1f\n"
    "    mov (%rbx), %rax\n"    /* rax = ctx->fn */
    "    test %rax, %rax\n"
    "    jz 1f\n"
    "    mov 8(%rbx), %rdi\n"   /* rdi = ctx->arg */
    "    call *%rax\n"          /* fn(arg) */
    "1:\n"
    "    mov $42, %eax\n"       /* SYS_THREAD_EXIT */
    "    syscall\n"
    "    ud2\n"
);
extern void thread_trampoline(void);

static unsigned long lkl_thread_create(void (*fn)(void *), void *arg)
{
    int slot = __atomic_fetch_add(&next_tid, 1, __ATOMIC_RELAXED) % MAX_LKL_THREADS;

    uint8_t *stack = (uint8_t *)arena_alloc(THREAD_STACK_SIZE);
    if (!stack) return 0;
    uint64_t sp = ((uint64_t)stack + THREAD_STACK_SIZE) & ~15ULL;

    struct trampoline_ctx *ctx = (struct trampoline_ctx *)arena_alloc(sizeof(*ctx));
    if (!ctx) return 0;
    ctx->fn = fn;
    ctx->arg = arg;
    ctx->slot = slot;

    /* Asm trampoline does `pop %rbx` to get ctx, then aligns stack itself.
     * Just push ctx_ptr onto the stack. */
    sp -= 8; *(uint64_t *)sp = (uint64_t)ctx;

    int64_t tcap = sys_thread_create((uint64_t)thread_trampoline, sp, 0);
    if (tcap < 0) return 0;

    thread_table[slot].cap = (uint64_t)tcap;
    thread_table[slot].done = 0;

    /* MUST return the SAME value that lkl_thread_self() reads from the
     * new thread FS_BASE. The trampoline sets FS_BASE to the address
     * of ctx->slot (unique stable per-thread). Returning slot+1 was a
     * Phase-12 bug: lkl_cpu_put then called thread_equal(cpu.owner,
     * thread_self()) where cpu.owner had been set from THIS fn return
     * (slot+1) but thread_self returned the FS_BASE pointer. Mismatch
     * triggered "lkl_cpu_put: unbalanced put" then Linux kernel BUG. */
    return (unsigned long)&ctx->slot;
}

static void lkl_thread_detach(void) { /* noop */ }

static void lkl_thread_exit(void)
{
    sys_thread_exit();
}

static int lkl_thread_join(unsigned long tid)
{
    /* tid is now (uintptr_t)&ctx->slot per the create-side change.
     * Recover slot by deref'ing the pointer (slot was written into ctx). */
    if (tid == 0) return -1;
    int slot = *(volatile int *)tid;
    if (slot < 0 || slot >= MAX_LKL_THREADS) return -1;
    int spins = 0;
    while (!thread_table[slot].done) {
        sys_yield();
        if (++spins > 100000) return -1;  /* safety timeout */
    }
    return 0;
}

/* Thread identity via FS_BASE MSR: each created thread sets FS_BASE to its
 * unique slot ID via SYS_SET_FS_BASE(160). The main thread's FS_BASE is set
 * during init. lkl_thread_self reads FS_BASE via SYS_GET_FS_BASE(161). */

static unsigned long lkl_thread_self(void)
{
    return (unsigned long)sys_get_fs_base();
}

static int lkl_thread_equal(unsigned long a, unsigned long b)
{
    return a == b;
}

static void *lkl_thread_stack(unsigned long *size)
{
    if (size) *size = THREAD_STACK_SIZE;
    return NULL; /* not tracked precisely */
}

/* ---------------------------------------------------------------
 * TLS (thread-local storage)
 * --------------------------------------------------------------- */

#define MAX_TLS_KEYS 32
struct lkl_tls_key {
    int used;
    void (*destructor)(void *);
    /* Simplified: single-value (works for single-threaded LKL kernel) */
    void *value;
};
static struct lkl_tls_key tls_keys[MAX_TLS_KEYS];

static struct lkl_tls_key *lkl_tls_alloc(void (*destructor)(void *))
{
    for (int i = 0; i < MAX_TLS_KEYS; i++) {
        if (!tls_keys[i].used) {
            tls_keys[i].used = 1;
            tls_keys[i].destructor = destructor;
            tls_keys[i].value = NULL;
            return &tls_keys[i];
        }
    }
    return NULL;
}

static void lkl_tls_free(struct lkl_tls_key *key) {
    if (key) key->used = 0;
}

static int lkl_tls_set(struct lkl_tls_key *key, void *data) {
    if (!key) return -1;
    key->value = data;
    return 0;
}

static void *lkl_tls_get(struct lkl_tls_key *key) {
    if (!key) return NULL;
    return key->value;
}

/* ---------------------------------------------------------------
 * Memory
 * --------------------------------------------------------------- */

static void *lkl_mem_alloc(unsigned long size)
{
    return arena_alloc(size);
}

static void lkl_mem_free(void *ptr)
{
    arena_free(ptr);
}

static void *lkl_page_alloc(unsigned long size)
{
    /* Page-aligned allocation from arena. */
    unsigned long aligned = (size + 4095UL) & ~4095UL;
    /* Bump arena to page boundary first. */
    void *p = arena_alloc(aligned + 4096);
    if (!p) return NULL;
    uint64_t addr = ((uint64_t)p + 4095) & ~4095ULL;
    return (void *)addr;
}

static void lkl_page_free(void *addr, unsigned long size)
{
    (void)addr; (void)size; /* arena doesn't support targeted free */
}

/* ---------------------------------------------------------------
 * Time & Timers
 * --------------------------------------------------------------- */

static unsigned long long lkl_time(void)
{
    /* RDTSC; assume ~2 GHz → each tick = 0.5 ns */
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    uint64_t tsc = ((uint64_t)hi << 32) | lo;
    return tsc / 2; /* nanoseconds at 2 GHz */
}

struct lkl_timer {
    void (*fn)(void);
    uint64_t fire_ns;
    int armed;
};

#define MAX_TIMERS 16
static struct lkl_timer timers[MAX_TIMERS];

static void *lkl_timer_alloc(void (*fn)(void))
{
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (!timers[i].fn) {
            timers[i].fn = fn;
            timers[i].armed = 0;
            return &timers[i];
        }
    }
    return NULL;
}

static int lkl_timer_set_oneshot(void *timer, unsigned long delta_ns)
{
    struct lkl_timer *t = (struct lkl_timer *)timer;
    if (!t) return -1;
    t->fire_ns = lkl_time() + delta_ns;
    t->armed = 1;
    return 0;
}

static void lkl_timer_free(void *timer)
{
    struct lkl_timer *t = (struct lkl_timer *)timer;
    if (t) {
        t->fn = NULL;
        t->armed = 0;
    }
}

/* Called from main loop to process expired timers. */
void host_ops_tick(void)
{
    uint64_t now = lkl_time();
    for (int i = 0; i < MAX_TIMERS; i++) {
        if (timers[i].armed && timers[i].fn && now >= timers[i].fire_ns) {
            timers[i].armed = 0;
            timers[i].fn();
        }
    }
}

/* ---------------------------------------------------------------
 * Console
 * --------------------------------------------------------------- */

static void lkl_print(const char *str, int len)
{
    for (int i = 0; i < len; i++)
        sys_debug_putchar(str[i]);
}

static volatile int lkl_panicked = 0;

static void lkl_panic(void)
{
    serial_puts("[lkl] PANIC (non-fatal, continuing)\n");
    lkl_panicked = 1;
    /* Don't exit — let the caller handle it. Exiting kills the server. */
}

/* ---------------------------------------------------------------
 * I/O remap (stub — not needed for phase 1)
 * --------------------------------------------------------------- */

static void *lkl_ioremap(long addr, int size)
{
    (void)addr; (void)size;
    return NULL;
}

/* iomem_access used to be a stub returning -1, which broke virtio_mmio
 * device probing (Linux's readl(magic) got garbage → -ENODEV → eth0
 * never materialized). The real implementation lives in
 * tools/lkl/lib/iomem.c — it dispatches to the registered
 * struct lkl_iomem_ops (e.g. virtio_ops in virtio.c) keyed by the
 * iomem region index encoded in the addr pointer. liblkl.a exports
 * the symbol, we just forward to it. */
extern int lkl_iomem_access(const volatile void *addr, void *res, int size, int write);

static int my_iomem_access_shim(const volatile void *addr, void *val,
                                int size, int write)
{
    return lkl_iomem_access(addr, val, size, write);
}

/* ---------------------------------------------------------------
 * jmp_buf (using __builtin_setjmp / __builtin_longjmp)
 * --------------------------------------------------------------- */

/* Real setjmp/longjmp in inline asm — __builtin_setjmp only saves
 * RBP/RSP/RIP and skips callee-saved regs (rbx, r12-r15). LKL expects
 * full callee-save semantics: when scheduler longjmps back into a
 * blocked task, those registers must be restored or the task resumes
 * with garbage. Symptom: VMM SEGV at addr=0 from uninitialized RIP
 * after the first context switch through jmp_buf.
 *
 * Buffer layout (8 unsigned longs, 64 bytes — well within the 128-long
 * struct lkl_jmp_buf):
 *   [0]=rbx [1]=rbp [2]=r12 [3]=r13 [4]=r14 [5]=r15 [6]=rsp [7]=rip
 */

static int sotos_setjmp(unsigned long *buf)
{
    int ret;
    __asm__ volatile (
        "mov %%rbx, 0x00(%[b])\n"
        "mov %%rbp, 0x08(%[b])\n"
        "mov %%r12, 0x10(%[b])\n"
        "mov %%r13, 0x18(%[b])\n"
        "mov %%r14, 0x20(%[b])\n"
        "mov %%r15, 0x28(%[b])\n"
        "lea 0x08(%%rsp), %%rax\n"     /* rsp at caller (post-call) */
        "mov %%rax, 0x30(%[b])\n"
        "mov 0x00(%%rsp), %%rax\n"     /* return address */
        "mov %%rax, 0x38(%[b])\n"
        "xor %%eax, %%eax\n"           /* return 0 from setjmp path */
        : "=a"(ret)
        : [b] "r"(buf)
        : "memory"
    );
    return ret;
}

static __attribute__((noreturn)) void sotos_longjmp(unsigned long *buf, int val)
{
    if (val == 0) val = 1;
    __asm__ volatile (
        "mov 0x00(%[b]), %%rbx\n"
        "mov 0x08(%[b]), %%rbp\n"
        "mov 0x10(%[b]), %%r12\n"
        "mov 0x18(%[b]), %%r13\n"
        "mov 0x20(%[b]), %%r14\n"
        "mov 0x28(%[b]), %%r15\n"
        "mov 0x30(%[b]), %%rsp\n"
        "mov 0x38(%[b]), %%rdx\n"      /* saved return address */
        "mov %[v], %%eax\n"            /* return value from setjmp */
        "jmp *%%rdx\n"
        :
        : [b] "r"(buf), [v] "r"(val)
        : "memory"
    );
    __builtin_unreachable();
}

static void lkl_jmp_buf_set(struct lkl_jmp_buf *jmpb, void (*f)(void))
{
    if (sotos_setjmp((unsigned long *)jmpb->buf) == 0)
        f();
}

static void lkl_jmp_buf_longjmp(struct lkl_jmp_buf *jmpb, int val)
{
    sotos_longjmp((unsigned long *)jmpb->buf, val);
}

/* ---------------------------------------------------------------
 * mmap/munmap (stub using arena)
 * --------------------------------------------------------------- */

static void *lkl_mmap(void *addr, unsigned long size, int prot)
{
    (void)addr; (void)prot;
    return lkl_page_alloc(size);
}

static int lkl_munmap(void *addr, unsigned long size)
{
    (void)addr; (void)size;
    return 0;
}

/* ---------------------------------------------------------------
 * Public: populate the host ops struct
 * --------------------------------------------------------------- */

void host_ops_init(struct lkl_host_operations *ops)
{
    /* Don't memset — caller already zeroed. Set every field explicitly. */
    ops->virtio_devices    = (void *)0;

    ops->print             = lkl_print;
    ops->panic             = lkl_panic;

    ops->sem_alloc         = lkl_sem_alloc;
    ops->sem_free          = lkl_sem_free;
    ops->sem_up            = lkl_sem_up;
    ops->sem_down          = lkl_sem_down;

    ops->mutex_alloc       = lkl_mutex_alloc;
    ops->mutex_free        = lkl_mutex_free;
    ops->mutex_lock        = lkl_mutex_lock;
    ops->mutex_unlock      = lkl_mutex_unlock;

    ops->thread_create     = lkl_thread_create;
    ops->thread_detach     = lkl_thread_detach;
    ops->thread_exit       = lkl_thread_exit;
    ops->thread_join       = lkl_thread_join;
    ops->thread_self       = lkl_thread_self;
    ops->thread_equal      = lkl_thread_equal;
    ops->thread_stack      = lkl_thread_stack;

    ops->tls_alloc         = lkl_tls_alloc;
    ops->tls_free          = lkl_tls_free;
    ops->tls_set           = lkl_tls_set;
    ops->tls_get           = lkl_tls_get;

    ops->mem_alloc         = lkl_mem_alloc;
    ops->mem_free          = lkl_mem_free;
    ops->page_alloc        = lkl_page_alloc;
    ops->page_free         = lkl_page_free;

    ops->time              = lkl_time;

    ops->timer_alloc       = lkl_timer_alloc;
    ops->timer_set_oneshot = lkl_timer_set_oneshot;
    ops->timer_free        = lkl_timer_free;

    ops->ioremap           = lkl_ioremap;
    ops->iomem_access      = my_iomem_access_shim;

    ops->jmp_buf_set       = lkl_jmp_buf_set;
    ops->jmp_buf_longjmp   = lkl_jmp_buf_longjmp;

    ops->memcpy            = memcpy;
    ops->memset            = memset;
    ops->memmove           = memmove;

    ops->mmap              = (void *(*)(void*, unsigned long, int))lkl_mmap;
    ops->munmap            = lkl_munmap;
}
