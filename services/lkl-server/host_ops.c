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
    serial_puts("[lkl-host] thread_create fn=");
    serial_put_hex((uint64_t)fn);
    serial_puts(" arg=");
    serial_put_hex((uint64_t)arg);
    serial_puts("\n");
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

    serial_puts("[lkl-host] sys_thread_create rip=");
    serial_put_hex((uint64_t)thread_trampoline);
    serial_puts(" rsp=");
    serial_put_hex(sp);
    serial_puts("\n");
    int64_t tcap = sys_thread_create((uint64_t)thread_trampoline, sp, 0);
    serial_puts("[lkl-host] thread_create result=");
    serial_put_hex((uint64_t)tcap);
    serial_puts("\n");
    if (tcap < 0) return 0;

    thread_table[slot].cap = (uint64_t)tcap;
    thread_table[slot].done = 0;
    return (unsigned long)(slot + 1); /* non-zero = success */
}

static void lkl_thread_detach(void) { /* noop */ }

static void lkl_thread_exit(void)
{
    sys_thread_exit();
}

static int lkl_thread_join(unsigned long tid)
{
    int slot = (int)tid - 1;
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

static int lkl_iomem_access(const volatile void *addr, void *val,
                             int size, int write)
{
    (void)addr; (void)val; (void)size; (void)write;
    return -1;
}

/* ---------------------------------------------------------------
 * jmp_buf (using __builtin_setjmp / __builtin_longjmp)
 * --------------------------------------------------------------- */

static void lkl_jmp_buf_set(struct lkl_jmp_buf *jmpb, void (*f)(void))
{
    serial_puts("[lkl-host] jmp_buf_set\n");
    if (__builtin_setjmp((void **)jmpb->buf) == 0)
        f();
}

static void lkl_jmp_buf_longjmp(struct lkl_jmp_buf *jmpb, int val)
{
    (void)val;
    __builtin_longjmp((void **)jmpb->buf, 1);
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
    ops->iomem_access      = lkl_iomem_access;

    ops->jmp_buf_set       = lkl_jmp_buf_set;
    ops->jmp_buf_longjmp   = lkl_jmp_buf_longjmp;

    ops->memcpy            = memcpy;
    ops->memset            = memset;
    ops->memmove           = memmove;

    ops->mmap              = (void *(*)(void*, unsigned long, int))lkl_mmap;
    ops->munmap            = lkl_munmap;
}
