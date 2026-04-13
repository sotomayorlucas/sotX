/*
 * lkl_stub.h -- Stub declarations for LKL API.
 *
 * When liblkl.a is built (HAS_LKL defined), the real lkl.h replaces this.
 * Until then, this provides the struct definitions and extern declarations
 * so the host_ops implementation compiles.
 */

#ifndef LKL_STUB_H
#define LKL_STUB_H

#include <stdint.h>

/* ---------------------------------------------------------------
 * LKL host operations struct
 *
 * LKL calls these to interact with the host (sotX).
 * We fill in function pointers in host_ops.c.
 * --------------------------------------------------------------- */
struct lkl_host_operations {
    /* Threading */
    int   (*thread_create)(void (*fn)(void *), void *arg);
    void  (*thread_exit)(void);
    int   (*thread_join)(int tid);
    long  (*thread_self)(void);

    /* Semaphores */
    int   (*sem_alloc)(int count);
    void  (*sem_free)(int id);
    void  (*sem_up)(int id);
    void  (*sem_down)(int id);

    /* Mutexes */
    int   (*mutex_alloc)(int recursive);
    void  (*mutex_free)(int id);
    void  (*mutex_lock)(int id);
    void  (*mutex_unlock)(int id);

    /* Thread-local storage */
    int   (*tls_alloc)(void (*destructor)(void *));
    void  (*tls_free)(int key);
    int   (*tls_set)(int key, void *data);
    void *(*tls_get)(int key);

    /* Time */
    unsigned long long (*time)(void);

    /* Timers */
    int   (*timer_alloc)(void (*fn)(void *), void *arg);
    int   (*timer_set_oneshot)(int id, unsigned long delta);
    void  (*timer_free)(int id);

    /* Memory */
    void *(*mem_alloc)(unsigned long size);
    void  (*mem_free)(void *ptr);

    /* Console / debug */
    void  (*print)(const char *str, int len);
    void  (*panic)(void);
};

#ifndef HAS_LKL

/* Stub: lkl_start_kernel returns 0 (success) without doing anything. */
static inline int lkl_start_kernel(struct lkl_host_operations *ops,
                                   const char *cmdline)
{
    (void)ops;
    (void)cmdline;
    return 0;
}

/* Stub: lkl_sys_halt. */
static inline int lkl_sys_halt(void)
{
    return 0;
}

/* Stub: lkl_syscall (returns -ENOSYS). */
static inline long lkl_syscall(long nr, long *params)
{
    (void)nr;
    (void)params;
    return -38; /* -ENOSYS */
}

#else /* HAS_LKL -- real LKL library linked */

extern int  lkl_start_kernel(struct lkl_host_operations *ops,
                              const char *cmdline);
extern int  lkl_sys_halt(void);
extern long lkl_syscall(long nr, long *params);

#endif /* HAS_LKL */

#endif /* LKL_STUB_H */
