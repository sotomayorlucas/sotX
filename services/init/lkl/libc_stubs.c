/*
 * libc_stubs.c -- Freestanding libc stubs.
 *
 * Byte-by-byte implementations to avoid compiler_builtins issues.
 * GCC may emit implicit calls to memcpy/memset/memcmp, so these must
 * exist as real symbols even in -ffreestanding builds.
 */

#include "libc_stubs.h"

void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        for (size_t i = 0; i < n; i++)
            d[i] = s[i];
    } else {
        for (size_t i = n; i > 0; i--)
            d[i - 1] = s[i - 1];
    }
    return dst;
}

void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    for (size_t i = 0; i < n; i++)
        p[i] = (unsigned char)c;
    return s;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    for (size_t i = 0; i < n; i++) {
        if (pa[i] != pb[i])
            return (int)pa[i] - (int)pb[i];
    }
    return 0;
}

size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len])
        len++;
    return len;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i]; i++)
        dst[i] = src[i];
    for (; i < n; i++)
        dst[i] = '\0';
    return dst;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0')
            return 0;
    }
    return 0;
}

/*
 * =========================================================================
 * POSIX-host stubs for `liblkl-in.o`.
 *
 * Upstream LKL (`tools/lkl/lib/posix-host.c`) is a single partial-linked
 * object that both defines the disk/fs helpers we actually use
 * (`lkl_disk_add`, `lkl_mount_dev`, ...) *and* installs a default
 * `lkl_host_operations` that calls POSIX libc (pthread, mmap, timer, etc.).
 *
 * We cannot strip the POSIX side — they share the same `.o` — so the link
 * step pulls their references in. At runtime, however, our own
 * `host_ops.c` registers the active `lkl_host_operations`, overriding the
 * POSIX default; these stubs are therefore never actually called. Their
 * sole purpose is to satisfy rust-lld during the final link.
 *
 * All stubs are `__attribute__((weak))` so a proper implementation (if
 * ever provided) transparently takes precedence.
 * =========================================================================
 */

/* Thin no-op implementations. Return values picked so that any accidental
 * real call at runtime would surface as an obvious failure (NULL pointer,
 * -1 result, missing pid) rather than silently succeed. */

__attribute__((weak)) void *malloc(size_t n)            { (void)n; return (void *)0; }
__attribute__((weak)) void  free(void *p)               { (void)p; }
__attribute__((weak)) void *calloc(size_t n, size_t s)  { (void)n; (void)s; return (void *)0; }
__attribute__((weak)) void *realloc(void *p, size_t n)  { (void)p; (void)n; return (void *)0; }

__attribute__((weak)) void *mmap(void *a, size_t l, int p, int f, int fd, long o)
    { (void)a; (void)l; (void)p; (void)f; (void)fd; (void)o; return (void *)-1; }
__attribute__((weak)) void *mmap64(void *a, size_t l, int p, int f, int fd, long long o)
    { (void)a; (void)l; (void)p; (void)f; (void)fd; (void)o; return (void *)-1; }
__attribute__((weak)) int   munmap(void *a, size_t l)   { (void)a; (void)l; return -1; }

__attribute__((weak)) int   pthread_create(void *t, const void *a, void *(*fn)(void *), void *arg)
    { (void)t; (void)a; (void)fn; (void)arg; return -1; }
__attribute__((weak)) int   pthread_join(unsigned long t, void **r)    { (void)t; (void)r; return -1; }
__attribute__((weak)) int   pthread_detach(unsigned long t)            { (void)t; return -1; }
__attribute__((weak)) void  pthread_exit(void *r)                       { (void)r; for (;;); }
__attribute__((weak)) unsigned long pthread_self(void)                  { return 0; }
__attribute__((weak)) int   pthread_equal(unsigned long a, unsigned long b) { return a == b; }
__attribute__((weak)) int   pthread_getattr_np(unsigned long t, void *a)   { (void)t; (void)a; return -1; }
__attribute__((weak)) int   pthread_attr_get_np(unsigned long t, void *a)  { (void)t; (void)a; return -1; }
__attribute__((weak)) int   pthread_attr_getstack(const void *a, void **s, size_t *sz) { (void)a; (void)s; (void)sz; return -1; }
__attribute__((weak)) int   pthread_attr_destroy(void *a)                  { (void)a; return -1; }
__attribute__((weak)) int   pthread_key_create(void *k, void (*d)(void *)) { (void)k; (void)d; return -1; }
__attribute__((weak)) int   pthread_key_delete(unsigned int k)             { (void)k; return -1; }
__attribute__((weak)) void *pthread_getspecific(unsigned int k)            { (void)k; return (void *)0; }
__attribute__((weak)) int   pthread_setspecific(unsigned int k, const void *v) { (void)k; (void)v; return -1; }
__attribute__((weak)) int   pthread_mutex_init(void *m, const void *a)     { (void)m; (void)a; return -1; }
__attribute__((weak)) int   pthread_mutex_destroy(void *m)                 { (void)m; return -1; }
__attribute__((weak)) int   pthread_mutex_lock(void *m)                    { (void)m; return -1; }
__attribute__((weak)) int   pthread_mutex_unlock(void *m)                  { (void)m; return -1; }
__attribute__((weak)) int   pthread_mutexattr_init(void *a)                { (void)a; return -1; }
__attribute__((weak)) int   pthread_mutexattr_settype(void *a, int t)      { (void)a; (void)t; return -1; }
__attribute__((weak)) int   pthread_cond_init(void *c, const void *a)      { (void)c; (void)a; return -1; }
__attribute__((weak)) int   pthread_cond_destroy(void *c)                  { (void)c; return -1; }
__attribute__((weak)) int   pthread_cond_signal(void *c)                   { (void)c; return -1; }
__attribute__((weak)) int   pthread_cond_wait(void *c, void *m)            { (void)c; (void)m; return -1; }

__attribute__((weak)) int   sem_init(void *s, int p, unsigned int v)       { (void)s; (void)p; (void)v; return -1; }
__attribute__((weak)) int   sem_destroy(void *s)                           { (void)s; return -1; }
__attribute__((weak)) int   sem_post(void *s)                              { (void)s; return -1; }
__attribute__((weak)) int   sem_wait(void *s)                              { (void)s; return -1; }

__attribute__((weak)) int   timer_create(int c, void *e, void *t)          { (void)c; (void)e; (void)t; return -1; }
__attribute__((weak)) int   timer_delete(void *t)                          { (void)t; return -1; }
__attribute__((weak)) int   timer_settime(void *t, int f, const void *n, void *o) { (void)t; (void)f; (void)n; (void)o; return -1; }

__attribute__((weak)) int   clock_gettime(int id, void *ts)                { (void)id; (void)ts; return -1; }
__attribute__((weak)) int   getpid(void)                                   { return 1; }
__attribute__((weak)) void  _exit(int status)                              { (void)status; for (;;); }

/* printf/snprintf/strerror: stubbed to no-op / empty string. LKL only uses
 * these for diagnostic paths (kernel oops dumps, debug logs) that we
 * wouldn't see anyway in a freestanding embed. */
__attribute__((weak)) int   printf(const char *fmt, ...)                   { (void)fmt; return 0; }
__attribute__((weak)) int   snprintf(char *buf, size_t n, const char *fmt, ...) {
    (void)fmt;
    if (buf && n) buf[0] = '\0';
    return 0;
}
__attribute__((weak)) char *strerror(int e)                                { (void)e; return (char *)""; }

/* setjmp/longjmp — LKL uses its own `jmp_buf_*` names via macros; these
 * are the resolved symbols rust-lld complains about. */
__attribute__((weak)) int  jmp_buf_set(void *buf, void (*fn)(void))        { (void)buf; (void)fn; return 0; }
__attribute__((weak)) void jmp_buf_longjmp(void *buf, int val)             { (void)buf; (void)val; for (;;); }
__attribute__((weak)) int  _setjmp(void *buf)                              { (void)buf; return 0; }
__attribute__((weak)) void __longjmp_chk(void *buf, int val)               { (void)buf; (void)val; for (;;); }

/*
 * -------------------------------------------------------------------------
 * Second tranche — functions referenced from other translation units inside
 * `liblkl-in.o` (virtio_net_fd.c, assert.h, FORTIFY_SOURCE-enabled copies
 * of the libc string/print helpers, 64-bit POSIX file I/O).
 * All weak, all stubbed — runtime paths are overridden by our host_ops.
 * -------------------------------------------------------------------------
 */

/* errno + assert: FORTIFY assertions land here. */
__attribute__((weak)) int   __assert_fail_dummy;
static int __errno_storage = 0;
__attribute__((weak)) int  *__errno_location(void)                         { return &__errno_storage; }
__attribute__((weak)) void  __assert_fail(const char *a, const char *f, unsigned int l, const char *fn)
    { (void)a; (void)f; (void)l; (void)fn; for (;;); }

/* FORTIFY_SOURCE string/print checks — forward to the non-_chk variants. */
__attribute__((weak)) int   __snprintf_chk(char *buf, size_t n, int flag, size_t slen, const char *fmt, ...) {
    (void)flag; (void)slen; (void)fmt;
    if (buf && n) buf[0] = '\0';
    return 0;
}
__attribute__((weak)) int   __vsnprintf_chk(char *buf, size_t n, int flag, size_t slen, const char *fmt, void *ap) {
    (void)flag; (void)slen; (void)fmt; (void)ap;
    if (buf && n) buf[0] = '\0';
    return 0;
}
__attribute__((weak)) char *__strcpy_chk(char *dst, const char *src, size_t dlen) {
    (void)dlen;
    /* Reuse the real strcpy-ish behaviour; posix-host.c expects byte-for-byte copy. */
    size_t i = 0;
    while (src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
    return dst;
}
__attribute__((weak)) char *__strncat_chk(char *dst, const char *src, size_t n, size_t dlen) {
    (void)dlen;
    size_t dlen0 = 0; while (dst[dlen0]) dlen0++;
    size_t i = 0;
    while (i < n && src[i]) { dst[dlen0 + i] = src[i]; i++; }
    dst[dlen0 + i] = '\0';
    return dst;
}

/* Real string helpers. strcmp/strchr/strtok are genuinely used by LKL
 * kernel code (not only posix-host), so implement for real rather than
 * stubbing. strtol/strtok_r we stub — never reached at runtime. */
int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
char *strchr(const char *s, int c)
{
    while (*s) { if (*s == (char)c) return (char *)s; s++; }
    return (c == '\0') ? (char *)s : (void *)0;
}
__attribute__((weak)) char *strtok(char *s, const char *d)                 { (void)s; (void)d; return (void *)0; }
__attribute__((weak)) char *strtok_r(char *s, const char *d, char **p)     { (void)s; (void)d; (void)p; return (void *)0; }
__attribute__((weak)) long  strtol(const char *s, char **e, int b)         { (void)s; (void)e; (void)b; return 0; }

/* 64-bit POSIX I/O — only referenced from posix-host.c's disk path, which
 * we never activate (our own disk_backend.c handles virtio-blk). */
typedef long ssize_t_stub;
__attribute__((weak)) long       lseek64(int fd, long off, int w)                 { (void)fd; (void)off; (void)w; return -1; }
__attribute__((weak)) ssize_t_stub pread64(int fd, void *b, size_t n, long off)   { (void)fd; (void)b; (void)n; (void)off; return -1; }
__attribute__((weak)) ssize_t_stub pwrite64(int fd, const void *b, size_t n, long off) { (void)fd; (void)b; (void)n; (void)off; return -1; }
__attribute__((weak)) ssize_t_stub preadv64(int fd, const void *iov, int iovc, long off)  { (void)fd; (void)iov; (void)iovc; (void)off; return -1; }
__attribute__((weak)) ssize_t_stub pwritev64(int fd, const void *iov, int iovc, long off) { (void)fd; (void)iov; (void)iovc; (void)off; return -1; }
__attribute__((weak)) int         fdatasync(int fd)                                { (void)fd; return -1; }
__attribute__((weak)) ssize_t_stub write(int fd, const void *b, size_t n)          { (void)fd; (void)b; (void)n; return -1; }

/*
 * -------------------------------------------------------------------------
 * Third tranche — virtio_net_fd.c + other tools/lkl helpers pull in a wide
 * array of POSIX file/socket APIs. Every runtime path through these is
 * superseded by our kernel-side virtio drivers, so plain no-op stubs.
 * -------------------------------------------------------------------------
 */

/* POSIX file descriptor operations. */
__attribute__((weak)) int         open(const char *p, int f, ...)                  { (void)p; (void)f; return -1; }
__attribute__((weak)) int         close(int fd)                                    { (void)fd; return -1; }
__attribute__((weak)) ssize_t_stub read(int fd, void *b, size_t n)                 { (void)fd; (void)b; (void)n; return -1; }
__attribute__((weak)) ssize_t_stub readv(int fd, const void *iov, int iovc)        { (void)fd; (void)iov; (void)iovc; return -1; }
__attribute__((weak)) ssize_t_stub writev(int fd, const void *iov, int iovc)       { (void)fd; (void)iov; (void)iovc; return -1; }
__attribute__((weak)) ssize_t_stub pread(int fd, void *b, size_t n, long off)      { (void)fd; (void)b; (void)n; (void)off; return -1; }
__attribute__((weak)) ssize_t_stub pwrite(int fd, const void *b, size_t n, long off)   { (void)fd; (void)b; (void)n; (void)off; return -1; }
__attribute__((weak)) int         fcntl(int fd, int cmd, ...)                      { (void)fd; (void)cmd; return -1; }
__attribute__((weak)) int         ioctl(int fd, unsigned long req, ...)            { (void)fd; (void)req; return -1; }
__attribute__((weak)) int         pipe(int fds[2])                                 { (void)fds; return -1; }
__attribute__((weak)) int         poll(void *fds, unsigned long nfds, int to)      { (void)fds; (void)nfds; (void)to; return -1; }

/* POSIX sockets (LKL's virtio_net_fd uses these for tap/raw interfaces). */
__attribute__((weak)) int         socket(int d, int t, int p)                      { (void)d; (void)t; (void)p; return -1; }
__attribute__((weak)) int         bind(int fd, const void *a, unsigned int l)      { (void)fd; (void)a; (void)l; return -1; }
__attribute__((weak)) int         setsockopt(int fd, int lv, int on, const void *v, unsigned int l)
    { (void)fd; (void)lv; (void)on; (void)v; (void)l; return -1; }
__attribute__((weak)) unsigned int if_nametoindex(const char *n)                   { (void)n; return 0; }

/* Stdio-ish. stderr is the tricky one — a FILE* — but since nobody uses
 * it at runtime we just expose a null marker. fwrite/perror/__fprintf_chk
 * are no-ops. */
__attribute__((weak)) void *stderr = (void *)0;
__attribute__((weak)) size_t fwrite(const void *p, size_t s, size_t n, void *f)    { (void)p; (void)s; (void)n; (void)f; return 0; }
__attribute__((weak)) void   perror(const char *m)                                  { (void)m; }
__attribute__((weak)) int    __fprintf_chk(void *f, int flag, const char *fmt, ...) { (void)f; (void)flag; (void)fmt; return 0; }

/* String helper. posix-host.c uses strdup for logging. */
__attribute__((weak)) char *strdup(const char *s)                                   { (void)s; return (void *)0; }

/*
 * -------------------------------------------------------------------------
 * Fourth tranche — remaining long-tail references (eventfd, select, FORTIFY
 * variants, getenv, inet_pton, time helpers). All weak no-ops.
 * -------------------------------------------------------------------------
 */

__attribute__((weak)) int    eventfd(unsigned int initval, int flags)               { (void)initval; (void)flags; return -1; }
__attribute__((weak)) int    select(int n, void *r, void *w, void *e, void *t)      { (void)n; (void)r; (void)w; (void)e; (void)t; return -1; }
__attribute__((weak)) char  *getenv(const char *name)                                { (void)name; return (void *)0; }
__attribute__((weak)) int    inet_pton(int af, const char *src, void *dst)           { (void)af; (void)src; (void)dst; return 0; }
__attribute__((weak)) int    nanosleep(const void *req, void *rem)                   { (void)req; (void)rem; return -1; }
__attribute__((weak)) int    usleep(unsigned int us)                                 { (void)us; return -1; }
__attribute__((weak)) ssize_t_stub readlink(const char *p, char *buf, size_t n)     { (void)p; (void)buf; (void)n; return -1; }
__attribute__((weak)) unsigned long strtoul(const char *s, char **e, int b)          { (void)s; (void)e; (void)b; return 0; }

/* strrchr — LKL kernel code uses it; implement for real. */
char *strrchr(const char *s, int c)
{
    char *last = (void *)0;
    while (*s) { if (*s == (char)c) last = (char *)s; s++; }
    return (c == '\0') ? (char *)s : last;
}

/* More FORTIFY_SOURCE checks — forward to plain fallbacks. */
__attribute__((weak)) int   __fdelt_chk(long fd)                                     { return (int)fd; }
__attribute__((weak)) char *__strcat_chk(char *dst, const char *src, size_t dlen) {
    (void)dlen;
    size_t i = 0; while (dst[i]) i++;
    size_t j = 0; while (src[j]) { dst[i + j] = src[j]; j++; }
    dst[i + j] = '\0';
    return dst;
}
__attribute__((weak)) int  __isoc99_sscanf(const char *s, const char *fmt, ...)      { (void)s; (void)fmt; return 0; }
