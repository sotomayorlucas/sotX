/*
 * sotos_syscall.h -- Inline asm wrappers for sotX kernel syscalls.
 *
 * Mirrors the Rust ABI in libs/sotos-common/src/lib.rs exactly:
 *   rax = syscall number
 *   rdi = arg1 (or cap for IPC)
 *   rsi = arg2
 *   rdx = arg3
 *   r8  = arg4
 *   r10 = arg5
 *   r9  = arg6
 *   Returns: rax = result
 *
 * IPC messages use the full register set:
 *   Send:  rdi=ep_cap, rsi=tag, rdx=regs[0], r8=regs[1], r9=regs[2],
 *          r10=regs[3], r12=regs[4], r13=regs[5], r14=regs[6], r15=regs[7]
 *   Recv:  rdi=ep_cap  ->  rsi=tag, rdx=regs[0], r8=regs[1], r9=regs[2],
 *          r10=regs[3], r12=regs[4], r13=regs[5], r14=regs[6], r15=regs[7]
 */

#ifndef SOTOS_SYSCALL_H
#define SOTOS_SYSCALL_H

#include <stdint.h>

/* ---------------------------------------------------------------
 * Syscall numbers (from sotos-common Syscall enum)
 * --------------------------------------------------------------- */
#define SYS_YIELD            0
#define SYS_SEND             1
#define SYS_RECV             2
#define SYS_CALL             3
#define SYS_ENDPOINT_CREATE 10
#define SYS_FRAME_ALLOC     20
#define SYS_FRAME_FREE      21
#define SYS_MAP             22
#define SYS_UNMAP           23
#define SYS_UNMAP_FREE      24
#define SYS_THREAD_CREATE   40
#define SYS_THREAD_EXIT     42
#define SYS_NOTIFY_CREATE   70
#define SYS_NOTIFY_WAIT     71
#define SYS_NOTIFY_SIGNAL   72
#define SYS_VM_READ        128
#define SYS_VM_WRITE       129
#define SYS_SVC_REGISTER   130
#define SYS_SVC_LOOKUP     131
#define SYS_PROTECT        134
#define SYS_SET_FS_BASE    160
#define SYS_GET_FS_BASE    161
#define SYS_DEBUG_PRINT    255

/* ---------------------------------------------------------------
 * IPC message structure (tag + 8 registers = 72 bytes)
 * --------------------------------------------------------------- */
struct ipc_msg {
    uint64_t tag;
    uint64_t regs[8];
};

/* ---------------------------------------------------------------
 * Raw syscall helpers (0-4 arguments)
 * --------------------------------------------------------------- */

static inline uint64_t syscall0(uint64_t nr)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall1(uint64_t nr, uint64_t a1)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall2(uint64_t nr, uint64_t a1, uint64_t a2)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall3(uint64_t nr, uint64_t a1, uint64_t a2,
                                uint64_t a3)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall4(uint64_t nr, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4)
{
    uint64_t ret;
    register uint64_t r8 __asm__("r8") = a4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r8)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall5(uint64_t nr, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4, uint64_t a5)
{
    uint64_t ret;
    register uint64_t r8  __asm__("r8")  = a4;
    register uint64_t r10 __asm__("r10") = a5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r8), "r"(r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ---------------------------------------------------------------
 * High-level wrappers
 * --------------------------------------------------------------- */

/* Yield the current timeslice. */
static inline void sys_yield(void)
{
    syscall0(SYS_YIELD);
}

/* Set FS_BASE MSR for current thread. */
static inline void sys_set_fs_base(uint64_t addr)
{
    syscall1(SYS_SET_FS_BASE, addr);
}

/* Get FS_BASE MSR of current thread. */
static inline uint64_t sys_get_fs_base(void)
{
    return syscall0(SYS_GET_FS_BASE);
}

/* Write a single byte to serial (COM1). */
static inline void sys_debug_putchar(uint8_t ch)
{
    syscall1(SYS_DEBUG_PRINT, (uint64_t)ch);
}

/* Allocate a physical frame. Returns frame cap or negative error. */
static inline int64_t sys_frame_alloc(void)
{
    return (int64_t)syscall0(SYS_FRAME_ALLOC);
}

/* Map a frame into the caller's address space.
 * flags: bit 1 = WRITABLE, bit 63 = NO_EXECUTE. */
static inline int64_t sys_map(uint64_t vaddr, uint64_t frame_cap,
                              uint64_t flags)
{
    return (int64_t)syscall3(SYS_MAP, vaddr, frame_cap, flags);
}

/* Change page permissions (mprotect-like, W^X enforced). */
static inline int64_t sys_protect(uint64_t vaddr, uint64_t flags)
{
    return (int64_t)syscall2(SYS_PROTECT, vaddr, flags);
}

/* Create a new IPC endpoint. Returns ep cap or negative error. */
static inline int64_t sys_endpoint_create(void)
{
    return (int64_t)syscall0(SYS_ENDPOINT_CREATE);
}

/* Create a new thread. Returns thread cap or negative error. */
static inline int64_t sys_thread_create(uint64_t rip, uint64_t rsp,
                                        uint64_t arg)
{
    return (int64_t)syscall3(SYS_THREAD_CREATE, rip, rsp, arg);
}

/* Terminate the current thread (never returns). */
static inline void __attribute__((noreturn)) sys_thread_exit(void)
{
    syscall0(SYS_THREAD_EXIT);
    __builtin_unreachable();
}

/* Create a notification object. Returns cap or negative error. */
static inline int64_t sys_notify_create(void)
{
    return (int64_t)syscall0(SYS_NOTIFY_CREATE);
}

/* Wait on a notification (blocks if not pending). */
static inline void sys_notify_wait(uint64_t cap)
{
    syscall1(SYS_NOTIFY_WAIT, cap);
}

/* Signal a notification (wakes waiter or sets pending). */
static inline void sys_notify_signal(uint64_t cap)
{
    syscall1(SYS_NOTIFY_SIGNAL, cap);
}

/* Register a service name -> endpoint mapping.
 * SYS_SVC_REGISTER(130): rdi=name_ptr, rsi=name_len, rdx=ep_cap */
static inline int64_t sys_svc_register(const char *name, uint64_t name_len,
                                       uint64_t ep_cap)
{
    return (int64_t)syscall3(SYS_SVC_REGISTER, (uint64_t)name, name_len,
                             ep_cap);
}

/* Look up a service by name. Returns derived ep cap or negative error. */
static inline int64_t sys_svc_lookup(const char *name, uint64_t name_len)
{
    return (int64_t)syscall2(SYS_SVC_LOOKUP, (uint64_t)name, name_len);
}

/* Read bytes from a target address space into caller's buffer.
 * as_cap: AddrSpace cap, remote_vaddr: source in target AS,
 * local_buf: dest in caller AS, len: byte count (max 4096). */
static inline int64_t sys_vm_read(uint64_t as_cap, uint64_t remote_vaddr,
                                  void *local_buf, uint64_t len)
{
    return (int64_t)syscall4(SYS_VM_READ, as_cap, remote_vaddr,
                             (uint64_t)local_buf, len);
}

/* Write bytes from caller's buffer into a target address space.
 * Handles CoW pages transparently. */
static inline int64_t sys_vm_write(uint64_t as_cap, uint64_t remote_vaddr,
                                   const void *local_buf, uint64_t len)
{
    return (int64_t)syscall4(SYS_VM_WRITE, as_cap, remote_vaddr,
                             (uint64_t)local_buf, len);
}

/* ---------------------------------------------------------------
 * IPC: Send / Recv / Call (full register ABI)
 *
 * Send: rdi=ep_cap, rsi=tag, rdx=regs[0], r8=regs[1], r9=regs[2],
 *       r10=regs[3], r12=regs[4], r13=regs[5], r14=regs[6], r15=regs[7]
 *
 * Recv: rdi=ep_cap -> tag in rsi, regs in rdx/r8/r9/r10/r12-r15
 * --------------------------------------------------------------- */

static inline int64_t sys_send(uint64_t ep_cap, const struct ipc_msg *msg)
{
    uint64_t ret;
    register uint64_t r8  __asm__("r8")  = msg->regs[1];
    register uint64_t r9  __asm__("r9")  = msg->regs[2];
    register uint64_t r10 __asm__("r10") = msg->regs[3];
    register uint64_t r12 __asm__("r12") = msg->regs[4];
    register uint64_t r13 __asm__("r13") = msg->regs[5];
    register uint64_t r14 __asm__("r14") = msg->regs[6];
    register uint64_t r15 __asm__("r15") = msg->regs[7];
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"((uint64_t)SYS_SEND), "D"(ep_cap), "S"(msg->tag),
          "d"(msg->regs[0]),
          "r"(r8), "r"(r9), "r"(r10), "r"(r12), "r"(r13), "r"(r14), "r"(r15)
        : "rcx", "r11", "memory"
    );
    return (int64_t)ret;
}

static inline int64_t sys_recv(uint64_t ep_cap, struct ipc_msg *msg)
{
    uint64_t ret;
    uint64_t tag, r0;
    register uint64_t r8  __asm__("r8");
    register uint64_t r9  __asm__("r9");
    register uint64_t r10 __asm__("r10");
    register uint64_t r12 __asm__("r12");
    register uint64_t r13 __asm__("r13");
    register uint64_t r14 __asm__("r14");
    register uint64_t r15 __asm__("r15");
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "=S"(tag), "=d"(r0),
          "=r"(r8), "=r"(r9), "=r"(r10),
          "=r"(r12), "=r"(r13), "=r"(r14), "=r"(r15)
        : "a"((uint64_t)SYS_RECV), "D"(ep_cap)
        : "rcx", "r11", "memory"
    );
    if ((int64_t)ret >= 0) {
        msg->tag     = tag;
        msg->regs[0] = r0;
        msg->regs[1] = r8;
        msg->regs[2] = r9;
        msg->regs[3] = r10;
        msg->regs[4] = r12;
        msg->regs[5] = r13;
        msg->regs[6] = r14;
        msg->regs[7] = r15;
    }
    return (int64_t)ret;
}

static inline int64_t sys_call(uint64_t ep_cap, struct ipc_msg *msg)
{
    uint64_t ret;
    uint64_t tag_out, r0_out;
    register uint64_t r8  __asm__("r8")  = msg->regs[1];
    register uint64_t r9  __asm__("r9")  = msg->regs[2];
    register uint64_t r10 __asm__("r10") = msg->regs[3];
    register uint64_t r12 __asm__("r12") = msg->regs[4];
    register uint64_t r13 __asm__("r13") = msg->regs[5];
    register uint64_t r14 __asm__("r14") = msg->regs[6];
    register uint64_t r15 __asm__("r15") = msg->regs[7];
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "=S"(tag_out), "=d"(r0_out),
          "+r"(r8), "+r"(r9), "+r"(r10),
          "+r"(r12), "+r"(r13), "+r"(r14), "+r"(r15)
        : "a"((uint64_t)SYS_CALL), "D"(ep_cap),
          "S"(msg->tag), "d"(msg->regs[0])
        : "rcx", "r11", "memory"
    );
    if ((int64_t)ret >= 0) {
        msg->tag     = tag_out;
        msg->regs[0] = r0_out;
        msg->regs[1] = r8;
        msg->regs[2] = r9;
        msg->regs[3] = r10;
        msg->regs[4] = r12;
        msg->regs[5] = r13;
        msg->regs[6] = r14;
        msg->regs[7] = r15;
    }
    return (int64_t)ret;
}

/* ---------------------------------------------------------------
 * Serial print helpers (build on sys_debug_putchar)
 * --------------------------------------------------------------- */

static inline void serial_puts(const char *s)
{
    while (*s)
        sys_debug_putchar((uint8_t)*s++);
}

static inline void serial_put_hex(uint64_t val)
{
    static const char hex[] = "0123456789abcdef";
    serial_puts("0x");
    for (int i = 60; i >= 0; i -= 4)
        sys_debug_putchar((uint8_t)hex[(val >> i) & 0xF]);
}

static inline void serial_put_dec(uint64_t val)
{
    if (val == 0) {
        sys_debug_putchar('0');
        return;
    }
    char buf[20];
    int n = 0;
    while (val > 0) {
        buf[n++] = '0' + (char)(val % 10);
        val /= 10;
    }
    for (int i = n - 1; i >= 0; i--)
        sys_debug_putchar((uint8_t)buf[i]);
}

#endif /* SOTOS_SYSCALL_H */
