/*
 * syscall_xlat.h -- Translate x86_64 Linux syscall numbers to LKL (generic).
 *
 * LKL uses the generic syscall table (same as AArch64/RISC-V),
 * while apps on sotX use x86_64 numbers. This table maps between them.
 */

#ifndef SYSCALL_XLAT_H
#define SYSCALL_XLAT_H

#include <stdint.h>

/* x86_64 → LKL generic syscall number translation.
 * Returns the LKL number, or -1 if not mapped. */
static inline long xlat_syscall_x86_to_lkl(long x86_nr)
{
    switch (x86_nr) {
    /* File I/O */
    case 0:   return 63;   /* read */
    case 1:   return 64;   /* write */
    case 2:   return 56;   /* open → openat (AT_FDCWD) -- needs arg fixup */
    case 3:   return 57;   /* close */
    case 4:   return 79;   /* stat → fstatat (AT_FDCWD) -- needs arg fixup */
    case 5:   return 80;   /* fstat */
    case 6:   return 79;   /* lstat → fstatat -- needs arg fixup */
    case 8:   return 62;   /* lseek */
    case 9:   return 222;  /* mmap */
    case 10:  return 226;  /* mprotect */
    case 11:  return 215;  /* munmap */
    case 12:  return 214;  /* brk */
    case 16:  return 29;   /* ioctl */
    case 17:  return 67;   /* pread64 */
    case 18:  return 68;   /* pwrite64 */
    case 19:  return 65;   /* readv */
    case 20:  return 66;   /* writev */
    case 21:  return 48;   /* access → faccessat -- needs arg fixup */
    case 22:  return 59;   /* pipe → pipe2 */
    case 32:  return 23;   /* dup */
    case 33:  return 24;   /* dup2 → dup3 */
    case 39:  return 172;  /* getpid */
    case 41:  return 198;  /* socket */
    case 42:  return 203;  /* connect */
    case 43:  return 202;  /* accept */
    case 44:  return 206;  /* sendto */
    case 45:  return 207;  /* recvfrom */
    case 46:  return 211;  /* sendmsg */
    case 47:  return 212;  /* recvmsg */
    case 48:  return 208;  /* shutdown */
    case 49:  return 200;  /* bind */
    case 50:  return 201;  /* listen */
    case 51:  return 204;  /* getsockname */
    case 52:  return 205;  /* getpeername */
    case 53:  return 199;  /* socketpair */
    case 54:  return 209;  /* setsockopt */
    case 55:  return 210;  /* getsockopt */
    case 57:  return 220;  /* fork → clone */
    case 59:  return 221;  /* execve */
    case 60:  return 93;   /* exit */
    case 61:  return 260;  /* wait4 */
    case 62:  return 129;  /* kill */
    case 63:  return 160;  /* uname */
    case 72:  return 25;   /* fcntl */
    case 77:  return 81;   /* ftruncate */
    case 78:  return 61;   /* getdents → getdents64 */
    case 79:  return 17;   /* getcwd */
    case 80:  return 49;   /* chdir */
    case 83:  return 34;   /* mkdir → mkdirat */
    case 87:  return 35;   /* unlink → unlinkat */
    case 82:  return 38;   /* rename → renameat */
    case 96:  return 169;  /* gettimeofday */
    case 99:  return 179;  /* sysinfo */
    case 102: return 174;  /* getuid */
    case 104: return 176;  /* getgid */
    case 107: return 175;  /* geteuid */
    case 108: return 177;  /* getegid */
    case 110: return 173;  /* getppid */
    case 217: return 61;   /* getdents64 */
    case 228: return 113;  /* clock_gettime */
    case 231: return 94;   /* exit_group */
    case 257: return 56;   /* openat */
    case 262: return 79;   /* fstatat / newfstatat */
    case 267: return 78;   /* readlinkat */
    case 269: return 48;   /* faccessat */
    case 302: return 261;  /* prlimit64 */
    case 318: return 278;  /* getrandom */
    case 74:  return 82;   /* fsync */
    case 75:  return 83;   /* fdatasync */
    case 84:  return 35;   /* rmdir → unlinkat(AT_REMOVEDIR) */
    case 90:  return 53;   /* chmod → fchmodat */
    /* epoll */
    case 213: return 20;   /* epoll_create → epoll_create1 */
    case 232: return 22;   /* epoll_wait → epoll_pwait */
    case 233: return 21;   /* epoll_ctl */
    case 281: return 22;   /* epoll_pwait */
    /* poll/select */
    case 7:   return 73;   /* poll → ppoll */
    case 23:  return 72;   /* select → pselect6 */
    case 270: return 72;   /* pselect6 */
    case 271: return 73;   /* ppoll */
    /* signals */
    case 13:  return 134;  /* rt_sigaction */
    case 14:  return 135;  /* rt_sigprocmask */
    case 15:  return 139;  /* rt_sigreturn */
    case 35:  return 101;  /* nanosleep */
    case 131: return 132;  /* sigaltstack */
    case 186: return 178;  /* gettid */
    /* pipe/dup/misc */
    case 229: return 114;  /* clock_getres */
    case 230: return 115;  /* clock_nanosleep */
    case 258: return 34;   /* mkdirat */
    case 263: return 35;   /* unlinkat */
    case 288: return 242;  /* accept4 */
    case 284: return 19;   /* eventfd → eventfd2 */
    case 290: return 19;   /* eventfd2 */
    case 291: return 20;   /* epoll_create1 */
    case 292: return 24;   /* dup3 */
    case 293: return 59;   /* pipe2 */
    case 294: return 26;   /* inotify_init1 */
    case 254: return 27;   /* inotify_add_watch */
    case 255: return 28;   /* inotify_rm_watch */
    case 283: return 85;   /* timerfd_create */
    case 286: return 86;   /* timerfd_settime */
    case 287: return 87;   /* timerfd_gettime */
    case 319: return 279;  /* memfd_create */
    case 202: return 98;   /* futex */
    case 439: return 48;   /* faccessat2 → faccessat */
    default:  return -1;   /* unknown — fall back to LUCAS emulation */
    }
}

#endif /* SYSCALL_XLAT_H */
