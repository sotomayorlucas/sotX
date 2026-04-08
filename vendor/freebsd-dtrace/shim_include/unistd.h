/*
 * PANDORA Task 1: minimal <unistd.h> shim for compiling FreeBSD
 * libdtrace against the x86_64-unknown-none freestanding target.
 *
 * Only declares the subset of POSIX-ish identifiers libdtrace actually
 * references. Full libc stubs are not provided here; the caller of
 * any shim is expected to link against the `libdtrace_shim` C library
 * we build alongside sot-dtrace, which provides weak stub definitions.
 */
#ifndef _SHIM_UNISTD_H_
#define _SHIM_UNISTD_H_

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef long ssize_t;
typedef unsigned long size_t;
typedef long off_t;
typedef int pid_t;

#endif
