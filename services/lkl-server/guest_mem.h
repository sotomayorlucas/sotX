/*
 * guest_mem.h -- Guest memory read/write helpers.
 *
 * Uses sys_vm_read / sys_vm_write to access a child process's address
 * space via its AS capability (same pattern as context.rs guest_read/write).
 */

#ifndef GUEST_MEM_H
#define GUEST_MEM_H

#include <stdint.h>
#include <stddef.h>

/* Read `len` bytes from `vaddr` in the address space identified by
 * `as_cap` into local `buf`.  Reads in 4096-byte chunks, yielding
 * and retrying once on failure (CoW page not yet faulted).
 * Returns 0 on success, negative on persistent failure. */
int guest_read(uint64_t as_cap, uint64_t vaddr, void *buf, size_t len);

/* Write `len` bytes from local `buf` into `vaddr` in the target AS.
 * Handles CoW transparently (kernel allocates new frame on write to RO).
 * Returns 0 on success, negative on failure. */
int guest_write(uint64_t as_cap, uint64_t vaddr, const void *buf, size_t len);

/* Read a NUL-terminated string (up to max_len-1 chars) from guest.
 * Returns length of string (excluding NUL), or 0 on failure. */
size_t guest_read_str(uint64_t as_cap, uint64_t vaddr, char *buf,
                      size_t max_len);

#endif /* GUEST_MEM_H */
