/*
 * guest_mem.c -- Guest memory read/write helpers.
 *
 * Mirrors the pattern in services/init/src/syscalls/context.rs:
 * read/write in 4096-byte chunks, yield-and-retry on failure.
 */

#include "guest_mem.h"
#include "sotos_syscall.h"
#include "libc_stubs.h"

int guest_read(uint64_t as_cap, uint64_t vaddr, void *buf, size_t len)
{
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done;
        if (chunk > 4096)
            chunk = 4096;

        int64_t r = sys_vm_read(as_cap, vaddr + done, dst + done, chunk);
        if (r < 0) {
            /* Yield to let VMM handle pending CoW faults, retry once. */
            sys_yield();
            r = sys_vm_read(as_cap, vaddr + done, dst + done, chunk);
            if (r < 0)
                return (int)r;
        }
        done += chunk;
    }
    return 0;
}

int guest_write(uint64_t as_cap, uint64_t vaddr, const void *buf, size_t len)
{
    const uint8_t *src = (const uint8_t *)buf;
    size_t done = 0;

    while (done < len) {
        size_t chunk = len - done;
        if (chunk > 4096)
            chunk = 4096;

        int64_t r = sys_vm_write(as_cap, vaddr + done, src + done, chunk);
        if (r < 0)
            return (int)r;
        done += chunk;
    }
    return 0;
}

size_t guest_read_str(uint64_t as_cap, uint64_t vaddr, char *buf,
                      size_t max_len)
{
    if (vaddr == 0 || max_len == 0)
        return 0;

    size_t max = max_len - 1;
    size_t pos = 0;

    while (pos < max) {
        size_t chunk = max - pos;
        if (chunk > 64)
            chunk = 64;

        int64_t r = sys_vm_read(as_cap, vaddr + pos, buf + pos, chunk);
        if (r < 0) {
            buf[pos] = '\0';
            return 0;
        }

        /* Scan for NUL in the chunk we just read. */
        for (size_t i = pos; i < pos + chunk; i++) {
            if (buf[i] == '\0')
                return i;
        }
        pos += chunk;
    }
    buf[pos] = '\0';
    return pos;
}
