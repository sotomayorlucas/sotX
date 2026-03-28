/*
 * disk_backend.h -- Block device I/O bridge (LKL <-> virtio-blk).
 *
 * Phase 1: stub returning -ENOSYS.
 * Phase 2: IPC to virtio-blk service for real block I/O.
 */

#ifndef DISK_BACKEND_H
#define DISK_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#define DISK_ENOSYS (-38)

/* Initialise the disk backend (look up virtio-blk service, etc.).
 * Returns 0 on success, negative on error. */
int disk_init(void);

/* Read `count` bytes from disk at byte `offset` into `buf`.
 * Returns bytes read, or negative on error. */
int disk_read(void *buf, uint64_t offset, size_t count);

/* Write `count` bytes from `buf` to disk at byte `offset`.
 * Returns bytes written, or negative on error. */
int disk_write(const void *buf, uint64_t offset, size_t count);

/* Query disk capacity in bytes.  Returns 0 if unknown. */
uint64_t disk_capacity(void);

#endif /* DISK_BACKEND_H */
