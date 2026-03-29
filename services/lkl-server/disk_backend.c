/*
 * disk_backend.c -- Block device I/O bridge (stub).
 *
 * Phase 1: all operations return -ENOSYS.
 * Phase 2 will use IPC to the virtio-blk service.
 */

#include "disk_backend.h"
#include "sotos_syscall.h"

int disk_init(void)
{
    serial_puts("[lkl-disk] stub init (no backend yet)\n");
    return 0;
}

int disk_read(void *buf, uint64_t offset, size_t count)
{
    (void)buf;
    (void)offset;
    (void)count;
    return DISK_ENOSYS;
}

int disk_write(const void *buf, uint64_t offset, size_t count)
{
    (void)buf;
    (void)offset;
    (void)count;
    return DISK_ENOSYS;
}

uint64_t disk_capacity(void)
{
    return 0;
}
