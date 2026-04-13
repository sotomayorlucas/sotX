/*
 * disk_backend.c -- Block device I/O bridge (LKL fusion <-> sotX blk service).
 *
 * Fusion variant: LKL runs inside init process. This backend uses IPC to
 * init's "blk" service for real sector read/write on virtio-blk.
 *
 * Protocol (same as services/lkl-server/disk_backend.c):
 *   CMD=1 (READ):  regs[0]=sector, regs[1]=count, regs[2]=dest_vaddr, regs[3]=self_as_cap
 *   CMD=2 (WRITE): regs[0]=sector, regs[1]=count, regs[2]=src_vaddr,  regs[3]=self_as_cap
 *   CMD=3 (CAPACITY): no args -> reply regs[0]=total_sectors
 */

#include "disk_backend.h"
#include "sotos_syscall.h"
#include "libc_stubs.h"

static uint64_t blk_ep = 0;
static uint64_t self_as_cap = 0;

/* 4KB-aligned staging buffer for DMA-safe IPC transfers.
 * Max 8 sectors (4096 bytes) per read — same as blk service limit. */
static char __attribute__((aligned(4096))) disk_buf[4096];

#define BLK_CMD_READ     1
#define BLK_CMD_WRITE    2
#define BLK_CMD_CAPACITY 3
#define SECTOR_SIZE      512
#define MAX_SECTORS      8  /* blk service limit: 8 sectors per request */

int disk_init(void)
{
    serial_puts("[lkl-disk-fusion] looking up 'blk' service...\n");

    static const char name[] = "blk";
    int64_t cap = sys_svc_lookup(name, 3);
    if (cap <= 0) {
        serial_puts("[lkl-disk-fusion] 'blk' not found (disk I/O disabled)\n");
        return -1;
    }
    blk_ep = (uint64_t)cap;
    serial_puts("[lkl-disk-fusion] blk ep=");
    serial_put_dec(blk_ep);
    serial_puts("\n");

    /* Read self AS cap from BootInfo page at 0xB00000.
     * Layout: magic(0), cap_count(8), caps[32](16..272), guest_entry(272),
     *         fb_addr(280), fb_w(288), fb_h(292), fb_pitch(296), fb_bpp(300),
     *         stack_top(304), self_as_cap(312) */
    self_as_cap = *(volatile uint64_t *)(0xB00000ULL + 312);
    serial_puts("[lkl-disk-fusion] self_as=");
    serial_put_dec(self_as_cap);
    serial_puts("\n");

    /* Query and log capacity as a sanity check. */
    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = BLK_CMD_CAPACITY;
    int64_t r = sys_call(blk_ep, &msg);
    if (r == 0) {
        serial_puts("[lkl-disk-fusion] capacity=");
        serial_put_dec(msg.regs[0]);
        serial_puts(" sectors (");
        serial_put_dec(msg.regs[0] * SECTOR_SIZE);
        serial_puts(" bytes)\n");
    }
    return 0;
}

int disk_read(void *buf, uint64_t offset, size_t count)
{
    if (blk_ep == 0) return DISK_ENOSYS;

    size_t done = 0;
    while (done < count) {
        size_t chunk = count - done;
        if (chunk > 4096) chunk = 4096;

        uint64_t byte_off = offset + done;
        uint64_t sector = byte_off / SECTOR_SIZE;
        uint64_t sect_count = (chunk + SECTOR_SIZE - 1) / SECTOR_SIZE;
        if (sect_count > MAX_SECTORS) sect_count = MAX_SECTORS;

        struct ipc_msg msg;
        memset(&msg, 0, sizeof(msg));
        msg.tag = BLK_CMD_READ;
        msg.regs[0] = sector;
        msg.regs[1] = sect_count;
        msg.regs[2] = (uint64_t)disk_buf;
        msg.regs[3] = self_as_cap;

        int64_t r = sys_call(blk_ep, &msg);
        if (r != 0 || (int64_t)msg.regs[0] < 0) return -5; /* EIO */

        /* Copy from staging buffer, handling sub-sector offset. */
        size_t intra = (size_t)(byte_off % SECTOR_SIZE);
        size_t avail = (size_t)(sect_count * SECTOR_SIZE) - intra;
        if (avail > chunk) avail = chunk;
        memcpy((char *)buf + done, disk_buf + intra, avail);
        done += avail;
    }
    return (int)done;
}

int disk_write(const void *buf, uint64_t offset, size_t count)
{
    if (blk_ep == 0) return DISK_ENOSYS;

    size_t done = 0;
    while (done < count) {
        size_t chunk = count - done;
        if (chunk > SECTOR_SIZE) chunk = SECTOR_SIZE;

        uint64_t byte_off = offset + done;
        uint64_t sector = byte_off / SECTOR_SIZE;

        /* Read-modify-write for partial sector writes. */
        struct ipc_msg msg;
        memset(&msg, 0, sizeof(msg));
        msg.tag = BLK_CMD_READ;
        msg.regs[0] = sector;
        msg.regs[1] = 1;
        msg.regs[2] = (uint64_t)disk_buf;
        msg.regs[3] = self_as_cap;
        sys_call(blk_ep, &msg);

        /* Patch in the new data. */
        size_t intra = (size_t)(byte_off % SECTOR_SIZE);
        size_t avail = SECTOR_SIZE - intra;
        if (avail > chunk) avail = chunk;
        memcpy(disk_buf + intra, (const char *)buf + done, avail);

        /* Write the full sector back. */
        memset(&msg, 0, sizeof(msg));
        msg.tag = BLK_CMD_WRITE;
        msg.regs[0] = sector;
        msg.regs[1] = 1;
        msg.regs[2] = (uint64_t)disk_buf;
        msg.regs[3] = self_as_cap;
        int64_t r = sys_call(blk_ep, &msg);
        if (r != 0 || (int64_t)msg.regs[0] < 0) return -5; /* EIO */

        done += avail;
    }
    return (int)done;
}

uint64_t disk_capacity(void)
{
    if (blk_ep == 0) return 0;

    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = BLK_CMD_CAPACITY;
    if (sys_call(blk_ep, &msg) == 0)
        return msg.regs[0] * SECTOR_SIZE;
    return 0;
}
