/*
 * net_backend.c -- LKL network device bridge (Camino B: IPC to net-raw).
 *
 * Phase 5b / §10.7 activation. Real external connectivity via a
 * dedicated second virtio-net NIC, owned by init's "net-raw" service.
 * We're a thin IPC client — mirrors disk_backend.c's relationship
 * with the "blk" service.
 *
 * IPC protocol (see services/init/src/main.rs constants NET_RAW_CMD_*):
 *   CMD=1 TX:      regs[0]=frame_vaddr, regs[1]=len, regs[2]=self_as_cap
 *                  → reply regs[0] = bytes_sent or negative errno
 *   CMD=2 RX_POLL: regs[0]=dst_vaddr,   regs[1]=len, regs[2]=self_as_cap
 *                  → reply regs[0] = bytes_received (0 if none)
 *   CMD=3 MAC:     → reply regs[0..5] = MAC bytes
 *   CMD=4 RX_WAIT: regs[0]=dst_vaddr,   regs[1]=len, regs[2]=self_as_cap
 *                  → block until a frame arrives, then reply as RX_POLL
 *
 * If the "net-raw" service does not exist (single-NIC QEMU cmdline or
 * SOTOS_LKL=0 build), net_backend_register returns -ENOSYS and LKL is
 * left without an external netdev. 127.0.0.1 still works via LKL's
 * built-in `lo`.
 */

#include <stdint.h>
#include <stddef.h>
#include "net_backend.h"
#include "sotos_syscall.h"
#include "libc_stubs.h"

#ifdef HAS_LKL
#include <lkl.h>
#include <lkl_host.h>
#else
#include "lkl_stub.h"
/* Stub mode fallback — same as loopback scaffold. */
struct iovec { void *iov_base; size_t iov_len; };
struct lkl_netdev { struct lkl_dev_net_ops *ops; int id; uint8_t has_vnet_hdr: 1; uint8_t mac[6]; };
struct lkl_netdev_args { void *mac; unsigned int offload; };
struct lkl_dev_net_ops {
    int  (*tx)(struct lkl_netdev *nd, struct iovec *iov, int cnt);
    int  (*rx)(struct lkl_netdev *nd, struct iovec *iov, int cnt);
    int  (*poll)(struct lkl_netdev *nd);
    void (*poll_hup)(struct lkl_netdev *nd);
    void (*free)(struct lkl_netdev *nd);
};
static inline int  lkl_netdev_add(struct lkl_netdev *nd, struct lkl_netdev_args *a) { (void)nd; (void)a; return -38; }
static inline int  lkl_netdev_get_ifindex(int id) { (void)id; return -38; }
static inline int  lkl_if_up(int i) { (void)i; return -38; }
static inline int  lkl_if_set_ipv4(int i, unsigned int a, unsigned int n) { (void)i; (void)a; (void)n; return -38; }
static inline int  lkl_set_ipv4_gateway(unsigned int a) { (void)a; return -38; }
#endif

/* ──────────────────────────────────────────────────────────────────
 * State.
 * ────────────────────────────────────────────────────────────────── */

#define NET_RAW_CMD_TX      1
#define NET_RAW_CMD_RX_POLL 2
#define NET_RAW_CMD_MAC     3
#define NET_RAW_CMD_RX_WAIT 4

#define FRAME_MAX 1514

static uint64_t raw_ep = 0;
static uint64_t self_as_cap = 0;
static uint8_t  raw_mac[6] = {0};

/* Staging buffers (4K-aligned, DMA-compatible). Separate TX/RX so
 * concurrent calls don't clash. */
static uint8_t __attribute__((aligned(4096))) tx_staging[4096];
static uint8_t __attribute__((aligned(4096))) rx_staging[4096];

static volatile int hup_requested = 0;
static uint64_t hup_notify_cap = 0;
static volatile int initialized = 0;

/* Default IP config matching QEMU user-mode networking defaults. */
static const uint32_t SOTOS_LKL_IPV4_ADDR    = 0x0A00020F;  /* 10.0.2.15 */
static const uint32_t SOTOS_LKL_IPV4_NETMASK = 24;
static const uint32_t SOTOS_LKL_IPV4_GATEWAY = 0x0A000202;  /* 10.0.2.2 */

/* ──────────────────────────────────────────────────────────────────
 * IPC helpers.
 * ────────────────────────────────────────────────────────────────── */

static int64_t fetch_mac_from_service(uint8_t out[6])
{
    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = NET_RAW_CMD_MAC;
    int64_t r = sys_call(raw_ep, &msg);
    if (r != 0) return r;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)msg.regs[i];
    return 0;
}

/* ──────────────────────────────────────────────────────────────────
 * lkl_dev_net_ops implementations.
 * ────────────────────────────────────────────────────────────────── */

static int sotos_net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void)nd;
    if (raw_ep == 0) return 0;

    /* Flatten iovec into tx_staging. */
    size_t total = 0;
    for (int i = 0; i < cnt; i++) {
        if (total + iov[i].iov_len > FRAME_MAX) {
            /* Frame too large for our staging buffer — drop. */
            return 0;
        }
        memcpy(tx_staging + total, iov[i].iov_base, iov[i].iov_len);
        total += iov[i].iov_len;
    }

    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = NET_RAW_CMD_TX;
    msg.regs[0] = (uint64_t)tx_staging;
    msg.regs[1] = (uint64_t)total;
    msg.regs[2] = self_as_cap;
    int64_t r = sys_call(raw_ep, &msg);
    if (r != 0) return 0;

    int64_t sent = (int64_t)msg.regs[0];
    if (sent < 0) return 0;
    return (int)sent;
}

static int sotos_net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void)nd;
    if (raw_ep == 0) return 0;

    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = NET_RAW_CMD_RX_POLL;
    msg.regs[0] = (uint64_t)rx_staging;
    msg.regs[1] = FRAME_MAX;
    msg.regs[2] = self_as_cap;
    int64_t r = sys_call(raw_ep, &msg);
    if (r != 0) return 0;

    int64_t got = (int64_t)msg.regs[0];
    if (got <= 0) return 0;

    /* Scatter into caller iovec. */
    size_t remaining = (size_t)got;
    size_t src_off = 0;
    for (int i = 0; i < cnt && remaining > 0; i++) {
        size_t take = iov[i].iov_len;
        if (take > remaining) take = remaining;
        memcpy(iov[i].iov_base, rx_staging + src_off, take);
        src_off += take;
        remaining -= take;
    }
    return (int)got;
}

static int sotos_net_poll(struct lkl_netdev *nd)
{
    (void)nd;
    if (raw_ep == 0 || hup_requested) {
        return /* LKL_DEV_NET_POLL_HUP */ 4;
    }

    /* Issue a blocking RX_WAIT. The service spins on poll_rx with
     * yield, so this thread sleeps inside sys_call until a frame
     * arrives or someone wakes it with poll_hup. */
    struct ipc_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.tag = NET_RAW_CMD_RX_WAIT;
    msg.regs[0] = (uint64_t)rx_staging;
    msg.regs[1] = FRAME_MAX;
    msg.regs[2] = self_as_cap;
    int64_t r = sys_call(raw_ep, &msg);
    (void)r;

    if (hup_requested) return /* LKL_DEV_NET_POLL_HUP */ 4;
    return /* LKL_DEV_NET_POLL_RX */ 1;
}

static void sotos_net_poll_hup(struct lkl_netdev *nd)
{
    (void)nd;
    hup_requested = 1;
    if (hup_notify_cap != 0) {
        sys_notify_signal(hup_notify_cap);
    }
}

static void sotos_net_free(struct lkl_netdev *nd)
{
    (void)nd;
    /* Static struct — nothing to free. */
}

/* ──────────────────────────────────────────────────────────────────
 * Public interface.
 * ────────────────────────────────────────────────────────────────── */

static struct lkl_dev_net_ops sotos_net_ops = {
    .tx       = sotos_net_tx,
    .rx       = sotos_net_rx,
    .poll     = sotos_net_poll,
    .poll_hup = sotos_net_poll_hup,
    .free     = sotos_net_free,
};

static struct lkl_netdev sotos_netdev;

int net_backend_init(void)
{
    if (initialized) return 0;

    serial_puts("[lkl-net-raw] looking up 'net-raw' service...\n");

    static const char name[] = "net-raw";
    int64_t cap = sys_svc_lookup(name, 7);
    if (cap <= 0) {
        serial_puts("[lkl-net-raw] 'net-raw' not found (external net disabled)\n");
        /* Proceed anyway so the interface registers and loopback still
         * works. tx/rx short-circuit when raw_ep == 0. */
        initialized = 1;
        return 0;
    }
    raw_ep = (uint64_t)cap;
    serial_puts("[lkl-net-raw] net-raw ep=");
    serial_put_dec(raw_ep);
    serial_puts("\n");

    /* Read self AS cap from BootInfo page at 0xB00000 offset 312.
     * Same layout used by disk_backend.c. */
    self_as_cap = *(volatile uint64_t *)(0xB00000ULL + 312);
    serial_puts("[lkl-net-raw] self_as=");
    serial_put_dec(self_as_cap);
    serial_puts("\n");

    /* Fetch the real MAC from the service (QEMU assigns it per-NIC). */
    if (fetch_mac_from_service(raw_mac) != 0) {
        /* Fall back to a fixed MAC if the service doesn't respond. */
        static const uint8_t fallback[6] = {0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF};
        for (int i = 0; i < 6; i++) raw_mac[i] = fallback[i];
    }
    serial_puts("[lkl-net-raw] mac=");
    for (int i = 0; i < 6; i++) {
        static const char hex[] = "0123456789abcdef";
        if (i > 0) serial_puts(":");
        char buf[3] = { hex[(raw_mac[i] >> 4) & 0xF], hex[raw_mac[i] & 0xF], 0 };
        serial_puts(buf);
    }
    serial_puts("\n");

    /* Reserve notification cap for HUP wake. */
    int64_t nc = sys_notify_create();
    if (nc > 0) hup_notify_cap = (uint64_t)nc;

    memset(&sotos_netdev, 0, sizeof(sotos_netdev));
    sotos_netdev.ops = &sotos_net_ops;
    for (int i = 0; i < 6; i++) sotos_netdev.mac[i] = raw_mac[i];

    initialized = 1;
    return 0;
}

int net_backend_register(void)
{
#ifndef HAS_LKL
    serial_puts("[lkl-net-raw] HAS_LKL not set, skipping netdev add\n");
    return -38;
#else
    if (!initialized) return -22;

    struct lkl_netdev_args args;
    memset(&args, 0, sizeof(args));
    args.mac = (void *)raw_mac;
    args.offload = 0;

    int nd_id = lkl_netdev_add(&sotos_netdev, &args);
    if (nd_id < 0) {
        serial_puts("[lkl-net-raw] lkl_netdev_add failed: ");
        serial_put_dec((uint64_t)(-(long)nd_id));
        serial_puts("\n");
        return nd_id;
    }
    serial_puts("[lkl-net-raw] netdev registered, id=");
    serial_put_dec((uint64_t)nd_id);
    serial_puts("\n");
    return nd_id;
#endif
}

int net_backend_up(int nd_id)
{
#ifndef HAS_LKL
    (void)nd_id;
    return -38;
#else
    if (nd_id < 0) return -22;

    int ifidx = lkl_netdev_get_ifindex(nd_id);
    if (ifidx < 0) {
        serial_puts("[lkl-net-raw] get_ifindex failed: ");
        serial_put_dec((uint64_t)(-(long)ifidx));
        serial_puts("\n");
        return ifidx;
    }
    serial_puts("[lkl-net-raw] ifindex=");
    serial_put_dec((uint64_t)ifidx);
    serial_puts("\n");

    int rc = lkl_if_up(ifidx);
    if (rc < 0) {
        serial_puts("[lkl-net-raw] if_up failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts("\n");
        return rc;
    }

    rc = lkl_if_set_ipv4(ifidx,
                         __builtin_bswap32(SOTOS_LKL_IPV4_ADDR),
                         SOTOS_LKL_IPV4_NETMASK);
    if (rc < 0) {
        serial_puts("[lkl-net-raw] set_ipv4 failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts("\n");
    } else {
        serial_puts("[lkl-net-raw] ipv4=10.0.2.15/24\n");
    }

    rc = lkl_set_ipv4_gateway(__builtin_bswap32(SOTOS_LKL_IPV4_GATEWAY));
    if (rc < 0) {
        serial_puts("[lkl-net-raw] set_gateway failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts(" (non-fatal)\n");
    } else {
        serial_puts("[lkl-net-raw] gw=10.0.2.2\n");
    }

    if (raw_ep != 0) {
        serial_puts("[lkl-net-raw] up — external connectivity via net-raw service\n");
    } else {
        serial_puts("[lkl-net-raw] up — net-raw service missing; only LKL lo works\n");
    }
    return 0;
#endif
}

void net_backend_poll_hup_all(void)
{
    sotos_net_poll_hup(&sotos_netdev);
}
