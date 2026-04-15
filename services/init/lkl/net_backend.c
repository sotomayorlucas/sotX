/*
 * net_backend.c -- LKL network device bridge (loopback-only scaffold).
 *
 * See net_backend.h for rationale. This backend registers a struct
 * lkl_netdev with LKL so its external TCP/IP stack initializes. Tx
 * frames are accepted and silently discarded; rx always blocks until
 * poll_hup is raised. 127.0.0.1 traffic bypasses this backend because
 * LKL maintains a separate built-in loopback device internally.
 *
 * Upgrade path (Camino B in docs/phase-5-design.md): replace the tx()
 * stub with a real virtio-net driver that pushes frames onto a second
 * NIC the QEMU command line exposes, and replace rx()/poll() with
 * IRQ-driven reads from the same NIC's RX queue.
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
/* Stub-mode fallback: declare the symbols we reference so the file still
 * compiles when LKL headers are absent. The code guarded by HAS_LKL is
 * the only path that actually calls these. */
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
 * Constants: one RX notification cap, static MAC address.
 * ────────────────────────────────────────────────────────────────── */

/* 52:54:00:xx:xx:xx is the QEMU/KVM locally-administered prefix. Pick
 * a suffix unlikely to collide with sotos-net (which uses the default
 * QEMU MAC when left unset).  */
static const uint8_t SOTOS_LKL_MAC[6] = {
    0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF,
};

/* Static IPv4 config. Matches QEMU's user-mode networking defaults so
 * DHCP is not required. Upgrade to actual DHCP (lkl_dhcp) once Camino B
 * delivers a real carrier. */
static const uint32_t SOTOS_LKL_IPV4_ADDR     = 0x0A00020F;  /* 10.0.2.15 */
static const uint32_t SOTOS_LKL_IPV4_NETMASK  = 24;
static const uint32_t SOTOS_LKL_IPV4_GATEWAY  = 0x0A000202;  /* 10.0.2.2 */

/* ──────────────────────────────────────────────────────────────────
 * State: rx notification + hup flag. Tx is completely stateless (drop).
 * ────────────────────────────────────────────────────────────────── */

static uint64_t rx_notify_cap = 0;
static volatile int hup_requested = 0;
static volatile int initialized = 0;

/* ──────────────────────────────────────────────────────────────────
 * lkl_dev_net_ops implementations.
 * ────────────────────────────────────────────────────────────────── */

static int sotos_net_tx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void)nd;
    /* Sum iovec lengths and return the total. LKL expects the byte
     * count of what was transmitted; returning 0 or a short count
     * signals an error to the stack. For the loopback scaffold we
     * pretend every frame was sent successfully. */
    int total = 0;
    for (int i = 0; i < cnt; i++) {
        total += (int)iov[i].iov_len;
    }
    return total;
}

static int sotos_net_rx(struct lkl_netdev *nd, struct iovec *iov, int cnt)
{
    (void)nd; (void)iov; (void)cnt;
    /* No external frames ever arrive. Returning -LKL_EAGAIN would be
     * more precise but the stack also accepts 0 as "no data". Pick 0
     * so the caller's poll wait is the only blocking mechanism. */
    return 0;
}

static int sotos_net_poll(struct lkl_netdev *nd)
{
    (void)nd;
    /* Block until poll_hup wakes us. We never have RX data, so any
     * wake is a HUP — the right return is LKL_DEV_NET_POLL_HUP. */
    if (rx_notify_cap == 0) {
        /* No notification cap — spin with yield so we don't burn CPU. */
        while (!hup_requested) {
            sys_yield();
        }
    } else {
        while (!hup_requested) {
            sys_notify_wait(rx_notify_cap);
        }
    }
    return /* LKL_DEV_NET_POLL_HUP */ 4;
}

static void sotos_net_poll_hup(struct lkl_netdev *nd)
{
    (void)nd;
    hup_requested = 1;
    if (rx_notify_cap != 0) {
        sys_notify_signal(rx_notify_cap);
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

    serial_puts("[lkl-net-loopback] init (scaffold only — no external carrier)\n");

    /* Reserve a notification cap for RX wake (only used by poll_hup
     * today — upgrade path: real RX signal when Camino B lands). */
    int64_t nc = sys_notify_create();
    if (nc > 0) {
        rx_notify_cap = (uint64_t)nc;
        serial_puts("[lkl-net-loopback] rx_notify=");
        serial_put_dec(rx_notify_cap);
        serial_puts("\n");
    } else {
        serial_puts("[lkl-net-loopback] notify_create failed (using yield-spin fallback)\n");
    }

    memset(&sotos_netdev, 0, sizeof(sotos_netdev));
    sotos_netdev.ops = &sotos_net_ops;
    for (int i = 0; i < 6; i++) sotos_netdev.mac[i] = SOTOS_LKL_MAC[i];

    initialized = 1;
    return 0;
}

int net_backend_register(void)
{
#ifndef HAS_LKL
    serial_puts("[lkl-net-loopback] HAS_LKL not set, skipping netdev add\n");
    return -38;
#else
    if (!initialized) return -22; /* EINVAL */

    struct lkl_netdev_args args;
    memset(&args, 0, sizeof(args));
    args.mac = (void *)SOTOS_LKL_MAC;
    args.offload = 0;

    int nd_id = lkl_netdev_add(&sotos_netdev, &args);
    if (nd_id < 0) {
        serial_puts("[lkl-net-loopback] lkl_netdev_add failed: ");
        serial_put_dec((uint64_t)(-(long)nd_id));
        serial_puts("\n");
        return nd_id;
    }
    serial_puts("[lkl-net-loopback] netdev registered, id=");
    serial_put_dec((uint64_t)nd_id);
    serial_puts(" mac=52:54:00:ab:cd:ef\n");
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
        serial_puts("[lkl-net-loopback] get_ifindex failed: ");
        serial_put_dec((uint64_t)(-(long)ifidx));
        serial_puts("\n");
        return ifidx;
    }
    serial_puts("[lkl-net-loopback] ifindex=");
    serial_put_dec((uint64_t)ifidx);
    serial_puts("\n");

    int rc = lkl_if_up(ifidx);
    if (rc < 0) {
        serial_puts("[lkl-net-loopback] if_up failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts("\n");
        return rc;
    }

    rc = lkl_if_set_ipv4(ifidx,
                         __builtin_bswap32(SOTOS_LKL_IPV4_ADDR),
                         SOTOS_LKL_IPV4_NETMASK);
    if (rc < 0) {
        serial_puts("[lkl-net-loopback] set_ipv4 failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts("\n");
        /* Not fatal — loopback still works without an external IP. */
    } else {
        serial_puts("[lkl-net-loopback] ipv4=10.0.2.15/24\n");
    }

    rc = lkl_set_ipv4_gateway(__builtin_bswap32(SOTOS_LKL_IPV4_GATEWAY));
    if (rc < 0) {
        serial_puts("[lkl-net-loopback] set_gateway failed: ");
        serial_put_dec((uint64_t)(-(long)rc));
        serial_puts(" (non-fatal)\n");
    } else {
        serial_puts("[lkl-net-loopback] gw=10.0.2.2\n");
    }

    serial_puts("[lkl-net-loopback] up — external traffic dropped, loopback via LKL internal lo\n");
    return 0;
#endif
}

void net_backend_poll_hup_all(void)
{
    sotos_net_poll_hup(&sotos_netdev);
}
