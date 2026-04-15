/*
 * net_backend.h -- LKL network device bridge (loopback-only scaffold).
 *
 * Phase 5b activation scaffold. Camino A from docs/phase-5-design.md:
 * registers an external netdev with LKL so its TCP/IP stack initializes
 * fully, but drops all tx traffic and never produces rx frames. LKL's
 * built-in `lo` device still handles 127.0.0.1 entirely within its own
 * stack, so self-directed syscalls (socket+bind+listen+connect on
 * loopback) work end-to-end.
 *
 * Purpose: validate that the dispatcher-level plumbing (fases 3-5a) is
 * correct by getting `LKL_READY` set + `[lkl-boot] netdev registered`
 * to appear in the serial log. External connectivity requires a real
 * virtio-net backend (Camino B).
 */

#ifndef NET_BACKEND_H
#define NET_BACKEND_H

#include <stdint.h>

/* Initialise the backend state (notification cap, static struct).
 * Call before `net_backend_register`. Returns 0 on success. */
int  net_backend_init(void);

/* Register the netdev with LKL via `lkl_netdev_add`. MUST be called
 * BEFORE `lkl_start_kernel` (per LKL docs). Returns the LKL netdev id
 * on success, negative on error. */
int  net_backend_register(void);

/* Bring the interface up (if_up + static IPv4 config). Call AFTER
 * `lkl_start_kernel`. Returns 0 on success, negative on error. */
int  net_backend_up(int nd_id);

/* Wake any poller (used by lkl on shutdown). */
void net_backend_poll_hup_all(void);

#endif /* NET_BACKEND_H */
