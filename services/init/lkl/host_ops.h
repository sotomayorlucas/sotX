/*
 * host_ops.h -- LKL host operations backed by sotX primitives.
 */

#ifndef HOST_OPS_H
#define HOST_OPS_H

#ifdef HAS_LKL
#include <lkl/asm/host_ops.h>
#else
#include "lkl_stub.h"
#endif

/* Fill in the lkl_host_operations struct with sotX-backed implementations.
 * Must be called after arena_init(). */
void host_ops_init(struct lkl_host_operations *ops);

/* Process pending timer callbacks.  Call from the main IPC loop. */
void host_ops_tick(void);

#endif /* HOST_OPS_H */
