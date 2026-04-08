/*
 * PANDORA Task 1: <assert.h> shim. assert(x) becomes a no-op in the
 * freestanding build since libdtrace assertions assume a debugging
 * environment we don't have yet.
 */
#ifndef _SHIM_ASSERT_H_
#define _SHIM_ASSERT_H_

#define assert(x) ((void)0)

#endif
