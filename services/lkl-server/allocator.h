/*
 * allocator.h -- Arena bump allocator with free-list reuse.
 *
 * Pre-allocates 128 MiB at ARENA_BASE (0x7A000000) using frame_alloc + map.
 * arena_alloc() bumps a pointer (8-byte aligned).
 * arena_free()  adds to a simple free-list for best-effort reuse.
 */

#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdint.h>
#include <stddef.h>

#define ARENA_BASE   0x30000000ULL
#define ARENA_SIZE   (128ULL * 1024 * 1024)  /* 128 MiB */
#define PAGE_SIZE    4096ULL

/* Initialise the arena: allocate physical frames and map them.
 * Returns 0 on success, negative on error. */
int arena_init(void);

/* Allocate `size` bytes (8-byte aligned). Returns NULL on OOM. */
void *arena_alloc(unsigned long size);

/* Return memory to the free-list (best-effort). */
void arena_free(void *ptr);

/* Query bytes currently allocated (bump pointer offset). */
unsigned long arena_used(void);

#endif /* ALLOCATOR_H */
