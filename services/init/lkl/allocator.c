/*
 * allocator.c -- Arena bump allocator with free-list reuse.
 *
 * Maps 128 MiB of physical frames at ARENA_BASE using sotOS frame_alloc+map.
 * arena_alloc bumps a pointer; arena_free adds to a size-bucketed free-list.
 */

#include "allocator.h"
#include "sotos_syscall.h"

/* Map flags: WRITABLE (bit 1) | NO_EXECUTE (bit 63) */
#define MAP_RW_NX  (2ULL | (1ULL << 63))

/* Free-list node stored at the start of freed blocks. */
struct free_node {
    struct free_node *next;
    unsigned long     size;
};

static uint64_t       arena_bump;       /* next allocation address */
static uint64_t       arena_end;        /* one past last usable byte */
static struct free_node *free_head;     /* singly-linked free list */
static int            arena_ready;

int arena_init(void)
{
    uint64_t pages = ARENA_SIZE / PAGE_SIZE;
    uint64_t addr  = ARENA_BASE;

    for (uint64_t i = 0; i < pages; i++) {
        int64_t frame = sys_frame_alloc();
        if (frame < 0)
            return (int)frame;
        int64_t r = sys_map(addr, (uint64_t)frame, MAP_RW_NX);
        if (r < 0)
            return (int)r;
        addr += PAGE_SIZE;
    }

    arena_bump  = ARENA_BASE;
    arena_end   = ARENA_BASE + ARENA_SIZE;
    free_head   = (void *)0;
    arena_ready = 1;
    return 0;
}

void *arena_alloc(unsigned long size)
{
    if (!arena_ready || size == 0)
        return (void *)0;

    /* Round up to 8-byte alignment. */
    size = (size + 7UL) & ~7UL;

    /* First-fit search in free list. */
    struct free_node **pp = &free_head;
    while (*pp) {
        if ((*pp)->size >= size) {
            void *ptr = (void *)*pp;
            *pp = (*pp)->next;
            return ptr;
        }
        pp = &(*pp)->next;
    }

    /* Bump allocator fallback. */
    if (arena_bump + size > arena_end)
        return (void *)0;  /* OOM */

    void *ptr = (void *)arena_bump;
    arena_bump += size;
    return ptr;
}

void arena_free(void *ptr)
{
    if (!ptr)
        return;
    /* We don't know the original allocation size, so we store a minimum
     * node.  For LKL's mem_free this is acceptable since LKL pairs
     * alloc/free with known sizes via its slab. */
    struct free_node *node = (struct free_node *)ptr;
    node->size = sizeof(struct free_node);  /* minimum */
    node->next = free_head;
    free_head  = node;
}

unsigned long arena_used(void)
{
    return (unsigned long)(arena_bump - ARENA_BASE);
}
