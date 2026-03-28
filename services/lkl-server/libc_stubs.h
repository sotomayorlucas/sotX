/*
 * libc_stubs.h -- Freestanding libc stubs (memcpy, memset, memcmp, strlen).
 *
 * Declared here so other translation units can call them; defined in
 * libc_stubs.c.  These are the minimum set required by LKL and GCC
 * codegen (the compiler may emit implicit calls to these).
 */

#ifndef LIBC_STUBS_H
#define LIBC_STUBS_H

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char  *strncpy(char *dst, const char *src, size_t n);
int    strncmp(const char *a, const char *b, size_t n);

#endif /* LIBC_STUBS_H */
