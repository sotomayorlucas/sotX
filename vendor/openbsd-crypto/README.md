# OpenBSD Security Primitives

Standalone C files fetched from [OpenBSD src](https://github.com/openbsd/src)
(master branch) for use in sotX userspace security components.

## Contents

### arc4random/ -- ChaCha20-based CSPRNG
- `arc4random.c` (4,979 B) -- core CSPRNG implementation
- `arc4random.h` (1,648 B) -- internal header
- `chacha_private.h` (5,382 B) -- ChaCha20 stream cipher (D.J. Bernstein)

### string/ -- Safe string and memory operations
- `strlcpy.c` (1,612 B) -- bounded string copy
- `strlcat.c` (1,759 B) -- bounded string concatenation
- `explicit_bzero.c` (358 B) -- secure memory clearing (compiler cannot optimize away)

### bcrypt/ -- Password hashing
- `bcrypt.c` (9,770 B) -- bcrypt password hashing (Blowfish-based)
- `blowfish.c` (23,349 B) -- Blowfish block cipher implementation

### signify/ -- Cryptographic signing
- `signify.c` (21,899 B) -- Ed25519-based file signing/verification tool

## License

All files are under the **ISC license** (the standard OpenBSD license), except
`explicit_bzero.c` which is **public domain**.

The ISC license permits use, copy, modification, and distribution for any
purpose with or without fee, provided the copyright notice and permission
notice appear in all copies.

## Source URLs

```
https://github.com/openbsd/src/blob/master/lib/libc/crypt/arc4random.c
https://github.com/openbsd/src/blob/master/lib/libc/crypt/arc4random.h
https://github.com/openbsd/src/blob/master/lib/libc/crypt/chacha_private.h
https://github.com/openbsd/src/blob/master/lib/libc/string/strlcpy.c
https://github.com/openbsd/src/blob/master/lib/libc/string/strlcat.c
https://github.com/openbsd/src/blob/master/lib/libc/string/explicit_bzero.c
https://github.com/openbsd/src/blob/master/lib/libc/crypt/bcrypt.c
https://github.com/openbsd/src/blob/master/lib/libc/crypt/blowfish.c
https://github.com/openbsd/src/blob/master/usr.bin/signify/signify.c
```

## Notes

These are the upstream OpenBSD sources and may reference OpenBSD-specific
headers (e.g., `<sys/param.h>` macros, `DEF_WEAK`). For use in sotX, a
compatibility shim or minor edits may be needed. The signify tool has
additional dependencies (libcrypto for Ed25519) not included here.

Fetched: 2026-03-29
