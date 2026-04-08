# FreeBSD Linuxulator Syscall Tables

Reference files extracted from the FreeBSD Linuxulator (Linux binary compatibility layer).
These are data/translation tables used as reference for sotOS's Linux ABI implementation.

## Source

Repository: https://github.com/freebsd/freebsd-src
Branch: `main`
Date fetched: 2026-03-29

### Files from `sys/amd64/linux/` (AMD64-specific)

| File | Description |
|------|-------------|
| `linux_syscall.h` | Linux syscall number defines (350 syscalls, max 453) |
| `linux_sysent.c` | Syscall entry table (function pointers + argument info) |
| `linux_sysvec.c` | Syscall vector setup, ELF brand registration |
| `linux_machdep.c` | Machine-dependent compat (arch_prctl, iopl, etc.) |
| `linux_systrace_args.c` | Syscall argument descriptions for tracing/dtrace |
| `linux.h` | Core AMD64 Linux compatibility header (types, structs) |

### Files from `sys/compat/linux/` (architecture-independent)

| File | Description |
|------|-------------|
| `linux_errno.inc` | Linux-to-BSD errno translation table |
| `linux_signal.h` | Linux signal number mapping |
| `linux_misc.c` | Misc syscall implementations (uname, sysinfo, prctl, etc.) |
| `linux_file.c` | File syscall implementations (open, stat, getdents, etc.) |

### Files from `sys/sys/`

| File | Description |
|------|-------------|
| `capsicum.h` | Capsicum capability framework header (reference for cap design) |

## License

All files in this directory are from the FreeBSD project and are licensed under the
BSD-2-Clause license:

```
SPDX-License-Identifier: BSD-2-Clause

Copyright (c) The FreeBSD Foundation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## Usage

These files are reference material only. They are not compiled as part of sotOS.
The Linuxulator's syscall tables, errno mappings, and signal translations serve as
a verified reference for implementing Linux ABI compatibility in the sotOS microkernel.
