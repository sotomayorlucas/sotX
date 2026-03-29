# Makefile for lkl-server -- freestanding sotOS service in C
#
# Cross-compile with x86_64-linux-gnu-gcc or x86_64-elf-gcc.
# Links against liblkl.a if available in ../../lkl/output/.

# Try to find a cross-compiler.  Prefer x86_64-elf-gcc (bare metal),
# fall back to x86_64-linux-gnu-gcc (Linux cross, works with -ffreestanding).
CC_ELF   := $(shell command -v x86_64-elf-gcc 2>/dev/null)
CC_LINUX := $(shell command -v x86_64-linux-gnu-gcc 2>/dev/null)

ifdef CC_ELF
  CC := x86_64-elf-gcc
  LD := x86_64-elf-ld
else ifdef CC_LINUX
  CC := x86_64-linux-gnu-gcc
  LD := x86_64-linux-gnu-ld
else
  CC := gcc
  LD := ld
endif

CFLAGS := -ffreestanding -nostdlib -nostartfiles -fno-stack-protector \
          -fno-builtin -mno-red-zone -mcmodel=large \
          -Wall -Wextra -Werror=implicit-function-declaration \
          -O2 -g

LDFLAGS := -T linker.ld -nostdlib -static

# Check for LKL library
LKL_DIR  := ../../lkl/output
LKL_LIB  := $(LKL_DIR)/liblkl.a

ifneq ($(wildcard $(LKL_LIB)),)
  CFLAGS  += -DHAS_LKL -I$(LKL_DIR)/include
  LDLIBS  += $(LKL_LIB)
  $(info LKL library found at $(LKL_LIB))
else
  $(info LKL library not found -- building in stub mode)
endif

# Source files
SRCS := main.c host_ops.c allocator.c guest_mem.c disk_backend.c libc_stubs.c
OBJS := $(SRCS:.c=.o)
TARGET := lkl-server

.PHONY: all clean check-syntax

all: $(TARGET)

$(TARGET): $(OBJS) linker.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependency tracking (header changes trigger rebuild)
main.o:         main.c sotos_syscall.h allocator.h host_ops.h guest_mem.h \
                disk_backend.h lkl_stub.h libc_stubs.h
host_ops.o:     host_ops.c host_ops.h lkl_stub.h allocator.h sotos_syscall.h \
                libc_stubs.h
allocator.o:    allocator.c allocator.h sotos_syscall.h
guest_mem.o:    guest_mem.c guest_mem.h sotos_syscall.h libc_stubs.h
disk_backend.o: disk_backend.c disk_backend.h sotos_syscall.h
libc_stubs.o:   libc_stubs.c libc_stubs.h

# Syntax check only (no linking, useful when cross-compiler is absent)
check-syntax: $(SRCS)
	$(CC) $(CFLAGS) -fsyntax-only $^

clean:
	rm -f $(OBJS) $(TARGET)
