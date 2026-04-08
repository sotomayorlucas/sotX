# Makefile -- Build rumpuser_sot.o (SOT rump hypervisor adaptation layer)
#
# This compiles rumpuser_sot.c for the x86_64-unknown-none target using
# GCC or Clang in freestanding mode.  The resulting .o is linked with
# the rump kernel components and the sotOS server binary.
#
# Usage:
#   make                  -- build rumpuser_sot.o
#   make CC=clang         -- use Clang instead of GCC
#   make clean            -- remove build artifacts
#   make check            -- syntax-check only (no linking)

# Toolchain (override with make CC=clang)
CC      ?= x86_64-elf-gcc
OBJDUMP ?= x86_64-elf-objdump

# Freestanding flags: no libc, no standard startup, no stack protector,
# no red zone (kernel/server code), no PIC (static linking in sotOS).
CFLAGS  = -std=c11 \
          -ffreestanding \
          -fno-stack-protector \
          -fno-builtin \
          -fno-pic \
          -mno-red-zone \
          -mno-sse \
          -Wall -Wextra -Wpedantic -Wno-unused-parameter \
          -O2 \
          -g \
          -DLIBRUMPUSER \
          -I. \
          -Isys/rump/include

# Target architecture
CFLAGS += -march=x86_64 -mcmodel=large

# Sources
SRCS    = rumpuser_sot.c
OBJS    = $(SRCS:.c=.o)

# Default target
all: $(OBJS)
	@echo "[rumpuser] Built rumpuser_sot.o for SOT"

rumpuser_sot.o: rumpuser_sot.c rumpuser_sot.h
	$(CC) $(CFLAGS) -c $< -o $@

# Syntax check (compile to assembly, don't assemble)
check: rumpuser_sot.c rumpuser_sot.h
	$(CC) $(CFLAGS) -fsyntax-only $<
	@echo "[rumpuser] Syntax OK"

# Disassemble for inspection
disasm: rumpuser_sot.o
	$(OBJDUMP) -d -S $< > rumpuser_sot.dis
	@echo "[rumpuser] Disassembly in rumpuser_sot.dis"

clean:
	rm -f $(OBJS) rumpuser_sot.dis

.PHONY: all check disasm clean
