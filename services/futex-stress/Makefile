# Makefile for futex-stress — invoke under WSL (Linux toolchain).
#
#   wsl -- make -C services/futex-stress
#
# Produces a static, x86_64 ELF ready to drop into sotOS initrd.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -pthread
LDFLAGS ?= -static -pthread

TARGET  := futex-stress
SRC     := futex-stress.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
