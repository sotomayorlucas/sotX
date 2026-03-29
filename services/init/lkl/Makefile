# Makefile for liblkl_fused.a — LKL + bridge code as static library for init
#
# Build: wsl -d Ubuntu -- make  (from services/init/lkl/)
# Output: liblkl_fused.a (linked into init via build.rs)

CC := x86_64-linux-gnu-gcc
AR := x86_64-linux-gnu-ar

CFLAGS := -ffreestanding -nostdlib -nostartfiles -fno-stack-protector \
          -fno-builtin -mno-red-zone -O2 -g \
          -Wall -Wextra -Wno-unused-parameter

LKL_DIR := ../../../lkl/output
LKL_OBJ := $(LKL_DIR)/lkl.o

ifneq ($(wildcard $(LKL_OBJ)),)
  CFLAGS += -DHAS_LKL -I$(LKL_DIR)/include
  HAS_LKL := 1
  $(info LKL found at $(LKL_OBJ))
else
  HAS_LKL := 0
  $(info LKL not found — building in stub mode)
endif

SRCS := lkl_bridge.c host_ops.c allocator.c guest_mem.c libc_stubs.c
OBJS := $(SRCS:.c=.o)

TARGET := liblkl_fused.a

.PHONY: all clean

all: $(TARGET)

ifeq ($(HAS_LKL),1)
$(TARGET): $(OBJS)
	$(AR) rcs $@ $(OBJS) $(LKL_OBJ)
else
$(TARGET): $(OBJS)
	$(AR) rcs $@ $(OBJS)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
