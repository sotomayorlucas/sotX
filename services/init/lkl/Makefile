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

# Use the full LKL static library (built by lkl/build-lkl.sh) rather than
# the partial-link lkl.o. lkl.o only contains the kernel core (~11 globals:
# lkl_init, lkl_start_kernel, lkl_syscall, etc.); the disk/fs helpers the
# bridge actually calls — lkl_disk_add, lkl_mount_dev, lkl_dev_blk_ops,
# etc. — live in tools/lkl/ and are only present in liblkl.a. Linking
# lkl.o therefore leaves those symbols unresolved at init link time.
LKL_ARCHIVE := $(LKL_DIR)/liblkl.a

ifneq ($(wildcard $(LKL_ARCHIVE)),)
  CFLAGS += -DHAS_LKL -I$(LKL_DIR)/include
  HAS_LKL := 1
  $(info LKL archive found at $(LKL_ARCHIVE))
else
  HAS_LKL := 0
  $(info LKL not found — building in stub mode)
endif

SRCS := lkl_bridge.c host_ops.c allocator.c guest_mem.c libc_stubs.c disk_backend.c net_backend.c
OBJS := $(SRCS:.c=.o)

TARGET := liblkl_fused.a

.PHONY: all clean

all: $(TARGET)

ifeq ($(HAS_LKL),1)
# Build a single "fused" archive containing both our bridge .o files and
# every member of liblkl.a, so build.rs can link a single -l static=lkl_fused.
# Uses an MRI script: `create` opens a new archive, `addmod` stages our
# bridge objects, `addlib` pulls in every member of liblkl.a by reference,
# and `save` writes it out. GNU ar (and llvm-ar) both understand this.
$(TARGET): $(OBJS) $(LKL_ARCHIVE)
	@rm -f $@ .mri_script.txt
	@echo "create $@" > .mri_script.txt
	@for o in $(OBJS); do echo "addmod $$o" >> .mri_script.txt; done
	@echo "addlib $(LKL_ARCHIVE)" >> .mri_script.txt
	@echo "save" >> .mri_script.txt
	@echo "end" >> .mri_script.txt
	$(AR) -M < .mri_script.txt
	@rm -f .mri_script.txt
else
$(TARGET): $(OBJS)
	$(AR) rcs $@ $(OBJS)
endif

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
