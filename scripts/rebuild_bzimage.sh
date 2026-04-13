#!/bin/bash
set -ex
cd /tmp/sotos-linux
chmod 666 .config
for cfg in BLK_DEV_INITRD BINFMT_ELF BINFMT_SCRIPT DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS; do
    grep -q "CONFIG_${cfg}=y" .config || echo "CONFIG_${cfg}=y" >> .config
done
make ARCH=x86_64 olddefconfig
make ARCH=x86_64 bzImage -j$(nproc)
cp arch/x86/boot/bzImage /mnt/c/Users/sotom/sotX/target/bzImage
echo "=== bzImage DONE ==="
ls -la /mnt/c/Users/sotom/sotX/target/bzImage
