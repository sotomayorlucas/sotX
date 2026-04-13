#!/bin/bash
set -ex
rm -rf /tmp/gird
mkdir -p /tmp/gird/bin /tmp/gird/dev
cp "$(which busybox)" /tmp/gird/bin/busybox
chmod +x /tmp/gird/bin/busybox
cat > /tmp/gird/init << 'EOF'
#!/bin/busybox sh
/bin/busybox echo "=== sotX guest /init alive ==="
/bin/busybox echo "PID 1 running busybox"
exec /bin/busybox sh
EOF
chmod +x /tmp/gird/init
mknod /tmp/gird/dev/console c 5 1
mknod /tmp/gird/dev/ttyS0 c 4 64
mknod /tmp/gird/dev/null c 1 3
cd /tmp/gird
find . | cpio -o -H newc | gzip > /mnt/c/Users/sotom/sotX/target/guest-initramfs.cpio.gz
echo "=== initramfs DONE ==="
ls -la /mnt/c/Users/sotom/sotX/target/guest-initramfs.cpio.gz
