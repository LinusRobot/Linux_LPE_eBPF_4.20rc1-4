#! /bin/sh
#-device hitb,id=vda
#./qemu-system-x86_64 \
#-device virtio
/home/extra_space/ctf/qemu-4.1.0/x86_64-softmmu/qemu-system-x86_64 \
-kernel ./bzImage \
-initrd ./rootfs.cpio \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1 nokaslr kpti=1' \
-cpu kvm64,+smep \
-monitor /dev/null \
-m 640M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
-gdb tcp::1234 \
#-enable-kvm \
