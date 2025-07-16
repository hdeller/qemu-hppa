#!/bin/bash

set -e  # Exit on any error

# Build the project
echo "Building QEMU..."
make -j$(nproc)

# If build succeeded, run QEMU
echo "Running QEMU..."
# gdb --args ./build/qemu-system-hppa \
#     -accel tcg,thread=multi \
#     -trace "i82596_*" \
#     -trace "lasi_*" \
#     -cdrom OS_test/ODE_2006_ohne_Passwort.iso \
#     -m 512 \
#     -boot d \
#     -drive if=scsi,bus=0,index=6,file=OS_test/hpux.img,format=raw \
#     -net nic,model=lasi_82596 \
#     -net user \
#     -serial mon:stdio \
#     -nographic \
#     -D hpuxtrace.log


# gdb --args ./build/qemu-system-hppa \
#     -trace "i82596_*" \
#     -trace "lasi_*" \
#     -accel tcg,thread=multi -m 512 \
#     -drive if=scsi,bus=0,index=6,file=OS_test/hpux.img,format=raw \
#     -net nic,model=lasi_82596 -net user -boot c \
#     -serial mon:stdio -nographic -D hpuxtrace.log

gdb --args ./build/qemu-system-hppa \
    -drive file=OS_test/debian-10/Linux-hppa-hdd-image.img \
    -trace "i82596_*" \
    -trace "lasi_*" \
    -kernel OS_test/debian-10/vmlinux-6.15.ok-32bit  \
    -append "root=/dev/sda5 cryptomgr.notests panic=10 apparmor=0 no_hash_pointers" \
    -serial mon:stdio -smp cpus=4 -machine B160L  \
    -nographic -net nic,model=lasi_82596 -net user \
    -D trace.log






# ./build/qemu-system-hppa \
#     -trace "i82596_*" \
#     -trace "lasi_*" \
#     -kernel OS_test/vmlinux \
#     -drive file=OS_test/debian-12-hdd-2023.img \
#     -nographic \
#     -serial mon:stdio \
#     -accel tcg,thread=multi \
#     -smp cpus=4 \
#     -append "root=/dev/sda5 rw console=ttyS0 debug ignore_loglevel" \
#     -net nic,model=lasi_82596 \
#     -net user \
#     -D trace.log