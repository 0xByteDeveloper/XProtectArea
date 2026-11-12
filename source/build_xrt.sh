#!/bin/bash
# build_xrt.sh — xrt_core.c -> xrt86.bin/xrt64.bin -> xrt_blob.cpp
# vm_core.c ile ayni yontem: freestanding + flat binary
set -e
cd "$(dirname "$0")"

CFL="-O2 -fno-tree-vectorize -ffreestanding -fno-stack-protector -fno-jump-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-pie -Wall"

echo "== [1/4] x86 =="
gcc -m32 $CFL -DXRT_IS_X86 -c xrt_core.c -o xrt86.o
ld -m elf_i386 -Ttext=0x100000 -e xrt_entry xrt86.o -o xrt86.elf
objcopy -O binary xrt86.elf xrt86.bin

echo "== [2/4] x64 =="
gcc $CFL -DXRT_IS_X64 -c xrt_core.c -o xrt64.o
ld -Ttext=0x100000 -e xrt_entry xrt64.o -o xrt64.elf
objcopy -O binary xrt64.elf xrt64.bin

echo "== [3/4] semboller =="
nm xrt86.elf | grep -E "xrt_entry|xrt_resolve" || true
nm xrt64.elf | grep -E "xrt_entry|xrt_resolve" || true

echo "== [4/4] xrt_blob.cpp =="
python3 gen_xrt_blob.py
ls -la xrt86.bin xrt64.bin xrt_blob.cpp
