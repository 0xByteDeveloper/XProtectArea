#!/bin/bash
# build_xrt_trace.sh — XVF_TRACE'li xrt blob uretimi (VF bisect icin)
# URETIM blob'unu YEDEKLER; test sonrasi restore_restore.sh ile geri konur.
set -e
cd "$(dirname "$0")"
# yedek (varsa)
[ -f xrt_blob.cpp.prod ] || cp xrt_blob.cpp xrt_blob.cpp.prod
[ -f xrt86.bin.prod ] || cp xrt86.bin xrt86.bin.prod 2>/dev/null || true
[ -f xrt64.bin.prod ] || cp xrt64.bin xrt64.bin.prod 2>/dev/null || true

CFL="-O2 -fno-tree-vectorize -ffreestanding -fno-stack-protector -fno-jump-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-pie -Wall -DXVF_TRACE"

echo "== [1/4] x86 trace =="
gcc -m32 $CFL -DXRT_IS_X86 -c xrt_core.c -o xrt86.o
ld -m elf_i386 -Ttext=0x100000 -e xrt_entry xrt86.o -o xrt86.elf
objcopy -O binary xrt86.elf xrt86.bin

echo "== [2/4] x64 trace =="
gcc $CFL -DXRT_IS_X64 -c xrt_core.c -o xrt64.o
ld -Ttext=0x100000 -e xrt_entry xrt64.o -o xrt64.elf
objcopy -O binary xrt64.elf xrt64.bin

echo "== [3/4] blob (TRACE) =="
python3 gen_xrt_blob.py
echo "TRACE blob aktif (uretim: bash restore_xrt_prod.sh)"
