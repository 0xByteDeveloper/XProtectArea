#!/bin/bash
# build_vmblob.sh — vm_core.c -> vm64/vmx86 flat binary -> vm_blob.cpp
# (0.8.0 dersNotu: vm_core.c her degistiginde BU script + build_ui.sh zorunlu;
#  aksi halde motor bayat interpreter tasisini sürer — c=stale bug'i boyle yakalandi)
set -e
cd "$(dirname "$0")"
CFL="-O2 -fno-tree-vectorize -ffreestanding -fno-stack-protector -fno-jump-tables -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident -fno-pie -Wall"

echo "== [1/4] vm x64 =="
gcc $CFL -DVM_IS_X64 -DVM_WINDOWS -c vm_core.c -o vm64.o
ld -Ttext=0x100000 -e vm_entry vm64.o -o vm64.elf
objcopy -O binary vm64.elf vm64.bin

echo "== [2/4] vm x86 =="
gcc -m32 $CFL -DVM_IS_X86 -DVM_WINDOWS -c vm_core.c -o vmx86.o
ld -m elf_i386 -Ttext=0x100000 -e vm_entry vmx86.o -o vmx86.elf
objcopy -O binary vmx86.elf vmx86.bin

echo "== [3/4] gen_blob.py =="
python3 gen_blob.py

echo "== [4/4] boyutlar =="
ls -la vm64.bin vmx86.bin vm_blob.cpp
