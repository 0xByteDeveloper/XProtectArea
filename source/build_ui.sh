#!/bin/bash
# ============================================================
# build_ui.sh — XProtectUI'yi bastan sona derler (x64 + x86)
# Gereksinim: pip install ziglang  (python3 -m ziglang)
# Kullanim:  bash build_ui.sh
# Cikti:     XProtectUI.exe (x64) + XProtectUI32.exe (x86)
# 0.6.0: engine_pack.cpp + lzma/ (LZMA SDK, _7ZIP_ST tek-iplik;
#        C dosyalari ayri derlenir — zig -std=c++17 karisimi yasak)
# ============================================================
set -e
cd "$(dirname "$0")"
ZIG="python3 -m ziglang"
SRCS="xprotect_ui.cpp engine_main.cpp engine_pe.cpp engine_disasm.cpp engine_mut.cpp \
    engine_lift.cpp engine_stub.cpp engine_util.cpp engine_sym.cpp vm_blob.cpp xrt_blob.cpp \
    engine_pack.cpp"
LZMA="lzma/LzmaEnc.c lzma/LzFind.c"

echo "== [0/2] LZMA C nesneleri =="
$ZIG cc -O2 -c -D_7ZIP_ST -Ilzma -I. lzma/LzmaEnc.c -o lzma_enc_x64.o -target x86_64-windows-gnu
$ZIG cc -O2 -c -D_7ZIP_ST -Ilzma -I. lzma/LzFind.c  -o lzma_find_x64.o -target x86_64-windows-gnu
$ZIG cc -O2 -c -D_7ZIP_ST -Ilzma -I. lzma/LzmaEnc.c -o lzma_enc_x86.o -target x86-windows-gnu
$ZIG cc -O2 -c -D_7ZIP_ST -Ilzma -I. lzma/LzFind.c  -o lzma_find_x86.o -target x86-windows-gnu

echo "== [1/2] XProtectUI.exe (x64) =="
$ZIG c++ -O2 -std=c++17 -target x86_64-windows-gnu -DUNICODE -D_UNICODE -I. \
    $SRCS lzma_enc_x64.o lzma_find_x64.o \
    -DXPROTECT_BC_DUMP -o XProtectUI.exe \
    -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -luser32 -fno-sanitize=undefined

echo "== [2/2] XProtectUI32.exe (x86) =="
$ZIG c++ -O2 -std=c++17 -target x86-windows-gnu -DUNICODE -D_UNICODE -I. \
    $SRCS lzma_enc_x86.o lzma_find_x86.o \
    -o XProtectUI32.exe \
    -lcomctl32 -lcomdlg32 -lshell32 -lgdi32 -luser32 -fno-sanitize=undefined

echo "== TAMAM =="
ls -la XProtectUI.exe XProtectUI32.exe
