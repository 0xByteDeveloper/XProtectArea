#!/usr/bin/env python3
# gen_xrt_blob.py — xrt86.bin/xrt64.bin -> xrt_blob.cpp
# xrt_entry VE xrt_resolve ofsetleri nm ile bulunur (engine sozlesmesi).
import subprocess

def emit(path, name):
    d = open(path, 'rb').read()
    lines = []
    for i in range(0, len(d), 16):
        lines.append('  ' + ','.join(f'0x{b:02X}' for b in d[i:i+16]) + ',')
    body = '\n'.join(lines)
    return f'const unsigned char {name}[] = {{\n{body}\n}};\nconst int {name}_LEN = {len(d)};\n', len(d)

def sym_off(elf, sym):
    r = subprocess.run(['nm', elf], capture_output=True, text=True).stdout
    for line in r.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == sym:
            return int(parts[0], 16) - 0x100000
    raise RuntimeError(f'{sym} bulunamadi: {elf}')

b86, l86 = emit('xrt86.bin', 'XRT_BLOBX86')
b64, l64 = emit('xrt64.bin', 'XRT_BLOB64')
e86 = sym_off('xrt86.elf', 'xrt_entry')
r86 = sym_off('xrt86.elf', 'xrt_resolve')
u86 = sym_off('xrt86.elf', 'xrt_unpack')
s86 = sym_off('xrt86.elf', 'xrt_sdk_entry86')
e64 = sym_off('xrt64.elf', 'xrt_entry')
r64 = sym_off('xrt64.elf', 'xrt_resolve')
u64o = sym_off('xrt64.elf', 'xrt_unpack')
s64 = sym_off('xrt64.elf', 'xrt_sdk_entry')

# 1.2.2-A20: .bss statik extent (blob basina goreli) — motor bu araliga
# SIFIR dolgu ayirmak ZORUNDADIR (flat binary bss icermez; aksi halde
# xvr_* statikleri cfg blokunu ezer).
def bss_end(elf):
    r = subprocess.run(['nm', elf], capture_output=True, text=True).stdout
    mx = 0
    for line in r.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ('b', 'B'):
            mx = max(mx, int(parts[0], 16) - 0x100000)
    return mx

be86 = bss_end('xrt86.elf')
be64 = bss_end('xrt64.elf')

out = '// OTOMATIK uretildi: gen_xrt_blob.py (xrt_core.c -> ld flat binary)\n#include "engine.hpp"\n'
out += b64 + '\n' + b86 + '\n'
out += f'const u32 XRT_BLOB64_BSS_END = {be64};\nconst u32 XRT_BLOBX86_BSS_END = {be86};\n'
out += f'const u32 XRT_BLOB64_ENTRY_OFF = {e64};\nconst u32 XRT_BLOB64_RESOLVE_OFF = {r64};\n'
out += f'const u32 XRT_BLOB64_UNPACK_OFF = {u64o};\n'
out += f'const u32 XRT_BLOB64_SDK_OFF = {s64};\n'
out += f'const u32 XRT_BLOBX86_ENTRY_OFF = {e86};\nconst u32 XRT_BLOBX86_RESOLVE_OFF = {r86};\n'
out += f'const u32 XRT_BLOBX86_UNPACK_OFF = {u86};\n'
out += f'const u32 XRT_BLOBX86_SDK_OFF = {s86};\n'
open('xrt_blob.cpp', 'w').write(out)
print(f'x86: len={l86} entry={e86:#x} resolve={r86:#x} unpack={u86:#x}')
print(f'x64: len={l64} entry={e64:#x} resolve={r64:#x} unpack={u64o:#x}')
print('xrt_blob.cpp yazildi')

# ---- PIC KAPISI: blob yalniz .text icerebilir (rodata/data = mutlak adres = kirilir) ----
import subprocess as _sp, sys as _sys
for _elf in ['vm64.elf', 'vmx86.elf'] if 'vm' in 'gen_xrt_blob.py' else ['xrt64.elf', 'xrt86.elf']:
    try:
        _h = _sp.run(['objdump', '-h', _elf], capture_output=True, text=True).stdout
    except FileNotFoundError:
        break
    _bad = [ln.split()[1] for ln in _h.splitlines() if len(ln.split()) >= 7
            and ln.split()[1] not in ('.text', '.bss') and ln.split()[1].startswith('.')]
    if _bad:
        print(f'HATA: {_elf} PIC degil — bolumler: {_bad}')
        _sys.exit(1)
print('PIC kapisi: temiz (.text + .bss; bss VirtualAlloc/sahne-sifir')
