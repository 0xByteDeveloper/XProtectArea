#!/usr/bin/env python3
# vm64.bin / vmx86.bin -> vm_blob.cpp (engine'e gomulen bayt dizileri)
import sys
def emit(path, name):
    d = open(path,'rb').read()
    lines = []
    for i in range(0, len(d), 16):
        lines.append('  ' + ','.join(f'0x{b:02X}' for b in d[i:i+16]) + ',')
    body = '\n'.join(lines)
    return f'const unsigned char {name}[] = {{\n{body}\n}};\nconst int {name}_LEN = {len(d)};\n'
import subprocess
def entry_off(elf, textbase):
    r = subprocess.run(['nm', elf], capture_output=True, text=True).stdout
    for line in r.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == 'vm_entry':
            return int(parts[0], 16) - textbase
    return 0
o64 = entry_off('vm64.elf', 0x100000)
o86 = entry_off('vmx86.elf', 0x100000)
out = '// OTOMATIK uretildi: gen_blob.py (vm_core.c -> ld flat binary)\n#include "engine.hpp"\n'
out += emit('vm64.bin','VM_BLOB64') + '\n'
out += emit('vmx86.bin','VM_BLOBX86') + '\n'
out += f'const u32 VM_BLOB64_ENTRY_OFF = {o64};\nconst u32 VM_BLOBX86_ENTRY_OFF = {o86};\n'
open('vm_blob.cpp','w').write(out)
print('vm_entry offsetleri: x64=%d x86=%d' % (o64, o86))
print('vm_blob.cpp yazildi:', len(out), 'bayt')

# ---- PIC KAPISI: blob yalniz .text icerebilir (rodata/data = mutlak adres = kirilir) ----
import subprocess as _sp, sys as _sys
for _elf in ['vm64.elf', 'vmx86.elf'] if 'vm' in 'gen_blob.py' else ['xrt64.elf', 'xrt86.elf']:
    try:
        _h = _sp.run(['objdump', '-h', _elf], capture_output=True, text=True).stdout
    except FileNotFoundError:
        break
    _bad = [ln.split()[1] for ln in _h.splitlines() if len(ln.split()) >= 7
            and ln.split()[1] not in ('.text', '.bss') and ln.split()[1].startswith('.')]
    if _bad:
        print(f'HATA: {_elf} PIC degil — bolumler: {_bad}')
        _sys.exit(1)
print('PIC kapisi: temiz (yalniz .text)')
