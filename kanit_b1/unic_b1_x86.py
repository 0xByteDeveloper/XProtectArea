#!/usr/bin/env python3
# unic_b1_x86.py — 1.2.0-B1 x86 Unicorn fark-koşusu.
# KORUMALI PE32'nin (stub+VM) t_* ihrac sutunlarini Unicorn'da kosturur;
# beklenti degerleri PYTHON'da ayna-matematikten uretilir.
# Kullanim: unic_b1_x86.py <orijinal.exe> <korumali.exe>
import struct, sys
from unicorn import *
from unicorn.x86_const import *

IMG = 0x00400000
IMGSZ = 0x800000
STK = 0x7F000000
STKSZ = 0x200000
TEB = 0x7E800000
PEB = 0x7E100000
LDR = 0x7E200000
SENTINEL = 0x031F0000
M = 0xFFFFFFFF

def m2_inner(n):
    s = 2166136261
    for i in range(n & 63):
        s = ((s ^ i) * 16777619) & M
        s = (s ^ (s >> 7)) & M
    return s

def m1_outer(n):
    a = m2_inner(n); b = m2_inner(n + 1)
    return (a ^ ((b * 2654435761) & M)) & M

EXPECT = {
    't_multvm':  m1_outer(20),
    't_multvm2': m1_outer(0x2A),
    't_njcc1':   5 ^ 0xBEEF,
    't_njcc0':   111,
    't_reti8w':  (3 * 3 + 4) & M,
    't_reti4w':  7 ^ 0xABCD,
    't_mixa':    14,
    't_mixb':    (4 - 9) & M,
}

def load_pe(path, base):
    import pefile
    pe = pefile.PE(path)
    out = {'base': base, 'delta': base - pe.OPTIONAL_HEADER.ImageBase, 'exports': {}}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        out['exports'][e.name.decode()] = e.address
    secs = []
    for s in pe.sections:
        secs.append((base + s.VirtualAddress, s.get_data(), s.Misc_VirtualSize))
    out['secs'] = secs
    return out

def run_func(pe, rva):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    for a, d, _sz in pe['secs']:
        if d:
            mu.mem_map(a, (len(d) + 0xFFF) & ~0xFFF)
            mu.mem_write(a, d)
    mu.mem_map(STK, STKSZ); mu.mem_map(TEB, 0x1000); mu.mem_map(PEB, 0x1000)
    mu.mem_map(LDR, 0x1000); mu.mem_map(SENTINEL, 0x1000)
    mu.mem_write(TEB + 0x18, struct.pack('<I', TEB))
    mu.mem_write(TEB + 0x30, struct.pack('<I', PEB))
    # unicorn x86-32: FS segmenti desteklenmiyor -> fs:[abs] okumalarini
    # yuklenen gostergedе sabit deger yuklemesiyle DEGISTIR:
    #   64 A1 <d32> (mov eax, fs:[d32]) -> B8 <val> 90 90 (mov eax,imm; nop nop)
    for sa, sd, _sz in pe['secs']:
        blob = bytearray(sd)
        changed = False
        off = 0
        while True:
            i = blob.find(b'\x64\xA1', off)
            if i < 0 or i + 6 > len(blob): break
            disp = struct.unpack_from('<I', blob, i + 2)[0]
            val = TEB if disp == 0x18 else (PEB if disp == 0x30 else 0)
            blob[i:i + 6] = b'\xB8' + struct.pack('<I', val) + b'\x90'
            changed = True
            off = i + 6
        if changed:
            mu.mem_write(sa, bytes(blob))
    mu.mem_write(PEB + 2, struct.pack('<B', 0))
    mu.mem_write(PEB + 0x68, struct.pack('<I', 0))
    mu.mem_write(PEB + 0x0C, struct.pack('<I', LDR))
    mu.mem_write(LDR + 0x14, struct.pack('<I', LDR + 0x40))
    mu.mem_write(LDR + 0x40 + 8, struct.pack('<I', LDR + 0x14))
    esp = STK + STKSZ - 0x10000
    mu.mem_write(esp, struct.pack('<I', SENTINEL))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, STK + STKSZ - 0x8000)
    err = 'OK'
    try:
        mu.emu_start(pe['base'] + rva, SENTINEL, timeout=30_000_000, count=50_000_000)
    except UcError as e:
        err = 'UCERR %s eip=0x%X' % (e, mu.reg_read(UC_X86_REG_EIP))
    return mu.reg_read(UC_X86_REG_EAX) & M, err

def main():
    orig_path, prot_path = sys.argv[1], sys.argv[2]
    prot = load_pe(prot_path, IMG)
    fails, oks = [], 0
    for name, want in EXPECT.items():
        rva = prot['exports'].get(name)
        if rva is None:
            fails.append('%s: export yok' % name); continue
        got, err = run_func(prot, rva)
        if got == want and err == 'OK':
            oks += 1; print('OK  %-10s eax=%08X' % (name, got))
        else:
            fails.append('%s got=%08X want=%08X %s' % (name, got, want, err))
            print('FAIL %-10s got=%08X want=%08X %s' % (name, got, want, err))
    print('SONUC: %d/%d' % (oks, len(EXPECT)))
    if not fails:
        print('TAMAM')
    else:
        for f in fails: print('  !', f)
        sys.exit(1)

if __name__ == '__main__':
    main()
