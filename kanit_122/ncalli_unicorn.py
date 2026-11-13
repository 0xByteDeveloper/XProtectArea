#!/usr/bin/env python3
# ncalli_unicorn.py — 1.2.2-A10 OP_NCALLI runtime kaniti (Unicorn x86)
# tcalli0_p.exe (korumali) icinde do_calli/do_calli2 bolgeleri:
#   FF 90 88000000 (call dword ptr [eax+88h]) — kullanici E96D0 opcodu
# Kanit: korumali fonksiyon gercek vtable hedefine natcall yapar,
# donus degeri dogru (777 / 888) -> done=1, rc yok.
import struct, sys
from unicorn import *
from unicorn.x86_const import *
import pefile

IMG   = 0x00400000
STK   = 0x00300000; STKSZ = 0x00100000
TEB   = 0x7FFDF000; PEB = 0x7FFDE000; LDR = 0x7FFDD000
CALLP = 0x00A00000
STOP  = 0x00A02000
VTB   = 0x00B00000          # sahte vtable (harness koyar)
RES   = 0x00A03000

UNP = '/home/z/my-project/scripts/xp122_test/tcalli0.exe'
PRO = '/home/z/my-project/scripts/xp122_test/tcalli0_p.exe'

def text_data(path):
    pe = pefile.PE(path)
    for s in pe.sections:
        if s.Name.decode().rstrip('\0') == '.text':
            return IMG + s.VirtualAddress, s.get_data()
    raise SystemExit('.text yok')

def load_pe(mu, path, base):
    pe = pefile.PE(path)
    for s in pe.sections:
        va = base + s.VirtualAddress
        vs = (s.Misc_VirtualSize + 0xFFF) & ~0xFFF
        try: mu.mem_map(va, max(vs, 0x1000))
        except UcError: pass
        raw = s.get_data()
        if raw: mu.mem_write(va, raw)
    # fs:[0x18] okumalarini yamala (m2vm_repro ayni yontem)
    for s in pe.sections:
        va = base + s.VirtualAddress
        blob = bytearray(s.get_data()); off = 0; n = 0
        while True:
            i = blob.find(b'\x64\xA1', off)
            if i < 0 or i + 6 > len(blob): break
            disp = struct.unpack_from('<I', blob, i + 2)[0]
            val = TEB if disp == 0x18 else (PEB if disp == 0x30 else 0)
            blob[i:i+6] = b'\xB8' + struct.pack('<I', val) + b'\x90'
            off = i + 6; n += 1
        if n: mu.mem_write(va, bytes(blob))

def find_va(data, tbase, pat):
    i = data.find(pat)
    return (tbase + i) if i >= 0 else None

def main():
    tb, tdata = text_data(UNP)
    # 1) vtcall / vtcall2 hedef VAlari (korumasiz exe'den — RVA korunur)
    vt1 = find_va(tdata, tb, b'\x55\x89\xE5\xB8\x09\x03\x00\x00')  # zig 89E5 kodlamasi
    vt2 = find_va(tdata, tb, b'\x55\x89\xE5\xB8\x78\x03\x00\x00')
    print('[1] vtcall=%s vtcall2=%s' % (hex(vt1 or 0), hex(vt2 or 0)))
    assert vt1 and vt2, 'vtcall/vtcall2 bulunamadi'

    # 2) do_calli / do_calli2 fonksiyon girişleri: SDK BEG marker ->
    #    geriye dogru 55 8B EC prolog (-O0 deterministik)
    m = bytes.fromhex('B8B5E1379C')
    entries = []
    off = 0
    while True:
        i = tdata.find(m, off)
        if i < 0: break
        j = tdata.rfind(b'\x55\x89\xE5', max(0, i - 64), i)  # zig mov ebp,esp
        entries.append(tb + j)
        off = i + 5
    print('[2] SDK bolgeleri=%d girisler=%s' % (len(entries), [hex(e) for e in entries]))
    assert len(entries) >= 2, 'SDK bolgeleri bulunamadi'
    f1, f2 = entries[0], entries[1]

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    load_pe(mu, PRO, IMG)
    mu.mem_map(STK, STKSZ)
    for a in (TEB, PEB, LDR):
        try: mu.mem_map(a, 0x1000)
        except UcError: pass
    mu.mem_map(CALLP, 0x2000); mu.mem_map(VTB & ~0xFFF, 0x1000)
    mu.mem_map(RES & ~0xFFF, 0x1000)
    mu.mem_write(TEB + 0x18, struct.pack('<I', TEB))
    mu.mem_write(TEB + 0x30, struct.pack('<I', PEB))
    mu.mem_write(PEB + 2, b'\x00')
    mu.mem_write(PEB + 0x68, struct.pack('<I', 0))
    mu.mem_write(PEB + 0x0C, struct.pack('<I', LDR))
    mu.mem_write(LDR + 0x14, struct.pack('<I', LDR + 0x40))
    mu.mem_write(LDR + 0x40 + 8, struct.pack('<I', LDR + 0x14))
    # sahte vtable: slot 0x88=vtcall, 0x8C=vtcall2
    mu.mem_write(VTB + 0x88, struct.pack('<I', vt1))
    mu.mem_write(VTB + 0x8C, struct.pack('<I', vt2))

    # 3) cagirici: push VTB; call f1; mov [RES],eax; push VTB; call f2;
    #    mov [RES+4],eax; jmp $
    rel1 = f1 - (CALLP + 10)            # push(5) sonrasi call
    rel2 = f2 - (CALLP + 28)            # push(5)+call(5)+add3+A3(5)+push(5)=23; call sonrasi 28
    code = (b'\x68' + struct.pack('<I', VTB) +       # push VTB (arg)
            b'\xE8' + struct.pack('<i', rel1) +      # call do_calli
            b'\x83\xC4\x04' +                        # add esp,4 (cdecl)
            b'\xA3' + struct.pack('<I', RES) +       # mov [RES],eax
            b'\x68' + struct.pack('<I', VTB) +       # push VTB
            b'\xE8' + struct.pack('<i', rel2) +      # call do_calli2
            b'\x83\xC4\x04' +
            b'\xA3' + struct.pack('<I', RES + 4) +
            b'\xEB\xFE')                             # jmp $ (durdur)
    mu.mem_write(CALLP, code)
    rsp = STK + STKSZ - 0x10000
    mu.reg_write(UC_X86_REG_ESP, rsp)
    mu.reg_write(UC_X86_REG_ECX, 0x1)   # this-ornegi

    trace_ok = []
    def hook(mu, addr, size, ud):
        if addr in (f1, f2): trace_ok.append(addr)
        if addr == vt1: print('[k] vtcall VA calisti (native)')
        if addr == vt2: print('[k] vtcall2 VA calisti (native)')

    mu.hook_add(UC_HOOK_CODE, hook)
    mu.emu_start(CALLP, STOP, count=20000000)
    a = struct.unpack('<I', mu.mem_read(RES, 4))[0]
    b = struct.unpack('<I', mu.mem_read(RES + 4, 4))[0]
    print('[3] do_calli=%d (beklenen 777)  do_calli2=%d (beklenen 888)' % (a, b))
    print('[4] korumali-fonksiyon girişleri hit: %s' % [hex(x) for x in trace_ok])
    ok = (a == 777 and b == 888)
    print('[SONUC] %s' % ('PASS — OP_NCALLI dogru hedefe dogru natcall yapti' if ok else 'FAIL'))
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main())
