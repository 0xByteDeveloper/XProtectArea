#!/usr/bin/env python3
# x86diff.py — mini32 x86: orijinal vs XProtect korumali fonksiyon diferansiyeli
# (Unicorn x86 + sahte PEB; x86 stub+gate+xrt+VM tam zincir testi)
import struct, sys
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

def load_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    opt = e + 24
    ib = struct.unpack_from('<I', d, opt + 28)[0]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        name = d[o:o+8].split(b'\0')[0].decode(errors='replace')
        vsz, rva, rsz, rptr = struct.unpack_from('<IIII', d, o+8)
        secs.append((name, rva, vsz, rsz, rptr))
    return d, ib, secs

def w32(mu, a, v): mu.mem_write(a, struct.pack('<I', v))
def w16(mu, a, v): mu.mem_write(a, struct.pack('<H', v))

def fake_peb_x86(mu):
    """x86 sahte PEB: fs:0x30 -> PEB; kernel32 modulu listede."""
    FSAREA = 0x7FF00000
    PEB = 0x7FF10000; LDR = 0x7FF20000; ENT = 0x7FF30000
    NAMEBUF = 0x7FF35000; MOD = 0x7FF40000
    for a, n in [(FSAREA, 0x1000), (PEB, 0x1000), (LDR, 0x1000),
                 (ENT, 0x1000), (NAMEBUF, 0x1000), (MOD, 0x20000)]:
        mu.mem_map(a, n)
    mu.reg_write(UC_X86_REG_FS_BASE, FSAREA)
    w32(mu, FSAREA + 0x30, PEB)
    w32(mu, PEB + 0x0C, LDR)
    head = LDR + 0x14                       # InMemoryOrderModuleList (x86 +0x14)
    w32(mu, head, ENT + 0x08)
    w32(mu, head + 4, ENT + 0x08)
    # LDR_DATA_TABLE_ENTRY (x86): links +0x08, DllBase +0x18, BaseDllName +0x2C
    w32(mu, ENT + 0x08, head)
    w32(mu, ENT + 0x0C, head)
    w32(mu, ENT + 0x18, MOD)                # DllBase
    name = "kernel32.dll".encode('utf-16-le')
    mu.mem_write(NAMEBUF, name)
    w16(mu, ENT + 0x2C, len(name))
    w16(mu, ENT + 0x2E, len(name) + 2)
    w32(mu, ENT + 0x30, NAMEBUF)
    # modul 'MZ' (find_export cagrilmayacak ama guvenli olsun)
    mu.mem_write(MOD, b'MZ')
    w32(mu, MOD + 0x3C, 0x80)
    mu.mem_write(MOD + 0x80, b'PE\0\0')

def run_fn(path, rva, fake_peb):
    d, ib, secs = load_pe(path)
    if fake_peb:
        # Unicorn x86-32'de FS_BASE ayari no-op (deprecated): xrt blob'daki
        # 'mov eax, fs:[0x30]' (64 A1 30 00 00 00) talimatini test icin
        # mutlak 'mov eax, PEB' (B8 ..) ile yamala — yalniz bu test icin.
        pat = bytes([0x64, 0xA1, 0x30, 0x00, 0x00, 0x00])
        rep = bytes([0xB8]) + struct.pack('<I', 0x7FF10000) + bytes([0x90])
        n = d.count(pat)
        d = d.replace(pat, rep)
        print(f"  [test] fs:[0x30] yamasi: {n} yer")
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    top = max(rva + vsz for (_, rva, vsz, _, _) in secs)
    mu.mem_map(ib, (top + 0xFFF) & ~0xFFF)
    for (_, rva2, vsz, rsz, rptr) in secs:
        if rsz: mu.mem_write(ib + rva2, d[rptr:rptr + rsz])
    STK = 0x300000
    mu.mem_map(STK, 0x8000)
    RETM = STK + 0x7000                     # STK bolgesi icinde (mapped)
    esp0 = STK + 0x6000
    w32(mu, esp0, RETM)                     # donus adresini IT
    # fastcall benzeri: ecx = this; yigin arglari [esp+4], [esp+8]
    mu.mem_write(esp0 + 4, struct.pack('<I', 0x11))   # arg1 (ret 8 temizler)
    mu.mem_write(esp0 + 8, struct.pack('<I', 0x22))   # arg2
    if fake_peb: fake_peb_x86(mu)
    mu.reg_write(UC_X86_REG_ESP, esp0)
    mu.reg_write(UC_X86_REG_ECX, ib + 0x2000)         # this (data bolgesi)
    mu.mem_write(ib + 0x2000, struct.pack('<BII', 2, 0x33, 0x44))
    tr = []
    def hook(uc, address, size, ud):
        tr.append(address - ib)
    mu.hook_add(UC_HOOK_CODE, hook)
    try:
        mu.emu_start(ib + rva, RETM, count=8000000)
        ok = True
    except UcError as ex:
        ok = False
    return {
        'ok': ok, 'eax': mu.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF,
        'esp': mu.reg_read(UC_X86_REG_ESP), 'n': len(tr), 'tr': tr,
        'mem': bytes(mu.mem_read(ib + 0x2000, 9)),
        'last': (mu.reg_read(UC_X86_REG_RIP) - ib) if not ok else None,
    }

if __name__ == '__main__':
    orig, prot = sys.argv[1], sys.argv[2]
    rva = int(sys.argv[3], 16)
    fake = len(sys.argv) > 4 and sys.argv[4] == 'peb'
    a = run_fn(orig, rva, False)
    b = run_fn(prot, rva, fake)
    print(f"ORIJINAL : ok={a['ok']} eax={a['eax']:#x} esp={a['esp']:#x} n={a['n']} mem={a['mem'].hex()}")
    print(f"KORUMALI : ok={b['ok']} eax={b['eax']:#x} esp={b['esp']:#x} n={b['n']} mem={b['mem'].hex()}" +
          (f" SON rip=+{b['last']:#x}" if b['last'] else ''))
    same = (a['ok'] and b['ok'] and a['eax'] == b['eax'] and
            a['esp'] == b['esp'] and a['mem'] == b['mem'])
    print("SONUC:", "*** ESLESIYOR ***" if same else "*** FARKLI ***")
