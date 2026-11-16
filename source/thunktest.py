#!/usr/bin/env python3
# thunktest.py — korunmus exe'nin IAT thunk'ini Unicorn'da sahte PEB ile izle (x64)
import struct, sys
from unicorn import *
from unicorn.x86_const import *

def load_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    opt = e + 24
    ib = struct.unpack_from('<Q', d, opt + 24)[0]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        name = d[o:o+8].split(b'\0')[0].decode(errors='replace')
        vsz, rva, rsz, rptr = struct.unpack_from('<IIII', d, o+8)
        secs.append((name, rva, vsz, rsz, rptr))
    return d, ib, secs

def w64(mu, a, v): mu.mem_write(a, struct.pack('<Q', v))
def w32(mu, a, v): mu.mem_write(a, struct.pack('<I', v))
def w16(mu, a, v): mu.mem_write(a, struct.pack('<H', v))

def fake_peb(mu, exports):
    """Sahte PEB + LDR + kernel32 modulu + export tablosu (Unicorn).
    exports: {isim: adres}"""
    PEB = 0x7E100000; LDR = 0x7E200000; ENT = 0x7E300000
    NAMEBUF = 0x7E350000; MOD = 0x7E400000; EXPDIR = 0x7E500000
    NAMES = 0x7E510000; ORDS = 0x7E520000; FUNCS = 0x7E530000
    mu.mem_map(0x7E000000, 0x1000)   # GS slot sayfasi
    mu.mem_map(PEB, 0x1000); mu.mem_map(LDR, 0x1000)
    mu.mem_map(ENT, 0x1000); mu.mem_map(MOD, 0x20000)
    mu.mem_map(EXPDIR, 0x1000); mu.mem_map(NAMES, 0x1000)
    mu.mem_map(ORDS, 0x1000); mu.mem_map(FUNCS, 0x1000)
    mu.mem_map(NAMEBUF, 0x1000)
    # GS:0x60 -> PEB
    mu.reg_write(UC_X86_REG_GS_BASE, 0x7E000000)
    w64(mu, 0x7E000060, PEB)
    # PEB+0x18 -> Ldr
    w64(mu, PEB + 0x18, LDR)
    # Ldr+0x20 = InMemoryOrderModuleList HEAD (kendine bagli liste, tek girdi)
    head = LDR + 0x20
    w64(mu, head, ENT + 0x10)        # Flink -> girdinin InMemoryOrderLinks
    w64(mu, head + 8, ENT + 0x10)    # Blink
    # LDR_DATA_TABLE_ENTRY (x64):
    #   +0x10 InMemoryOrderLinks (LIST_ENTRY)
    #   +0x30 DllBase ; +0x58 BaseDllName (UNICODE_STRING: len,max,pad,buf)
    links = ENT + 0x10
    w64(mu, links, head)             # Flink -> head
    w64(mu, links + 8, head)         # Blink -> head
    w64(mu, ENT + 0x30, MOD)         # DllBase
    name = "kernel32.dll".encode('utf-16-le')
    mu.mem_write(NAMEBUF, name)
    w16(mu, ENT + 0x58, len(name))   # Length
    w16(mu, ENT + 0x5A, len(name) + 2)
    w64(mu, ENT + 0x60, NAMEBUF)     # Buffer
    # --- sahte modul PE (MZ/PE + export dizini) ---
    mu.mem_write(MOD, b'MZ')
    w32(mu, MOD + 0x3C, 0x80)
    mu.mem_write(MOD + 0x80, b'PE\0\0')
    # OptionalHeader = PE sig + 4 + 20 (COFF) = MOD+0x98
    w16(mu, MOD + 0x98, 0x20B)       # PE32+ magic
    # DataDirectory[0] (export): OptionalHeader+112 = MOD+0x108
    w32(mu, MOD + 0x108, EXPDIR - MOD)
    w32(mu, MOD + 0x10C, 0x100)
    # --- export dizini ---
    names = list(exports.keys())
    w32(mu, EXPDIR + 0x18, len(names))       # NumberOfFunctions
    w32(mu, EXPDIR + 0x20, len(names))       # NumberOfNames
    w32(mu, EXPDIR + 0x1C, FUNCS - MOD)      # AddressOfFunctions (+28)
    w32(mu, EXPDIR + 0x20, NAMES - MOD)      # AddressOfNames (+32)
    w32(mu, EXPDIR + 0x24, ORDS - MOD)       # AddressOfNameOrdinals (+36)
    STRS = 0x7E540000
    mu.mem_map(STRS, 0x1000)
    for i, nm in enumerate(names):
        w32(mu, NAMES + i * 4, STRS + i * 64 - MOD)   # isim RVA'si
        mu.mem_write(STRS + i * 64, nm.encode())       # isim kendisi
        mu.mem_write(STRS + i * 64 + len(nm), b'\0')
        w16(mu, ORDS + i * 2, i)
        w32(mu, FUNCS + i * 4, exports[nm] - MOD)

def main(path, thunk_rva, ib):
    d, ib_, secs = load_pe(path)
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    top = max(rva + vsz for (_, rva, vsz, _, _) in secs)
    mu.mem_map(ib, ((top + 0xFFFF) & ~0xFFFF) - ib)
    for (_, rva, vsz, rsz, rptr) in secs:
        if rsz: mu.mem_write(ib + rva, d[rptr:rptr + rsz])
    STK = 0x7F0000000000
    mu.mem_map(STK - 0x200000, 0x200000)
    RET = STK - 0x800
    w64(mu, RET, 0xDEAD0000)
    # cozumlenen printf'in dusecegi zararsiz hedef:
    TARGET = 0x7E600000
    mu.mem_map(TARGET, 0x1000)
    mu.mem_write(TARGET, b'\xc3')          # ret
    fake_peb(mu, {'printf': TARGET})
    mu.reg_write(UC_X86_REG_RSP, STK - 0x10000)
    mu.reg_write(UC_X86_REG_RCX, 0x1111111)   # fastcall arg1
    mu.reg_write(UC_X86_REG_RDX, 0x2222222)
    mu.reg_write(UC_X86_REG_R8, 0x3333333)
    mu.reg_write(UC_X86_REG_R9, 0x4444444)
    trace = []
    def hook(uc, address, size, ud):
        rip = address
        tag = ''
        if rip == TARGET: tag = '  <<< HEDEF (printf) — BASARI!'
        trace.append((rip, tag))
        if len(trace) > 400: uc.emu_stop()
    mu.hook_add(UC_HOOK_CODE, hook)
    try:
        mu.emu_start(ib + thunk_rva, RET, count=2000)
        print(f"BITTI ({len(trace)} komut)")
    except UcError as ex:
        print(f"UC HATA: {ex} rip={mu.reg_read(UC_X86_REG_RIP):#x}")
    for (rip, tag) in trace[:50]:
        if ib <= rip < ib + 0x100000:
            print(f"  img+{rip-ib:#06x}{tag}")
        else:
            print(f"  {rip:#x}{tag}")

if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2], 16), 0x140000000)
