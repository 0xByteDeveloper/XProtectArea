#!/usr/bin/env python3
# ============================================================
# verify_mut.py — 0.3.0 mutasyon dogrulayici (Unicorn tam-goruntu)
# Orijinal PE ile korunmus PE'yi ayni register/bellek durumuyla
# Unicorn'da kosturir: rax + yazilan bellek farki karsilastirir.
# x64 VE x86 calisir (wine32 konteynerde imkansiz oldugu icin x86
# bu sekilde dogrulanir — 0.1.0'un "Unicorn 44/44" yontemi).
# Kullanim: python3 verify_mut.py <orijinal.exe> <korumali.exe> [guc]
# ============================================================
import struct, sys
from unicorn import *
from unicorn.x86_const import *

def load_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    optsz = struct.unpack_from('<H', d, e+20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    is64 = (magic == 0x20B)
    fmt = '<Q' if is64 else '<I'
    ib = struct.unpack_from(fmt, d, opt + (24 if is64 else 28))[0]
    ep = struct.unpack_from('<I', d, opt + 16)[0]
    secs = []
    for i in range(nsec):
        o = opt + optsz + 40 * i
        name = d[o:o+8].split(b'\0')[0].decode(errors='replace')
        vsz, rva, rsz, rptr = struct.unpack_from('<IIII', d, o+8)
        secs.append((name, rva, vsz, rsz, rptr))
    # export tablosu (fonksiyon RVA'lari — x86/x64 adresleme farki icin ZORUNLU)
    # DataDirectory oflesi: PE32=96, PE32+=112 (opsiyonel baslik basindan)
    exports = {}
    dd = opt + (96 if not is64 else 112)
    exp_rva = struct.unpack_from('<I', d, dd)[0]
    if exp_rva:
        def r2o(r):
            for (n, s_rva, s_vsz, s_rsz, s_rp) in secs:
                if s_rva <= r < s_rva + max(s_vsz, s_rsz) and s_rsz:
                    if r - s_rva < s_rsz:
                        return s_rp + (r - s_rva)
            return None
        eo = r2o(exp_rva)
        if eo:
            nnames = struct.unpack_from('<I', d, eo + 24)[0]
            funcs_rva = struct.unpack_from('<I', d, eo + 28)[0]   # AddressOfFunctions
            names_rva = struct.unpack_from('<I', d, eo + 32)[0]   # AddressOfNames
            ords_rva  = struct.unpack_from('<I', d, eo + 36)[0]   # AddressOfNameOrdinals
            for i in range(nnames):
                name_rva = struct.unpack_from('<I', d, r2o(names_rva) + 4 * i)[0]
                ordv = struct.unpack_from('<H', d, r2o(ords_rva) + 2 * i)[0]
                frva = struct.unpack_from('<I', d, r2o(funcs_rva) + 4 * ordv)[0]
                nm = d[r2o(name_rva):d.index(b'\0', r2o(name_rva))].decode()
                exports[nm] = frva
    return d, is64, ib, ep, secs, exports

class Img:
    def __init__(self, path):
        self.d, self.is64, self.ib, self.ep, self.secs, self.exports = load_pe(path)
        self.base = self.ib & ~0xFFFF
        top = max(rva + vsz for (_, rva, vsz, _, _) in self.secs)
        self.imgsz = (top + 0xFFF) & ~0xFFF
        # yazilabilir bolum snapshot bolgeleri (.data benzeri)
        self.wregs = [(rva, vsz) for (n, rva, vsz, rsz, rp) in self.secs
                      if n in ('.data', '.rdata')]

    def map_into(self, mu):
        mu.mem_map(self.base, self.imgsz)
        for (_, rva, vsz, rsz, rptr) in self.secs:
            if rsz:
                mu.mem_write(self.base + rva, self.d[rptr:rptr + rsz])

def run_fn(img, rva, argsets, max_insn=500000):
    """fonksiyonu her arguman setiyle kostur; (rax, yazma seti) listesi dondurur"""
    results = []
    RETM = 0x50000000
    STACK = 0x40000000
    for args in argsets:
        mu = Uc(UC_ARCH_X86, UC_MODE_64 if img.is64 else UC_MODE_32)
        img.map_into(mu)
        mu.mem_map(STACK - 0x200000, 0x200000)
        mu.mem_map(RETM, 0x1000)
        w = 4 if img.is64 else 4
        sp = STACK - 0x1000
        if img.is64:
            mu.mem_write(sp, struct.pack('<Q', RETM))
            for k, a in enumerate(args[:4]):
                mu.reg_write([UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9][k], a & 0xFFFFFFFFFFFFFFFF)
            mu.reg_write(UC_X86_REG_RSP, sp)
        else:
            # cdecl: [sp]=ret, [sp+4]=arg1, ...
            mu.mem_write(sp, struct.pack('<I', RETM))
            for k, a in enumerate(args):
                mu.mem_write(sp + 4 + 4 * k, struct.pack('<I', a & 0xFFFFFFFF))
            mu.reg_write(UC_X86_REG_ESP, sp)
        # yazilabilir bolge on-goruntusu
        before = {}
        for (wrva, wvsz) in img.wregs:
            before[wrva] = mu.mem_read(img.base + wrva, min(wvsz, 0x4000))
        try:
            mu.emu_start(img.base + rva, RETM, count=max_insn)
            rax = mu.reg_read(UC_X86_REG_RAX if img.is64 else UC_X86_REG_EAX)
        except UcError as ex:
            results.append(('EXC', str(ex), None))
            continue
        writes = {}
        for (wrva, wvsz) in img.wregs:
            after = mu.mem_read(img.base + wrva, min(wvsz, 0x4000))
            b = before[wrva]
            n = min(len(b), len(after))
            for i in range(n):
                if b[i] != after[i]:
                    writes[img.base + wrva + i] = after[i]
        results.append((rax, writes, None))
    return results

def fmt_w(writes):
    return ' '.join(f'{a:#x}:{v:02X}' for a, v in sorted(writes.items())[:12])

def main():
    orig_p, prot_p = sys.argv[1], sys.argv[2]
    o = Img(orig_p)
    p = Img(prot_p)
    # fonksiyon RVA'lari export tablosundan (x86/x64 farki guvenli sekilde asilir)
    names = ['WrapPos', 'MovePlayer', 'GhostStep', 'CheckCollision', 'GameTick']
    argmap = {
        'WrapPos':        [(5, 15), (-3, 15), (17, 15), (0, 1), (123, 100)],
        'MovePlayer':     [(0,), (1,), (2,), (3,), (99,)],
        'GhostStep':      [(0,), (1,), (2,), (7,)],
        'CheckCollision': [()],
        'GameTick':       [(0,), (1,), (2,), (3,)],
    }
    fns = []
    for n in names:
        if n in o.exports and n in p.exports:
            fns.append((o.exports[n], n, argmap[n]))
    npass = nfail = 0
    for rva, name, argsets in fns:
        ro = run_fn(o, rva, argsets)
        rp = run_fn(p, rva, argsets)
        ok = True
        for k, (a, b) in enumerate(zip(ro, rp)):
            if a[0] == 'EXC' or b[0] == 'EXC' or a[0] != b[0] or a[1] != b[1]:
                ok = False
                print(f'  [{name}] argset#{k} {argsets[k]}: FARK')
                print(f'     orij : {a[0]} {"" if a[0]=="EXC" else fmt_w(a[1])}')
                print(f'     korun: {b[0]} {"" if b[0]=="EXC" else fmt_w(b[1])}')
        if ok:
            npass += 1
            print(f'  [{name}] {len(argsets)}/{len(argsets)} argset ESIT ✓  (rax={ro[0][0] if ro and ro[0][0]!="EXC" else "?"})')
        else:
            nfail += 1
    print(f'SONUC: {npass} fonksiyon ESIT, {nfail} FARK'
          f' | {"DOGRULANDI ✓✓" if nfail == 0 else "HATA VAR ✗"}')
    return 1 if nfail else 0

if __name__ == '__main__':
    sys.exit(main())
