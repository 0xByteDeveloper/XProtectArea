#!/usr/bin/env python3
# unic_deepvm_x86.py — 0.9.0-DeepVM x86 Unicorn diferansiyeli (oyun mimarisi).
# KORUMALI exe'nin stub+VM'ini Unicorn'da kosturur; ayni fonksiyonu
# ORIJINAL exe'de (ham CPU semantigi = Unicorn) kosturur; EAX + bayrak
# etkisi birebir karsilastirilir.
# Kullanim: unic_deepvm_x86.py <orijinal.exe> <korumali.exe>
import struct, sys, os
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

# main'in cagirdigi argumanlar (fonksiyon adi -> args tuple)
ARGS = {
    't_adc':     (0xFFFFFF01, 2),
    't_pushf':   (0x41,),
    't_flagops': (7,),
    't_muldiv':  (0x12345, 0x6789),
    't_bt':      (0,),
    't_shld':    (0x12345678, 0x9ABCDEF0),
    't_loop':    (5,),
    't_xadd':    (0x40, 0x22),
    't_str':     (0x5E,),
    't_parity':  (0,),
    't_imulmem': (3,),
    't_mul8':    (0,),
    't_mulonly': (0,),
    't_divonly': (0,),
    # 1.0.0-UO kapi (NOR/NAND yigin) testleri
    't_gate32':    (0xF0F0A5A5, 0x0FF03C3C),
    't_gate816':   (0x0000BEEF,),
    't_gate_zr':   (0x41,),
    't_gate_loop': (7,),
    't_gate_stack':(0xDEAD,),
    't_gate_imm':  (0x000000C3,),
}

def load_pe(path, base):
    import pefile
    pe = pefile.PE(path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    out = {}
    out['base'] = base
    out['delta'] = base - ib
    out['exports'] = {}
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        out['exports'][e.name.decode()] = e.address
    secs = []
    for s in pe.sections:
        raw = s.get_data()
        secs.append((base + s.VirtualAddress, raw, s.Misc_VirtualSize, s.Name.decode().rstrip('\0')))
    out['secs'] = secs
    out['entry'] = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    return out

def setup_world(mu, delta):
    for a, sz in [(STK, STKSZ), (TEB, 0x1000), (PEB, 0x1000),
                  (LDR, 0x1000), (SENTINEL, 0x1000)]:
        mu.mem_map(a, sz)
    # TEB self-ptr (x86: fs:[0x18] = TEB; fs:[0x30] = PEB)
    mu.mem_write(TEB + 0x18, struct.pack('<I', TEB))
    mu.mem_write(TEB + 0x30, struct.pack('<I', PEB))
    # PEB: BeingDebugged=0, NtGlobalFlag=0 (K1/K2/K3 temiz yol)
    mu.mem_write(PEB + 2, struct.pack('<B', 0))
    mu.mem_write(PEB + 0x68, struct.pack('<I', 0))
    # minimal LDR: xa_module kapidan bos donsun (K3 skip)
    mu.mem_write(PEB + 0x0C, struct.pack('<I', LDR))
    mu.mem_write(LDR + 0x14, struct.pack('<I', LDR + 0x40))
    mu.mem_write(LDR + 0x40 + 8, struct.pack('<I', LDR + 0x14))  # Flink -> head

def find_fs_sites(blob):
    """64 A1 xx xx xx xx (fs:[abs] eax'a okuma) siteleri — Unicorn x86
    FS_BASE reg no-op oldugu icin bu siteler hook ile emule edilir."""
    sites = []
    i = 0
    while True:
        i = blob.find(b'\x64\xA1', i)
        if i < 0: break
        disp = struct.unpack('<I', blob[i+2:i+6])[0]
        sites.append((i, disp))
        i += 1
    return sites

def run_func(pe, mu, rva, args, fs_sites=None, blob_base=None):
    """cdecl x86: [esp]=ret, [esp+4..]=arglar; sentinel'e ret beklenir."""
    esp = STK + STKSZ - 0x10000
    esp -= 4 * len(args)
    for k, a in enumerate(args):
        mu.mem_write(esp + 4 + 4 * k, struct.pack('<I', a & 0xFFFFFFFF))
    mu.mem_write(esp, struct.pack('<I', SENTINEL))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, STK + STKSZ - 0x8000)
    if fs_sites:
        amap = dict(fs_sites)  # offset -> disp
        def hook_code(m, addr, size, ud):
            off = addr - blob_base
            if off in amap:
                disp = amap[off]
                val = TEB if disp == 0x18 else (PEB if disp == 0x30 else 0)
                m.reg_write(UC_X86_REG_EAX, val)
                m.reg_write(UC_X86_REG_EIP, addr + 6)
        mu.hook_add(UC_HOOK_CODE, hook_code)
    err = 'OK'
    try:
        mu.emu_start(pe['base'] + rva, SENTINEL, timeout=20_000_000, count=20_000_000)
    except UcError as e:
        err = 'UCERR %s eip=0x%X' % (e, mu.reg_read(UC_X86_REG_EIP))
    return mu.reg_read(UC_X86_REG_EAX), err

def main():
    orig_path, prot_path = sys.argv[1], sys.argv[2]
    orig = load_pe(orig_path, IMG)
    prot = load_pe(prot_path, IMG)

    # Unicorn her fonksiyon icin taze instance (bayrak/state kirliligi yok)
    fails, oks = [], 0
    for name, rva in sorted(orig['exports'].items()):
        if not name.startswith('t_'):
            continue
        args = ARGS.get(name)
        if args is None:
            continue
        # --- orijinal (native Unicorn) ---
        mu1 = Uc(UC_ARCH_X86, UC_MODE_32)
        mu1.mem_map(IMG, IMGSZ)
        for a, raw, vsz, nm in orig['secs']:
            mu1.mem_write(a, raw)
        setup_world(mu1, orig['delta'])
        eax1, err1 = run_func(orig, mu1, rva, args)

        # --- korumali (stub + VM) — blob fs:[abs] siteleri hook'lanir ---
        mu2 = Uc(UC_ARCH_X86, UC_MODE_32)
        mu2.mem_map(IMG, IMGSZ)
        for a, raw, vsz, nm in prot['secs']:
            mu2.mem_write(a, raw)
        setup_world(mu2, prot['delta'])
        # vm blob'nu .vmp0 seciyonunda bul (MZ... blob flat .text)
        blob = b''
        for a, raw, vsz, nm in prot['secs']:
            if nm.startswith('.vmp'):
                blob = raw
                break
        fs_sites = find_fs_sites(blob)
        # blob'un sektor RVA'si
        blob_rva = 0
        for a, raw, vsz, nm in prot['secs']:
            if nm.startswith('.vmp'):
                blob_rva = a - IMG
        fs_offs = [(off, disp) for off, disp in fs_sites]
        eax2, err2 = run_func(prot, mu2, rva, args, fs_sites=fs_offs,
                              blob_base=IMG + blob_rva)

        st = 'ESIT' if (err1 == 'OK' and err2 == 'OK' and eax1 == eax2) else 'FARK'
        if st == 'ESIT':
            oks += 1
        else:
            fails.append(name)
        print('%-10s native=%08X (%s)  vm=%08X (%s)  -> %s' % (
            name, eax1, err1, eax2, err2, st))
    print('== SONUC: %d/%d ESIT' % (oks, oks + len(fails)))
    if fails:
        print('BASARISIZ:', ', '.join(fails))
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
