#!/usr/bin/env python3
# m2vm_repro.py — metin2 0xD7610 ULTRA(M+V) CheckDebugger cökme reprodüksiyonu
# Orijinal / normal-korumali / CheckDebugger-korumali exe'leri Unicorn'da
# ayni cagri senaryosuyla kosturur; farklari ve cökme EIP'ini raporlar.
import struct, sys
from unicorn import *
from unicorn.x86_const import *

IMG   = 0x00400000
STK   = 0x00300000; STKSZ = 0x00100000
TEB   = 0x7FFDF000; PEB = 0x7FFDE000; LDR = 0x7FFDD000
CALLP = 0x00A00000        # cagirici kod sayfasi (goruntu 0x942000'e kadar)
STOP  = 0x00A01000        # durdurma adresi
FUNC  = 0x004D7610        # hasar fonksiyonu VA (imagebase 0x400000)
# ic cagrilar (VA): [doncek al] -> stub
STUBS = [0x004DC1A0, 0x004D7670, 0x00541660, 0x00552520]

def load_pe(mu, path, base):
    import pefile
    pe = pefile.PE(path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    delta = base - ib
    for s in pe.sections:
        va = base + s.VirtualAddress
        vs = (s.Misc_VirtualSize + 0xFFF) & ~0xFFF
        try: mu.mem_map(va, max(vs, 0x1000))
        except UcError: pass
        raw = s.get_data()
        if raw: mu.mem_write(va, raw)
    # fs:[disp] okumalarini yamala: 64 A1 d32 -> B8 val 90 90
    for s in pe.sections:
        va = base + s.VirtualAddress
        raw = s.get_data()
        blob = bytearray(raw); off = 0; n = 0
        while True:
            i = blob.find(b'\x64\xA1', off)
            if i < 0 or i + 6 > len(blob): break
            disp = struct.unpack_from('<I', blob, i + 2)[0]
            val = TEB if disp == 0x18 else (PEB if disp == 0x30 else 0)
            blob[i:i+6] = b'\xB8' + struct.pack('<I', val) + b'\x90'
            off = i + 6; n += 1
        if n: mu.mem_write(va, bytes(blob))
    return pe

def build_env(mu, stub_ret):
    mu.mem_map(STK, STKSZ)
    mu.mem_map(TEB, 0x1000); mu.mem_map(PEB, 0x1000); mu.mem_map(LDR, 0x1000)
    mu.mem_map(CALLP, 0x2000)
    # TEB
    mu.mem_write(TEB + 0x18, struct.pack('<I', TEB))     # self
    mu.mem_write(TEB + 0x30, struct.pack('<I', PEB))      # PEB (yamali kod bunu kullanmaz ama olur)
    # PEB: temiz makine — BeingDebugged=0, NtGlobalFlag=0
    mu.mem_write(PEB + 2,  b'\x00')
    mu.mem_write(PEB + 0x68, struct.pack('<I', 0))
    # LDR: BOS modul listesi -> xa_module 0 doner -> API bataryasi atlar
    mu.mem_write(PEB + 0x0C, struct.pack('<I', LDR))
    mu.mem_write(LDR + 0x14, struct.pack('<I', LDR + 0x40))   # head.next = kendisi
    mu.mem_write(LDR + 0x40 + 8, struct.pack('<I', LDR + 0x14))
    # ic-cagri stub'lari: xor eax,eax; ret / ret 8 / mov al,ret8-degisken
    for t in STUBS:
        if t == 0x004D7670:
            code = b'\x31\xc0\xc2\x08\x00' if not stub_ret else b'\xb0\x01\xc2\x08\x00'
        elif t == 0x004DC1A0:
            code = b'\xb0\x00\xc3' if not stub_ret else b'\xb0\x01\xc3'
        else:
            code = b'\xb0\x00\xc3'
        mu.mem_write(t, code)

def run(path, stub_ret=False, trace=False):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    load_pe(mu, path, IMG)
    build_env(mu, stub_ret)
    # cagirici: push arg2; push arg1; mov ecx,this; call FUNC; ...dur
    args2 = 0x11223344; args1 = 0x55; this = 0x00A02000
    mu.mem_map(this & ~0xFFF, 0x1000)  # this-bellek (yazilabilir)
    code = (b'\x68' + struct.pack('<I', args2) +
            b'\x68' + struct.pack('<I', args1) +
            b'\xb9' + struct.pack('<I', this) +
            b'\xe8' + struct.pack('<i', FUNC - (CALLP + 5 + 5 + 5 + 5)) +
            b'\x89\xc2' +                       # mov edx,eax (dönüşü koru)
            b'\xeb\xfe')                        # dur (sonsuz döngü=stop noktası)
    mu.mem_write(CALLP, code)
    stop_at = CALLP + 5 + 5 + 5 + 5 + 2
    esp = STK + STKSZ - 0x8000
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, esp + 0x100)
    mu.reg_write(UC_X86_REG_ECX, this)
    err = 'OK'
    # iz: CHKRET okuma adresleri (blob icinde mrd cagrilari) yakalamak icin
    hits = []
    try:
        mu.emu_start(CALLP, stop_at, timeout=60_000_000, count=200_000_000)
    except UcError as e:
        err = 'UCERR %s eip=0x%08X esp=0x%08X' % (e.errno, mu.reg_read(UC_X86_REG_EIP),
                                                  mu.reg_read(UC_X86_REG_ESP))
    eax = mu.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF
    return eax, err, mu

def main():
    up = '/home/z/my-project/upload/'
    exes = [('metin2client.exe', 'ORIJINAL'),
            ('metin2client_vmp.exe', 'NORMAL'),
            ('metin2client_vmp_CheckDebugger.exe', 'CHECKDBG')]
    for stub_ret in (False, True):
        print('=== ic-cagri stub donusu %s ===' % ('TRUE' if stub_ret else 'FALSE'))
        for fn, tag in exes:
            eax, err, mu = run(up + fn, stub_ret)
            print('  %-8s eax=%08X %s' % (tag, eax, err))
            if err != 'OK':
                eip = mu.reg_read(UC_X86_REG_EIP)
                print('           -> cökme EIP=%08X  (.vmp0 Relative: %s)'
                      % (eip, hex(eip - 0x942000) if 0x942000 <= eip < 0x94E1E8 else 'DISARI'))

if __name__ == '__main__':
    main()
