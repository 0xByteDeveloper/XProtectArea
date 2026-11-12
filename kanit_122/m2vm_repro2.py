#!/usr/bin/env python3
# m2vm_repro2.py — TAM anti-debug bataryasi reprodüksiyonu:
# sahte kernel32/ntdll (LDR + export tablolari + API stub'lari) ile
# CheckDebugger exe'sinin VM bataryasini Unicorn'da kosturur.
import struct, sys
from unicorn import *
from unicorn.x86_const import *

IMG   = 0x00400000
STK   = 0x00300000; STKSZ = 0x00100000
TEB   = 0x7FFDF000; PEB = 0x7FFDE000; LDR = 0x7FFDD000
CALLP = 0x00A00000; STOP = 0x00A01000
FUNC  = 0x004D7610
STUBS = [0x004DC1A0, 0x004D7670, 0x00541660, 0x00552520]
K32   = 0x00D00000; NTD = 0x00E00000     # sahte modul tabanlari

def load_pe(mu, path, base):
    import pefile
    pe = pefile.PE(path)
    for s in pe.sections:
        va = base + s.VirtualAddress
        vs = (s.Misc_VirtualSize + 0xFFF) & ~0xFFF
        try: mu.mem_map(va, max(vs, 0x1000))
        except UcError: pass
        raw = s.get_data()
        if raw: mu.mem_write(va, raw)
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

def w32(mu, a, v): mu.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))
def w16(mu, a, v): mu.mem_write(a, struct.pack('<H', v & 0xFFFF))

def build_fake_module(mu, base, name_w, funcs):
    """funcs: [(isim, kod baytlari)] — export tablosu + isimler + stub kodlari"""
    mu.mem_map(base, 0x10000)
    # --- MZ/PE iskeleti ---
    mu.mem_write(base, b'MZ')
    w32(mu, base + 0x3C, 0x80)
    mu.mem_write(base + 0x80, b'PE\x00\x00')
    w16(mu, base + 0x80 + 4, 0x14C)   # machine
    w16(mu, base + 0x80 + 24, 0x10B)  # optional magic (PE32)
    # export dizini RVA (pe+24+96): 0x200'e
    w32(mu, base + 0x80 + 24 + 96, 0x200)
    # --- export tablosu (RVA 0x200) ---
    ex = base + 0x200
    w32(mu, ex + 24, len(funcs))            # NumberOfNames
    w32(mu, ex + 28, 0x300)                 # AddressOfFunctions RVA
    w32(mu, ex + 32, 0x340)                 # AddressOfNames RVA
    w32(mu, ex + 36, 0x380)                 # AddressOfNameOrdinals RVA
    # isimler (0x340): her isim bir RVA; stringler 0x400'den
    # fonksiyonlar (0x300): her kod 0x800'den (64B alan)
    for i, (nm, code) in enumerate(funcs):
        w32(mu, base + 0x300 + 4 * i, 0x800 + 0x40 * i)   # func RVA
        w32(mu, base + 0x340 + 4 * i, 0x400 + 0x40 * i)   # name RVA
        w16(mu, base + 0x380 + 2 * i, i)                   # ordinal
        mu.mem_write(base + 0x400 + 0x40 * i, nm.encode() + b'\x00')
        mu.mem_write(base + 0x800 + 0x40 * i, code)
    # --- LDR girisi icin modul ismi (genis-karakter) ---
    nb = base + 0x500
    w32(mu, nb - 4, 0)  # (Buffer'dan once Length alani ent+0x2C'de olur)
    wstr = name_w.encode('utf-16-le') + b'\x00\x00'
    mu.mem_write(nb, wstr)
    return nb

def build_env(mu, stub_ret, api_mode=True):
    mu.mem_map(STK, STKSZ)
    mu.mem_map(TEB, 0x1000); mu.mem_map(PEB, 0x1000); mu.mem_map(LDR, 0x1000)
    mu.mem_map(CALLP, 0x2000)
    mu.mem_write(TEB + 0x18, struct.pack('<I', TEB))
    mu.mem_write(PEB + 2, b'\x00')
    w32(mu, PEB + 0x68, 0)
    w32(mu, PEB + 0x0C, LDR)
    # LDR bolumu + 2 giris (InMemoryOrderLinks @ ent+0x08)
    ent_k32 = LDR + 0x60
    ent_ntd = LDR + 0x90
    # head.next = k32 linki; k32->ntd; ntd->head
    w32(mu, LDR + 0x14, ent_k32 + 0x08)
    w32(mu, ent_k32 + 0x08, ent_ntd + 0x08)
    w32(mu, ent_ntd + 0x08, LDR + 0x14)
    # giris alanlari: +0x18 DllBase, +0x2C Length, +0x30 Buffer
    if api_mode:
        nb_k32 = build_fake_module(mu, K32, 'kernel32.dll', [
            # GetThreadContext(h, ctx) — stdcall ret 8; basari, DR=0
            ('GetThreadContext',
             b'\x56\x8b\x74\x24\x0c\x31\xc0'          # push esi; mov esi,[esp+0xc]
             b'\x89\x46\x04\x89\x46\x08\x89\x46\x0c'  # [ctx+4..0xC]=0
             b'\x89\x46\x10\x5e\xb8\x01\x00\x00\x00\xc2\x08\x00'),
            # CloseHandle(h) — stdcall ret 4; FALSE
            ('CloseHandle', b'\x31\xc0\xc2\x04\x00'),
        ])
        nb_ntd = build_fake_module(mu, NTD, 'ntdll.dll', [
            # NtSetInformationThread(h,cls,info,len) — stdcall ret 16; 0
            ('NtSetInformationThread', b'\x31\xc0\xc2\x10\x00'),
            # NtQuerySystemInformation(cls,buf,len,rl) — stdcall ret 16; INFO_MISMATCH
            ('NtQuerySystemInformation', b'\xb8\x04\x00\x00\xc0\xc2\x10\x00'),
            # NtQueryInformationProcess(h,cls,buf,len,rl) — stdcall ret 20; PORT_NOT_SET
            ('NtQueryInformationProcess', b'\xb8\x53\x03\x00\xc0\xc2\x14\x00'),
        ])
        w32(mu, ent_k32 + 0x18, K32); w32(mu, ent_k32 + 0x2C, 24); w32(mu, ent_k32 + 0x30, nb_k32)
        w32(mu, ent_ntd + 0x18, NTD); w32(mu, ent_ntd + 0x2C, 18); w32(mu, ent_ntd + 0x30, nb_ntd)
    else:
        # bos liste: batarya API kismi atlar
        w32(mu, LDR + 0x14, LDR + 0x40)
        w32(mu, LDR + 0x40 + 8, LDR + 0x14)
    # ic-cagri stublari
    for t in STUBS:
        if t == 0x004D7670:
            code = b'\x31\xc0\xc2\x08\x00' if not stub_ret else b'\xb0\x01\xc2\x08\x00'
        elif t == 0x004DC1A0:
            code = b'\xb0\x00\xc3' if not stub_ret else b'\xb0\x01\xc3'
        else:
            code = b'\xb0\x00\xc3'
        mu.mem_write(t, code)

def run(path, stub_ret=False, api_mode=True, hooks=None):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    load_pe(mu, path, IMG)
    build_env(mu, stub_ret, api_mode)
    args2 = 0x11223344; args1 = 0x55; this = 0x00A02000
    mu.mem_map(this & ~0xFFF, 0x1000)
    code = (b'\x68' + struct.pack('<I', args2) +
            b'\x68' + struct.pack('<I', args1) +
            b'\xb9' + struct.pack('<I', this) +
            b'\xe8' + struct.pack('<i', FUNC - (CALLP + 5 + 5 + 5 + 5)) +
            b'\x89\xc2' + b'\xeb\xfe')
    mu.mem_write(CALLP, code)
    stop_at = CALLP + 5 + 5 + 5 + 5 + 2
    esp = STK + STKSZ - 0x8000
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, esp + 0x100)
    mu.reg_write(UC_X86_REG_ECX, this)
    log = []
    if hooks:
        def hk(mu, addr, size, ud):
            log.append(addr)
        mu.hook_add(UC_HOOK_CODE, hk, begin=hooks[0], end=hooks[1])
    err = 'OK'
    try:
        mu.emu_start(CALLP, stop_at, timeout=60_000_000, count=200_000_000)
    except UcError as e:
        err = 'UCERR %s eip=0x%08X esp=%08X' % (e.errno, mu.reg_read(UC_X86_REG_EIP),
                                                mu.reg_read(UC_X86_REG_ESP))
    eax = mu.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF
    return eax, err, mu, log

def main():
    up = '/home/z/my-project/upload/'
    for api in (True,):
        for stub_ret in (False, True):
            print('=== API=%s stub=%s ===' % (api, 'TRUE' if stub_ret else 'FALSE'))
            for fn, tag in [('metin2client.exe', 'ORIJINAL'),
                            ('metin2client_vmp.exe', 'NORMAL'),
                            ('metin2client_vmp_CheckDebugger.exe', 'CHECKDBG')]:
                eax, err, mu, log = run(up + fn, stub_ret, api)
                print('  %-8s eax=%08X %s' % (tag, eax, err))
                if err != 'OK':
                    eip = mu.reg_read(UC_X86_REG_EIP)
                    print('           -> EIP=%08X  .vmp0-rel=%s' %
                          (eip, hex(eip - 0x942000) if 0x942000 <= eip < 0x94E1E8 else '-'))

if __name__ == '__main__':
    main()
