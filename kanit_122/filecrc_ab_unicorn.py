#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
filecrc_ab_unicorn.py — FileCRC çökmesi A/B dinamik kanıtı (Unicorn x86).

A) ESKİ blob (ENT_FULLBUF_OFF=0x2C): sahte x86 PEB/LDR'da FullDllName.Buffer
   yerine BaseDllName.Length+MaximumLength'i (0x002A0028) işaretçi sanıp
   okur -> movzx ecx,word ptr [edx] AV @ 0x002A0028.
   Kullanıcı errorlog (edx=0x002a0028, Exc 0xC0000005) birebir reprodüksiyon.
B) YENİ blob (0x28): yol bulunur -> CreateFileA/ReadFile emülsyonu ->
   CRC eşleşir -> xrt_entry 0 döner. Tersine kanıt: bozuk CRC -> err=3.

x86 LDR_DATA_TABLE_ENTRY (InMemoryOrderLinks +0x08):
  +0x18 DllBase, +0x24 FullDllName{Len,Max,Buffer@+0x28},
  +0x2C BaseDllName{Len,Max,Buffer@+0x30}
IMAGE_EXPORT_DIRECTORY (winnt.h): +0x14 NoF, +0x18 NoN, +0x1C AoF,
  +0x20 AoN, +0x24 AoO.
"""
import struct
import unicorn as uc
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ESP, UC_X86_REG_EBP,
    UC_X86_REG_MSR)

BLOB_BASE = 0x00100000
STACK_TOP = 0x00210000
STACK_BOT = 0x001F0000
PEB_ADDR  = 0x7FFDD000
LDR_ADDR  = 0x7FFDD100
ENT_EXE   = 0x7FFDD200
ENT_K32   = 0x7FFDD300
WBUF      = 0x7FFDE000
K32       = 0x75330000
EXE_BASE  = 0x00B90000          # kullanıcının ASLR base'i (ebp=0x00b90000)
CFG_ADDR  = 0x00B91000
GDT_ADDR  = 0x00120000          # kullanilmiyor (FS base MSR ile kuruluyor)
SENTINEL  = 0x00110000
XRT_ENTRY_OFF = 0x2710

WIDE_PATH = "C:\\Users\\Admin\\Desktop\\NightTownFullpack\\metin2client_vmp.exe"
BASE_NAME = "metin2client_vmp.exe"
K32_NAME  = "kernel32.dll"

FILEBYTES = bytes(((i * 131 + 17) & 0xFF) for i in range(9227))
CKOFF, VR0, VR1 = 0x58, 0x10, 0x14

def crc_up(c, b):
    c ^= b
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 if (c & 1) else 0)
    return c & 0xFFFFFFFF

def beklenen_crc():
    c = 0xFFFFFFFF
    for a, b in enumerate(FILEBYTES):
        if not ((CKOFF <= a < CKOFF + 4) or (VR0 <= a < VR1)):
            c = crc_up(c, b)
    return (~c) & 0xFFFFFFFF

def fnv_a(s):
    h = 2166136261
    for ch in s.encode():
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return h

def fnv_w(s):
    h = 2166136261
    for ch in s:
        if 'A' <= ch <= 'Z':
            ch = chr(ord(ch) + 32)
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return h

EXPORTS = ["CreateFileA", "ReadFile", "CloseHandle",
           "GetModuleFileNameA", "ExitProcess", "MessageBoxA"]
API = {}

def desc(base):
    # 8B kesim tanımlayıcısı: limit_lo(2) base(3x1B) access(1B) flags(1B) base_hi(2x1B)
    return struct.pack('<HBBBBBB', 0xFFFF, base & 0xFF, (base >> 8) & 0xFF,
                       0x92, 0xCF, (base >> 16) & 0xFF, (base >> 24) & 0xFF)

def sahte_peb_region():
    r = bytearray(0x5000)  # PEB@0, LDR@0x100, ent@0x200/0x300, WBUF@0x1000, TEB@0x4000
    wide = WIDE_PATH.encode('utf-16-le') + b'\0\0'
    base = BASE_NAME.encode('utf-16-le') + b'\0\0'
    k32w = K32_NAME.encode('utf-16-le') + b'\0\0'
    r[0x1000:0x1000 + len(wide)] = wide
    r[0x1000 + len(wide):0x1000 + len(wide) + len(base)] = base
    r[0x1000 + len(wide) + len(base):0x1000 + len(wide) + len(base) + len(k32w)] = k32w
    pFull = PEB_ADDR + 0x1000
    pBase = pFull + len(wide)
    pK32 = pBase + len(base)
    struct.pack_into('<I', r, 0x0C, LDR_ADDR)              # PEB->Ldr
    struct.pack_into('<I', r, 0x114, ENT_EXE + 0x08)       # head.Flink
    struct.pack_into('<I', r, 0x118, ENT_K32 + 0x08)       # head.Blink
    e = 0x200
    struct.pack_into('<I', r, e + 0x08, ENT_K32 + 0x08)    # exe Flink
    struct.pack_into('<I', r, e + 0x0C, LDR_ADDR + 0x14)    # exe Blink
    struct.pack_into('<I', r, e + 0x18, EXE_BASE)          # DllBase
    struct.pack_into('<H', r, e + 0x24, len(wide) - 2)     # FullDllName.Length
    struct.pack_into('<H', r, e + 0x26, len(wide))
    struct.pack_into('<I', r, e + 0x28, pFull)             # FullDllName.Buffer (DÜZELTİLEN)
    struct.pack_into('<H', r, e + 0x2C, len(base) - 2)     # BaseDllName.Length = 0x28
    struct.pack_into('<H', r, e + 0x2E, len(base))         # Max = 0x2A
    struct.pack_into('<I', r, e + 0x30, pBase)
    k = 0x300
    struct.pack_into('<I', r, k + 0x08, LDR_ADDR + 0x14)   # k32 Flink -> head
    struct.pack_into('<I', r, k + 0x0C, ENT_EXE + 0x08)
    struct.pack_into('<I', r, k + 0x18, K32)
    struct.pack_into('<H', r, k + 0x24, len(k32w) - 2)
    struct.pack_into('<H', r, k + 0x26, len(k32w))
    struct.pack_into('<I', r, k + 0x28, pK32)
    struct.pack_into('<H', r, k + 0x2C, len(k32w) - 2)
    struct.pack_into('<H', r, k + 0x2E, len(k32w))
    struct.pack_into('<I', r, k + 0x30, pK32)
    # TEB: fs:[0x30] = PEB işaretçisi (gerçek x86 TEB+0x30 semantiği)
    struct.pack_into('<I', r, 0x4030, PEB_ADDR)
    return r

def sahte_k32_region():
    r = bytearray(0x1000)
    r[0:2] = b'MZ'
    struct.pack_into('<I', r, 0x3C, 0x40)
    r[0x40:0x44] = b'PE\0\0'
    struct.pack_into('<H', r, 0x40 + 24, 0x10B)
    struct.pack_into('<I', r, 0x40 + 24 + 96, 0x100)       # export DD RVA
    N = len(EXPORTS)
    struct.pack_into('<I', r, 0x100 + 0x0C, 0x700)          # Name RVA
    struct.pack_into('<I', r, 0x100 + 0x10, 1)             # Base
    struct.pack_into('<I', r, 0x100 + 0x14, N)             # NumberOfFunctions
    struct.pack_into('<I', r, 0x100 + 0x18, N)             # NumberOfNames
    struct.pack_into('<I', r, 0x100 + 0x1C, 0x200)         # AddressOfFunctions
    struct.pack_into('<I', r, 0x100 + 0x20, 0x300)         # AddressOfNames
    struct.pack_into('<I', r, 0x100 + 0x24, 0x400)         # AddressOfNameOrdinals
    sz = 0x500
    for i, nm in enumerate(EXPORTS):
        rva_stub = 0x600 + i * 16
        struct.pack_into('<I', r, 0x200 + 4 * i, rva_stub)
        struct.pack_into('<I', r, 0x300 + 4 * i, sz)
        struct.pack_into('<H', r, 0x400 + 2 * i, i)
        r[sz:sz + len(nm) + 1] = nm.encode() + b'\0'
        sz += len(nm) + 1
        API[nm] = K32 + rva_stub
    return r

def kur_cfg(filecrc):
    cfg = bytearray(0x40)
    struct.pack_into('<I', cfg, 0x00, 0x31545258)
    struct.pack_into('<I', cfg, 0x04, 0x04 | 0x08 | 0x10)  # FILECRC+MSG+EXIT
    struct.pack_into('<I', cfg, 0x2C, filecrc)
    struct.pack_into('<I', cfg, 0x30, VR0)
    struct.pack_into('<I', cfg, 0x34, VR1)
    struct.pack_into('<I', cfg, 0x38, CKOFF)
    struct.pack_into('<I', cfg, 0x3C, 0x1000)
    return cfg

def calistir(blob_yolu, filecrc, etiket):
    API.clear()
    peb = sahte_peb_region()
    k32r = sahte_k32_region()
    cfg = kur_cfg(filecrc)
    blob = open(blob_yolu, 'rb').read()

    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(BLOB_BASE, 0x30000)                 # blob + sentinel + gdt
    u.mem_map(STACK_BOT, 0x30000)
    u.mem_map(EXE_BASE, 0x3000)
    u.mem_map(PEB_ADDR, 0x30000)
    u.mem_map(K32, 0x1000)
    u.mem_write(BLOB_BASE, blob)
    u.mem_write(PEB_ADDR, bytes(peb))
    u.mem_write(K32, bytes(k32r))
    u.mem_write(CFG_ADDR, bytes(cfg))
    # FS base = TEB (PEB+0x4000); fs:[0x30] içindeki PEB işaretçisinden yürünür
    u.reg_write(UC_X86_REG_MSR, (0xC0000100, PEB_ADDR + 0x4000))

    durum = {'son': None, 'eax': None, 'exit': None, 'mb': False,
             'path': None, 'cfa': None, 'okuyuldu': bytearray(), 'av': None}

    def w32(a, v):
        u.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))
    def stdcall_ret(nargs, retval):
        esp = u.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', bytes(u.mem_read(esp, 4)))[0]
        u.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * nargs)
        u.reg_write(UC_X86_REG_EAX, retval)
        u.reg_write(uc.x86_const.UC_X86_REG_EIP, ret)

    def kod_kanca(uc_, adr, boy, kutu):
        if adr == SENTINEL:
            durum['son'] = 'dondu'
            durum['eax'] = u.reg_read(UC_X86_REG_EAX)
            u.emu_stop()
            return
        if adr not in API.values():
            return
        esp = u.reg_read(UC_X86_REG_ESP)
        arg = lambda i: struct.unpack('<I', bytes(u.mem_read(esp + 4 + 4 * i, 4)))[0]
        if adr == API['CreateFileA']:
            p = arg(0)
            durum['path'] = bytes(u.mem_read(p, 96)).split(b'\0')[0].decode('latin1')
            durum['cfa'] = arg(1)
            stdcall_ret(7, 0x2A00)
        elif adr == API['ReadFile']:
            buf, n, got = arg(1), arg(2), arg(3)
            off = len(durum['okuyuldu'])
            k = min(n, len(FILEBYTES) - off)
            u.mem_write(buf, FILEBYTES[off:off + k])
            w32(got, k)
            durum['okuyuldu'] += FILEBYTES[off:off + k]
            stdcall_ret(5, 1)
        elif adr == API['CloseHandle']:
            stdcall_ret(1, 1)
        elif adr == API['GetModuleFileNameA']:
            stdcall_ret(3, 0)
        elif adr == API['ExitProcess']:
            durum['exit'] = arg(0)
            durum['son'] = 'exit'
            u.emu_stop()
        elif adr == API['MessageBoxA']:
            durum['mb'] = True
            stdcall_ret(4, 1)

    def mem_kanca(uc_, erisim, adr, boy, deger, kutu):
        durum.setdefault('faultlar', []).append((erisim, adr, u.reg_read(uc.x86_const.UC_X86_REG_EIP)))
        if 0x2A0000 <= adr < 0x2A1000:
            durum['av'] = adr
            durum['son'] = 'AV'
            u.emu_stop()
            return False
        return False   # bilinmeyen erisim: dur ve raporla

    u.hook_add(uc.UC_HOOK_CODE, kod_kanca, None, begin=SENTINEL, end=SENTINEL + 1)
    for b in list(API.values()):
        u.hook_add(uc.UC_HOOK_CODE, kod_kanca, None, begin=b, end=b + 1)
    u.hook_add(uc.UC_HOOK_MEM_INVALID, mem_kanca)
    if __import__('os').environ.get('XRT_IZ'):
        _iz = {'n': 0}
        def iz_kanca(uc_, adr, boy, kutu):
            if _iz['n'] < 120:
                print("   EIP %08X" % adr)
                _iz['n'] += 1
        u.hook_add(uc.UC_HOOK_CODE, iz_kanca)

    # cdecl: [esp]=dönüş adresi (SENTINEL), [esp+4]=argüman (cfg)
    u.mem_write(STACK_TOP - 8, struct.pack('<I', SENTINEL))
    u.mem_write(STACK_TOP - 4, struct.pack('<I', CFG_ADDR))
    u.reg_write(UC_X86_REG_ESP, STACK_TOP - 8)
    u.reg_write(UC_X86_REG_EBP, STACK_TOP)
    try:
        u.emu_start(BLOB_BASE + XRT_ENTRY_OFF, SENTINEL, timeout=20 * uc.UC_SECOND_SCALE)
    except uc.UcError as e:
        if durum['son'] is None:
            durum['son'] = 'uc_err:%s' % e
    if durum['son'] is None:
        eip = u.reg_read(uc.x86_const.UC_X86_REG_EIP)
        if eip == SENTINEL:
            durum['son'] = 'dondu'
            durum['eax'] = u.reg_read(UC_X86_REG_EAX)

    print("[%s]" % etiket)
    if durum['son'] == 'AV':
        print("  >>> AV @ %08X — KULLANICI ÇÖKMESİ BİREBİR YENİDEN ÜRETİLDİ" % durum['av'])
        print("      (edx=0x002A0028 = BaseDllName MaxLen<<16|Length — errorlog ile aynı)")
    elif durum['son'] == 'exit':
        print("  ExitProcess(0x%X) — tamper yolu (0x73 = 0x70+3 file-CRC) MessageBox=%s"
              % (durum['exit'], durum['mb']))
    elif durum['son'] == 'dondu':
        print("  xrt_entry döndü: %s (0=başarılı, 3=file-CRC hatası)" % durum['eax'])
        print("  yol = %r  (beklenen: %r)" % (durum['path'], WIDE_PATH))
        print("  yol doğru = %s" % (durum['path'] == WIDE_PATH))
        print("  CreateFileA erişim = %s (0x80000000 GENERIC_READ)" % hex(durum['cfa'] or 0))
        print("  ReadFile toplam = %d / %d bayt, içerik birebir = %s"
              % (len(durum['okuyuldu']), len(FILEBYTES), bytes(durum['okuyuldu']) == FILEBYTES))
    else:
        print("  BEKLENMEDİK DURUM: %r" % durum['son'])
        print("  faultlar: %s" % durum.get('faultlar'))
    return durum

if __name__ == '__main__':
    YENI = '/tmp/my-project/download/XProtect_1.2.2/source/xrt86.bin'
    ESKI = '/tmp/my-project/download/XProtect_1.2.2/source/xrt86_old.bin'
    CRC = beklenen_crc()
    print("beklenen dosya CRC = %08X  (atlamalar: ckoff=%X, vr=%X..%X)\n" % (CRC, CKOFF, VR0, VR1))
    print("### A) ESKİ blob (ENT_FULLBUF_OFF=0x2C) — çökme reprodüksiyonu ###")
    dA = calistir(ESKI, CRC, 'ESKİ 0x2C')
    print()
    print("### B1) YENİ blob (0x28) — CRC doğru → başarı ###")
    dB1 = calistir(YENI, CRC, 'YENİ 0x28 doğru-CRC')
    print()
    print("### B2) YENİ blob (0x28) — CRC bozuk → tamper tespiti ###")
    dB2 = calistir(YENI, (CRC ^ 0x55) & 0xFFFFFFFF, 'YENİ 0x28 bozuk-CRC')
    print()
    print("hash doğrulama: fnv_a('CreateFileA')=%08X (XH_CREATEFILEA=0xBDCAC9CE)"
          % fnv_a('CreateFileA'))
    print("                fnv_w('kernel32.dll')=%08X (XH_KERNEL32=0xA3E6F6C3)"
          % fnv_w(K32_NAME))
    ok = (dA['son'] == 'AV' and dA.get('av') == 0x2A0028
          and dB1['son'] == 'dondu' and dB1['eax'] == 0 and dB1['path'] == WIDE_PATH
          and bytes(dB1['okuyuldu']) == FILEBYTES
          and (dB2['son'] == 'exit' or (dB2['son'] == 'dondu' and dB2['eax'] == 3)))
    print("\nSONUÇ: %s" % ("A/B KANITI TAM — eski çöküyor, yeni tam yol + CRC + tamper tespiti" if ok else "KANIT SORUNU — kontrol et"))
