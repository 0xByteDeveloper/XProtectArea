#!/usr/bin/env python3
# xrt_crc_check.py — korunmus exe'nin cfg'sindeki CRC'leri, xrt algoritmasinin
# Python aynasi ile yeniden hesaplayip karsilastirir (hangi taraf hatali?).
import struct, sys
import pefile

def crc_up(c, b):
    c ^= b
    for _ in range(8):
        c = (c >> 1) ^ (0xEDB88320 & (0 - (c & 1)))
        c &= 0xFFFFFFFF
    return c

def crc_text(d, text_rva, text_sz, reloc_bytes):
    # xrt crc_text aynasi: sayfa sayfa, reloc yamalarini atla
    c = 0xFFFFFFFF
    pg = 0
    while pg < text_sz:
        pgrva = text_rva + pg
        plen = min(0x1000, text_sz - pg)
        flag = [0] * (4096 + 16)
        if reloc_bytes:
            ro = 0
            while ro + 8 <= len(reloc_bytes):
                page_rva, bsz = struct.unpack_from('<II', reloc_bytes, ro)
                if bsz < 8 or ro + bsz > len(reloc_bytes):
                    break
                if page_rva == pgrva:
                    eo = 8
                    while eo + 2 <= bsz:
                        e = struct.unpack_from('<H', reloc_bytes, ro + eo)[0]
                        typ, off = e >> 12, e & 0xFFF
                        ln = 4 if typ == 3 else (8 if typ == 10 else 0)
                        if ln and off < plen + 8:
                            for i in range(ln):
                                if off + i < len(flag):
                                    flag[off + i] = 1
                        eo += 2
                ro += bsz
        for i in range(plen):
            if not flag[i]:
                c = crc_up(c, d[pgrva + i])
        pg += 0x1000
    return (~c) & 0xFFFFFFFF

def main(path):
    pe = pefile.PE(path, fast_load=True)
    d = open(path, 'rb').read()
    ib = pe.OPTIONAL_HEADER.ImageBase
    # .vmp0 icinde cfg'yi bul: XRT1 magic tara
    vmp = [s for s in pe.sections if s.Name.decode().startswith('.vmp0')][0]
    vraw = d[vmp.PointerToRawData : vmp.PointerToRawData + vmp.SizeOfRawData]
    off = vraw.rfind(struct.pack("<I", 0x31545258))
    assert off >= 0, 'cfg bulunamadi'
    cfg = vraw[off:off + 0x40]
    f = lambda o: struct.unpack_from('<I', cfg, o)[0]
    flags, state = f(4), f(8)
    self_rva, self_len, self_crc = f(0xC), f(0x10), f(0x14)
    text_rva, text_sz, text_crc = f(0x18), f(0x1C), f(0x20)
    rel_rva, rel_sz = f(0x24), f(0x28)
    file_crc, v0, v1 = f(0x2C), f(0x30), f(0x34)
    cksum_off, cfg_rva = f(0x38), f(0x3C)
    print(f"cfg @.vmp0+0x{off:X} flags=0x{flags:X} state={state}")
    print(f"  self rva=0x{self_rva:X} len={self_len} crc=0x{self_crc:08X}")
    print(f"  text rva=0x{text_rva:X} sz=0x{text_sz:X} crc=0x{text_crc:08X} reloc=0x{rel_rva:X}+0x{rel_sz:X}")
    print(f"  file crc=0x{file_crc:08X} skip=[{v0},{v1}) cksum@{cksum_off}")
    # bellek modeli: dosya baytlari RVA ile (hizali tam goruntu)
    top = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
    img = bytearray((top + 0xFFF) & ~0xFFF)
    for s in pe.sections:
        if s.SizeOfRawData:
            img[s.VirtualAddress : s.VirtualAddress + s.SizeOfRawData] = \
                d[s.PointerToRawData : s.PointerToRawData + s.SizeOfRawData]
    # self crc
    c = 0xFFFFFFFF
    for i in range(self_len):
        c = crc_up(c, img[self_rva + i])
    print(f"  HESAP self = 0x{(~c) & 0xFFFFFFFF:08X}  {'ESLESIYOR' if ((~c)&0xFFFFFFFF)==self_crc else 'FAARKLI!'}")
    # text crc
    rel = bytes(img[rel_rva : rel_rva + rel_sz]) if rel_rva else b''
    tc = crc_text(img, text_rva, text_sz, rel)
    print(f"  HESAP text = 0x{tc:08X}  {'ESLESIYOR' if tc == text_crc else 'FAARKLI!'}")
    # file crc
    c = 0xFFFFFFFF
    for i in range(len(d)):
        if cksum_off <= i < cksum_off + 4: continue
        if v0 <= i < v1: continue
        c = crc_up(c, d[i])
    print(f"  HESAP file = 0x{(~c) & 0xFFFFFFFF:08X}  {'ESLESIYOR' if ((~c)&0xFFFFFFFF)==file_crc else 'FAARKLI!'}")

if __name__ == '__main__':
    main(sys.argv[1])
