#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_rsrc.py — PE'ye .rsrc bolumu + RCDATA kaynagi ekler (B3 kanit testi icin)
Kullanim: python3 add_rsrc.py <girdi.exe> <cikti.exe> "XPROTECT-RES-GIZLI-042"
RDT agaci (Windows birebir):
  @0  Root dir hdr (Named=0, ID=1)
  @16 Root ID entry   {id=8 (RT_RCDATA), off=0x18|DIR_FLAG}
  @24 Type dir hdr    (Named=0, ID=1)
  @40 Type ID entry   {id=1 (isim), off=0x30|DIR_FLAG}
  @48 Name(Lang) hdr  (Named=0, ID=1)
  @64 Lang ID entry   {id=0x409, off=0x48 (DataEntry, flag YOK)}
  @72 DataEntry       {dataRVA, size, cp, res}
  @88 data
DIR_FLAG = 0x80000000 (offset subdir'i gosterir); offsetler RDT basina GORELI.
Dersler: SizeOfImage GUNCELLENMELI (yoksa loader rc=6); dir hdr 16B; entry 8B.
"""
import struct
import sys


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def rsrc_tree(data):
    hdr = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    root_e = struct.pack("<II", 10, 0x18 | 0x80000000)         # @16 (RT_RCDATA=10)
    type_e = struct.pack("<II", 1, 0x30 | 0x80000000)          # @40
    lang_e = struct.pack("<II", 0x409, 0x48)                   # @64
    de = struct.pack("<IIII", 0, len(data), 0, 0)              # @72 {rva, size, cp, res}
    blob = hdr + root_e + hdr + type_e + hdr + lang_e + de      # 88 bayt
    return blob, len(blob)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    girdi, cikti, metin = sys.argv[1], sys.argv[2], sys.argv[3].encode()
    d = bytearray(open(girdi, "rb").read())
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    is64 = magic == 0x20B
    opto = pe + 24
    ddoff = opto + (112 if is64 else 96)
    sa, fa = struct.unpack_from("<II", d, opto + 32)

    sec_off = opto + optsz
    last_end = 0
    max_va = 0
    for i in range(nsec):
        o = sec_off + i * 40
        vsz, va, rsz, raw = struct.unpack_from("<IIII", d, o + 8)
        last_end = max(last_end, raw + rsz)
        max_va = max(max_va, va + max(vsz, rsz))

    blob, _ = rsrc_tree(metin)
    rsrc_vsz = len(blob) + len(metin)
    rsrc_rva = align(max_va, sa if sa > 0x1000 else 0x1000)
    raw = align(last_end, fa)
    data_rva = rsrc_rva + 88   # DataEntry'den sonra
    # DataEntry RVA alanini (offset 72) guncelle
    body = bytearray(blob)
    struct.pack_into("<I", body, 72, data_rva)
    body += metin

    sect = struct.pack("<8sIIIIIIHHI", b".rsrc", rsrc_vsz, rsrc_rva,
                       align(len(body), fa), raw, 0, 0, 0, 0, 0x40000040)
    if raw + align(len(body), fa) > len(d):
        d.extend(b"\0" * (raw + align(len(body), fa) - len(d)))
    d[raw:raw + len(body)] = body
    hdr_ek = sec_off + nsec * 40
    size_of_headers = struct.unpack_from("<I", d, opto + 60)[0]
    if hdr_ek + 40 > size_of_headers:
        print("UYARI: SizeOfHeaders tasiyor — genisletilemiyor")
        return 1
    d[hdr_ek:hdr_ek + 40] = sect
    struct.pack_into("<H", d, pe + 6, nsec + 1)
    struct.pack_into("<II", d, ddoff + 2 * 8, rsrc_rva, rsrc_vsz)  # data-dir 2
    new_soi = align(rsrc_rva + align(rsrc_vsz, sa), sa)
    struct.pack_into("<I", d, opto + 56, new_soi)   # SizeOfImage

    open(cikti, "wb").write(bytes(d))
    print("OK: .rsrc RVA=0x%x raw=0x%x data_rva=0x%x len=%d vsz=%d"
          % (rsrc_rva, raw, data_rva, len(body), rsrc_vsz))


if __name__ == "__main__":
    sys.exit(main())
