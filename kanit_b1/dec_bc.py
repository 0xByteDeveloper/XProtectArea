#!/usr/bin/env python3
# dec_bc.py — XProtect bytecode decoder (0.8.0 CFB + perm tablosu).
# Kullanim: dec_bc.py <korumali.exe> <stub_rva> [uzunluk]
# Stub'tan key/bc_rva/bc_len/perm_seed yamalarini ceker, bc'yi cozup
# ham plain akisini ve itab-cozulmus op dizisini basar.
import struct, sys, re

M64 = (1 << 64) - 1

def vm_roll(k):
    k &= M64
    return ((k * 0x100000001B3) & M64) ^ (k >> 23) ^ 0x51ED270B4C5A3D0F

def VM_KS(key, pos):
    a = ((key & M64) ^ ((pos * 0x9E3779B97F4A7C15) & M64)) & M64
    a = (a * 0x2545F4914F6CDD1D + 0x9E3779B97F4A7C15) & M64
    b = ((vm_roll(key) ^ (((pos >> 3) * 0xD1B54A32D192ED03) & M64)) & M64)
    b = (b * 0x94D049BB133111EB) & M64
    return ((a ^ b) >> 56) & 0xFF

def VM_KSC(key, prev, pos):
    return VM_KS(key ^ ((prev & 0xFF) * 0x2545F4914F6CDD1D), pos)

def VM_KEYXOR(bc_rva, bc_len):
    x = (0x5850424D ^ ((bc_rva & 0xFFFFFFFF) << 32) ^ (bc_len & 0xFFFFFFFF)) & M64
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & M64
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & M64
    x ^= x >> 31
    return x

def vm_perm_tab(seed, opn=0x42):
    p = list(range(opn))
    z = ((seed & 0xFFFFFFFF) ^ 0x5850424D9E3779B9) | 1
    for i in range(opn - 1, 0, -1):
        z ^= z >> 30; z = (z * 0xBF58476D1CE4E5B9) & M64
        z ^= z >> 27; z = (z * 0x94D049BB133111EB) & M64; z ^= z >> 31
        j = ((z >> 32) & 0xFFFFFFFF) % (i + 1)
        p[i], p[j] = p[j], p[i]
    # C: dec -> t[i] = p[i] (yani DECODE tablosu p'nin kendisi)
    return p

def main():
    path, stub_rva = sys.argv[1], int(sys.argv[2], 0)
    want_len = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
    import pefile
    pe = pefile.PE(path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    raw_of = {}
    for s in pe.sections:
        raw_of[s.VirtualAddress] = (s.PointerToRawData, s.Name.decode().rstrip('\0'))
    def rva2raw(rva):
        best = None
        for va in raw_of:
            if va <= rva and (best is None or va > best):
                best = va
        pro, nm = raw_of[best]
        return pro + (rva - best), nm
    data = bytearray(open(path, 'rb').read())
    sraw, _ = rva2raw(stub_rva)
    stub = data[sraw:sraw + 0x200]
    # x64 stub desenleri:
    #  mov rax,key64 (obf) : 48 B8 <8B>  mov [rsp+0x10], rax
    #  add rax, bc_rva     : 48 05 <4B>   mov [rsp], rax
    #  mov rax, bc_len     : 48 B8 <8B>   mov [rsp+0x08], rax
    #  perm seed (ops.)    : C7 84 24 E0 00 00 00 <4B>
    i = stub.find(b'\x48\xB8')
    keyobf = struct.unpack_from('<Q', stub, i + 2)[0]
    j = stub.find(b'\x48\x05', i)
    bc_rva = struct.unpack_from('<I', stub, j + 2)[0]
    k = stub.find(b'\x48\xB8', j + 5)
    bc_len = struct.unpack_from('<Q', stub, k + 2)[0]
    seed = 0
    m = stub.find(b'\xC7\x84\x24\xE0\x00\x00\x00')
    if m >= 0:
        seed = struct.unpack_from('<I', stub, m + 7)[0]
    key = keyobf ^ VM_KEYXOR(bc_rva, bc_len)
    print('stub=0x%X key=0x%016X (obf 0x%016X) bc_rva=0x%X bc_len=%d seed=0x%X'
          % (stub_rva, key, keyobf, bc_rva, bc_len, seed))
    n = want_len if want_len else bc_len
    craw, _ = rva2raw(bc_rva)
    enc = data[craw:craw + n]
    plain = bytearray()
    for i2 in range(n):
        prev = enc[i2 - 1] if i2 > 0 else 0
        ks = VM_KSC(key, prev, i2)
        plain.append(enc[i2] ^ ks)
    print('enc  :', enc.hex(' '))
    itab = vm_perm_tab(seed) if seed else list(range(0x42))
    names = {}
    for line in open('/home/z/my-project/scripts/xiangu_gh/XProtect/source/XProtectUI_Source/vm_opcodes.h'):
        mm = re.match(r'#define (OP_\w+)\s+(0x[0-9A-Fa-f]+)', line)
        if mm:
            names[int(mm.group(2), 16)] = mm.group(1)
    print('plain:', plain.hex(' '))
    i2 = 0
    while i2 < len(plain):
        b = plain[i2]
        op = itab[b] if b < len(itab) else -1
        nm = names.get(op, 'OP_?0x%02X' % op) if op >= 0 else 'RAW!'
        if op < 0:
            print('%03d: RAW 0x%02X (itab-disi — cozum yanlis? kalan: %s)' % (i2, b, plain[i2:i2+12].hex(' ')))
            break
        print('%03d: %s' % (i2, nm), end='')
        i2 += 1
        # operand uzunluklarini yaklasik goster (bilinen formlar)
        if op == 0x40:  # NJCC
            cc, t, e = plain[i2], struct.unpack_from('<I', plain, i2 + 1)[0], struct.unpack_from('<I', plain, i2 + 5)[0]
            print(' cc=%d t=0x%X else=+%d' % (cc, t, e)); i2 += 9
        elif op == 0x41:  # RETI
            print(' imm=%d' % struct.unpack_from('<H', plain, i2)[0]); i2 += 2
        else:
            print(' ...%s' % plain[i2:i2 + 8].hex(' ')); i2 += 0
        if op in (0x1A, 0x41):  # RET/RETI terminal (kaba)
            pass
        if i2 > 200:
            break

if __name__ == '__main__':
    main()
