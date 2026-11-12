#!/usr/bin/env python3
# bc_diff121.py — XProtect 1.2.1 bytecode cozumleyici + normal/CheckDebugger karsilastirmasi
# Kullanim: python3 bc_diff121.py
import struct, sys

M64 = (1 << 64) - 1

def vm_roll(k):
    return ((((k & M64) * 0x100000001B3) ^ ((k & M64) >> 23)) ^ 0x51ED270B4C5A3D0F) & M64

def vm_ks(key, pos):
    a = (((key ^ ((pos * 0x9E3779B97F4A7C15) & M64)) & M64) * 0x2545F4914F6CDD1D + 0x9E3779B97F4A7C15) & M64
    b = (((vm_roll(key) ^ (((pos >> 3) * 0xD1B54A32D192ED03) & M64)) & M64) * 0x94D049BB133111EB) & M64
    return ((a ^ b) >> 56) & 0xFF

def vm_ksc(key, prev, pos):
    return vm_ks(key ^ (prev * 0x2545F4914F6CDD1D & M64), pos)

def vm_roll_a(k):
    return (((k & M64) * 0x9E3779B97F4A7C15) ^ ((k & M64) >> 17) ^ 0x2545F4914F6CDD1D) & M64

def vm_ksa(key, pos):
    a = (((key ^ ((pos * 0xD1B54A32D192ED03) & M64)) & M64) * 0x100000001B3 + 0xA24BAED4963EE407) & M64
    b = (((vm_roll_a(key) ^ (((pos >> 2) * 0x9E3779B97F4A7C15) & M64)) & M64) * 0x2545F4914F6CDD1D) & M64
    return ((a ^ b) >> 56) & 0xFF

def vm_ksca(key, prev, pos):
    return vm_ksa(key ^ (prev * 0x100000001B3 & M64), pos)

def vm_kxi(rva, ln):
    return (0x5850424D ^ (rva << 32) ^ ln) & M64
def sm64(x):
    x &= M64
    x ^= x >> 30; x = (x * 0xBF58476D1CE4E5B9) & M64
    x ^= x >> 27; x = (x * 0x94D049BB133111EB) & M64
    x ^= x >> 31
    return x & M64
def vm_keyxor(rva, ln):
    return sm64(sm64(sm64(sm64(sm64(vm_kxi(rva, ln))))))
def vm_vmk(vm_id):
    if not vm_id: return 0
    return ((0x5850424D ^ (vm_id * 0x9E3779B97F4A7C15 & M64)) ^ (vm_id << 41)) & M64

VM_OPN = 0x44
def vm_perm_tab(seed):
    p = list(range(VM_OPN))
    z = (seed ^ 0x5850424D9E3779B9) | 1
    for i in range(VM_OPN - 1, 0, -1):
        z ^= z >> 30; z = (z * 0xBF58476D1CE4E5B9) & M64
        z ^= z >> 27; z = (z * 0x94D049BB133111EB) & M64; z ^= z >> 31
        j = ((z >> 32) & 0xFFFFFFFF) % (i + 1)
        p[i], p[j] = p[j], p[i]
    # dec tablo: t[raw] = gercek
    t = [0] * VM_OPN
    for i in range(VM_OPN): t[p[i]] = i
    return t

def parse_stub(d, stub_raw):
    # x86 stub: 60 81 ec SUB32 | 8d 84 24 SUB32 | 89 84 24 A8 | 05 20 | 89 84 24 B0 |
    # b8 keylo | 89 44 24 10 | b8 keyhi | 89 44 24 14 | e8(L1) | 58 | 2d L1rva | 89 44 24 18 |
    # 05 bcrva | 89 04 24 | b8 len | 89 44 24 08 | [c7 84 24 E0 perm] | c6 84 24 F0 ks |
    # c7 84 24 00 01 vmid | ...
    s = {}
    o = stub_raw
    assert d[o] == 0x60
    SUB = struct.unpack_from('<I', d, o + 3)[0]
    s['sub'] = SUB
    o += 7                    # 60 81 ec SUB32
    assert d[o:o+3] == b'\x8d\x84\x24' and struct.unpack_from('<I', d, o+3)[0] == SUB
    o += 7                    # lea eax,[esp+SUB]
    assert d[o:o+3] == b'\x89\x84\x24'
    o += 7                    # mov [esp+0xA8],eax
    assert d[o] == 0x05 and struct.unpack_from('<I', d, o+1)[0] == 0x20
    o += 5                    # add eax,0x20
    assert d[o:o+3] == b'\x89\x84\x24'
    o += 7                    # mov [esp+0xB0],eax (init_rsp)
    assert d[o] == 0xB8
    s['key_lo'] = struct.unpack_from('<I', d, o+1)[0]
    o += 5                    # mov eax,key_lo
    assert d[o:o+4] == b'\x89\x44\x24\x10'
    o += 4                    # mov [esp+0x10],eax
    assert d[o] == 0xB8
    s['key_hi'] = struct.unpack_from('<I', d, o+1)[0]
    o += 5                    # mov eax,key_hi
    assert d[o:o+4] == b'\x89\x44\x24\x14'
    o += 4                    # mov [esp+0x14],eax
    assert d[o] == 0xE8
    o += 5                    # call L1
    assert d[o] == 0x58
    o += 1                    # pop eax
    assert d[o] == 0x2D
    s['l1_rva'] = struct.unpack_from('<I', d, o+1)[0]
    o += 5                    # sub eax,L1_rva
    assert d[o:o+4] == b'\x89\x44\x24\x18'
    o += 4                    # mov [esp+0x18],eax
    assert d[o] == 0x05
    s['bc_rva'] = struct.unpack_from('<I', d, o+1)[0]
    o += 5                    # add eax,bc_rva
    assert d[o:o+3] == b'\x89\x04\x24'
    o += 3                    # mov [esp],eax
    assert d[o] == 0xB8
    s['bc_len'] = struct.unpack_from('<I', d, o+1)[0]
    o += 5                    # mov eax,len
    assert d[o:o+4] == b'\x89\x44\x24\x08'
    o += 4                    # mov [esp+8],eax
    assert d[o:o+7] == b'\xc7\x84\x24\xe0\x00\x00\x00'
    s['perm_seed'] = struct.unpack_from('<I', d, o+7)[0]
    o += 11                   # mov dword [esp+0xE0],perm
    assert d[o:o+7] == b'\xc6\x84\x24\xf0\x00\x00\x00'
    s['ks_flags'] = d[o+7]
    o += 8                    # mov byte [esp+0xF0],ks
    assert d[o:o+7] == b'\xc7\x84\x24\x00\x01\x00\x00'
    s['vm_id'] = struct.unpack_from('<I', d, o+7)[0]
    return s

def decrypt(d, st):
    keyraw = (st['key_hi'] << 32) | st['key_lo']
    key = keyraw ^ vm_keyxor(st['bc_rva'], st['bc_len'])
    ekey = key ^ vm_vmk(st['vm_id'])
    adv = st['ks_flags'] & 1
    raw = d[st['bc_rva'] - 0x542000 + 0x4f9800: st['bc_rva'] - 0x542000 + 0x4f9800 + st['bc_len']]
    plain = []
    prev = 0
    for i, rb in enumerate(raw):
        p = rb ^ (vm_ksca(ekey, prev, i) if adv else vm_ksc(ekey, prev, i))
        plain.append(p)
        prev = rb
    return bytes(plain), itab_of(st), ekey, key

def itab_of(st):
    seed = st['perm_seed'] if st['perm_seed'] else st['bc_rva']  # tohum 0 -> f.rva'ya (motor boyle degil ama bizim ornkte perm=0d7610)
    return vm_perm_tab(seed)

OPNAME = {
 0x00:'NOP',0x01:'MOV_RR',0x02:'MOV_RI',0x03:'MOV_RM',0x04:'MOV_MR',0x05:'MOV_MI',
 0x06:'LEA_RM',0x07:'ALU_RR',0x08:'ALU_RI',0x09:'ALU_RM',0x0A:'ALU_MR',0x0B:'ALU_MI',
 0x0C:'SHI_RI',0x0D:'SHI_CL',0x0E:'IMUL_RRI',0x0F:'IMUL_RR',0x10:'INCDEC_R',0x11:'INCDEC_M',
 0x12:'MOVZX',0x13:'MOVSX',0x14:'PUSH_R',0x15:'PUSH_I',0x16:'POP_R',0x17:'JMP',0x18:'JCC',
 0x19:'NCALL',0x1A:'RET',0x1B:'SETCC',0x1C:'CQO',0x1D:'IDIV_R',0x1E:'ANTIDBG',0x1F:'STRDEC',
 0x20:'MOV_RI64',0x21:'CMOV',0x22:'SHI_RM_RI',0x23:'SHI_RM_CL',0x24:'IMUL_RMRI',0x25:'NEG_R',
 0x26:'NOT_R',0x27:'NEG_M',0x28:'NOT_M',0x2A:'BSWAP_R',0x2B:'XCHG_RR',0x2C:'PUSHF',0x2D:'POPF',
 0x2E:'SAHF',0x2F:'LAHF',0x30:'SETFLAG',0x31:'MUL_R',0x32:'DIV_R',0x33:'BT_X',0x34:'SHLD',
 0x35:'SHRD',0x36:'LOOP',0x37:'JECXZ',0x38:'XADD',0x39:'STR',0x3A:'IMUL_RM',0x3B:'NOR1',0x3C:'NOR2',
 0x3D:'NAND1',0x3E:'NAND2',0x3F:'JMPEXT',0x40:'?',0x41:'JMPEXT2',0x42:'JCCEXT',0x43:'CHKRET'}

if __name__ == '__main__':
    up = '/home/z/my-project/upload/'
    fns = [('metin2client_vmp.exe', 'NORMAL'), ('metin2client_vmp_CheckDebugger.exe', 'CHECKDBG')]
    stub_rva = 0x54E130
    stub_raw = stub_rva - 0x542000 + 0x4f9800
    out = {}
    for fn, tag in fns:
        d = open(up + fn, 'rb').read()
        st = parse_stub(d, stub_raw)
        plain, itab, ekey, key = decrypt(d, st)
        out[tag] = (st, plain, itab)
        print(f"=== {tag} ===")
        print(' sub=%x key_raw=%08x%08x bc_rva=%06x bc_len=%x perm=%08x ks=%02x vm_id=%u'
              % (st['sub'], st['key_hi'], st['key_lo'], st['bc_rva'], st['bc_len'],
                 st['perm_seed'], st['ks_flags'], st['vm_id']))
        print(' plain[0:40]:', plain[:40].hex(' '))
        # ilk 2 byte ANTIDBG mi?
        real0 = itab[plain[0]]
        real1 = itab[plain[1]]
        print(' op0=%02X(%s) op1=%02X(%s)' % (real0, OPNAME.get(real0,'?'), real1, OPNAME.get(real1,'?')))
        # CHKRET (0x43) ham degerini bul
        chk_raw = plain.index(itab.index(0x43)) if 0x43 in itab else None
        # itab: raw->gercek. gercek->raw = ters
        raw_of = {}
        for r in range(VM_OPN): raw_of[itab[r]] = r
        cr = raw_of.get(0x43)
        cnt = sum(1 for b in plain if b == cr) if cr is not None else 0
        print(' CHKRET raw byte=%s count=%d' % (hex(cr) if cr is not None else '-', cnt))
        ar = raw_of.get(0x1E)
        cnta = sum(1 for b in plain if b == ar) if ar is not None else 0
        print(' ANTIDBG raw byte=%s count=%d' % (hex(ar) if ar is not None else '-', cnta))
    # iki akisi hizala: checkdbg = prefix(2) + govde (+CHKRET'ler)
    n = out['NORMAL']; c = out['CHECKDBG']
    np_, cp = n[1], c[1]
    print()
    print('normal len=%d checkdbg len=%d (fark=%d)' % (len(np_), len(cp), len(cp)-len(np_)))
