#!/usr/bin/env python3
# x86_unic_matrix.py — x86 ANTIDBG bataryasinin Unicorn-matrisi (ilk GERCEK
# x86 runtime dogrulamasi — 0.8.2'nin "veh_matrix_x86.txt" kaniti aslinda
# wine syswow64 yokken rc=1'leri "DURDU" sayan bozuk bir kanitti).
# Blob: gercek derlenmiş vmx86.bin (vm_core.c -> ld flat, Ttext=0x100000).
# Windows dunyasi: sahte PEB (fs:0x30) + sahte ntdll/kernel32 (PE export
# tablolari — blob xa_module/xa_export ile cozer) + stdcall API thunk'lari +
# TF-probe teslimat senaryosu ('win'=isleyicimiz aldi / 'eaten'=birisi yuttu).
import struct, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *
from unicorn.x86_const import *

M1 = 0x9E3779B97F4A7C15
M2 = 0x2545F4914F6CDD1D
M3 = 0xD1B54A32D192ED03
M4 = 0x94D049BB133111EB
M5 = 0x100000001B3
R1 = 0x51ED270B4C5A3D0F
M64 = (1 << 64) - 1
POISON_MODE = False
VM_OPN = 0x2C
OP_ANTIDBG = 0x1E
OP_RET = 0x1A

XA_TFMAGIC = 0x5A17C0DE

GDT_ADDR = 0x032F0000
GDT_LIMIT = 0x1000

def gdt_entry(base, limit, access, flags):
    e = (limit & 0xFFFF)
    e |= (base & 0xFFFFFF) << 16
    e |= (base & 0xFF000000) << 32
    e |= access << 40
    e |= ((limit >> 16) & 0xF) << 48
    e |= flags << 52
    return struct.pack('<Q', e)

FS_SITES = (0xA7B, 0x394B)   # mov %fs:0x30,%eax — blob icinde iki site

BLOB = 0x00100000
IMG = 0x00400000
IMGSZ = 0x600000
STK = 0x7F000000
STKSZ = 0x100000
PEB = 0x7E100000
LDR = 0x7E200000
ENT = 0x7E300000
MOD_NTD = 0x01000000
MOD_K32 = 0x02000000
THUNK = 0x03000000
NTSTUB = THUNK + 0x1F0
BC = IMG + 0x545BC8
FN_RVA = 0xD7610
CTX = 0x03100000
SCRATCH = 0x03110000
SENTINEL = 0x031F0000

OFF_VM_ENTRY = 0x17E0
OFF_TF_RDTSC = 0x3CED   # rdtsc — popf DOGAL calisir (yigin dengesi),
                        # rdtsc+nop atlanir; mark=0x3BA0'da okunur
OFF_TF_MOVS = 0x3CF0     # mov %eax,%esi — mark burada okunur

def rol_key(k):
    return ((k * M5) & M64) ^ (k >> 23) ^ R1

def vm_ks(key, pos):
    a = (((key ^ ((pos * M1) & M64)) * M2) & M64) + M1 & M64
    b = ((rol_key(key)) ^ (((pos >> 3) * M3) & M64)) * M4 & M64
    return ((a ^ b) >> 56) & 0xFF

def vm_ksc(key, prev, pos):
    return vm_ks(key ^ ((prev * M2) & M64), pos)

def vm_keyxor(rva, ln):
    x = (0x5850424D ^ ((rva & 0xFFFFFFFF) << 32) ^ (ln & 0xFFFFFFFF)) & M64
    x ^= x >> 30; x = (x * 0xBF58476D1CE4E5B9) & M64
    x ^= x >> 27; x = (x * M4) & M64; x ^= x >> 31
    return x

def perm_p(seed):
    """Fisher-Yates permütasyonu (static_ad_check.py birebir)."""
    p = list(range(VM_OPN))
    z = ((seed ^ 0x5850424D9E3779B9) & M64) | 1
    for i in range(VM_OPN - 1, 0, -1):
        z ^= z >> 30; z = (z * 0xBF58476D1CE4E5B9) & M64
        z ^= z >> 27; z = (z * M4) & M64; z ^= z >> 31
        j = (z >> 32) % (i + 1)
        p[i], p[j] = p[j], p[i]
    return p

def build_pe_image(base, exports):
    """Minimal PE32 + export tablosu. exports: {isim: mutlak thunk adresi}."""
    img = bytearray(0x4000)
    img[0:2] = b'MZ'
    struct.pack_into('<I', img, 0x3C, 0x40)
    img[0x40:0x44] = b'PE\0\0'
    struct.pack_into('<H', img, 0x44, 0x14C)          # i386
    opt = 0x58                                        # optional header ofset
    struct.pack_into('<H', img, opt, 0x10B)           # PE32 magic
    exp_rva = 0x1000
    struct.pack_into('<I', img, opt + 96, exp_rva)    # data dir[0] export
    struct.pack_into('<I', img, opt + 100, 0x400)
    names = sorted(exports)
    nf = len(names)
    names_ptr = exp_rva + 0x40
    funcs_ptr = names_ptr + 4 * nf
    ords_ptr = funcs_ptr + 2 * nf
    namebuf_ptr = ords_ptr + 2 * nf + 0x40
    # ExportDirectory alanlari (xa_export'un okudugu ofsetlerle):
    # +0x18 NumberOfNames | +0x1C AddressOfFunctions | +0x20 AddressOfNames
    # +0x24 AddressOfNameOrdinals
    struct.pack_into('<I', img, exp_rva + 0x18, nf)
    struct.pack_into('<I', img, exp_rva + 0x1C, funcs_ptr)
    struct.pack_into('<I', img, exp_rva + 0x20, names_ptr)
    struct.pack_into('<I', img, exp_rva + 0x24, ords_ptr)
    for i, nm in enumerate(names):
        struct.pack_into('<I', img, names_ptr + 4 * i, namebuf_ptr + i * 0x20)
        s = nm.encode() + b'\0'
        o = namebuf_ptr + i * 0x20
        img[o:o + len(s)] = s
        struct.pack_into('<H', img, ords_ptr + 2 * i, i)
        struct.pack_into('<I', img, funcs_ptr + 4 * i, (exports[nm] - base) & 0xFFFFFFFF)
    return bytes(img)


def build_real_image(base, pe_path, exports, stub_rva=None):
    """GERCEK wine i386 PE'sini section-mapping ile yukle; export fonksiyon
    RVA'larini thunk'larimiza yamala (isimler/tablo yapisi gercek kalir).
    exports: {isim: mutlak thunk adresi}. Diger exportlar stub_rva'ya gider."""
    d = open(pe_path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    assert magic == 0x10B, 'PE32 bekleniyor'
    imgsz = struct.unpack_from('<I', d, opt + 56)[0]
    img = bytearray(imgsz + 0x20000)
    img[0:0x400] = d[0:0x400]                     # headerlar
    for i in range(nsec):
        o = opt + optsz + 40 * i
        vsz, va, rsz, rptr = struct.unpack_from('<IIII', d, o + 8)
        if rsz:
            n = min(rsz, vsz) if vsz else rsz
            img[va:va + n] = d[rptr:rptr + n]
    # export tablosunu yamala
    erva = struct.unpack_from('<I', d, opt + 96)[0]
    ex = erva
    nnames = struct.unpack_from('<I', img, ex + 24)[0]
    aofn = struct.unpack_from('<I', img, ex + 32)[0]   # AddressOfNames
    aofo = struct.unpack_from('<I', img, ex + 28)[0]   # AddressOfFunctions
    aoo = struct.unpack_from('<I', img, ex + 36)[0]
    if stub_rva is None:
        stub_rva = imgsz + 0x10000
    thunk_by_name = {n: (a - base) for n, a in exports.items()}
    patched = 0
    for i in range(nnames):
        nrva = struct.unpack_from('<I', img, aofn + 4 * i)[0]
        nm = bytes(img[nrva:nrva + 64]).split(b'\0')[0].decode(errors='replace')
        ordi = struct.unpack_from('<H', img, aoo + 2 * i)[0]
        want = thunk_by_name.get(nm)
        if want is None:
            # CC-tarama hedefleri icin gercek-Nt-stub benzeri donus
            struct.pack_into('<I', img, aofo + 4 * ordi, stub_rva)
        else:
            struct.pack_into('<I', img, aofo + 4 * ordi, want)
            patched += 1
    return bytes(img), imgsz + 0x20000


class World:
    def __init__(self, sc):
        self.sc = sc
        self.veh = []
        self.calls = []
        self.qip_handles = []

    def _ret(self, mu, argbytes):
        esp = mu.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack('<I', mu.mem_read(esp, 4))[0]
        mu.reg_write(UC_X86_REG_EIP, ret)
        mu.reg_write(UC_X86_REG_ESP, esp + 4 + argbytes)

    def api_qip(self, mu):
        esp = mu.reg_read(UC_X86_REG_ESP)
        h, cls, buf, ln, rl = struct.unpack('<IIIII', mu.mem_read(esp + 4, 20))
        self.calls.append(('QIP', h, cls))
        self.qip_handles.append(h)
        ok = (h == 0xFFFFFFFF)
        v = 0
        if ok:
            if cls == 7:      v = self.sc.get('dbgport', 0)
            elif cls == 0x1E: v = self.sc.get('dbgobj', 0)
        else:
            self.calls.append(('QIP-BADHANDLE', hex(h)))
        mu.mem_write(buf, struct.pack('<I', v & 0xFFFFFFFF))
        mu.reg_write(UC_X86_REG_EAX, 0 if ok else 0xC000000B)
        self._ret(mu, 20)

    def api_pvm(self, mu):
        esp = mu.reg_read(UC_X86_REG_ESP)
        h, paddr, psize, prot, pold = struct.unpack('<IIIII', mu.mem_read(esp + 4, 20))
        self.calls.append(('PVM', hex(h)))
        ok = (h == 0xFFFFFFFF)
        if ok:
            mu.mem_write(pold, struct.pack('<I', self.sc.get('pageprot', 0x20)))
        mu.reg_write(UC_X86_REG_EAX, 0 if ok else 0xC000000B)
        self._ret(mu, 20)

    def api_gtc(self, mu):
        esp = mu.reg_read(UC_X86_REG_ESP)
        h, ctx = struct.unpack('<II', mu.mem_read(esp + 4, 8))
        self.calls.append(('GTC', hex(h)))
        dr = self.sc.get('drx', 0)
        # x86 CONTEXT: ContextFlags@0, DR0@4, DR1@8, DR2@0xC, DR3@0x10
        # (gercek GetThreadContext DR0-DR7'nin HEPSINI doldurur — bos birakilan
        #  alanlar yigin copu kalirdi = suni FP)
        mu.mem_write(ctx + 4, struct.pack('<IIII', dr, 0, 0, 0))
        mu.mem_write(ctx + 0x14, struct.pack('<II', 0, 0))   # DR6, DR7
        mu.reg_write(UC_X86_REG_EAX, 1)
        self._ret(mu, 8)

    def api_aveh(self, mu):
        esp = mu.reg_read(UC_X86_REG_ESP)
        first, fn = struct.unpack('<II', mu.mem_read(esp + 4, 8))
        self.calls.append(('AVEH', first, hex(fn)))
        self.veh.append(fn)
        mu.reg_write(UC_X86_REG_EAX, 0xABCD0000 + len(self.veh))
        self._ret(mu, 8)

    def api_rveh(self, mu):
        esp = mu.reg_read(UC_X86_REG_ESP)
        (h,) = struct.unpack('<I', mu.mem_read(esp + 4, 4))
        self.calls.append(('RVEH', hex(h)))
        mu.reg_write(UC_X86_REG_EAX, 1)
        self._ret(mu, 4)


def run_scenario(blob, sc, verbose=False):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    w = World(sc)
    for a, sz in [(BLOB, 0x40000), (IMG, IMGSZ), (STK, STKSZ), (PEB, 0x1000),
                  (LDR, 0x1000), (ENT, 0x1000), (THUNK, 0x1000), (CTX, 0x1000),
                  (SCRATCH, 0x1000), (SENTINEL, 0x1000)]:
        mu.mem_map(a, sz)
    mu.mem_write(BLOB, blob)

    # --- PEB ---
    mu.mem_write(PEB + 2, struct.pack('<B', sc.get('beingdbg', 0)))
    mu.mem_write(PEB + 0x68, struct.pack('<I', sc.get('ntglobal', 0)))
    mu.mem_write(PEB + 0x0C, struct.pack('<I', LDR))
    head = LDR + 0x14
    e1 = ENT + 0x40
    e2 = ENT + 0xC0
    mu.mem_write(head, struct.pack('<I', e1 + 0x08))
    mu.mem_write(e1 + 0x08, struct.pack('<I', e2 + 0x08))
    mu.mem_write(e1 + 0x0C, struct.pack('<I', head))
    mu.mem_write(e2 + 0x08, struct.pack('<I', head))
    mu.mem_write(e2 + 0x0C, struct.pack('<I', e1 + 0x08))
    nb1 = ENT + 0x180
    nb2 = ENT + 0x1C0
    mu.mem_write(nb1, "ntdll.dll".encode('utf-16-le'))
    mu.mem_write(nb2, "kernel32.dll".encode('utf-16-le'))
    for ent, base_, nbuf, nlen in [(e1, MOD_NTD, nb1, 18), (e2, MOD_K32, nb2, 24)]:
        mu.mem_write(ent + 0x18, struct.pack('<I', base_))
        mu.mem_write(ent + 0x2C, struct.pack('<H', nlen))
        mu.mem_write(ent + 0x30, struct.pack('<I', nbuf))

    # --- API thunk'lari ---
    APIS = {}
    def TH(n):
        a = THUNK + 0x20 * len(APIS)
        APIS[n] = a
        return a
    t_qip, t_pvm, t_gtc = TH('qip'), TH('pvm'), TH('gtc')
    t_aveh, t_rveh = TH('aveh'), TH('rveh')
    mu.mem_write(t_qip, b'\xC2\x14\x00')
    mu.mem_write(t_pvm, b'\xC2\x14\x00')
    mu.mem_write(t_gtc, b'\xC2\x08\x00')
    mu.mem_write(t_aveh, b'\xC2\x08\x00')
    mu.mem_write(t_rveh, b'\xC2\x04\x00')

    NTD_PE = '/tmp/wine32x/usr/lib/i386-linux-gnu/wine/i386-windows/ntdll.dll'
    K32_PE = '/tmp/wine32x/usr/lib/i386-linux-gnu/wine/i386-windows/kernel32.dll'
    ntd_img, ntd_sz = build_real_image(MOD_NTD, NTD_PE, {
        'NtQueryInformationProcess': t_qip,
        'NtProtectVirtualMemory': t_pvm,
        'RtlAddVectoredExceptionHandler': t_aveh,
        'RtlRemoveVectoredExceptionHandler': t_rveh})
    k32_img, k32_sz = build_real_image(MOD_K32, K32_PE, {
        'GetThreadContext': t_gtc})
    mu.mem_map(MOD_NTD, (ntd_sz + 0xFFF) & ~0xFFF)
    mu.mem_map(MOD_K32, (k32_sz + 0xFFF) & ~0xFFF)
    mu.mem_write(MOD_NTD, ntd_img)
    mu.mem_write(MOD_K32, k32_img)
    # CC-tarama hedefi stub'u (Nt* diger exportlar buraya yonlendirildi):
    # 'mov eax,eax; ret 0x04' — apicc senaryosunda girisine CC yazilir
    STUB_RVA_NTD = ntd_sz - 0x10000   # imgsz+0x10000 (build_real_image varsayilani)
    STUB_RVA_K32 = k32_sz - 0x10000
    mu.mem_write(MOD_NTD + STUB_RVA_NTD, b'\x66\x90\xC2\x04\x00')
    mu.mem_write(MOD_K32 + STUB_RVA_K32, b'\x66\x90\xC2\x04\x00')
    globals()['_STUB_NTD'] = MOD_NTD + STUB_RVA_NTD
    globals()['_STUB_K32'] = MOD_K32 + STUB_RVA_K32
    if sc.get('apicc'):
        mu.mem_write(globals()['_STUB_NTD'], b'\xCC')  # debugger bp'si

    # --- oyun imaji ---
    mu.mem_write(IMG + FN_RVA, b'\xCC' if sc.get('kapicc') else b'\xE9')

    # --- sentetik bytecode: [ANTIDBG][RET] (perm + CFB) ---
    p = perm_p(0xD7610)
    bc_rva = BC - IMG
    bc_len = 8
    plain = bytes([p.index(OP_ANTIDBG), p.index(OP_RET), 0x90, 0x90, 0x90, 0x90, 0x90, 0x90])
    enc = bytearray()
    prev = 0
    for i, b in enumerate(plain):
        c = b ^ vm_ksc(0, prev, i)
        enc.append(c)
        prev = c
    mu.mem_write(BC, bytes(enc))

    key = vm_keyxor(bc_rva, bc_len)   # vm_entry cozer -> efektif anahtar 0
    mu.mem_write(CTX + 0x00, struct.pack('<I', BC))
    mu.mem_write(CTX + 0x08, struct.pack('<I', bc_len))
    mu.mem_write(CTX + 0x10, struct.pack('<I', key & 0xFFFFFFFF))
    mu.mem_write(CTX + 0x14, struct.pack('<I', (key >> 32) & 0xFFFFFFFF))
    mu.mem_write(CTX + 0x18, struct.pack('<I', IMG))
    mu.mem_write(CTX + 0xA8, struct.pack('<I', SCRATCH))
    mu.mem_write(SCRATCH + 28, struct.pack('<I', 0x11223344))  # push_area[7] = EAX (x86 pushad)
    mu.mem_write(CTX + 0xB0, struct.pack('<I', STK + STKSZ - 0x1000))
    mu.mem_write(CTX + 0xE0, struct.pack('<I', 0xD7610))   # scratch[3] = seed

    def hook_code(mu, addr, size, ud):
        if verbose and addr == BLOB + 0xA70:
            esp = mu.reg_read(UC_X86_REG_ESP)
            want = struct.unpack('<I', mu.mem_read(esp + 4, 4))[0]
            print('  xa_module(want=0x%08X) esp=%08X' % (want, esp))
        if verbose and addr == BLOB + 0xCB0:
            esp = mu.reg_read(UC_X86_REG_ESP)
            kb, want = struct.unpack('<II', mu.mem_read(esp + 4, 8))
            print('  xa_export(kbase=0x%08X want=0x%08X)' % (kb, want))
        if verbose and addr == BLOB + 0x3855:   # mov %eax,%edi — QIP donusu
            print('  QIP xa_export ret eax=%08X edx=%08X ebp=%08X'
                  % (mu.reg_read(UC_X86_REG_EAX), mu.reg_read(UC_X86_REG_EDX),
                     mu.reg_read(UC_X86_REG_EBP)))
        if addr == t_qip: w.api_qip(mu)
        elif addr == t_pvm: w.api_pvm(mu)
        elif addr == t_gtc: w.api_gtc(mu)
        elif addr == t_aveh: w.api_aveh(mu)
        elif addr == t_rveh: w.api_rveh(mu)
        elif addr in (BLOB + 0xA7B, BLOB + 0x394B):
            # movl %fs:0x30,%eax — unicorn 32-bit segment desteği yok:
            # PEB'i dogrudan yaz, 6 baytlik instruction'i atla.
            mu.reg_write(UC_X86_REG_EAX, PEB)
            mu.reg_write(UC_X86_REG_EIP, addr + 6)
        elif addr == BLOB + OFF_TF_RDTSC:
            # TF-probe teslimat noktasi: 'win' -> VEH'imiz rax=MAGIC yazdi;
            # 'eaten' -> baskasi yuttu (rax=tsc copu). rdtsc+nop atlanir.
            if sc.get('tfdeliver', 'win') == 'win':
                # VEH'imiz calisti: rax=MAGIC + ecx=baglam-DRx (handler davranisi)
                mu.reg_write(UC_X86_REG_EAX, XA_TFMAGIC)
                mu.reg_write(UC_X86_REG_ECX, sc.get('ctxdrx', 0))
            else:
                # baskasi yuttu: rax=tsc copu, ecx=handler yazmadi (eski deger)
                mu.reg_write(UC_X86_REG_EAX, 0xCAFEBABE)
            # kernel+VEH: TF istisna teslimatinda temizlenir (yoksa Unicorn
            # #DB raise eder)
            efl = mu.reg_read(UC_X86_REG_EFLAGS)
            mu.reg_write(UC_X86_REG_EFLAGS, efl & ~0x100)
            mu.reg_write(UC_X86_REG_EIP, BLOB + OFF_TF_MOVS)
    mu.hook_add(UC_HOOK_CODE, hook_code)
    if verbose:
        def mem_inv(mu, access, address, size, value, ud):
            print('  !! INVALID access=%d addr=0x%08X size=%d eip=0x%08X eax=%08X ebx=%08X ecx=%08X edx=%08X'
                  % (access, address, size, mu.reg_read(UC_X86_REG_EIP),
                     mu.reg_read(UC_X86_REG_EAX), mu.reg_read(UC_X86_REG_EBX),
                     mu.reg_read(UC_X86_REG_ECX), mu.reg_read(UC_X86_REG_EDX)))
            return False
        mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                    | UC_HOOK_MEM_FETCH_UNMAPPED, mem_inv)

    # --- vm_entry(c) cdecl: [esp]=SENTINEL, [esp+4]=CTX ---
    esp0 = STK + STKSZ - 0x2000
    mu.mem_write(esp0, struct.pack('<I', SENTINEL))
    mu.mem_write(esp0 + 4, struct.pack('<I', CTX))
    mu.reg_write(UC_X86_REG_ESP, esp0)
    try:
        mu.emu_start(BLOB + OFF_VM_ENTRY, SENTINEL, timeout=10_000_000, count=3_000_000)
        err = 'OK'
    except UcError as e:
        err = 'UCERR %s eip=0x%X' % (e, mu.reg_read(UC_X86_REG_EIP))
    done = struct.unpack('<I', mu.mem_read(CTX + 0xC0, 4))[0]
    eax = struct.unpack('<I', mu.mem_read(CTX + 0x20, 4))[0]
    return done, eax, w, err


# beklenen == None -> senaryo sadece bilgi (0.8.2'de bilinen kusur)
SC = [
    ('clean',       {},                                              False),
    ('tfeaten',     {'tfdeliver': 'eaten'},                          False),  # 0.8.3: GOLGE -> temiz
    ('peb',         {'beingdbg': 1},                                 True),
    ('ntglobal',    {'ntglobal': 0x70},                              True),
    ('kapicc',      {'kapicc': 1},                                   True),
    ('dbgport',     {'dbgport': 1},                                  True),  # 0.8.3: handle fix
    ('dbgobj',      {'dbgobj': 1},                                   True),  # 0.8.3: handle fix
    ('drx',         {'drx': 0x70000000},                             True),
    ('apicc',       {'apicc': 1},                                    False),  # 0.8.3: GOLGE -> temiz (hook FP'siz)
    ('pageguard',   {'pageprot': 0x100},                             True),  # 0.8.3: NtPVM fix -> KESIN
    ('tfeaten+drx', {'tfdeliver': 'eaten', 'drx': 0x70000000},       True),
    # 0.8.3 yeni kanal: istisna baglamindan DRx (core.cc:771 1:1) —
    # GetThreadContext hook'lansa bile yakalar
    ('tfctxdrx',    {'ctxdrx': 0x70000000},                          True),
    ('tfeaten+ctxdrx', {'tfdeliver': 'eaten', 'ctxdrx': 0x70000000}, False),  # yutulduysa baglam yok
]

def main():
    blob = open(sys.argv[1] if len(sys.argv) > 1 else 'vmx86.bin', 'rb').read()
    poison_val = 0 if (len(sys.argv) > 2 and sys.argv[2] == 'poison0') else 0xDEADBEEF
    global POISON_MODE
    POISON_MODE = (poison_val == 0)
    print('=== x86 ANTIDBG Unicorn matrisi (zehir=0x%X) ===' % poison_val)
    fails = 0
    for name, sc, want_stop in SC:
        done, eax, w, err = run_scenario(blob, sc)
        stopped = (eax != 0x11223344) if POISON_MODE else (eax == poison_val)
        verdict = 'DURDU' if stopped else 'CALISIR'
        if want_stop is None:
            ok = True   # 0.8.2 bilinen kusur — bilgi amacli
            note = '= 0.8.2 KUSUR (bilgi)'
        else:
            ok = (stopped == want_stop)
            note = '= GECTI' if ok else '= HATA'
        fails += 0 if ok else 1
        print('[%s] done=%d eax=0x%08X -> %s (beklenen %s) %s %s'
              % (name, done, eax, verdict,
                 'DURDU' if want_stop else ('CALISIR' if want_stop is False else '-'),
                 note, err if err != 'OK' else ''))
        if name in ('dbgport', 'dbgobj'):
            bad = [h for h in w.qip_handles if h != 0xFFFFFFFF]
            if bad:
                print('    UYARI: QIP handle hatali: %s (x86 bug — process yerine thread)' % bad)
                fails += 1
            else:
                print('    QIP handle=0xFFFFFFFF OK (NtCurrentProcess)')
    print('SONUC: %s (%d hata)' % ('TAM' if fails == 0 else 'EKSIK', fails))
    return 1 if fails else 0

if __name__ == '__main__':
    sys.exit(main())
