#!/usr/bin/env python3
# v294_lic_e2e.py — V294-3: keygen→motor→runtime E2E lisans kanıtı (Unicorn)
# Zincir:
#   1) xprotect_keygen (C++) ile serial üret (kg2048.pem — V293 keygen çıktısı)
#   2) host_cli --lic-key ile LSD gömülü korumalı exe (motor)
#   3) Unicorn x64: PE'yi map et, xrt_sdk_entry(fnid=1 SetSerial) çağır
#   4) fnid=2 GetState ile sonucu oku (0 = OK; XS_INVALID vs. hata kodları)
# LSD taraması lic_lsd() imajda 'XLSD' arar — SetSerial LSD'yi bulup modexp
# ile doğrular. Böylece keygen-imzası ↔ runtime-modulus E2E kanıtlanır.
import struct, subprocess, sys, base64
from unicorn import *
from unicorn.x86_const import *

def rd_pe(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e+6)[0]
    szopt = struct.unpack_from('<H', d, e+20)[0]
    opt = e + 0x18
    magic = struct.unpack_from('<H', d, opt)[0]
    is64 = magic == 0x20b
    ep = struct.unpack_from('<I', d, opt+16)[0]
    imgbase = struct.unpack_from('<Q' if is64 else '<I', d, opt+(24 if is64 else 28))[0]
    imgsz = struct.unpack_from('<I', d, opt+56)[0]
    secs = []
    st = opt + szopt
    for i in range(n):
        off = st + i*0x28
        name = d[off:off+8].rstrip(b'\x00').decode('latin1', 'replace')
        vs, va, rs, pr = struct.unpack_from('<IIII', d, off+8)
        secs.append((name, va, vs, pr, rs))
    return d, is64, imgbase, imgsz, secs, ep

def find_lsd(d, secs):
    # LSD 'XLSD' + ver=1 + CRC — raw veri icinde tara (sectionlara bak)
    for name, va, vs, pr, rs in secs:
        blob = d[pr:pr+rs]
        idx = 0
        while True:
            i = blob.find(b'XLSD', idx)
            if i < 0: break
            if i + 4 < len(blob) and blob[i+4] == 1:
                return va + i, blob[i:i+0x174]
            idx = i + 1
    return None, None

def main():
    vmp = sys.argv[1] if len(sys.argv) > 1 else '/tmp/dbg/lic2048.vmp.exe'
    serial = None
    TRACE = '--trace' in sys.argv
    for a in sys.argv[2:]:
        if a != '--trace':
            serial = a
    if not serial:
        serial = subprocess.run(
            ['/tmp/dbg/xprotect_keygen', '--key', '/tmp/dbg/kg2048.pem',
             '--prodcode', '0102030405060708', '--name', 'V294E2E',
             '--email', 'test@xprotect.local', '--maxbuild', '2030-01-01'],
            capture_output=True, text=True, check=True).stdout.strip()
    print('[1] serial (C++ keygen):', serial[:44] + '...', 'uzunluk', len(serial))

    d, is64, imgbase, imgsz, secs, ep = rd_pe(vmp)
    assert is64, 'bu harness x64'
    lsd_va, lsd_blob = find_lsd(d, secs)
    assert lsd_va, 'LSD bulunamadi'
    kb = lsd_blob[0x12E] | (lsd_blob[0x12F] << 8)
    print(f'[2] LSD @ rva {lsd_va:#x}: keylen={kb} urun={lsd_blob[0x110:0x118].hex()} wm_len={lsd_blob[0x12C]}')

    # sdk entry RVA: cfg = [xrt blob sonu hizali]; ama motor logu veriyor:
    # pratik yol: xrt blob'u .vmp0 icinda ara (cfg XCFG magic ile bulunur),
    # SDK RVA = xrt_rva + XRT_BLOB64_SDK_OFF (678) — xrt_rva = cfg'nin blob tarafı.
    # Daha saglami: kanit dosyasindan oku — host_cli ciktisinda yok; o halde
    # XRT bloğunun ELf off'u statik: XRT_BLOB64_SDK_OFF=678, xrt_rva = cfg_rva - (span hizali).
    # En guvenilir: isaret 'XLSD' oncesi cfg'yi bul (XCFG magic), SDK RVA =
    # cfg_rva'dan geriye dogru blob basi + 678. Motor: xrt_code_off bilinmiyor...
    # ALTERNATIF GUVENLIL YOL: xrt_sdk_entry semasini blobda imza-tarayarak bul.
    sig = bytes.fromhex('')  # imza yerine: SDK off sabiti 678'i cfg'den tasi:
    # cfg_rva = lsd_rva - vf_area - 0x60; vf_area=0 (bu build'de vfile yok)
    cfg_va = lsd_va - 0x60
    # xrt_rva: blob span hizali — cfg_off = (xrt_code_off + span + 15) & ~15
    # span bilinmiyor; ANCAK xrt_sdk_entry = xrt_rva + 678 oldugundan ve
    # cfg - xrt_rva = hizali span: XCFG icinde SELF rva alanlari var!
    print('[3] cfg atlamasi: SDK VA xrt64.bin icerik taramasindan (vmp0)')
    # xrt_rva: blob baslangici = cfg hizali geriye — SDK off 678 sabiti:
    # blob, cfg'den once biter; xrt_rva = ? — motor kodunda span hizali.
    # PRATIK: xrt blob 'ELF' yerine raw makine kodu; sdk_entry offset
    # XRT_BLOB64_SDK_OFF=678 (xrt_blob.cpp derlenmis sabit). xrt_rva'yi
    # XCFG'den cikaramiyoruz; motor logundan lsd_rva + cfg_rva iliskisi:
    # lsd_rva = cfg_rva + 0x60 (vf yok) -> cfg_rva = lsd_rva - 0x60
    # xrt_rva = cfg_rva - hizali_span; span = XRT_BLOB64_BSS_END ile max.
    # en saglam: testte TUM adaylarda (cfg_rva - 0x100000000 degil) —
    # sdk_entry'yi bilinen sub-sec icinde ara: 68 E9 rel32 (jmp) uretilmiyor...
    # BASIT VE KESIN: harness zaten cfg+lsd konumlarini biliyor; SDK girisi
    # icin xrt blobunun BASINI bulmak yeterli: blob .vmp0 basinda degil,
    # bytecode oncesi yerlesir. Motor kaynakli kesin kural:
    #   xrt_code_off = lsd_rva'dan geriye: [cfg][LSD][bytecode...] DUZENINDE
    #   bytecode LSD sonrasi; blob cfg'den once. Kanit dosyasinda sabit:
    #   XRT_BLOB64_SDK_OFF = 678 (xrt64.elf sembol offseti).
    # xrt_rva = cfg_va - span_align; span = blob uzunlugu (46KB) hizali...
    # KESIN COZUM: sembol offsetini elf'ten degil, KANIT LOGUNDAN al:
    # host_cli --verbose? yok. O halde ELF'i bastan olustur:
    xrt_rva = None
    # XCFG 0x38+ alanlarinda xrt rva olabilir — dene (TEXTRVA = orijinal .text)
    # ---Gerçek çözüm: engine_main 846: xrt_rva = newva_guess + xrt_code_off;
    #   cfg_off = (xrt_code_off + span + 15) & ~15 -> cfg_va - xrt_rva = hizali span
    #   SDK = xrt_rva + 678. span'i bilmek icin blob uzunlugu lazim:
    #   xrt64.bin dosya boyu = span'in alt siniri; bss uzantisi var.
    #   bss_end sabitini xrt_blob.cpp'den oku:
    import re as _re
    src = open('/tmp/xpa3/source/xrt_blob.cpp').read()
    bss_end = int(_re.search(r'XRT_BLOB64_BSS_END = (\d+)', src).group(1))
    sdk_off = int(_re.search(r'XRT_BLOB64_SDK_OFF = (\d+)', src).group(1))
    xrt_len = len(open('/tmp/xpa3/source/xrt64.bin', 'rb').read())
    # motor kurallari (engine_main 799-851) birebir:
    secalign = 0x1000
    newva_guess = (max(va + max(vs, rs) for _, va, vs, _, rs in secs) + secalign - 1) & ~(secalign - 1)
    XRT_BSS_PAD = 0x800          # engine.hpp'ten sabit — dogrula:
    mpad = _re.search(r'XRT_BSS_PAD\s*=\s*(0x[0-9A-Fa-f]+|\d+)',
                      open('/tmp/xpa3/source/engine.hpp').read())
    if mpad: XRT_BSS_PAD = int(mpad.group(1), 0)
    xrt_code_off = (((0) + 15) & ~15)   # blob_len bilinmiyor — asagida taramayla
    # blob_len: vmp0 icinde xrt64.bin icerigi VAR — ilk 64 bayti tara:
    blob_head = open('/tmp/xpa3/source/xrt64.bin', 'rb').read()[:64]
    for name, va, vs, pr, rs in secs:
        raw = d[pr:pr+rs]
        i = raw.find(blob_head)
        if i >= 0:
            xrt_rva_found = va + i
            print(f'[4] xrt blob @ rva {xrt_rva_found:#x} (section {name})')
            sdk_va = imgbase + xrt_rva_found + sdk_off
            print(f'    SDK VA={sdk_va:#x} (sdk_off={sdk_off})')
            break
    else:
        # vmp0'da bulunamadi — cfg'den geri hesap (span hizali)
        bespan = (bss_end + 15) & ~15
        span = max(xrt_len, bespan)
        span = (span + 15) & ~15
        newva_guess = (max(va + max(vs, rs) for _, va, vs, _, rs in secs) + 0xFFF) & ~0xFFF
        xrt_rva_found = (newva_guess + 0x800 + span) & 0xFFFFFFFF   # motor: cfg_off - span
        sdk_va = imgbase + xrt_rva_found + sdk_off
        print(f'[4] tarama yok — hesapla: xrt_rva={xrt_rva_found:#x} SDK VA={sdk_va:#x}')

    # ---- Unicorn: PE'yi map et ----
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    maxva = max(va + max(vs, rs) for _, va, vs, _, rs in secs)
    mapsz = max(imgsz, maxva) + 0x10000
    mu.mem_map(imgbase, (mapsz + 0xFFF) & ~0xFFF)
    for name, va, vs, pr, rs in secs:
        if rs:
            mu.mem_write(imgbase + va, d[pr:pr+rs])
    # PE header (MZ + PE + section tablosu) — section degil, dosya basi:
    # Windows loader imajin basina header'i map'ler (SizeOfHeaders).
    szh = struct.unpack_from('<I', d, e + 0x3C + 4)[0] if False else 0x400
    mu.mem_write(imgbase, d[:0x400])
    # stack
    STACK = 0x7FF000000000
    mu.mem_map(STACK, 0x100000)
    mu.reg_write(UC_X86_REG_RSP, STACK + 0x80000)
    # serial string
    SR = 0x600000
    mu.mem_map(SR, 0x10000)
    mu.mem_write(SR, serial.encode() + b'\x00')
    # geridonus adresi: magic RET adimi
    RET = 0x400000
    mu.mem_map(RET, 0x1000)
    mu.mem_write(RET, b'\xC3')   # ret
    # ---- KUSER_SHARED_DATA (0x7FFE0000) — lic_now_date/tick okur ----
    KUSD = 0x7FFE0000
    mu.mem_map(KUSD, 0x1000)
    # SystemTime @0x14 (FILETIME, 100ns): 2026-11-21 ~ 1338156800000000000
    import time as _t
    ft = 133815680000000000
    mu.mem_write(KUSD + 0x14, struct.pack('<I', ft & 0xFFFFFFFF))
    mu.mem_write(KUSD + 0x18, struct.pack('<I', ft >> 32))
    # TickCount @0x320 (çoklu duyarlık): makul deger
    mu.mem_write(KUSD + 0x320, struct.pack('<I', 60000))
    # ---- sahte PEB + LDR (lic_exe_base GS:[0x60] zinciri) ----
    # lic_exe_base: PEB->Ldr->InMemoryOrderLinks.Flink ILK giris = exe'nin
    # kendisi (load-order: exe once). Ilk giris DllBase = imgbase.
    PEB = 0x500000
    mu.mem_map(PEB, 0x10000)
    LDR = PEB + 0x800
    mu.mem_write(PEB + 0x18, struct.pack('<Q', LDR))
    ENT = PEB + 0x1000          # exe girisi (ilk)
    ENT2 = PEB + 0x1200         # kernel32 girisi (ikinci — peb_module bulur)
    head = LDR + 0x20
    # liste: head -> ENT+0x10 -> ENT2+0x10 -> head
    mu.mem_write(head, struct.pack('<Q', ENT + 0x10))
    mu.mem_write(head + 8, struct.pack('<Q', ENT2 + 0x10))
    mu.mem_write(ENT + 0x10, struct.pack('<Q', ENT2 + 0x10))
    mu.mem_write(ENT + 0x10 + 8, struct.pack('<Q', head))
    mu.mem_write(ENT2 + 0x10, struct.pack('<Q', head))
    mu.mem_write(ENT2 + 0x10 + 8, struct.pack('<Q', ENT + 0x10))
    mu.mem_write(ENT + 0x30, struct.pack('<Q', imgbase))       # exe DllBase
    mu.mem_write(ENT2 + 0x30, struct.pack('<Q', 0x7FE00000000))  # kernel32 base (sahte)
    # GS base ayarla: unicorn x86_64 GS base wrmsr benzeri — reg_write ile
    mu.reg_write(UC_X86_REG_GS_BASE, 0)     # GS:[0x60] = TEB+0x60
    # TEB: GS base'in kendisi TEB; GS:[0x60] -> PEB. TEB+0x60'a PEB yaz:
    TEB = 0x600000  # degisken — SR 0x600000 ile CATISIR! yeni adres:
    TEB = 0x7F0000000000
    mu.mem_map(TEB, 0x4000)
    mu.reg_write(UC_X86_REG_GS_BASE, TEB)
    mu.mem_write(TEB + 0x60, struct.pack('<Q', PEB))
    # x64 Win32 ABI: RCX=fnid? — sdk_entry asm: Win32 -> SysV; kontrol:
    # build_api_stub_x64: mov r10d, fnid; mov r11d, lsd_rva; jmp sdk_entry
    #   => sdk_entry(fnid=r10? hayir) — gercek imza: Win32 ABI RCX=fnid, RDX=a1
    # xrt_sdk_entry asm govdesi (xrt_license.c 1466+): bkz. — Win32->SysV
    #   RCX->RDI, RDX->RSI, R8->RDX, R9->RCX
    # --- Unicorn belleginde LSD taramasi (runtime gordugu gibi) ---
    img = mu.mem_read(imgbase, imgsz)
    li = img.find(b'XLSD\x01')
    if li < 0:
        print('[!] Unicorn belleginde XLSD YOK — section map sorunu')
    else:
        lsd_u = bytes(img[li:li+0x12C])
        crc = 0xFFFFFFFF
        for by in lsd_u[:0x120]:
            crc ^= by
            for _ in range(8):
                crc = (crc >> 1) ^ (0xEDB88320 & (0 - (crc & 1))) & 0xFFFFFFFF
        crc ^= 0xFFFFFFFF
        import struct as st2
        stored = st2.unpack_from('<I', lsd_u, 0x128)[0]
        print(f'[*] Unicorn LSD @ rva {li:#x}: CRC {crc:#x} vs {stored:#x} — {"ESIT" if crc==stored else "BOZUK"}')
    # lic_exe_base donusu (0x101545 — call sonrasi):
    exebase_va = imgbase + xrt_rva_found + (0x101545 - 0x100000)
    def hook_exebase(uc, addr, size, ud):
        rax = uc.reg_read(UC_X86_REG_RAX)
        edx = 0
        try:
            import struct as _st
            e = _st.unpack('<I', uc.mem_read(rax + 0x3C, 4))[0]
            imgsz2 = _st.unpack('<I', uc.mem_read(rax + e + 0x50, 4))[0]
            print(f'  [exebase] rax={hex(rax)} e={hex(e)} imgsz={hex(imgsz2)}')
        except Exception as ex:
            print(f'  [exebase] rax={hex(rax)} okuma HATASI: {ex}')
    mu.hook_add(UC_HOOK_CODE, hook_exebase, begin=exebase_va, end=exebase_va+1)
    # tarama döngüsündeki magic karsilastirmasini izle (0x101589):
    cmp_va = imgbase + xrt_rva_found + (0x101589 - 0x100000)
    seen_rdi = [0, 0]
    def hook_cmp(uc, addr, size, ud):
        if seen_rdi[0] < 3 or seen_rdi[0] % 20000 == 0:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            r9 = uc.reg_read(UC_X86_REG_R9)
            if seen_rdi[0] < 3:
                print(f'  [tarama] ilk rdi={hex(rdi)} (LSD rva {hex(rdi-0x120-0x140000000)}) son={hex(r9)}')
        seen_rdi[0] += 1
    mu.hook_add(UC_HOOK_CODE, hook_cmp, begin=cmp_va, end=cmp_va+1)
    # lic_lsd govdesinde imgsz okuma noktasini izle:
    # 0x101540..: prolog sonrasi PE header okuma — giriste reg dök:
    lsd_va = imgbase + xrt_rva_found + (0x101540 - 0x100000)
    def hook_lsd_enter(uc, addr, size, ud):
        # peb_addr yakinda cagrildi; zinciri elle yeniden oku:
        pebp = uc.reg_read(UC_X86_REG_GS_BASE)
        try:
            peb = struct.unpack('<Q', uc.mem_read(pebp + 0x60, 8))[0]
            ldr = struct.unpack('<Q', uc.mem_read(peb + 0x18, 8))[0]
            first = struct.unpack('<Q', uc.mem_read(ldr + 0x20, 8))[0]
            dllbase = struct.unpack('<Q', uc.mem_read(first + 0x20, 8))[0]
            print(f'  [zincir] peb={hex(peb)} ldr={hex(ldr)} first={hex(first)} dllbase={hex(dllbase)}')
        except Exception as ex:
            print('  [zincir] HATA:', ex)
    mu.hook_add(UC_HOOK_CODE, hook_lsd_enter, begin=lsd_va, end=lsd_va+1)
    # lic_lsd donusunu izle (0x101540):
    lsdfn_va = imgbase + xrt_rva_found + (0x101540 - 0x100000)
    lsd_rets = []
    def hook_lsd_in(uc, addr, size, ud):
        pass
    def hook_lsd_out(uc, addr, size, ud):
        # her 'ret' yakala — lic_lsd icinde mi diye devam eden iz:
        pass
    # pratik: lic_lsd cagrisindan SONRAki ilk komut noktasi RAX'i verir:
    # call site 104931+5 = 0x104936
    aft_va = imgbase + xrt_rva_found + (0x104936 - 0x100000)
    def hook_after_lsd(uc, addr, size, ud):
        print(f'  [lic_lsd sonrasi] rax={hex(uc.reg_read(UC_X86_REG_RAX))}')
    mu.hook_add(UC_HOOK_CODE, hook_after_lsd, begin=aft_va, end=aft_va+1)
    # dispatch girisinde fnid (rdi) dogrula:
    disp_va = imgbase + xrt_rva_found + (0x10b000 - 0x100000)
    def hook_disp(uc, addr, size, ud):
        print(f'  [dispatch] rdi(fnid)={uc.reg_read(UC_X86_REG_RDI)} rsi(a1)={hex(uc.reg_read(UC_X86_REG_RSI))} rdx(a2)={hex(uc.reg_read(UC_X86_REG_RDX))}')
    mu.hook_add(UC_HOOK_CODE, hook_disp, begin=disp_va, end=disp_va+1)
    mu.reg_write(UC_X86_REG_R10, 1)          # fnid = XPAPI_SETSERIAL (r10d!)
    mu.reg_write(UC_X86_REG_RCX, SR)         # a1 = serial* (Win32 RCX)
    mu.reg_write(UC_X86_REG_RDX, 0)          # a2
    mu.reg_write(UC_X86_REG_R8, 0)
    mu.reg_write(UC_X86_REG_R9, 0)
    # lsd_rva r11d'ye yazilir stub tarafindan; dispatch lsd'i lic_lsd() ile
    # IMAJDAN tarar (RVA pişirmek yerine) — dogrudan cagri icin gerek yok.
    if TRACE:
        seen = []
        import collections
        calls = []
        def hook_code(uc, addr, size, ud):
            # 'ret' komutlarini izle: RAX degeri donus
            code = uc.mem_read(addr, size)
            if code[0] == 0xC3 and len(calls) < 40:
                calls.append((addr, uc.reg_read(UC_X86_REG_RAX)))
        mu.hook_add(UC_HOOK_CODE, hook_code)
    try:
        sp = STACK + 0x80000 - 8
        mu.reg_write(UC_X86_REG_RSP, sp)
        mu.mem_write(sp, struct.pack('<Q', RET))
        mu.emu_start(sdk_va, RET, timeout=30*1000000)
        if TRACE:
            print('[ret-iz] (adres, rax):', calls[:40])
    except UcError as ex:
        print('[!] emu hatasi:', ex, 'RIP=', hex(mu.reg_read(UC_X86_REG_RIP)))
        return 1
    rax = mu.reg_read(UC_X86_REG_RAX)
    print(f'[5] SetSerial donusu: {rax:#x} ({rax})')
    # state oku: fnid=2 GetState
    mu.reg_write(UC_X86_REG_R10, 2)
    mu.reg_write(UC_X86_REG_RCX, 0)
    mu.reg_write(UC_X86_REG_RDX, 0)
    sp = STACK + 0x80000 - 8
    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.mem_write(sp, struct.pack('<Q', RET))
    try:
        mu.emu_start(sdk_va, RET, timeout=30*1000000)
    except UcError as ex:
        print('[!] GetState hatasi:', ex)
        return 1
    st = mu.reg_read(UC_X86_REG_RAX)
    print(f'[6] GetState: {st:#x}')
    OK = (st == 0)
    print('[SONUC]', 'LISANS GECERLI ✓ (state=0)' if OK else f' durum={st:#x}')
    # negatif test: bozuk serial
    bad = 'QQ' + serial[2:]
    mu.mem_write(SR, bad.encode() + b'\x00')
    mu.reg_write(UC_X86_REG_R10, 1)
    mu.reg_write(UC_X86_REG_RCX, SR)
    mu.reg_write(UC_X86_REG_RDX, 0)
    sp = STACK + 0x80000 - 8
    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.mem_write(sp, struct.pack('<Q', RET))
    try:
        mu.emu_start(sdk_va, RET, timeout=30*1000000)
    except UcError as ex:
        print('[!] negatif hatasi:', ex); return 1
    r2 = mu.reg_read(UC_X86_REG_RAX)
    print(f'[7] negatif (bozuk b64): {r2:#x} (XS_INVALID=2 beklenir)')
    print('[E2E]', 'BASARILI' if (OK and r2 != 0) else 'KISMEN/KONTROL')
    return 0 if OK else 1

if __name__ == '__main__':
    sys.exit(main())
