// ============================================================
// engine_stub.cpp — elle kodlanmis VM giris stub'lari
// x64: 15 reg push + ctx kur + call vm_entry(RDI) + pop'lar + ret
// x86: pushad + ctx kur + push ctx + call vm_entry(cdecl) + popad + ret[imm16]
// DELTA sabitleri vm_opcodes.h ile birebir ayni olmali!
// ============================================================
#include "engine.hpp"

struct Patch32 { u32 off, val; };

static void put(std::vector<u8>& v, std::initializer_list<u8> b) {
    for (u8 x : b) v.push_back(x);
}
static void put32(std::vector<u8>& v, u32 x) {
    for (int k = 0; k < 4; k++) v.push_back((u8)(x >> (8 * k)));
}
static void put64(std::vector<u8>& v, u64 x) {
    for (int k = 0; k < 8; k++) v.push_back((u8)(x >> (8 * k)));
}

std::vector<u8> build_stub_x64(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len,
                               u32 xrt_entry_rva, u32 cfg_rva, u32 cont_rva,
                               u32 perm_seed, u32 vm_id, int ksadv, int regsenc, int rt_msg, int rt_exit,
                               const std::string& msgtext) {
    std::vector<u8> s;
    Patch32 p_key{}, p_l1{}, p_bc{}, p_len{}, p_rel{}, p_call2{}, p_msg{};
    u32 off_pop = 0;
    u32 off_xrt_call = 0;

    // --- 15 register push: SIRA ONEMILI! vm_entry push_area[k]'yi YUKARI
    // dogru okur: push_area[0]=rax, [1]=rcx, ... [14]=r15. Yigin asagi
    // uzandigi icin rax'in EN ALCAK adreste olmasi gerekir -> push'lari
    // TERSTEN yap (r15 once ... rax enson). x86 pushad duzeniyle ayni model
    // (EAX en alcak). Eski sirada src[1]=[entry] oluyor ve copy-back
    // DONUS ADRESINI EZIYORDU (wild ret -> crash).
    for (int r = 15; r >= 8; r--) put(s, {0x41, (u8)(0x50 + (r - 8))});
    put(s, {0x57,0x56,0x55,0x53,0x52,0x51,0x50});       // push rdi,rsi,rbp,rbx,rdx,rcx,rax
    // --- ctx kurulumu ---
    // r12 = push_area = rax'in yuvasi (push'lar sonrasi rsp'nin kendisi).
    // REX=0x4C (W|R): 0x49 olsayd reg=rsp olurdu -> "lea rsp,[rsp+0]" olurdu.
    put(s, {0x49,0x89,0xE4});                           // mov r12, rsp (push_area)
    put(s, {0x48,0x81,0xEC}); put32(s, VM_STUB_SUB64); // sub rsp (ctx+marj)
    put(s, {0x4C,0x89,0xA4,0x24,0xA8,0,0,0});           // mov [rsp+0xA8], r12 (push_area)
    put(s, {0x49,0x8D,0x84,0x24,0x78,0,0,0});           // lea rax,[r12+0x78] (init_rsp = giris rsp)
    put(s, {0x48,0x89,0x84,0x24,0xB0,0,0,0});           // mov [rsp+0xB0], rax (init_rsp)
    put(s, {0x48,0xB8}); p_key = {(u32)s.size(), 0}; put64(s, 0);   // mov rax,key
    put(s, {0x48,0x89,0x44,0x24,0x10});                 // mov [rsp+0x10], rax
    p_call2 = {(u32)s.size() + 1, 0};                   // call L1'in rel32 alani
    put(s, {0xE8,0,0,0,0});                             // call L1
    off_pop = (u32)s.size();                            // L1: <- call buraya doner
    put(s, {0x58});                                     // pop rax
    put(s, {0x48,0x2D}); p_l1 = {(u32)s.size(), 0}; put32(s, 0);    // sub rax, L1_rva
    put(s, {0x48,0x89,0x44,0x24,0x18});                 // mov [rsp+0x18], rax (base)
    // 1.2.5-A13 (x7): ozel tespit mesaji (UO/VMP Messages paritesi) — metin
    // stub'un SONUNA data olarak yasilir (hic calismaz), PIC lea ile
    // ctx+0x110 (VMContext.msgp) yazilir; 0 = varsayilan "#5" metni.
    if (!msgtext.empty()) {
        p_msg = {(u32)s.size() + 3, 0};
        put(s, {0x48,0x8D,0x88}); put32(s, 0);          // lea rcx,[rax+msg_rva]
        put(s, {0x48,0x89,0x8C,0x24,0x10,0x01,0x00,0x00}); // mov [rsp+0x110],rcx
    }
    put(s, {0x48,0x05}); p_bc = {(u32)s.size(), 0}; put32(s, 0);    // add rax, bc_rva
    put(s, {0x48,0x89,0x04,0x24});                      // mov [rsp], rax (bc)
    put(s, {0x48,0xB8}); p_len = {(u32)s.size(), 0}; put64(s, 0);   // mov rax,bc_len
    put(s, {0x48,0x89,0x44,0x24,0x08});                 // mov [rsp+0x08], rax
    // 0.8.0 polimorfik: opcode permütasyon tohumu -> ctx scratch[3] (+0xE0)
    // DİKKAT: C7 44 24 <disp8> disp8'i İMZALI yorumlar (0xE0 = -32!) —
    // yazım ctx ALTINA duser. disp32 formu zorunlu: C7 84 24 E0 00 00 00.
    if (perm_seed) {
        put(s, {0xC7,0x84,0x24,0xE0,0x00,0x00,0x00});
        for (int k = 0; k < 4; k++) put(s, {(u8)(perm_seed >> (8 * k))});
    }
    // 1.2.0-B1: vtAdvanced komut-sifreleyici kipi -> ctx scratch[5] (+0xF0)
    // ve mult-VM gostergesi -> ctx scratch[7] (+0x100). disp8 IMZALI: 0xF0
    // = -16 -> ctx altina duser; disp32 formu zorunlu (0.8.0 dersi).
    // KOŞULSUZ yazim: ctx yigin-çöpü scratch[5]/[7]'den okunamaz —
    // decoder KS kipi ve VM_VMK karisimi bu slotlardan gelir (DERS: koşullu
    // yazim klasiK modda anahtari bozdu -> 0xC0000005).
    // 1.2.0-A9: scratch[5] bit1 = Encrypt Registers bayragi (rdec/renc
    // bunu okur; bit0 = ksadv eski kipini korur).
    put(s, {0xC6,0x84,0x24,0xF0,0x00,0x00,0x00});                    // mov byte [rsp+0xF0],
    put(s, {(u8)((ksadv ? 1 : 0) | (regsenc ? 2 : 0) | (rt_msg ? 4 : 0) | (rt_exit ? 8 : 0))});   /* 1.2.5: bit2=rt_msg bit3=rt_exit (vm_poison okur) */
    put(s, {0xC7,0x84,0x24,0x00,0x01,0x00,0x00});                    // mov dword [rsp+0x100],
    for (int k = 0; k < 4; k++) put(s, {(u8)(vm_id >> (8 * k))});
    // --- 0.5.0: XProtect Runtime kapisi (bir-kez butunluk kontrolu) ---
    // xrt_entry SysV'dir; rax,rcx,rdx,rsi,rdi,r8-r11 bozar — 15 GPR
    // zaten push'lu, rax'in son kullanimi (len yazimi) geride kaldi.
    if (xrt_entry_rva && cfg_rva) {
        // 0.5.0 HIZALAMA DÜZELTMESI: bolgeye E9 (jmp) ile girilir — donus
        // adresi YOK, rsp hizasi cagirana bagli (0 veya 8 mod 16). xrt_entry
        // (SysV C) movaps kullanir -> giris rsp mutlaka 8 mod 16 olmali.
        // rbx 15-push blogunda zaten sakli (sonraki pop geri yukler).
        put(s, {0x48,0x8B,0x4C,0x24,0x18});              // mov rcx,[rsp+0x18] (base)
        put(s, {0x48,0x8D,0x89}); put32(s, cfg_rva);     // lea rcx,[rcx+cfg_rva]
        put(s, {0x80,0x79,0x08,0x00});                    // cmp byte [rcx+8],0 (state)
        put(s, {0x75,0x18});                              // jne .skip (24 bayt)
        put(s, {0x48,0x89,0xE3});                         // mov rbx,rsp (kaydet)
        put(s, {0x48,0x83,0xE4,0xF0});                    // and rsp,-16 (hizala)
        put(s, {0x48,0x89,0xCF});                         // mov rdi,rcx (SysV arg1)
        put(s, {0xE8,0,0,0,0}); off_xrt_call = (u32)s.size() - 5; // call xrt_entry
        put(s, {0x48,0x89,0xDC});                         // mov rsp,rbx (geri)
        put(s, {0x85,0xC0});                              // test eax,eax
        put(s, {0x74,0x02});                              // jz .skip
        put(s, {0x0F,0x0B});                              // ud2 (zehir)
    }
    // NOT: blob Linux gcc ile derlenir -> vm_entry SysV ABI (ilk arg RDI).
    // (Windows'ta da ayni: blob kendi icinde tutarli; VM_WINDOWS sadece
    //  natcall'un Win64 konvansiyonunu secar — dis fonksiyon cagrilari icin.)
    put(s, {0x48,0x89,0xE7});                           // mov rdi, rsp (ctx)
    put(s, {0xE8,0,0,0,0});                             // call vm_entry
    u32 off_call2 = (u32)s.size() - 5;
    // 1.2.0-B1 natgt kolu: done==3 -> kuyruk-jmp. Kontrol rdi (ctx) hala
    // gecerli (add rsp HENUZ yapilmadi). .natgt blogu:
    //  - rcx = base + scratch[6] (OP_JMPEXT/JCCEXT yazdi)
    //  - rcx'i push_area'nin RCX slotuna yaz (ctx+0x338): pop'lar restore
    //    ettiginde rcx = hedef kalir (rcx volatile — ABI-gecerli ezme)
    //  - pop'lar F'nin SON degerlerini geri koyar (vm_entry SRC_STORE);
    //    donus adresi yiginda KALIR (hedef kendi ret-imm'ini temizler).
    u32 off_natgt_je = 0, off_natgt = 0;
    // DERS (0xC0000005): SysV'de RDI CALLER-SAVED — vm_entry ezebilir.
    // Kontrol RSP-goreli: call/ret dengesi icin rsp = ctx tabani (asagi).
    put(s, {0x48,0x83,0xBC,0x24,0xC0,0x00,0x00,0x00,0x03});  // cmp qword [rsp+0xC0],3
    put(s, {0x0F,0x84,0,0,0,0}); off_natgt_je = (u32)s.size() - 4;  // je .natgt
    put(s, {0x48,0x81,0xC4}); put32(s, VM_STUB_SUB64); // add rsp
    // pop'lar push'larin TERSTEN (rax once ... r15 enson)
    put(s, {0x58,0x59,0x5A,0x5B,0x5D,0x5E,0x5F});       // pop rax,rcx,rdx,rbx,rbp,rsi,rdi
    for (int r = 8; r <= 15; r++) put(s, {0x41, (u8)(0x58 + (r - 8))});
    // 0.5.0: BOLGE kipi — ret yerine region sonuna jmp (donus adresi yiginda
    // kalir; region sonu kodu epilogu yurutur). Normal fonksiyon: ret.
    u32 off_cont = 0;
    if (cont_rva) {
        off_cont = (u32)s.size();
        put(s, {0xE9,0,0,0,0});                         // jmp region_end
    } else {
        put(s, {0xC3});                                 // ret
    }
    // --- 1.2.0-B1: .natgt (kuyruk-jmp disari) — v3 ---
    // DERS (a2=-1073727498 kaniti): kuyruk-hedef kodu fonksiyonun KENDI
    // cerceve durumunu bekler (add rsp,0x20; pop rbp; ...). Stub'in entry
    // rsp'si DEGIL — natgt, pops'tan sonra RSP'yi konuk mantiksal rsp'ye
    // (ctx->regs[4], DELTA'siz) ayarlar; boylece hedefin frame-epilogu
    // dogru slotlarda yurur ve [rsp] = cagiranin geri-adresi kalir.
    // Hedef tasıyici = R10 (volatile, arg-degil; RCX = Win64 arg1 — dokunma).
    off_natgt = (u32)s.size();
    put(s, {0x4C,0x8B,0x94,0x24,0xF8,0x00,0x00,0x00});  // mov r10,[rsp+0xF8] (natgt rva)
    put(s, {0x4C,0x03,0x54,0x24,0x18});                 // add r10,[rsp+0x18] (base)
    put(s, {0x4C,0x89,0x94,0x24,0x78,0x03,0x00,0x00});  // mov [rsp+0x378],r10 (R10 slot!)
    put(s, {0x48,0x81,0xC4}); put32(s, VM_STUB_SUB64);  // add rsp
    put(s, {0x58,0x59,0x5A,0x5B,0x5D,0x5E,0x5F});       // pop rax,rcx,rdx,rbx,rbp,rsi,rdi
    for (int r = 8; r <= 15; r++) put(s, {0x41, (u8)(0x58 + (r - 8))});
    put(s, {0x48,0x8D,0x94,0x24,0x58,0xFC,0xFF,0xFF});  // lea rdx,[rsp-0x3A8] (ctx)
    put(s, {0x48,0x8B,0x92,0xB0,0x00,0x00,0x00});       // mov rdx,[rdx+0xB0] (init_rsp RAW — 1.2.2-A9FIX: regs[] sifreli)
    put(s, {0x48,0x89,0xD4});                           // mov rsp,rdx (konuk rsp)
    put(s, {0x41,0xFF,0xE2});                           // jmp r10

    // --- yamalar ---
    u32 l1_rva = stub_rva + off_pop;
    u32 buf[8]; (void)buf;
    // key (imm64) — 0.8.0 crypt_key: obfuscated (key ^ VM_KEYXOR(bc_rva,bc_len));
    // vm_entry giriste geri cozer (vm_opcodes.h'daki ayni makro).
    {
        u64 kx = key ^ VM_KEYXOR(bc_rva, bc_len);
        for (int k = 0; k < 8; k++) s[p_key.off + k] = (u8)(kx >> (8 * k));
    }
    // L1 rva
    s[p_l1.off]     = (u8)(l1_rva);
    s[p_l1.off + 1] = (u8)(l1_rva >> 8);
    s[p_l1.off + 2] = (u8)(l1_rva >> 16);
    s[p_l1.off + 3] = (u8)(l1_rva >> 24);
    // bc rva
    s[p_bc.off]     = (u8)(bc_rva);
    s[p_bc.off + 1] = (u8)(bc_rva >> 8);
    s[p_bc.off + 2] = (u8)(bc_rva >> 16);
    s[p_bc.off + 3] = (u8)(bc_rva >> 24);
    // bc len
    for (int k = 0; k < 8; k++) s[p_len.off + k] = (u8)((u64)bc_len >> (8 * k));
    // xrt_entry rel32
    if (off_xrt_call) {
        i32 xr = (i32)(xrt_entry_rva - (stub_rva + off_xrt_call + 5));
        for (int k = 0; k < 4; k++) s[off_xrt_call + 1 + k] = (u8)((u32)xr >> (8 * k));
    }
    // region devam rel32
    if (off_cont) {
        i32 rc = (i32)(cont_rva - (stub_rva + off_cont + 5));
        s[off_cont + 1] = (u8)(u32)rc;
        s[off_cont + 2] = (u8)((u32)rc >> 8);
        s[off_cont + 3] = (u8)((u32)rc >> 16);
        s[off_cont + 4] = (u8)((u32)rc >> 24);
    }
    // vm_entry rel32
    i32 rel = (i32)(vm_entry_rva - (stub_rva + off_call2 + 5));
    s[off_call2 + 1] = (u8)(u32)rel;
    s[off_call2 + 2] = (u8)((u32)rel >> 8);
    s[off_call2 + 3] = (u8)((u32)rel >> 16);
    s[off_call2 + 4] = (u8)((u32)rel >> 24);
    (void)p_rel;
    // 1.2.0-B1: je .natgt rel32
    {
        i32 nr = (i32)(stub_rva + off_natgt - (stub_rva + off_natgt_je + 4));
        for (int k = 0; k < 4; k++) s[off_natgt_je + k] = (u8)((u32)nr >> (8 * k));
    }
    // 1.2.5-A13 (x7): mesaj metni — kodun SONUNA data (hic calismaz);
    // lea disp32'si buraya isaret eder. NUL dahil, 255 bayt sinir.
    if (!msgtext.empty()) {
        u32 msg_off = (u32)s.size();
        size_t n = msgtext.size();
        if (n > 255) n = 255;
        for (size_t k = 0; k < n; k++) s.push_back((u8)msgtext[k]);
        s.push_back(0);
        for (int k = 0; k < 4; k++) s[p_msg.off + k] = (u8)((stub_rva + msg_off) >> (8 * k));
    }
    return s;
}

std::vector<u8> build_stub_x86(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len, u32 retimm,
                               u32 xrt_entry_rva, u32 cfg_rva, u32 cont_rva,
                               u32 perm_seed, u32 vm_id, int ksadv, int regsenc, int rt_msg, int rt_exit,
                               const std::string& msgtext) {
    // BUGFIX #12 (x86 w+Enter cokmesi): retimm eskiden u16 idi.
    // engine.hpp'deki "ret yok" sentinel'i 0xFFFFFFFF (u32) u16'ya
    // kirpilinca 0xFFFF oluyor, asagidaki sentinel kontrolu atlaniyor
    // ve "ret 0xFFFF" uretiliyordu -> her sanallastirilmis cagri
    // donusunde ESP +0x10003 kayiyor -> ilk VM cagrisinda (w+Enter)
    // stack corba -> SIGSEGV. Simdi param u32; sentinel veya 0 -> C3.
    std::vector<u8> s;
    u32 off_key, off_key2, off_l1, off_bc, off_len, off_call2, off_pop;
    u32 off_xrt_call = 0;
    Patch32 p_msg{};                                    // 1.2.5-A13 (x7)

    put(s, {0x60});                                     // pushad
    put(s, {0x81,0xEC}); put32(s, VM_STUB_SUB86);       // sub esp
    put(s, {0x8D,0x84,0x24}); put32(s, VM_STUB_SUB86);   // lea eax,[esp+SUB] (push_area)
    put(s, {0x89,0x84,0x24}); put32(s, VMOFF_PUSHAREA); // mov [esp+0xA8], eax
    put(s, {0x05}); put32(s, 0x20);                     // add eax,0x20
    put(s, {0x89,0x84,0x24}); put32(s, VMOFF_INITRSP);  // mov [esp+0xB0], eax
    put(s, {0xB8}); off_key = (u32)s.size(); put32(s, 0);           // mov eax,key_lo
    put(s, {0x89,0x44,0x24,0x10});                      // mov [esp+0x10], eax
    // ctx->key 64 BITTIR: yuksek 32 bit de yazilmali (eski kod sadece lo
    // yaziyor, hi yigin copu kaliyor -> VM_KS yanlis -> tum bc corba!)
    put(s, {0xB8}); off_key2 = (u32)s.size(); put32(s, 0);          // mov eax,key_hi
    put(s, {0x89,0x44,0x24,0x14});                      // mov [esp+0x14], eax
    put(s, {0xE8,0,0,0,0});                             // call L1
    off_pop = (u32)s.size();
    put(s, {0x58});                                     // pop eax
    put(s, {0x2D}); off_l1 = (u32)s.size(); put32(s, 0);            // sub eax,L1_rva
    put(s, {0x89,0x44,0x24,0x18});                      // mov [esp+0x18], eax
    // 1.2.5-A13 (x7): ozel tespit mesaji — ctx+0x110 (VMContext.msgp);
    // ecx burada ucretsiz (xrt kapisi ve vm_entry kendi yukler).
    if (!msgtext.empty()) {
        p_msg = {(u32)s.size() + 2, 0};
        put(s, {0x8D,0x88}); put32(s, 0);               // lea ecx,[eax+msg_rva]
        put(s, {0x89,0x8C,0x24}); put32(s, 0x110);      // mov [esp+0x110],ecx
    }
    put(s, {0x05}); off_bc = (u32)s.size(); put32(s, 0);            // add eax,bc_rva
    put(s, {0x89,0x04,0x24});                           // mov [esp], eax
    put(s, {0xB8}); off_len = (u32)s.size(); put32(s, 0);           // mov eax,len
    put(s, {0x89,0x44,0x24,0x08});                      // mov [esp+0x08], eax
    // 0.8.0 polimorfik: opcode permütasyon tohumu -> ctx scratch[3] (+0xE0)
    // DİKKAT: C7 44 24 <disp8> disp8'i İMZALI yorumlar (0xE0 = -32!) —
    // yazım ctx ALTINA duser. disp32 formu zorunlu: C7 84 24 E0 00 00 00.
    if (perm_seed) {
        put(s, {0xC7,0x84,0x24,0xE0,0x00,0x00,0x00});
        for (int k = 0; k < 4; k++) put(s, {(u8)(perm_seed >> (8 * k))});
    }
    // 1.2.0-B1: ksadv -> scratch[5] (+0xF0), vm_id -> scratch[7] (+0x100)
    // (disp32 formu zorunlu — disp8 imzali, ctx altina duser)
    // KOŞULSUZ yazim (x64 dersi: koşullu yazim klasiK modda anahtari bozdu)
    // 1.2.0-A9: scratch[5] bit1 = Encrypt Registers bayragi.
    put(s, {0xC6,0x84,0x24,0xF0,0x00,0x00,0x00});                    // mov byte [esp+0xF0],
    put(s, {(u8)((ksadv ? 1 : 0) | (regsenc ? 2 : 0) | (rt_msg ? 4 : 0) | (rt_exit ? 8 : 0))});   /* 1.2.5: bit2=rt_msg bit3=rt_exit (vm_poison okur) */
    put(s, {0xC7,0x84,0x24,0x00,0x01,0x00,0x00});                    // mov dword [esp+0x100],
    for (int k = 0; k < 4; k++) put(s, {(u8)(vm_id >> (8 * k))});
    // --- 0.5.0: XProtect Runtime kapisi (bir-kez butunluk kontrolu) ---
    // xrt_entry cdecl'dir; eax/ecx/edx bozar — bu noktada ucude de ihtiyac yok.
    if (xrt_entry_rva && cfg_rva) {
        put(s, {0x8B,0x4C,0x24,0x18});                  // mov ecx,[esp+0x18] (base)
        put(s, {0x8D,0x89}); put32(s, cfg_rva);         // lea ecx,[ecx+cfg_rva]
        put(s, {0x80,0x79,0x08,0x00});                  // cmp byte [ecx+8],0 (state)
        put(s, {0x75,0x0F});                            // jne .skip (15 bayt)
        put(s, {0x51});                                 // push ecx (cfg*)
        put(s, {0xE8,0,0,0,0}); off_xrt_call = (u32)s.size() - 5; // call xrt_entry
        put(s, {0x83,0xC4,0x04});                       // add esp,4
        put(s, {0x85,0xC0});                            // test eax,eax
        put(s, {0x74,0x02});                            // jz .skip
        put(s, {0x0F,0x0B});                            // ud2 (zehir)
    }
    put(s, {0x54});                                     // push esp (ctx)
    put(s, {0xE8,0,0,0,0});                             // call vm_entry
    off_call2 = (u32)s.size() - 5;
    // 1.2.0-B1 natgt kolu (x86): [esp] = ctx ptr (call sonrasi).
    //  - ecx = ctx; done==3 kontrol
    //  - .natgt: edx = base + [ctx+0xF8]; EDX'i pushad ECX slotuna yaz
    //    (esp + SUB + 0x1C = E-8); popad'da ecx = hedef (ecx volatile —
    //    ABI-gecerli ezme), eax/edx = F'nin son degerleri, donus adresi
    //    yiginda KALIR; jmp ecx (hedef kendi ret-imm'ini temizler).
    u32 off_natgt_je = 0, off_natgt = 0;
    put(s, {0x8B,0x0C,0x24});                           // mov ecx,[esp] (ctx ptr)
    put(s, {0x83,0x79,0xC0,0x03});                      // cmp dword [ecx+0xC0],3
    put(s, {0x0F,0x84,0,0,0,0}); off_natgt_je = (u32)s.size() - 4;  // je .natgt
    put(s, {0x83,0xC4,0x04});                           // add esp,4
    put(s, {0x81,0xC4}); put32(s, VM_STUB_SUB86);       // add esp
    put(s, {0x61});                                     // popad
    u32 off_cont = 0;
    if (cont_rva) {
        // 0.5.0: BOLGE kipi — ret/ret-imm yerine region sonuna jmp
        off_cont = (u32)s.size();
        put(s, {0xE9,0,0,0,0});                         // jmp region_end
    } else if (retimm != 0 && retimm != 0xFFFFFFFF) {
        put(s, {0xC2});
        put32(s, retimm); s.pop_back(); s.pop_back();   // ret imm16 (C2 + 2 bayt)
        // (eski kod tek pop_back yapiyordu, ucuncu byte cop kaliyordu)
    } else {
        put(s, {0xC3});                                 // plain ret (cdecl)
    }
    // --- 1.2.0-B1: .natgt (kuyruk-jmp disari) — v3 (x86) ---
    // pops'tan sonra esp = giris esp; ctx = giris-0x28C; guest esp RAW degeri
    // ctx+0xB0 (init_rsp, vm_entry done==3 yazar) -> esp = guest-esp; jmp ecx.
    off_natgt = (u32)s.size();
    put(s, {0x8B,0x51,0x18});                           // mov edx,[ecx+0x18] (base)
    put(s, {0x03,0x91,0xF8,0x00,0x00,0x00});            // add edx,[ecx+0xF8] (natgt rva)
    put(s, {0x89,0x94,0x24}); put32(s, VM_STUB_SUB86 + 0x1C);  // mov [esp+SUB+0x1C],edx (ECX slot!)
    put(s, {0x83,0xC4,0x04});                           // add esp,4 (ctx ptr)
    put(s, {0x81,0xC4}); put32(s, VM_STUB_SUB86);       // add esp
    put(s, {0x61});                                     // popad (ecx = hedef)
    put(s, {0x8B,0xA4,0x24,0x24,0xFE,0xFF,0xFF});       // mov esp,[esp-0x1DC] (ctx+0xB0 = init_rsp RAW — 1.2.2-A9FIX)
    put(s, {0xFF,0xE1});                                // jmp ecx

    u32 l1_rva = stub_rva + off_pop;
    {   /* 0.8.0 crypt_key: obfuscated key (key ^ K2) — iki yarmaya da */
        u64 kx = key ^ VM_KEYXOR(bc_rva, bc_len);
        for (int k = 0; k < 4; k++) s[off_key + k]  = (u8)((u32)kx >> (8 * k));
        for (int k = 0; k < 4; k++) s[off_key2 + k] = (u8)((u32)(kx >> 32) >> (8 * k));
    }
    for (int k = 0; k < 4; k++) s[off_l1 + k]  = (u8)(l1_rva >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_bc + k]  = (u8)(bc_rva >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_len + k] = (u8)(bc_len >> (8 * k));
    if (off_xrt_call) {
        i32 xr = (i32)(xrt_entry_rva - (stub_rva + off_xrt_call + 5));
        for (int k = 0; k < 4; k++) s[off_xrt_call + 1 + k] = (u8)((u32)xr >> (8 * k));
    }
    if (off_cont) {
        i32 rc = (i32)(cont_rva - (stub_rva + off_cont + 5));
        for (int k = 0; k < 4; k++) s[off_cont + 1 + k] = (u8)((u32)rc >> (8 * k));
    }
    i32 rel = (i32)(vm_entry_rva - (stub_rva + off_call2 + 5));
    for (int k = 0; k < 4; k++) s[off_call2 + 1 + k] = (u8)((u32)rel >> (8 * k));
    // 1.2.0-B1: je .natgt rel32
    {
        i32 nr = (i32)(stub_rva + off_natgt - (stub_rva + off_natgt_je + 4));
        for (int k = 0; k < 4; k++) s[off_natgt_je + k] = (u8)((u32)nr >> (8 * k));
    }
    // 1.2.5-A13 (x7): mesaj metni — kodun SONUNA data (ret sonrasi hic
    // calismaz); lea disp32'si buraya isaret eder. NUL dahil, 255 bayt.
    if (!msgtext.empty()) {
        u32 msg_off = (u32)s.size();
        size_t n = msgtext.size();
        if (n > 255) n = 255;
        for (size_t k = 0; k < n; k++) s.push_back((u8)msgtext[k]);
        s.push_back(0);
        for (int k = 0; k < 4; k++) s[p_msg.off + k] = (u8)((stub_rva + msg_off) >> (8 * k));
    }
    return s;
}

// ============================================================
// 0.5.0 — M-tipi govde onu runtime kapisi
// pushad/pushaq korumali: fastcall (ecx/edx) arglari dahil hicbir
// kayit bozulmaz. Zehir: ud2. Govde kapiye bitisik yerlesir.
// ============================================================
std::vector<u8> build_mgate_x86(u32 gate_rva, u32 xrt_entry_rva, u32 cfg_rva,
                                u32 body_rva) {
    std::vector<u8> s;
    u32 off_call = 0;
    put(s, {0x60});                                     // pushad (tum GPR'ler korunur)
    put(s, {0xE8,0,0,0,0}); off_call = (u32)s.size() - 5; // call L1
    u32 l1 = (u32)s.size();
    put(s, {0x58});                                     // pop eax (runtime addr)
    put(s, {0x2D}); put32(s, gate_rva + l1);            // sub eax,(L1 rva) -> base
    put(s, {0x8D,0x88}); put32(s, cfg_rva);             // lea ecx,[eax+cfg_rva]
    put(s, {0x80,0x79,0x08,0x00});                      // cmp byte [ecx+8],0
    put(s, {0x75,0x0F});                                // jne .ok
    put(s, {0x51});                                     // push ecx
    put(s, {0xE8,0,0,0,0});                             // call xrt_entry
    u32 xr = (u32)s.size() - 5;
    put(s, {0x83,0xC4,0x04});                           // add esp,4
    put(s, {0x85,0xC0});                                // test eax,eax
    put(s, {0x74,0x02});                                // jz .ok
    put(s, {0x0F,0x0B});                                // ud2
    put(s, {0x61});                                     // .ok: popad
    i32 r1 = (i32)(xrt_entry_rva - (gate_rva + xr + 5));
    for (int k = 0; k < 4; k++) s[xr + 1 + k] = (u8)((u32)r1 >> (8 * k));
    (void)body_rva;                                     // govde bitisik — jmp yok
    return s;
}

std::vector<u8> build_mgate_x64(u32 gate_rva, u32 xrt_entry_rva, u32 cfg_rva,
                                u32 body_rva) {
    std::vector<u8> s;
    // 7 push: rax,rcx,rdx,r8,r9,rsi,rdi (arg + varargs-al korunur;
    // rbx/rbp/r12-15 zaten callee-saved, xrt_entry (SysV) dokunmaz)
    put(s, {0x50,0x51,0x52});
    put(s, {0x41,0x50,0x41,0x51});
    put(s, {0x56,0x57});
    put(s, {0x53});                                     // 0.5.0: push rbx (hizalama kaydi — callee-saved)
    put(s, {0xE8,0,0,0,0});                             // call L1
    u32 l1 = (u32)s.size();
    put(s, {0x58});                                     // pop rax
    put(s, {0x48,0x2D}); put32(s, gate_rva + l1);       // sub rax,(L1 rva) -> base
    put(s, {0x48,0x8D,0x88}); put32(s, cfg_rva);        // lea rcx,[rax+cfg_rva]
    put(s, {0x80,0x79,0x08,0x00});                      // cmp byte [rcx+8],0
    put(s, {0x75,0x18});                                // jne .ok (24 bayt: hizalama blogu)
    put(s, {0x48,0x89,0xE3});                           // mov rbx,rsp
    put(s, {0x48,0x83,0xE4,0xF0});                      // and rsp,-16 (movass hizasi)
    put(s, {0x48,0x89,0xCF});                           // mov rdi,rcx (SysV arg1)
    put(s, {0xE8,0,0,0,0});                             // call xrt_entry
    u32 xr = (u32)s.size() - 5;
    put(s, {0x48,0x89,0xDC});                           // mov rsp,rbx
    put(s, {0x85,0xC0});                                // test eax,eax
    put(s, {0x74,0x02});                                // jz .ok
    put(s, {0x0F,0x0B});                                // ud2
    put(s, {0x5B});                                     // .ok: pop rbx
    put(s, {0x5F,0x5E,0x41,0x59,0x41,0x58,0x5A,0x59,0x58}); // pop'lar (ters)
    i32 r1 = (i32)(xrt_entry_rva - (gate_rva + xr + 5));
    for (int k = 0; k < 4; k++) s[xr + 1 + k] = (u8)((u32)r1 >> (8 * k));
    (void)body_rva;
    return s;
}

// ============================================================
// 0.5.0 — gecikmeli import thunk'lari
// Cagri noktasi (FF15 -> E8 thunk / FF25 -> E9 thunk) tarafindan
// cagrilir. Cozum: xrt_resolve(dllhash, namehash, fallback_abs);
// sonuc .vmp0 cache hucresine yazilir (bir kez cozulur).
// Tum arg kayitlari (fastcall/Win64 + varargs rax) korunur.
// ============================================================
std::vector<u8> build_thunk_x86(u32 thunk_rva, u32 resolve_rva, u32 cache_rva,
                                u32 dll_hash, u32 name_hash, u32 iat_rva) {
    std::vector<u8> s;
    // yigin duzeni (rsp'ye gore): edi+0 esi+4 edx+8 ecx+0xC eax+0x10
    put(s, {0x50,0x51,0x52,0x56,0x57});                 // push eax,ecx,edx,esi,edi
    put(s, {0xE8,0,0,0,0});                             // call L1
    u32 l1 = (u32)s.size();
    put(s, {0x58});                                     // pop eax
    put(s, {0x2D}); put32(s, thunk_rva + l1);           // sub eax,L1 -> base
    put(s, {0x89,0x44,0x24,0x10});                      // mov [esp+0x10],eax (eax yuvasi=base)
    put(s, {0x8D,0x90}); put32(s, cache_rva);           // lea edx,[eax+cache_rva]
    put(s, {0x83,0x3A,0x00});                           // cmp dword [edx],0
    put(s, {0x75,0x18});                                // jne .go (24 bayt)
    put(s, {0x8B,0x44,0x24,0x10});                      // mov eax,[esp+0x10] (base)
    put(s, {0x05}); put32(s, iat_rva);                  // add eax,iat_rva (fallback_abs)
    put(s, {0x50});                                     // push eax (arg3)
    put(s, {0x68}); put32(s, name_hash);                // push name_hash (arg2)
    put(s, {0x68}); put32(s, dll_hash);                 // push dll_hash (arg1)
    put(s, {0xE8,0,0,0,0});                             // call xrt_resolve
    u32 xr = (u32)s.size() - 5;
    put(s, {0x83,0xC4,0x0C});                           // add esp,12
    put(s, {0x8B,0x54,0x24,0x10});                      // mov edx,[esp+0x10] (base)
    put(s, {0x89,0x82}); put32(s, cache_rva);           // mov [edx+cache_rva],eax
    put(s, {0x8B,0x0A});                                // .go: mov ecx,[edx] (hedef)
    put(s, {0x89,0x4C,0x24,0x08});                      // mov [esp+8],ecx (edx yuvasina)
    put(s, {0x5F,0x5E,0x5A,0x59,0x58});                 // pop edi,esi,edx,ecx,eax
    put(s, {0xFF,0xE2});                                // jmp edx
    i32 r1 = (i32)(resolve_rva - (thunk_rva + xr + 5));
    for (int k = 0; k < 4; k++) s[xr + 1 + k] = (u8)((u32)r1 >> (8 * k));
    return s;
}

std::vector<u8> build_thunk_x64(u32 thunk_rva, u32 resolve_rva, u32 cache_rva,
                                u32 dll_hash, u32 name_hash, u32 iat_rva) {
    // 0.5.0 DUZELTME v2: rsp kaydi r10 ile yapiliyordu — r10 SysV'de
    // CALLER-SAVED, xrt_resolve (C fonksiyonu) cagrisi onu bozuyor ->
    // yigin kaybi -> crash. Cozum: rbx push'lu (Win64 callee-saved; SysV
    // resolve da kendisi korur) ve hizalama kaydi rbx uzerinden.
    // Yigin: [ret][rax][rcx][rdx][r8][r9][rsi][rdi][rbx]  (rsp -> rbx)
    //   [rsp+0] = saklanan rbx ; [rsp+8] = rdi-slot = base deposu
    std::vector<u8> s;
    put(s, {0x50,0x51,0x52});                        // push rax,rcx,rdx
    put(s, {0x41,0x50,0x41,0x51});                   // push r8,r9
    put(s, {0x56,0x57});                             // push rsi,rdi
    put(s, {0x53});                                  // push rbx (hizalama kaydi)
    put(s, {0xE8,0,0,0,0});                          // call L1
    u32 l1 = (u32)s.size();
    put(s, {0x58});                                  // pop rax
    put(s, {0x48,0x2D}); put32(s, thunk_rva + l1);   // sub rax,L1 -> base
    put(s, {0x48,0x89,0x44,0x24,0x08});              // mov [rsp+8],rax (base)
    put(s, {0x48,0x8D,0x90}); put32(s, cache_rva);   // lea rdx,[rax+cache_rva]
    put(s, {0x48,0x83,0x3A,0x00});                   // cmp qword [rdx],0
    // jne .go — atlanacak blogun baytlari:
    //   mov rdx,[rsp+8](5) add rdx,iat(7) mov rbx,rsp(3) and rsp,-16(4)
    //   mov rdi,imm64(10) mov esi,imm32(5) call(5) mov rsp,rbx(3)  = 42
    put(s, {0x75,0x2A});                             // jne .go (42)
    put(s, {0x48,0x8B,0x54,0x24,0x08});              // mov rdx,[rsp+8] (base)
    put(s, {0x48,0x81,0xC2}); put32(s, iat_rva);     // add rdx,iat_rva (fallback_abs)
    put(s, {0x48,0x89,0xE3});                        // mov rbx,rsp (KAYDET — callee-saved)
    put(s, {0x48,0x83,0xE4,0xF0});                   // and rsp,-16 (movaps hizasi)
    put(s, {0x48,0xBF}); put64(s, dll_hash);         // mov rdi,dll_hash
    put(s, {0xBE}); put32(s, name_hash);             // mov esi,name_hash
    put(s, {0xE8,0,0,0,0});                          // call xrt_resolve
    u32 xr = (u32)s.size() - 5;
    put(s, {0x48,0x89,0xDC});                        // mov rsp,rbx (geri — rbx resolve'da korundu)
    put(s, {0x48,0x8B,0x54,0x24,0x08});              // .go: mov rdx,[rsp+8] (base)
    put(s, {0x48,0x8D,0x92}); put32(s, cache_rva);   // lea rdx,[rdx+cache_rva]
    put(s, {0x48,0x89,0x02});                        // mov [rdx],rax (cache)
    put(s, {0x4C,0x8B,0x1A});                        // mov r11,[rdx] (hedef)
    put(s, {0x5B});                                  // pop rbx (orijinal geri)
    put(s, {0x5F,0x5E,0x41,0x59,0x41,0x58,0x5A,0x59,0x58}); // pop rdi,rsi,r9,r8,rdx,rcx,rax
    put(s, {0x41,0xFF,0xE3});                        // jmp r11
    i32 r1 = (i32)(resolve_rva - (thunk_rva + xr + 5));
    for (int k = 0; k < 4; k++) s[xr + 1 + k] = (u8)((u32)r1 >> (8 * k));
    return s;
}

// ============================================================
// 0.7.0 — SDK lisans API yamasi
// API fonksiyon govdesi (isaret blogu) su sekilde degisir:
//   mov r10d/ecx, fnid ; mov r11d/edx, lsd_rva ; jmp xrt_sdk_entry
// xrt_sdk_entry (blob): Win32 ABI -> SysV C (xrt_sdk_dispatch).
// ============================================================
std::vector<u8> build_api_stub_x64(u32 site_rva, u32 fnid, u32 lsd_rva,
                                   u32 sdk_entry_rva, u32 span) {
    (void)lsd_rva;                               // LSD dispatch'te imaj taramasıyla bulunur
    std::vector<u8> s;
    if (fnid == 8 || fnid == 9) {
        /* 1.2.2-A20: DecryptStringA/W — string A18 gate'inde yerinde
           çözüldü; stub salt ARGÜMANI döner (dispatch'e girMEZ —
           freestanding çerçevede SEH-güvenli). mov rax,rcx; ret */
        put(s, {0x48, 0x89, 0xC8, 0xC3});
        while (s.size() < span) s.push_back(0x90);
        return s;
    }
    put(s, {0x41, 0xBA}); put32(s, fnid);        // mov r10d, fnid
    put(s, {0xE9, 0, 0, 0, 0});                  // jmp xrt_sdk_entry
    i32 rel = (i32)(sdk_entry_rva - (site_rva + 11));
    for (int k = 0; k < 4; k++) s[7 + k] = (u8)((u32)rel >> (8 * k));
    while (s.size() < span) s.push_back(0x90);   // nop dolgu
    return s;
}
std::vector<u8> build_api_stub_x86(u32 site_rva, u32 fnid, u32 lsd_rva,
                                   u32 sdk_entry_rva, u32 span) {
    (void)lsd_rva;
    std::vector<u8> s;
    if (fnid == 8 || fnid == 9) {
        /* A20: mov eax,[esp+4]; ret 4 — stdcall argu donusu */
        put(s, {0x8B, 0x44, 0x24, 0x04, 0xC2, 0x04, 0x00});
        while (s.size() < span) s.push_back(0x90);
        return s;
    }
    put(s, {0xB9}); put32(s, fnid);              // mov ecx, fnid
    put(s, {0xE9, 0, 0, 0, 0});                  // jmp xrt_sdk_entry86
    i32 rel = (i32)(sdk_entry_rva - (site_rva + 10));
    for (int k = 0; k < 4; k++) s[6 + k] = (u8)((u32)rel >> (8 * k));
    while (s.size() < span) s.push_back(0x90);
    return s;
}
