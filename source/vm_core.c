// ============================================================
// vm_core.c — MiniVM: bayt-kod yorumlayici (korumali PE'ye gomulur)
// DERLEME (pozisyon-bagimsiz duz ikili):
//   x64: gcc -O2 -ffreestanding -fno-stack-protector -fno-jump-tables
//        -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident
//        -DVM_IS_X64 [-DVM_WINDOWS] -c vm_core.c
//        ld -Ttext=0x100000 -e vm_entry vm_core.o -o vm.elf
//        objcopy -O binary vm.elf vm.bin
//   x86: aynisi -DVM_IS_X86 (i386 hedefi)
// KURAL: libc YOK, switch/jump-table YOK, string literal YOK.
// Bayt-kod akis formati: vm_opcodes.h (encoder ile birebir ayna)
// ============================================================
#include "vm_opcodes.h"
#ifdef VM_TRACE
/* 0.5.0 hata ayiklama izi — tputn typedef'lerden sonra tanimlanir */
static int vm_trace_on = 1;
#define VM_TRACE_CHECK()
#else
#define VM_TRACE_CHECK()
#define tputn(p, a, b)
#endif

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef long long i64;

#ifdef VM_TRACE
static void tputn(const char* pre, u64 v, u64 v2) {
    char b[128]; int n = 0; int k;
    while (*pre && n < 40) b[n++] = *pre++;
    b[n++] = ' ';
    b[n++] = '0'; b[n++] = 'x';
    for (k = 15; k >= 0; k--) { char c = (char)((v >> (4 * k)) & 0xF); b[n++] = (char)(c < 10 ? '0' + c : 'a' + c - 10); }
    b[n++] = ' ';
    b[n++] = '0'; b[n++] = 'x';
    for (k = 15; k >= 0; k--) { char c = (char)((v2 >> (4 * k)) & 0xF); b[n++] = (char)(c < 10 ? '0' + c : 'a' + c - 10); }
    b[n++] = '\n';
    __asm__ volatile("syscall" : : "a"((u64)1), "D"((u64)2), "S"((u64)(unsigned long)b), "d"((u64)n) : "rcx", "r11", "memory");
}
#endif

#ifdef VM_TRACE
static int open2(const char* path) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"((u64)2), "D"(path),
                     "S"((u64)(0x41 /*O_WRONLY|O_CREAT*/)), "d"((u64)0644) : "rcx", "r11", "memory");
    return (int)r;
}
static void wr2(int fd, const void* b, unsigned n) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"((u64)1), "D"((u64)fd),
                     "S"(b), "d"((u64)n) : "rcx", "r11", "memory");
}
static void close2(int fd) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"((u64)3), "D"((u64)fd) : "rcx", "r11", "memory");
}
#endif

typedef struct {
    u64 bc;         // +0x00 bayt-kod gostergesi
    u64 bc_len;     // +0x08
    u64 key;        // +0x10 rolling anahtar
    u64 base;       // +0x18 modul image base
    u64 regs[16];   // +0x20
    u64 flags;      // +0xA0
    u64 push_area;  // +0xA8 stub push alani
    u64 init_rsp;   // +0xB0
    u64 extra_pop;  // +0xB8 (x86 stdcall)
    u64 done;       // +0xC0  0=devam 1=ret 2=zehir
    u64 scratch[8]; // +0xC8
    u64 regs_epoch; // +0x108 (A20: Encrypt Registers anahtar rotasyonu)
    u64 msgp;       // +0x110 (A13/x7: ozel tespit mesaji ASCII, 0=varsayilan
                    //        "butunluk kontrol kod = #5"; stub cfg sayfasindan)
} VMContext;

/* --- 1.2.0-A9 Encrypt Registers (cpEncryptRegs GERCEK portu) ---
   UO/VMProtect 3.5.1'de bu bayrak OLU bayraktir (kaynakta hicbir kod
   okumaz; islevsel karsiligi bytecode operand-bayt sifrelemesidir).
   XProtect bu oturumda UO'YU ASAR: VM register DOSYASI (regs[16])
   bellekte SIFRELI tutulur — per-slot deterministik maske (splitmix64
   finalizer) fonksiyon anahtarindan turetilir; her okuma cozer,
   her yazim yeniden sifreler. Bellek dump'inda sanal register degerleri
   DUZ gorunmez. Bayrak: ctx scratch[5] bit1 (stub yazar; bit0 = ksadv).
   Kapaliyken rdec/renc kimlik-islevidir (geriye uyumlu). */
static u64 rmask(u64 k, int i) {
    u64 x = k ^ (0x9E3779B97F4A7C15ULL * ((u64)i + 1ULL));
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}
static u64 rdec(VMContext* c, int i) {
    u64 s = c->regs[i];
    return (c->scratch[5] & 2) ? (s ^ rmask(c->key ^ c->regs_epoch, i)) : s;
}
static void renc(VMContext* c, int i, u64 v) {
    c->regs[i] = (c->scratch[5] & 2) ? (v ^ rmask(c->key ^ c->regs_epoch, i)) : v;
}
/* 1.2.2-A20: REGISTER-DOSYASI ANAHTAR ROTASYONU — her dogal-cagri
   sinirinda regs[] dosyasi YENI epoch ile yerinde yeniden sifrelenir.
   Anlam: dogal kod penceresinde (debugger'in thread'i dondurup dump
   alabilecegi tek an) regs[] sifresi epoch-basina baskadir; ayni adresin
   farkli anlarda alinan dump'lari FARKLI sifreler tasir (statik maske
   analizi/Hafiza-karsilastirma saldirisi zayiflatilir). UO'da YOK —
   XProtect UO'yu asan kisim (A9 uzantisi). */
static void regs_rotate(VMContext* c) {
    int i;
    if (!(c->scratch[5] & 2)) return;
    {
        u64 oe = c->regs_epoch;
        u64 ne = oe * 0x100000001B3ull + 0x9E3779B97F4A7C15ull;
        for (i = 0; i < 16; i++) {
            u64 v = c->regs[i] ^ rmask(c->key ^ oe, i);
            c->regs[i] = v ^ rmask(c->key ^ ne, i);
        }
        c->regs_epoch = ne;
    }
}

#if defined(VM_IS_X64)
  #define PUSHSZ 8
  #define NMAP 15
  #define VM_DELTA VM_DELTA64
#elif defined(VM_IS_X86)
  #define PUSHSZ 4
  #define NMAP 8
  #define VM_DELTA VM_DELTA86
#endif
// pushmap fonksiyon icinde kurulur (statik veri yok -> tam PIC)

static void* u2p(u64 v) { return (void*)(unsigned long)v; }

// --- sifreli bayt akisi okuyucu ---
typedef struct { u8* bc; u64 key; u64 ic; int adv; } STRM;

static u8 sf8(STRM* s) {
    /* 0.8.0 crypt_command: CFB geribesleme — akis bir onceki SIFRELI
       bayta bagli (saf (key, prev, pos) fonksiyonu; JMP guvenli).
       1.2.0-B1 vtAdvanced: VM_KSA ailesi (4-byte periyot) — kip STRM.adv
       (ctx scratch[5], stub yazar). Encoder ayni aileyi secer. */
    u8 v = s->adv
        ? (u8)(s->bc[s->ic] ^ VM_KSCA(s->key, s->ic ? s->bc[s->ic - 1] : 0, s->ic))
        : (u8)(s->bc[s->ic] ^ VM_KSC(s->key, s->ic ? s->bc[s->ic - 1] : 0, s->ic));
    s->ic++;
    return v;
}
static u32 sf32(STRM* s) {
    u32 v = 0; int i;
    for (i = 0; i < 4; i++) v |= ((u32)sf8(s)) << (8*i);
    return v;
}
static u64 sf64(STRM* s) {
    u64 v = 0; int i;
    for (i = 0; i < 8; i++) v |= ((u64)sf8(s)) << (8*i);
    return v;
}

// --- bellek ---
static u64 mrd(u64 a, int sz) {
    u8* p = (u8*)u2p(a); u64 v = 0; int i;
    for (i = 0; i < sz; i++) v |= ((u64)p[i]) << (8*i);
    return v;
}
static void mwr(u64 a, int sz, u64 v) {
    u8* p = (u8*)u2p(a); int i;
    for (i = 0; i < sz; i++) p[i] = (u8)(v >> (8*i));
}

// --- register ---
static u64 rget(VMContext* c, int enc, int sz) {
    if (enc >= 16) return (rdec(c, enc-16) >> 8) & 0xFF;
    if (sz == 1) return rdec(c, enc) & 0xFF;
    if (sz == 2) return rdec(c, enc) & 0xFFFF;
    if (sz == 4) return rdec(c, enc) & 0xFFFFFFFF;
    return rdec(c, enc);
}
static void rset(VMContext* c, int enc, int sz, u64 v) {
    if (enc >= 16) {
        renc(c, enc-16, (rdec(c, enc-16) & ~0xFF00ULL) | ((v & 0xFF) << 8));
        return;
    }
    if (sz == 1)      renc(c, enc, (rdec(c, enc) & ~0xFFULL) | (v & 0xFF));
    else if (sz == 2) renc(c, enc, (rdec(c, enc) & ~0xFFFFULL) | (v & 0xFFFF));
    else if (sz == 4) renc(c, enc, v & 0xFFFFFFFF);   /* x64: 32-bit yazim ust 32 biti SIFIRLAR */
    else              renc(c, enc, v);
}

static u64 szmask(int sz) {
    if (sz == 1) return 0xFFULL;
    if (sz == 2) return 0xFFFFULL;
    if (sz == 4) return 0xFFFFFFFFULL;
    return ~0ULL;
}

// MEM operandini akistan oku ve gercek adresi coz.
// Encoder sirasi: form:1 -> DISP: disp32 | SIB: base,idx,scale,disp32
static u64 mem_addr(STRM* s, VMContext* c) {
    int form = sf8(s);
    /* 0.9.0: segment ustu-on-eki — FS/GS taban. Win gercek semantigi:
       x86: FS=TEB (fs:[0x18] self-ptr), GS=0 | x64: GS=TEB (gs:[0x30]), FS=0.
       TEB vm_entry'de scratch[4]'e yakalanir (gercek seg okumasi).
       segmode'da disp HAM'dir (image-rva cevirimi yok — TEB-relative). */
    u64 segbase = 0;
    int segmode = 0;
    if (form == MEMF_SEG) {
        int seg = sf8(s);
        form = sf8(s);
        segmode = 1;
#if defined(VM_IS_X64)
        segbase = (seg == 5) ? c->scratch[4] : 0;   /* GS=TEB, FS=0 */
#else
        segbase = (seg == 4) ? c->scratch[4] : 0;   /* FS=TEB, GS=0 */
#endif
    }
    if (form == MEMF_DISP_SEG) {
        return segbase + (u64)(i64)(int)sf32(s);
    }
    if (form == MEMF_DISP) {
        return segbase + c->base + (u64)(u32)sf32(s);
    } else {
        int b = sf8(s), ix = sf8(s), sc = sf8(s);
        u32 d = sf32(s);
        /* MEMF_SIB_IMG: disp image-RVA'dir (x86 mutlak adresleme) ->
           c->base eklenir. MEMF_SIB (eski): x64 yigin SIB'i -> disp ham.
           segmode: img YOK (seg tabani zaten segbase'te). */
        u64 img = (!segmode && form == MEMF_SIB_IMG) ? c->base : 0;
        u64 a;
        if (b == SIB_NOBASE)      a = segbase + img + (u64)(i64)(int)d;
        else if (b == REG_RSP)    a = segbase + rdec(c, REG_RSP) - (u64)VM_DELTA + (u64)(i64)(int)d;
        else                      a = segbase + img + rdec(c, b) + (u64)(i64)(int)d;
        if (ix != SIB_NOBASE) a += rdec(c, ix) << sc;
#ifdef VM_TRACE
        if (vm_trace_on) tputn("[mem] a=", a, ((u64)(b & 0xFF) << 8) | (ix & 0xFF));
#endif
        return a;
    }
}

static int sext32(i64* out, u32 v) { *out = (i64)(int)v; return 0; }

// --- ALU + bayraklar ---
// 0.9.0-DeepVM TAM EFLAGS: CF/PF/AF/ZF/SF/OF (VMProtect intel.cc fl_ sabitleri
// ile ayni baglam — CF=0x0001 PF=0x0004 AF=0x0010 ZF=0x0040 SF=0x0080 OF=0x0800,
// VM dahili bicimde). PF = sonucun DUSUK 8 bitindeki 1-parite (cift -> 1).
// AF = bit-3'ten bit-4'e tasiyici: ((a ^ b ^ r) >> 4) & 1 (add/sub ikisinde de).
static u8 parity8(u64 r) {
    u8 p = (u8)(r & 0xFF);
    p ^= p >> 4; p ^= p >> 2; p ^= p >> 1;
    return (u8)((~p) & 1);   /* cift sayida 1 -> PF=1 */
}
static u64 do_alu_c(int alu, u64 a, u64 b, int sz, int cin, u64* fl);
static u64 do_alu(int alu, u64 a, u64 b, int sz, u64* fl) { return do_alu_c(alu, a, b, sz, 0, fl); }
static u64 do_alu_c(int alu, u64 a, u64 b, int sz, int cin, u64* fl) {
    u64 m = szmask(sz);
    int sb = sz * 8 - 1;
    u64 r = 0, f = 0;
    if (alu == ALU_ADD || alu == ALU_ADC) {
        u64 s = a + b + (u64)cin;
        r = s & m;
        if (sz == 8) { if (s < a) f |= FCF; }
        else         { if (s & ~m) f |= FCF; }
        if (((a ^ r) & (b ^ r)) >> sb & 1) f |= FOF;
        /* AF kesin: bit-3 tasiyici (cin dahil) */
        if (((a & 0xF) + (b & 0xF) + cin) > 0xF) f |= FAF;
    } else if (alu == ALU_SUB || alu == ALU_CMP || alu == ALU_SBB) {
        r = (a - b - (u64)cin) & m;
        if (a < b + (u64)cin) f |= FCF;
        if (((a ^ b) & (a ^ r)) >> sb & 1) f |= FOF;
        if ((int)(a & 0xF) - (int)(b & 0xF) - cin < 0) f |= FAF;
    } else if (alu == ALU_AND || alu == ALU_TEST) {
        r = a & b;
        /* CF=OF=0 (x86 mantiksal islemler) */
    } else if (alu == ALU_OR) {
        r = a | b;
    } else {
        r = a ^ b;
    }
    if (r == 0) f |= FZF;
    if ((r >> sb) & 1) f |= FSF;
    if (parity8(r)) f |= FPF;
    *fl = f;
    return r;
}

static int cond_eval(VMContext* c, int cc) {
    u64 f = c->flags;
    int C = (f & FCF) != 0, Z = (f & FZF) != 0, S = (f & FSF) != 0, O = (f & FOF) != 0;
    int P = (f & FPF) != 0;   /* 0.9.0: gercek parite (eski: hep 0) */
    if (cc == CC_O)  return O;
    if (cc == CC_NO) return !O;
    if (cc == CC_B)  return C;
    if (cc == CC_AE) return !C;
    if (cc == CC_E)  return Z;
    if (cc == CC_NE) return !Z;
    if (cc == CC_BE) return (C | Z);
    if (cc == CC_A)  return !(C | Z);
    if (cc == CC_S)  return S;
    if (cc == CC_NS) return !S;
    if (cc == CC_P)  return P;    /* 0.9.0-DeepVM: PF artik gercek */
    if (cc == CC_NP) return !P;
    if (cc == CC_L)  return (S != O);
    if (cc == CC_GE) return (S == O);
    if (cc == CC_LE) return (Z | (S != O));
    if (cc == CC_G)  return (!Z) && (S == O);
    return 0;
}

static u64 do_shift(int shi, u64 a, int n, int sz, u64 curf, u64* fl) {
    int sbits = sz * 8;
    u64 r = a, f = 0;
    /* x86: sayac 8/16/32-bitte &31, 64-bitte &63 ile maskelenir */
    n &= (sbits >= 64) ? 63 : 31;
    if (n) {
        if (shi == SHI_ROL) {
            r = ((a << n) | (a >> ((sbits - n) & (sbits - 1)))) & szmask(sz);
            /* 0.9.0: ROL/ROR yalniz CF degistirir — diger bayraklar KORUNUR
               (eski kod hepsini sifirliyordu — jcc-rol dizilerinde yanlis). */
            f = (curf & ~FCF) | (r & 1);
            *fl = f;
            return r;
        }
        if (shi == SHI_ROR) {
            r = ((a >> n) | (a << ((sbits - n) & (sbits - 1)))) & szmask(sz);
            f = (curf & ~FCF) | ((r >> (sbits - 1)) & 1);
            *fl = f;
            return r;
        }
        if (shi == SHI_SHL) {
            if (n <= sbits) { if ((a >> (sbits - n)) & 1) f |= FCF; }
            r = (a << n) & szmask(sz);
            /* OF (yalniz n==1 tanimli): MSB(r) ^ CF */
            if (n == 1) { if ((((r >> (sbits-1)) & 1) ^ ((f & FCF) ? 1u : 0u))) f |= FOF; }
        } else if (shi == SHI_SHR) {
            if (n <= sbits) { if ((a >> (n - 1)) & 1) f |= FCF; }
            r = (a >> n) & szmask(sz);
            if (n == 1) { if (((a >> (sbits-1)) & 1)) f |= FOF; }
        } else {
            i64 sv = (i64)(a << (64 - sbits)) >> (64 - sbits);
            if (n <= sbits) { if (((u64)sv >> (n-1)) & 1) f |= FCF; }
            r = ((u64)(sv >> n)) & szmask(sz);
            if (n == 1) { if (((a >> (sbits-1)) & 1)) f |= FOF; }
        }
        if (r == 0) f |= FZF;
        if ((r >> (sbits-1)) & 1) f |= FSF;
        if (parity8(r)) f |= FPF;
        /* AF: shiftlerde tanimsiz -> 0 */
    }
    *fl = f;
    return r;
}

/* --- 0.9.0-DeepVM: 64x64->128 carpim + 128/64 bolem (freestanding, u128 YOK) --- */
static void mulu64(u64 a, u64 b, u64* lo, u64* hi) {
    u64 alo = a & 0xFFFFFFFFULL, ahi = a >> 32;
    u64 blo = b & 0xFFFFFFFFULL, bhi = b >> 32;
    u64 ll = alo * blo, lh = alo * bhi, hl = ahi * blo, hh = ahi * bhi;
    u64 mid = (ll >> 32) + (lh & 0xFFFFFFFFULL) + (hl & 0xFFFFFFFFULL);
    *lo = (ll & 0xFFFFFFFFULL) | (mid << 32);
    *hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
static void div128_64(u64 hi, u64 lo, u64 d, u64* qo, u64* ro) {
    u64 q = 0, r = 0; int i;
    for (i = 127; i >= 0; i--) {
        u64 bit = (i >= 64) ? ((hi >> (i - 64)) & 1) : ((lo >> i) & 1);
        r = (r << 1) | bit;
        q <<= 1;
        if (r >= d) { r -= d; q |= 1; }
    }
    *qo = q; *ro = r;
}
/* 64-bit / 32-bit — i386 freestanding __udivmoddi4 YASAK (blob linki kopar);
   bit-dongusuyle tasinabilir (0.9.0 DIV/IDIV x86 yolu). */
static u64 div64_32(u64 n, u32 d, u32* rem) {
    u64 q = 0, r = 0; int i;
    for (i = 63; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1);
        q <<= 1;
        if (r >= (u64)d) { r -= (u64)d; q |= 1; }
    }
    *rem = (u32)r;
    return q;
}
/* isaretli 128/64 -> q (64-bit), r. Boleme #DE (d=0 veya q tasma) -> q=r=0
   (0.8.5 idiv-guvenlik gelenegi). */
static void idiv128(i64 hi, i64 lo, i64 dv, i64* qo, i64* ro) {
    u64 uhi, ulo, udv, q, r;
    int nq = 0, nr = 0;
    if (hi < 0) {
        ulo = (u64)(0 - lo); uhi = (u64)(~(u64)hi + ((lo == 0) ? 1u : 0u));
        nq = 1; nr = 1;
    } else { uhi = (u64)hi; ulo = (u64)lo; }
    if (dv < 0) { udv = (u64)(0 - dv); nq = !nq; } else udv = (u64)dv;
    if (udv == 0) { *qo = 0; *ro = 0; return; }
    div128_64(uhi, ulo, udv, &q, &r);
    if (q >> 63) { *qo = 0; *ro = 0; return; }   /* tasma -> #DE */
    *qo = nq ? (i64)(0 - (i64)q) : (i64)q;
    *ro = nr ? -(i64)r : (i64)r;
}

#if defined(VM_IS_X86)
// 0.5.1 — x86 dogal cagri, iki kok-duzeltme ile:
// (1) 0.5.0 "yigin bozumu": esp_after "=m" BELLEK operandiydi. -O2'de GCC/zig
//     esp-tabanli cerceve kullanir -> "movl %%esp, -N(%%esp)" yazimi o anda
//     esp = VM yigini OLDUGU ICIN VM yiginina yazar, gercek degisken 0 kalir
//     -> regs[RSP] = 0 + VM_DELTA = 0x420 -> ilk push 0xFFFFFFFC'ye yazar.
//     artik esp_after kayit cikisi (esi uzerinden).
// (2) ARGUMAN-KAYITCI AKTARIMI (0.5.0'da hic yoktu): uyumlu callee gelen
//     ecx/edx'i OKUR (thiscall ecx=this, fastcall ecx,edx). VM kayitcilari
//     bellekte oldugu icin gercek CPU ecx/edx coputti -> callee cop okuyor
//     -> wild ret. Cagridan ONCE VM eax/ecx/edx gercek CPU'ya yuklenir;
//     cagridan SONRA callee'nin eax/ecx/edx'i VM'e geri yazilir (gercek CPU
//     aynasi). ebx/esi/edi/ebp bilincli YUKLENMEZ: callee-saved'dir, uyumlu
//     callee gelen degerini OKUYAMAZ (Win32 ABI); natcall onlari korur.
static void vm_natcall86(u64* regs, u32 t, u32 vm_rsp, u64* out_ret, u64* out_rsp) {
    u32 ret = 0, c_ecx = 0, c_edx = 0, s_out = t;   /* s_out girisi = hedef */
    register u32 vrsp __asm__("edi") = (u32)vm_rsp; /* VM yigini (in-out)   */
    __asm__ volatile(
        "movl 0x00(%[rg]), %%eax  \n\t"   /* eax = VM eax (regs[0].lo) */
        "movl 0x08(%[rg]), %%ecx  \n\t"   /* ecx = VM ecx (regs[1].lo) */
        "movl 0x10(%[rg]), %%edx  \n\t"   /* edx = VM edx (regs[2].lo) */
        "pushl %%ebx              \n\t"   /* ebx kaydet (C-caller callee-saved) */
        "movl %%esp, %%ebx        \n\t"   /* ebx = gercek esp */
        "movl %[vr], %%esp        \n\t"   /* esp = VM yigini (arglar burada) */
        "call  *%[sp]             \n\t"   /* esi = hedef (s_out girdisi) */
        "movl %%esp, %[sp]        \n\t"   /* callee sonrasi esp (stdcall) */
        "movl %%ebx, %%esp        \n\t"   /* gercek esp geri */
        "popl %%ebx               \n\t"   /* ebx geri (callee zaten korudu) */
        : "=&a"(ret), "=&c"(c_ecx), "=&d"(c_edx), [sp] "+S"(s_out), [vr] "+D"(vrsp)
        : [rg] "r"(regs)
        : "memory", "cc");
    regs[0] = (u64)ret;                /* callee eax = donus degeri        */
    regs[1] = (u64)c_ecx;              /* callee ecx (gercek CPU aynasi)   */
    regs[2] = (u64)c_edx;              /* callee edx                       */
    *out_ret = (u64)ret;
    *out_rsp = (u64)s_out;             /* callee sonrasi esp               */
}
#endif

#ifdef VM_IS_X64
// Native cagri. VM_WINDOWS: Win64 ABI (rcx,rdx,r8,r9). VM_SYSV_NATCALL:
// Linux test duzenegi (rdi,rsi,rdx,rcx,r8,r9).
#ifdef VM_SYSV_NATCALL
static u64 vm_natcall(u64 t, const u64* regs) {
    u64 ret;
    register u64 va7 __asm__("rdi") = regs[7];
    register u64 va6 __asm__("rsi") = regs[6];
    register u64 va2 __asm__("rdx") = regs[2];
    register u64 va1 __asm__("rcx") = regs[1];
    register u64 vr8 __asm__("r8")  = regs[8];
    register u64 vr9 __asm__("r9")  = regs[9];
    register u64 vt  __asm__("r11") = t;
    /* KRITIK: callee (SysV) rax,rcx,rdx,rsi,rdi,r8-r11'i EZER. "+X" bildirimi
       olmadan derleyici canli degerleri bu register'larda tutar -> callee
       ezer -> wild pointer. Ayrica cagri oncesi rsp 16-hizali OLMALI (SysV +
       Win64 ayni kural): hizali degilse callee'deki movaps/sse cerceveleri
       SIGSEGV verir. rsp eski degerine r10 uzerinden geri getirilir. */
    __asm__ volatile(
        "mov %%rsp, %%rbx \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x20, %%rsp \n\t"
        "call *%%r11 \n\t"
        "mov %%rbx, %%rsp \n\t"
        : "=a"(ret), "+D"(va7), "+S"(va6), "+d"(va2), "+c"(va1),
          "+r"(vr8), "+r"(vr9), "+r"(vt)
        :
        : "memory", "cc", "rbx", "r10");
    return ret;
}
#else
static u64 vm_natcall(u64 t, const u64* regs) {
    u64 ret;
    register u64 va0 __asm__("rax") = regs[0];
    register u64 va1 __asm__("rcx") = regs[1];
    register u64 va2 __asm__("rdx") = regs[2];
    register u64 vr8 __asm__("r8")  = regs[8];
    register u64 vr9 __asm__("r9")  = regs[9];
    register u64 vt  __asm__("r11") = t;
    /* KRITIK: callee (Win64) rax,rcx,rdx,r8,r9,r10,r11'i EZER (volatile).
       "+X" bildirimi yoksa derleyici canli degerleri bu register'larda
       tutabilir ve callee ezer -> bc isaretcisi bozulur -> wild read.
       Ayrica rsp 16-hizalanmali: hizasizsa callee'nin movaps'i SIGSEGV. */
    __asm__ volatile(
        "mov %%rsp, %%rbx \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x20, %%rsp \n\t"
        "call *%%r11 \n\t"
        "mov %%rbx, %%rsp \n\t"
        : "+a"(ret), "+c"(va1), "+d"(va2), "+r"(vr8), "+r"(vr9), "+r"(vt)
        :
        : "memory", "cc", "rbx", "r10");
    (void)va0;
    return ret;
}
/* 1.2.0-A8 K8: NtQueryInformationProcess'e ozel 5-arg sarmalayici —
   dogrudan asm (vm_natcall deseninin temiz kopyasi; r[16] ara-dizisi YOK).
   NtQueryInformationProcess(GetCurrentProcess()=-1, cls, buf, 8, &rl).
   5. arg [rsp+0x20]; ReturnLength GECERLI isaretci (wine guvenli). */
static i64 xa_qip5(u64 fn, u64 cls, u64 bufaddr) {
    u64 ret; u64 rl = 0;
    u64 rla = (u64)(unsigned long)(void*)&rl;
    register u64 a1 __asm__("rcx") = 0xFFFFFFFFFFFFFFFFull;   /* GetCurrentProcess */
    register u64 a2 __asm__("rdx") = cls;
    register u64 a3 __asm__("r8")  = bufaddr;
    register u64 a4 __asm__("r9")  = 8;
    register u64 ft __asm__("r11") = fn;
    __asm__ volatile(
        "mov %%rsp, %%rbx \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x30, %%rsp \n\t"
        "movq %6, 0x20(%%rsp) \n\t"
        "call *%%r11 \n\t"
        "mov %%rbx, %%rsp \n\t"
        : "+a"(ret), "+c"(a1), "+d"(a2), "+r"(a3), "+r"(a4), "+r"(ft), "+r"(rla)
        :
        : "memory", "cc", "rbx", "r10");
    return (i64)ret;
}
/* 1.2.0-A8: 5-arg Win64 natcall — NtQueryInformationProcess (K8) icin.
   5. arg [rsp+0x20]'ye yazilir (r10 uzerinden; r10 zaten clobber listesinde).
   sub 0x30: 0x20 shadow + 8 arg = hizalamayi koruyacak 16'nin kati. */
static u64 vm_natcall5(u64 t, const u64* regs, u64 a5) {
    u64 ret;
    register u64 va1 __asm__("rcx") = regs[1];
    register u64 va2 __asm__("rdx") = regs[2];
    register u64 vr8 __asm__("r8")  = regs[8];
    register u64 vr9 __asm__("r9")  = regs[9];
    register u64 vt  __asm__("r11") = t;
    /* DERS (kok neden): a5 r10'a BAGLI register-asm degiskeniydi + r10 clobber
       listesinde YOKTU -> yorumlayicinin r10'daki canli degeri callee tarafindan
       ezildi -> karmasik bozulma (K8 testinde ilk-saptandi). SAGLIKLI desen:
       a5 DUZ yerel (+r operand ile herhangi bir register), r10 clobber listesinde
       (orijinal vm_natcall hizgiyle ayni). */
    __asm__ volatile(
        "mov %%rsp, %%rbx \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x30, %%rsp \n\t"
        "movq %6, 0x20(%%rsp) \n\t"
        "call *%%r11 \n\t"
        "mov %%rbx, %%rsp \n\t"
        : "+a"(ret), "+c"(va1), "+d"(va2), "+r"(vr8), "+r"(vr9), "+r"(vt), "+r"(a5)
        :
        : "memory", "cc", "rbx", "r10");
    return ret;
}
#endif
#endif

// ============================================================
// 0.8.4: VEH debugger yakalama — 0.8.1 tabanina IKI oyun-guvenli kontrol.
// (0.8.2/0.8.3 dersi: TF-probunun istisna-dispatch'i yorumlayici
//  cerceveleriyle carpisir; wine yigin-degistirme/is-parcacigi
//  senaryolarinda VEH baglam-yazimi YITIRILIR -> temiz oyunda tek-adim
//  dongusu/cokme. Asagidaki iki kontrol istisna-dispatch'i HIC devreye
//  sokmaz — dispatcher karismasi TASARIM OLARAK IMKANSIZ.)
//
// (K1) KAPI-0xCC: korunan fonksiyonun ORIJINAL giris bayti (E9 tramp).
//      CE VEH debugger yazilim-kirisini (F5/breakpoint) girise YAZAR ve
//      ARMALI birakir (tek-adim sonrasi geri yazar). Temiz oyunda o
//      bayt HICBIR ZAMAN 0xCC degildir (bizim E9'umuz) -> 0xCC = kesin
//      kanit. (UniversalObfuscator loader.cc:2120 0xCC-taramasinin
//      XProtect'e ozel, yanlis-pozitifsiz formu: yalniz KENDI girisimiz.)
//
// (K2) TF-BAYRAGI: pushfq ile anlik TF. Bir debugger (CE VEH / Windows)
//      fonksiyonu TEK-ADIM izlerken TF=1'dir. Temiz oyunda ring3'te TF
//      asla 1 kalmaz -> TF=1 = kesin kanit. (VMProtect loader.cc:2446
//      TF-probunun istisnasiz formu.)
//
//
// (K3) DRx — GetThreadContext(GetCurrentThread) ile DR0-3 okuma (0.8.5).
//      CE VEH debugger donanim-kirici (F5/hwbp) DR0-3'te KALIR; PEB ve
//      DebugPort temiz kalir (VEH debugger OS debug API'si kullanmaz) —
//      kullanicinin 0.8.4 raporu: VEH debugger F5 damage'i DURDURAMADI.
//      UniversalObfuscator runtime/core.cc:778 semantigi 1:1
//      (Dr0|Dr1|Dr2|Dr3 != 0 -> debugger) — ama orijinalin
//      istisna-baglamindan-okuma formu (core.cc:771, TF-probu + __except)
//      yerine AYNI degerleri SENKRON API ile okuruz: 0.8.2/0.8.3 dersi —
//      TF-probu + VEH baglam-yazimi yorumlayici cerceveleriyle carpisir
//      (wine: yigin-degistirme/is-parcacigi senaryosunda yazim YITIRILIR).
//      Istisna-dispatch'i HIC devreye sokmaz; tek maliyeti 1 syscall.
//      BILINCI SONUC: oyun KENDI gozetim noktasi icin DRx kurarsa
//      Check Debugger'li fonksiyon zehirlenir — UniversalObfuscator'in
//      da tam olarak bu semantigi (kendi DRx'ini kullanan koruma yoksa
//      yanlis-pozitif yok; metin2 istemcisi DRx kullanmiyor).
//
// KAPSAM (0.8.5): CE VEH debugger hwbp (F5 — kullanicinin senaryosu),
//      CE VEH yazilim-kirici giriste (K1), CE VEH/Windows tek-adim (K2),
//      Windows debugger (PEB + K1/K2/K3), x64dbg/winedbg.
//      QIP, guard-page, ntdll-0xCC taramalari BILINCLI YOK: 0.8.2'nin
//      temiz-oyun yanlis-pozitif yuzeyleri. Yabanci-VEH zincir gezinmesi
//      de yok: AV/crash-raporlayici VEH'leri yanlis-pozitif yapar.
// KURAL: libc YOK, string literal YOK, statik veri YOK (tam PIC).
// ============================================================
#if defined(VM_WINDOWS)

/* --- isim hash'leri (derleme sabiti; FNV-1a, xrt_core.c ayni aile) --- */
#define XA_K32   0xA3E6F6C3u   /* "kernel32.dll" (genis, kucuk-harf) */
#define XA_NTD   0xA62A3B3Bu   /* "ntdll.dll"    (genis, kucuk-harf) */
#define XA_GTC   0x85CCA27Eu   /* GetThreadContext */
#define XA_NSIT  0xF19E1321u   /* 1.1.0: NtSetInformationThread */
#define XA_NQSI  0x7A43974Au   /* 1.1.0: NtQuerySystemInformation */
#define XA_NQIP  0xEA2DDA8Au   /* 1.2.0-A8: NtQueryInformationProcess (K8) */
#define XA_CLOSEH 0xFABA0065u  /* 1.2.0-A8: CloseHandle (K9) */
#define XA_MSGBOX 0x23A979E4u  /* 1.2.5 (x1/x2): MessageBoxA (VM-poison mesaj yolu) */
#define XA_EXITP  0x0E80FD3Au  /* 1.2.5 (x1/x2): ExitProcess (VM-poison cikis yolu) */
/* 1.2.5-A13 (x1 FIX): MESAJ YOLU KIRIKTI — xa_export(kernel32, MessageBoxA)
   hep 0 donduruyor (MessageBoxA user32.dll'de, kernel32'de DEGIL) -> mesaj
   hic cikmiyor, rt_exit yalniz calisiyor = "direk silent cikis" (kullanici
   cp165 raporu). FIX: once PEB'de yuklu user32 ara; yoksa kernel32!
   LoadLibraryA("user32.dll") yukle (xrt rt_fatal ayni desen, kanitli). */
#define XA_U32    0xC0323159u  /* "user32.dll"  (genis, kucuk-harf) */
#define XA_LLDA   0x53B2070Fu  /* LoadLibraryA */

/* CONTEXT ofsetleri (winnt.h birebir) — yalniz DEBUG_REGISTERS alani.
   0.8.2 dersi: EFLAGS/RAX ofsetleri (TF-isleyicisi icin) yanlisti; K3
   yalniz FLAGS+DR0-3 kullanir ve bunlar iki mimaride de dogrudur. */
#if defined(VM_IS_X64)
  #define XA_CTX_FLAGS   0x30
  #define XA_CTX_DR0     0x48
  #define XA_CTX_DR1     0x50
  #define XA_CTX_DR2     0x58
  #define XA_CTX_DR3     0x60
  #define XA_CTX_SIZE    0x4D0
  #define XA_CTX_DBGFL   0x00100010u   /* CONTEXT_DEBUG_REGISTERS|AMD64 */
#else
  #define XA_CTX_FLAGS   0x00
  #define XA_CTX_DR0     0x04
  #define XA_CTX_DR1     0x08
  #define XA_CTX_DR2     0x0C
  #define XA_CTX_DR3     0x10
  #define XA_CTX_SIZE    0x2CC
  #define XA_CTX_DBGFL   0x00010010u   /* CONTEXT_DEBUG_REGISTERS|i386 */
#endif

static u32 xa_fnv_a(u64 s) {
    u32 h = 2166136261u;
    for (;;) { u8 ch = (u8)mrd(s, 1); if (!ch) break; h ^= ch; h *= 16777619u; s++; }
    return h;
}
static u32 xa_fnv_w(u64 s, u32 n) {
    u32 h = 2166136261u; u32 i;
    for (i = 0; i < n; i++) {
        u16 ch = (u16)mrd(s + (u64)(2u * i), 2);
        if (ch >= 'A' && ch <= 'Z') ch = (u16)(ch + 32);
        h ^= (u32)ch; h *= 16777619u;
    }
    return h;
}

/* PEB -> InLoadOrderModuleList -> modul tabani (isim hash ile).
   0.8.3 ders: DllBase==0 / absurt girdiler atlanir (manuel-maplenen
   koruma DLL'leri bozuk LDR girisi birakabilir). */
static u64 xa_module(u32 want) {
#if defined(VM_IS_X64)
    u64 peb; __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    u64 ldr  = mrd(peb + 0x18, 8);
    u64 head = ldr + 0x20;
    u64 cur  = mrd(head, 8);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent  = cur - 0x10;                    /* InMemoryOrderLinks -> entry */
        u32 nlen = (u32)mrd(ent + 0x58, 2);       /* BaseDllName.Length */
        u64 nbuf = mrd(ent + 0x60, 8);            /* BaseDllName.Buffer */
        u64 db   = mrd(ent + 0x30, 8);            /* DllBase */
        if (db && nbuf && nlen && nlen < 128) {
            if (xa_fnv_w(nbuf, nlen >> 1) == want) return db;
        }
        cur = mrd(cur, 8);
    }
#else
    u32 peb; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
    u64 ldr  = mrd((u64)peb + 0x0C, 4);
    u64 head = ldr + 0x14;
    u64 cur  = mrd(head, 4);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent  = cur - 0x08;
        u32 nlen = (u32)mrd(ent + 0x2C, 2);
        u64 nbuf = mrd(ent + 0x30, 4);
        u64 db   = mrd(ent + 0x18, 4);
        if (db && nbuf && nlen && nlen < 128) {
            if (xa_fnv_w(nbuf, nlen >> 1) == want) return db;
        }
        cur = mrd(cur, 4);
    }
#endif
    return 0;
}

/* export tablosunda isim-hash cozumle (xrt_core.c find_export ailesi) */
static u64 xa_export(u64 kbase, u32 want) {
    if (!kbase) return 0;
    u64 d = kbase;
    if (mrd(d, 1) != 'M' || mrd(d + 1, 1) != 'Z') return 0;
    u32 lfa = (u32)mrd(d + 0x3C, 4);
    if (!lfa || lfa > 0x400) return 0;
    u64 pe = d + lfa;
    if ((u32)mrd(pe, 4) != 0x00004550u) return 0;
    u32 magic = (u32)mrd(pe + 24, 2);
    u32 ddoff = (magic == 0x20B) ? 112 : 96;
    u32 erva = (u32)mrd(pe + 24 + ddoff, 4);
    if (!erva) return 0;
    u64 ex = d + erva;
    u32 nnames = (u32)mrd(ex + 24, 4);
    u32 aofn = (u32)mrd(ex + 32, 4);
    u32 aofo = (u32)mrd(ex + 28, 4);
    u32 aoo  = (u32)mrd(ex + 36, 4);
    u32 i;
    if (nnames > 0x20000) return 0;
    for (i = 0; i < nnames; i++) {
        u32 nrva = (u32)mrd(d + aofn + (u64)(4u * i), 4);
        if (!nrva) continue;
        if (xa_fnv_a(d + nrva) == want) {
            u32 ord = (u32)mrd(d + aoo + (u64)(2u * i), 2);
            u32 frva = (u32)mrd(d + aofo + (u64)(4u * ord), 4);
            if (!frva) return 0;
            return kbase + frva;
        }
    }
    return 0;
}

/* ---- API cagri sarmalayicilari ---- */
#if defined(VM_IS_X64)
/* GetThreadContext(h, ctx, 0, 0) — vm_natcall Win64 ABI yolu */
static u64 xa_call4(u64 t, u64 a1, u64 a2, u64 a3, u64 a4) {
    u64 r[16]; int i;
    for (i = 0; i < 16; i++) r[i] = 0;
    r[1] = a1; r[2] = a2; r[8] = a3; r[9] = a4;
    return vm_natcall(t, r);
}
/* 1.2.5-A13: 1-arg (LoadLibraryA — vm_poison user32 yukleme yolu) */
static u64 xa_call1(u64 t, u64 a1) {
    u64 r[16]; int i;
    for (i = 0; i < 16; i++) r[i] = 0;
    r[1] = a1;
    return vm_natcall(t, r);
}
/* 1.2.0-A8: 5-arg (NtQueryInformationProcess, K8) — 5. arg Win64
   ABI'de [rsp+0x20]'dedir; vm_natcall5 yoluyla yazilir. */
static u64 xa_call5(u64 t, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5) {
    u64 r[16]; int i;
    for (i = 0; i < 16; i++) r[i] = 0;
    r[1] = a1; r[2] = a2; r[8] = a3; r[9] = a4;
    return vm_natcall5(t, r, a5);
}
#else
/* 1.2.2 KOK-FIX (kullanici bulgusu: metin2 0xD7610 ULTRA + CheckDebugger
   damage'te cokus): x86 stdcall sarmalayicilari ECX/EDX'i clobber
   listesine ALMIYORDU. Gercek Windows API'leri ECX/EDX'i (caller-saved)
   serbestce EZER; GCC clobber bildirimi olmadigi icin yasan DEGERLERI
   (orn. siradaki API'nin fonksiyon isaretcisi!) bu registerlarda tutar.
   1.2.0-A8 K8'in ardi ardina IKI NtQueryInformationProcess cagrisi
   GCC'nin isaretciyi ECX'te OMNESIYLE sonucta buldu: ilk cagri ECX'i
   ezdi, ikinci 'call *%ecx' cop adrese atlayip 0xC0000005 veriyor.
   (Unicorn kanit: clobber-stub testi EIP=DEAD0001.)
   COZUM (1.2.2): tum sarmalayicilar (1/2/4/5-arg) TEK duzenli bicime
   gecti — argumanlar C tarafinda args[] dizisine kurulur, asm arg'lari
   DIZIDEN (register-gostergesi ile, esp-kaymasindan bagimsiz) push eder,
   clobber listesi ecx/edx icerir. Bylece GCC'in yasan degerleri
   caller-saved registerlarda tutmasi IMKANSIZ hale gelir. */
/* stdcall 2-arg (callee pop): GetThreadContext(hThread, pContext) */
static u32 xa_call2_86(u32 t, u32 a1, u32 a2) {
    u32 args[2] = { a1, a2 };
    u32 ret;
    __asm__ volatile("pushl 4(%2)\n\tpushl (%2)\n\tcall *%1\n\t"
        : "=a"(ret) : "r"(t), "r"(args) : "memory", "cc", "ecx", "edx");
    return ret;
}
/* 1.1.0: stdcall 4-arg (callee pop): NtSetInformationThread /
   NtQuerySystemInformationBattery icin */
static long xa_call4_86(u32 t, u32 a1, u32 a2, u32 a3, u32 a4) {
    u32 args[4] = { a1, a2, a3, a4 };
    u32 ret;
    __asm__ volatile(
        "pushl 12(%2)\n\tpushl 8(%2)\n\tpushl 4(%2)\n\tpushl (%2)\n\tcall *%1\n\t"
        : "=a"(ret) : "r"(t), "r"(args) : "memory", "cc", "ecx", "edx");
    return (long)ret;
}
/* 1.2.0-A8: stdcall 5-arg — NtQueryInformationProcess (K8) icin
   (5 arg push edilir; stdcall callee 5*4=20 bayti kendisi poplar). */
static long xa_call5_86(u32 t, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5) {
    u32 args[5] = { a1, a2, a3, a4, a5 };
    u32 ret;
    __asm__ volatile(
        "pushl 16(%2)\n\tpushl 12(%2)\n\tpushl 8(%2)\n\tpushl 4(%2)\n\tpushl (%2)\n\tcall *%1\n\t"
        : "=a"(ret) : "r"(t), "r"(args) : "memory", "cc", "ecx", "edx");
    return (long)ret;
}
/* 1.2.0-A8: stdcall 1-arg — CloseHandle (K9) icin */
static u32 xa_call1_86(u32 t, u32 a1) {
    u32 args[1] = { a1 };
    u32 ret;
    __asm__ volatile("pushl (%2)\n\tcall *%1\n\t"
        : "=a"(ret) : "r"(t), "r"(args) : "memory", "cc", "ecx", "edx");
    return ret;
}
#endif

/* 1.2.5 (x1/x2 FIX): VM tespit yollari (OP_ANTIDBG bataryasi, OP_CHKRET
   int3/ud2 donus-adresi, K7 hipervizor...) eskiyalarda SESSIZ zehir
   yapardı (done=2 → fonksiyon gobekte durur, mesaj/cikis YOK) — kullanici
   bulgusu: "VEH debugger'da mesaj cikmiyo, fonksiyonun kullanimi duruyor".
   Artik cfg bayraklarina uyar: scratch[5] bit2=rt_msg (MessageBoxA
   "butunluk kontrol kod = #5"), bit3=rt_exit (ExitProcess(0x75)).
   Bayraklar stub'dan yazilir (engine_stub: cfg 0x08/0x10 ile ayni anlamlar).
   UO/VMP paritesi: help/en/history.htm:492 "shows a corresponding message
   and closes". */
static void vm_poison(VMContext* c) {
#if defined(VM_WINDOWS)
    {
        u64 k32 = xa_module(XA_K32);
        u64 u32m = xa_module(XA_U32);
        if (c->scratch[5] & 4) {                       /* rt_msg */
            u64 mb;
            if (!u32m && k32) {
                /* user32 yuklu degil -> LoadLibraryA("user32.dll")
                   (PIC: stack-string, volatile u32 paketleri) */
                u64 ll = xa_export(k32, XA_LLDA);
                if (ll) {
                    volatile u32 un[3];
                    un[0] = 0x72657375u;   /* 'u','s','e','r' */
                    un[1] = 0x642E3233u;   /* '3','2','.','d' */
                    un[2] = 0x00006C6Cu;   /* 'l','l',0,0 */
#if defined(VM_IS_X64)
                    u32m = xa_call1(ll, (u64)(unsigned long)(void*)un);
#else
                    u32m = xa_call1_86((u32)ll, (u32)(unsigned long)(void*)un);
#endif
                }
            }
            mb = u32m ? xa_export(u32m, XA_MSGBOX) : 0;
            if (mb) {
                /* PIC: stack-string (rodata YASAK — cp44 dersi). GCC
                   char-char atamalari .rodata+memcpy'ye cevirebildigi
                   icin volatile u32 paketleri kullanilir (anlik-deger
                   kod icine gomulur; xrt VP4/A4 ayni teknik).
                   A13/x7: cfg'de ozel mesaj varsa (ctx->msgp) onu
                   kullan — UO/VMP "Messages" paritesi. */
                volatile u32 tw[3];
                volatile u32 mw[9];
                u64 msgp = c->msgp;
                tw[0] = 0x6F725058u;   /* 'X','P','r','o' */
                tw[1] = 0x74636574u;   /* 't','e','c','t' */
                tw[2] = 0x00000000u;
                if (!msgp) {
                    mw[0] = 0x6F727058u;   /* 'X','p','r','o' */
                    mw[1] = 0x74636574u;   /* 't','e','c','t' */
                    mw[2] = 0x7562203Au;   /* ':',' ','b','u' */
                    mw[3] = 0x6C6E7574u;   /* 't','u','n','l' */
                    mw[4] = 0x6B206B75u;   /* 'u','k',' ','k' */
                    mw[5] = 0x72746E6Fu;   /* 'o','n','t','r' */
                    mw[6] = 0x6B206C6Fu;   /* 'o','l',' ','k' */
                    mw[7] = 0x3D20646Fu;   /* 'o','d',' ','=' */
                    mw[8] = 0x00352320u;   /* ' ','#','5',0 */
                    msgp = (u64)(unsigned long)(void*)mw;
                }
                {
                    u64 ttlp = (u64)(unsigned long)(void*)tw;
#if defined(VM_IS_X64)
                    xa_call4(mb, 0, msgp, ttlp, 0x10);
#else
                    xa_call4_86((u32)mb, 0, (u32)msgp, (u32)ttlp, 0x10);
#endif
                }
            }
        }
        if (c->scratch[5] & 8) {                       /* rt_exit */
            u64 ep = xa_export(k32, XA_EXITP);
            if (ep) {
#if defined(VM_IS_X64)
                xa_call4(ep, 0x75, 0, 0, 0);           /* 1-arg cagri; oteki arglar onemsiz */
#else
                xa_call1_86((u32)ep, 0x75);
#endif
            }
        }
    }
#endif /* VM_WINDOWS */
    c->done = 2;   /* zehir (tespit sonrasi VM durur) */
}

#endif /* VM_WINDOWS */

// --- yorumlayici ---
static void vm_run(VMContext* c) {
    STRM s;
    s.bc  = (u8*)u2p(c->bc);
    s.key = c->key;
    s.ic  = 0;
    s.adv = (int)(c->scratch[5] & 1);   /* 1.2.0-B1: vtAdvanced komut-sifreleyici */

    VM_TRACE_CHECK();
    /* 0.8.0 polimorfik isleyiciler: fonksiyon-bazina opcode permütasyonu.
       Stub tohumu ctx->scratch[3]'e yazdi (fonksiyon RVA'si); ayni
       vm_perm_tab ile raw->gercek tablosu turetilir. */
    unsigned char itab[VM_OPN];
    vm_perm_tab((u32)c->scratch[3], itab, 1);
#ifdef VM_TRACE
    if (vm_trace_on) {
        tputn("[bc] len=", c->bc_len, (u64)(unsigned long)c->bc);
        {
            /* tam PLAIN akis (sf8 ile birebir cozum) + itab -> dosya */
            int fd = open2("/tmp/plain.bin");
            if (fd >= 0) {
                unsigned di;
                for (di = 0; di < (unsigned)c->bc_len; di++) {
                    unsigned char raw = ((const unsigned char*)u2p(c->bc))[di];
                    unsigned char pv = di ? ((const unsigned char*)u2p(c->bc))[di - 1] : 0;
                    unsigned char p1 = (unsigned char)(raw ^ VM_KSC(c->key, pv, di));
                    wr2(fd, &p1, 1);
                }
                close2(fd);
            }
            fd = open2("/tmp/itab.bin");
            if (fd >= 0) { wr2(fd, itab, VM_OPN); close2(fd); }
        }
    }
#endif
    /* 0.8.0 adim butcesi: CFB tamper-yayilimi bozuk akisi JUMP dongusune
       cevirebilir -> butcesiz while sonsuz aski (DoS sinifi) demek.
       Butce 1<<24 (16.7M adim): meşru lifted donguler (kucuk fonksiyon
       govdesi) asla ulasamaz; tamper-derailment sinirli surede durur. */
    {
        u64 budget = (u64)1 << 24;
        while (!c->done) {
            if (budget-- == 0) { c->done = 1; break; }
            /* 1.0.0 kok-fix (yakinma): akis-tasma korumasi — ic bc_len'i asarsa
               OOB bayti op diye cozmaya calisma (itab[garcop] stack-OOB okuma,
               rastgele VM op'u = oyun-cokmesi sinifi). Duru-cikis: stub retimm
               ile temiz doner (yanlis deger, cokme YOK). */
            if (s.ic >= c->bc_len) { c->done = 1; break; }
        u8 op = itab[sf8(&s)];
        int alu, shi, cc, ud, sz, ssz, r1, r2, form, n, idx;
        u32 v32;
        u64 a, b, r, addr, fl;
        i64 sv;
            c->scratch[0] = op;        /* hata ayiklama izi */
            c->scratch[1] = s.ic;
            c->scratch[2] = s.key;
#ifdef VM_TRACE
        if (vm_trace_on) tputn("[vm] ic=", s.ic, ((u64)op << 56) | s.key);
#endif

        if (op == OP_NOP) {
            /* junk */

        } else if (op == OP_MOV_RR) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            rset(c, r1, sz, rget(c, r2, sz));

        } else if (op == OP_MOV_RI) {
            sz = sf8(&s); r1 = sf8(&s); sext32(&sv, sf32(&s));
            rset(c, r1, sz, (u64)sv);

        } else if (op == OP_MOV_RI64) {
            r1 = sf8(&s);
            rset(c, r1, 8, sf64(&s));

        } else if (op == OP_CMOV) {
            cc = sf8(&s); sz = sf8(&s); r1 = sf8(&s); form = sf8(&s);
            if (form == 0) a = rget(c, sf8(&s), sz);
            else           a = mrd(mem_addr(&s, c), sz);
            if (cond_eval(c, cc)) rset(c, r1, sz, a);

        } else if (op == OP_MOV_RM) {
            sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            rset(c, r1, sz, mrd(addr, sz));

        } else if (op == OP_MOV_MR) {
            sz = sf8(&s);
            addr = mem_addr(&s, c);
            r1 = sf8(&s);
            mwr(addr, sz, rget(c, r1, sz));

        } else if (op == OP_MOV_MI) {
            sz = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            mwr(addr, sz, (u64)sv);

        } else if (op == OP_LEA_RM) {
            r1 = sf8(&s);
            rset(c, r1, 8, mem_addr(&s, c));

        } else if (op == OP_ALU_RR) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            int cin = (alu == ALU_ADC || alu == ALU_SBB) ? ((c->flags & FCF) ? 1 : 0) : 0;
            r = do_alu_c(alu, rget(c, r1, sz), rget(c, r2, sz), sz, cin, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_RI) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s); sext32(&sv, sf32(&s));
            b = (u64)sv;
            if (sz == 4) b &= 0xFFFFFFFFULL;
            if (sz == 2) b &= 0xFFFFULL;
            if (sz == 1) b &= 0xFFULL;
            int cin = (alu == ALU_ADC || alu == ALU_SBB) ? ((c->flags & FCF) ? 1 : 0) : 0;
            r = do_alu_c(alu, rget(c, r1, sz), b, sz, cin, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_RM) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            int cin = (alu == ALU_ADC || alu == ALU_SBB) ? ((c->flags & FCF) ? 1 : 0) : 0;
            r = do_alu_c(alu, rget(c, r1, sz), mrd(addr, sz), sz, cin, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_MR) {
            alu = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            r2 = sf8(&s);
            int cin = (alu == ALU_ADC || alu == ALU_SBB) ? ((c->flags & FCF) ? 1 : 0) : 0;
            r = do_alu_c(alu, mrd(addr, sz), rget(c, r2, sz), sz, cin, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) mwr(addr, sz, r);

        } else if (op == OP_ALU_MI) {
            alu = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            b = (u64)sv;
            if (sz == 4) b &= 0xFFFFFFFFULL;
            if (sz == 2) b &= 0xFFFFULL;
            if (sz == 1) b &= 0xFFULL;
            int cin = (alu == ALU_ADC || alu == ALU_SBB) ? ((c->flags & FCF) ? 1 : 0) : 0;
            r = do_alu_c(alu, mrd(addr, sz), b, sz, cin, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) mwr(addr, sz, r);

        } else if (op == OP_SHI_RI) {
            shi = sf8(&s); sz = sf8(&s); r1 = sf8(&s); n = sf8(&s);
            r = do_shift(shi, rget(c, r1, sz), n, sz, c->flags, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_SHI_CL) {
            shi = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            n = (int)(rdec(c, REG_RCX) & 0x3F);
            r = do_shift(shi, rget(c, r1, sz), n, sz, c->flags, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_SHI_RM_RI || op == OP_SHI_RM_CL) {
            shi = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            if (op == OP_SHI_RM_RI) n = sf8(&s);
            else                    n = (int)(rdec(c, REG_RCX) & 0x3F);
            r = do_shift(shi, mrd(addr, sz), n, sz, c->flags, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_IMUL_RRI) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s); sext32(&sv, sf32(&s));
            a = (u64)(i64)rget(c, r2, sz);
            if (sz == 4) a = (u64)(i64)(int)(a & 0xFFFFFFFF);
            r = (u64)(sv * (i64)a);
            /* 0.9.0: IMUL CF=OF = sonuc alt-yarida isaret-uzatmiyor (x86 tanimli).
               SF/ZF/PF/AF tanimsiz -> 0. */
            {
                i64 pr = sv * (i64)a;
                i64 tr = (sz == 8) ? pr : (i64)(int)(u32)((u64)pr & 0xFFFFFFFFULL);
                c->flags = (pr != tr) ? (FCF | FOF) : 0;
            }
            rset(c, r1, sz, r);

        } else if (op == OP_IMUL_RMRI) {
            sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            a = (u64)(i64)rget(c, 0, 0);           /* kullanilmaz */
            b = (u64)(i64)rget(c, 0, 0);           /* yer tutici */
            (void)a; (void)b;
            {
                u64 mv = mrd(addr, sz);
                i64 mvx = (sz == 8) ? (i64)mv : (i64)(int)(mv & 0xFFFFFFFF);
                r = (u64)(sv * mvx);
                i64 pr = sv * mvx;
                i64 tr = (sz == 8) ? pr : (i64)(int)(u32)((u64)pr & 0xFFFFFFFFULL);
                c->flags = (pr != tr) ? (FCF | FOF) : 0;
            }
            rset(c, r1, sz, r);

        } else if (op == OP_IMUL_RR) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            a = (u64)(i64)rget(c, r1, sz);
            b = (u64)(i64)rget(c, r2, sz);
            if (sz == 4) {
                a = (u64)(i64)(int)(a & 0xFFFFFFFF);
                b = (u64)(i64)(int)(b & 0xFFFFFFFF);
            }
            r = (u64)((i64)a * (i64)b);
            {
                i64 pr = (i64)a * (i64)b;
                i64 tr = (sz == 8) ? pr : (i64)(int)(u32)((u64)pr & 0xFFFFFFFFULL);
                c->flags = (pr != tr) ? (FCF | FOF) : 0;
            }
            rset(c, r1, sz, r);

        } else if (op == OP_INCDEC_R) {
            ud = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            r = do_alu(ud ? ALU_SUB : ALU_ADD, rget(c, r1, sz), 1, sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_INCDEC_M) {
            ud = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            r = do_alu(ud ? ALU_SUB : ALU_ADD, mrd(addr, sz), 1, sz, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_NEG_R) {
            sz = sf8(&s); r1 = sf8(&s);
            r = do_alu(ALU_SUB, 0, rget(c, r1, sz), sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_NOT_R) {
            sz = sf8(&s); r1 = sf8(&s);
            rset(c, r1, sz, ~rget(c, r1, sz) & szmask(sz));

        } else if (op == OP_NEG_M) {
            sz = sf8(&s); addr = mem_addr(&s, c);
            r = do_alu(ALU_SUB, 0, mrd(addr, sz), sz, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_NOT_M) {
            sz = sf8(&s); addr = mem_addr(&s, c);
            mwr(addr, sz, ~mrd(addr, sz) & szmask(sz));

        } else if (op == OP_MOVZX || op == OP_MOVSX) {
            sz = sf8(&s); ssz = sf8(&s); r1 = sf8(&s); form = sf8(&s);
            if (form == 0) {
                a = rget(c, sf8(&s), ssz);
            } else {
                addr = mem_addr(&s, c);
                a = mrd(addr, ssz);
            }
            if (op == OP_MOVZX) r = a & szmask(ssz);
            else {
                /* 0.8.0 fix: ssz==4 (movslq/MOVSXD) 16-bit degil 32-bit
                 * isaret genisletme olmali — eski kod (i64)(short) ile
                 * ssz==4'u 16-bit'e dusuruyordu (sdk_ext kanit bug'i). */
                if (ssz == 1)      r = (u64)(i64)(signed char)(a & 0xFF);
                else if (ssz == 2) r = (u64)(i64)(short)(a & 0xFFFF);
                else               r = (u64)(i64)(int)(a & 0xFFFFFFFF);
            }
            rset(c, r1, sz, r);

        } else if (op == OP_PUSH_R) {
            r1 = sf8(&s);
            renc(c, REG_RSP, rdec(c, REG_RSP) - (PUSHSZ));
            mwr(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ, rget(c, r1, PUSHSZ));

        } else if (op == OP_PUSH_I) {
            sext32(&sv, sf32(&s));
            renc(c, REG_RSP, rdec(c, REG_RSP) - (PUSHSZ));
            mwr(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ, (u64)sv);

        } else if (op == OP_POP_R) {
            r1 = sf8(&s);
            rset(c, r1, PUSHSZ, mrd(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ));
            renc(c, REG_RSP, rdec(c, REG_RSP) + (PUSHSZ));

        } else if (op == OP_NOR_ST || op == OP_NAND_ST) {
            /* 1.0.0-UO: VMP cmNor/cmNand yigin kapisi (intel.cc birebir).
               pop b (ust slot), pop a; push ~(a|b) | ~(a&b).
               Kapilar sz-maskeli calisir; bayraklar = mantiksal islem
               semantigi (do_alu AND yolu: CF=OF=0, AF=0, SF/ZF/PF=sonuc) —
               yerel and/or/xor ile bayt-bayt ayni. Yigin dengesi: -2 slot
               pop, +1 slot push = net RSP += PUSHSZ. Temp-reg YOK. */
            sz = sf8(&s);
            {
                /* 1.2.0-B1 DERS (host-harness kanitli): pop-a = top'un ALTINDAKI
                   slot = ta + PUSHSZ (eski kod ta - PUSHSZ okuyordu = konuk
                   yiginda HIC yazilmamis junk-slot -> kapilar bozuk sonuc;
                   junk=0 sansli ortamda bile XOR zinciri 0x5A'ya degere
                   cikiyordu — sdk_b1 b/c=136 kaniti). Sonuc da ta + PUSHSZ
                   yazilir (pop2/push1 -> net rsp += PUSHSZ, yeni top = eski
                   top'un altindaki slot = iki operandin birlesimi). */
                u64 ta = rdec(c, REG_RSP) - (u64)VM_DELTA;
                u64 vb = mrd(ta, PUSHSZ) & szmask(sz);
                u64 va = mrd(ta + PUSHSZ, PUSHSZ) & szmask(sz);
                u64 vr = (op == OP_NOR_ST) ? ((~(va | vb)) & szmask(sz))
                                           : ((~(va & vb)) & szmask(sz));
                mwr(ta + PUSHSZ, PUSHSZ, vr);
                renc(c, REG_RSP, rdec(c, REG_RSP) + (PUSHSZ));
                do_alu(ALU_AND, vr, vr, sz, &fl);
                c->flags = fl;
            }

        } else if (op == OP_POP_RP) {
            /* 1.0.0-UO: cmPop otRegistr size_ karsiligi — kismi-yazim pop.
               yigin slot'u PUSHSZ genisliginde okunur, reg'e sz boyutunda
               YAZILIR (sz<8'de ust baytlar KORUNUR — x64 and eax,ebx
               ust-32-koruma semantigi). */
            sz = sf8(&s); r1 = sf8(&s);
            rset(c, r1, sz, mrd(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ));
            renc(c, REG_RSP, rdec(c, REG_RSP) + (PUSHSZ));

        } else if (op == OP_JMP) {
            sext32(&sv, sf32(&s));
            s.ic = s.ic + (u64)sv;

        } else if (op == OP_JMPEXT) {
            /* 1.2.0-B1 rel32 dis-akis: kuyruk-jmp — VM cikisi (done=3),
               stub push_area'dan kayitlari geri yukledikten sonra volatile
               reg ile base+rva'ya atlar; donus adresi yiginda KALIR. */
            c->scratch[6] = (u64)sf32(&s);
            c->done = 3;

        } else if (op == OP_JCCEXT) {
            /* sartli kuyruk-jmp: kosul yanlissa akis buradan devam eder. */
            cc = sf8(&s);
            v32 = sf32(&s);
            if (cond_eval(c, cc)) { c->scratch[6] = (u64)v32; c->done = 3; }

        } else if (op == OP_JCC) {
            cc = sf8(&s); sext32(&sv, sf32(&s));
            if (cond_eval(c, cc)) s.ic = s.ic + (u64)sv;

        } else if (op == OP_NCALL) {
            v32 = sf32(&s);
#ifdef VM_TRACE
            /* harness modu: native cagri YOK — sahte donus (rax=gumus),
               akis devam eder (mem/SIB teshisi icin). */
            if (vm_trace_on) tputn("[ncall] hedef=", c->base + (u64)v32, rdec(c, REG_RSP));
            renc(c, 0, 0);
#else
#ifdef VM_IS_X64
            /* 1.2.0-A9 Encrypt Registers: natcall arg kayitcilari COZULMUS
               yerel kopyadan gelir; donus degeri yeniden SIFRELI yazilir.
               (vm_natcall regs[1]/[2]/[8]/[9] okur — Win64 rcx,rdx,r8,r9.) */
            {
                u64 ncr[16]; int nci;
                for (nci = 0; nci < 16; nci++) ncr[nci] = rdec(c, nci);
                regs_rotate(c);   /* A20: dogal-cagri penceresinde yeni epoch */
                renc(c, 0, vm_natcall(c->base + (u64)v32, ncr));
            }
#else
            {
                /* 0.5.1: x86 dogal cagri — arg kayitcilari (eax/ecx/edx)
                gercek CPU'ya tasınır, callee sonrasi esp + eax/ecx/edx VM'e
                yansitilir (0.5.0'da ikisi de yoktu -> yigin bozumu + cop
                thiscall). stdcall temizlemesi esp senkronu ile yansitilir.
                1.2.0-A9 Encrypt Registers: yerel COZULMUS kopya ile cagrilir,
                callee sonrasi donus/arg kayitcilari yeniden SIFRELI yazilir. */
                u64 nret = 0, nesp = 0;
                u64 ncr86[16]; int nci;
                for (nci = 0; nci < 16; nci++) ncr86[nci] = rdec(c, nci);
                regs_rotate(c);   /* A20: dogal-cagri penceresinde yeni epoch */
                vm_natcall86(ncr86, (u32)(c->base + (u64)v32),
                             (u32)(rdec(c, REG_RSP) - (u64)VM_DELTA), &nret, &nesp);
                renc(c, REG_RSP, nesp + (u64)VM_DELTA);
                renc(c, 0, ncr86[0]);
                renc(c, 1, ncr86[1]);
                renc(c, 2, ncr86[2]);
            }
#endif
#endif /* VM_TRACE */

        } else if (op == OP_NCALLI) {
            /* 1.2.2-A10: DOLAYLI dogal cagri (FF /2 call dword ptr [mem] VE
               FF D0 call reg). Lifter XP_CALLI karsiligi — vtable/girdi-
               isaretcisi aracili cagilar (metin2 E96D0 "call dword ptr
               [eax+00000088]" vtable-thiscall dahil). OP_NCALL'den TEK farki:
               hedef sabit base+rva DEGIL, bellekten/KAYITTAN okunan MUTLAK VA
               (base eklenmez). Kodlama: u8 form (0=u32 mem, 1=u64 mem,
               2=u8 reg-idx) + mem operandi (mem_addr kendi form baytini
               okur — lifter L.emem sirasi ile birebir). Encrypt Registers
               yolu OP_NCALL ile ayni: cozulmus yerel kopya ile cagrilir,
               donus kayitcilari yeniden sifreli yazilir. */
            int tf = sf8(&s);
            u64 ta = 0, tgt = 0;
            if (tf == 2) tgt = rdec(c, sf8(&s));
            else { ta = mem_addr(&s, c); tgt = mrd(ta, tf ? 8 : 4); }
#ifdef VM_TRACE
            /* harness modu: native cagri YOK — sahte donus (rax=gumus),
               akis devam eder (mem/SIB teshisi icin). */
            if (vm_trace_on) tputn("[ncalli] hedef=", tgt, rdec(c, REG_RSP));
            renc(c, 0, 0);
#else
#ifdef VM_IS_X64
            {
                u64 ncr[16]; int nci;
                for (nci = 0; nci < 16; nci++) ncr[nci] = rdec(c, nci);
                regs_rotate(c);   /* A20: dogal-cagri penceresinde yeni epoch */
                renc(c, 0, vm_natcall(tgt, ncr));
            }
#else
            {
                u64 nret = 0, nesp = 0;
                u64 ncr86[16]; int nci;
                for (nci = 0; nci < 16; nci++) ncr86[nci] = rdec(c, nci);
                regs_rotate(c);   /* A20: dogal-cagri penceresinde yeni epoch */
                vm_natcall86(ncr86, (u32)tgt,
                             (u32)(rdec(c, REG_RSP) - (u64)VM_DELTA), &nret, &nesp);
                renc(c, REG_RSP, nesp + (u64)VM_DELTA);
                renc(c, 0, ncr86[0]);
                renc(c, 1, ncr86[1]);
                renc(c, 2, ncr86[2]);
            }
#endif
#endif /* VM_TRACE */

        } else if (op == OP_RET) {
            c->done = 1;

        } else if (op == OP_SETCC) {
            cc = sf8(&s); r1 = sf8(&s);
            rset(c, r1, 1, cond_eval(c, cc) ? 1 : 0);

        } else if (op == OP_CQO) {
#if defined(VM_IS_X64)
            renc(c, REG_RDX, (rdec(c, 0) >> 63) ? ~0ULL : 0ULL);
#else
            renc(c, REG_RDX, (rdec(c, 0) & 0x80000000ULL) ? 0xFFFFFFFFULL : 0ULL);
#endif

        } else if (op == OP_IDIV_R) {
            sz = sf8(&s); r1 = sf8(&s);
#if defined(VM_IS_X64)
            if (sz == 4) {
                i64 dd = ((i64)(int)(rdec(c, REG_RDX) & 0xFFFFFFFF) << 32)
                       |  (i64)(int)(rdec(c, 0) & 0xFFFFFFFF);
                i64 dv = (i64)(int)(rdec(c, r1) & 0xFFFFFFFF);
                if (dv == 0) { renc(c, 0, 0); renc(c, REG_RDX, 0); }
                else { renc(c, 0, (u64)(int)(dd / dv)); renc(c, REG_RDX, (u64)(int)(dd % dv)); }
            } else {
                /* 0.9.0 KOK-FIX: 0.8.5'te dd = RDX YALNIZ (RAX yok sayiliyor)
                   — cqo sonrasi RDX = RAX isareti oldugu icin bolum hepsi
                   0/copluk cikiyordu. Dogrusu RDX:RAX 128-bit / r64. */
                i64 q, rm;
                idiv128((i64)rdec(c, REG_RDX), (i64)rdec(c, 0), (i64)rdec(c, r1), &q, &rm);
                renc(c, 0, (u64)q); renc(c, REG_RDX, (u64)rm);
            }
#else
            if (sz == 4) {
                /* 0.9.0 KOK-FIX: 0.8.5'te EDX yok sayiliyor (yalniz eax/dv).
                   Dogrusu EDX:EAX 64-bit / r32. */
                u64 dd = ((rdec(c, REG_RDX) & 0xFFFFFFFFULL) << 32)
                       |  (rdec(c, 0) & 0xFFFFFFFFULL);
                int sdv = (int)(rdec(c, r1) & 0xFFFFFFFF);
                if (sdv == 0) { renc(c, 0, 0); renc(c, REG_RDX, 0); }
                else {
                    int neg = ((i64)dd < 0) != (sdv < 0);
                    u64 un = ((i64)dd < 0) ? (u64)(0 - (i64)dd) : dd;
                    u32 ud = (sdv < 0) ? (u32)(0 - sdv) : (u32)sdv;
                    u32 rm2;
                    u64 q = div64_32(un, ud, &rm2);   /* i386 guvenli */
                    if (q > 0x7FFFFFFFULL) { renc(c, 0, 0); renc(c, REG_RDX, 0); }
                    else {
                        renc(c, 0, (u64)(u32)(neg ? (u32)(0 - (u32)q) : (u32)q));
                        renc(c, REG_RDX, (u64)(u32)(neg ? (u32)(0 - rm2) : rm2));
                    }
                }
            } else { c->done = 1; }
#endif

        } else if (op == OP_ANTIDBG) {
            /* 1.1.0-A7: maske bayti — bit0=anti-debug bataryasi (PEB/K1..K6),
               bit1=Check VM (K7 CPUID hipervizor-present, leaf1 ECX bit31). */
            ud = sf8(&s);
#ifdef VM_WINDOWS
            if (ud & 2) {
#if defined(VM_IS_X64)
                u32 ca, cb, ccx2, cd2;
                __asm__ volatile("cpuid" : "=a"(ca), "=b"(cb), "=c"(ccx2), "=d"(cd2) : "a"(1));
#else
                u32 ca, cb, ccx2, cd2;
                __asm__ volatile("pushl %%ebx\n\tcpuid\n\tpopl %%ebx"
                                 : "=a"(ca), "=c"(ccx2), "=d"(cd2) : "a"(1) : "memory");
#endif
                if (ccx2 & 0x80000000u) vm_poison(c);   /* hipervizor icinde */
                /* 1.2.2-A20: K7c — hypervisor leaf 0x40000000 VENDOR taramasi
                   (VBOX/KVM/HyperV/Xen/Parallels/VMware; UO checkvm deseni,
                   loader-parite: xrt_antidebug ile ayni sabitler). */
                if (!c->done) {
                    u32 va_, vb, vc, vd;
#if defined(VM_IS_X64)
                    __asm__ volatile("cpuid" : "=a"(va_), "=b"(vb), "=c"(vc), "=d"(vd) : "a"(0x40000000));
#else
                    __asm__ volatile("pushl %%ebx\n\tcpuid\n\tpopl %%ebx"
                                     : "=a"(va_), "=c"(vc), "=d"(vd) : "a"(0x40000000u) : "memory");
#endif
                    if (va_) {
                        if (vb == 0x4b4d564bu && vc == 0x564b4d56u && vd == 0x0000004du) vm_poison(c); /* KVMKVMKVM */
                        if (vb == 0x7263694du && vc == 0x666f736fu && vd == 0x76482074u) vm_poison(c); /* Microsoft Hv */
                        if (vb == 0x786f4256u && vc == 0x786f4256u && vd == 0x786f4256u) vm_poison(c); /* VBoxVBoxVBox */
                        if (vb == 0x206c7270u && vc == 0x65707968u && vd == 0x00002076u) vm_poison(c); /* prl hyperv  */
                        if (vb == 0x566e6558u && vc == 0x65584d4du && vd == 0x4d4d566eu) vm_poison(c); /* XenVMMXenVMM */
                        if (vb == 0x61774d56u && vc == 0x4d566572u && vd == 0x65726177u) vm_poison(c); /* VMwareVMware */
                    }
                }
                /* 1.2.2-A15: K7b - CPUID rdtsc-ZAMANLAMA yakalamasi (UO CheckVM
                   deseni): hipervizorlar CPUID'yi yakalayinca komut ~10x yavas
                   calisir. YANLIS-POZITIF korumasi: 8 ornekten EN KUCUK delta
                   kullanilir (yerel CPUID ilk orneklerde cache/TLB nedeniyle
                   yavas olabilir; trap her ornekte yavastir). Esik: 10000 devir
                   (yerel ~100-1000, trap ~10000+). */
                if (!c->done) {
#if defined(VM_IS_X64)
                    u32 t0lo, t0hi, t1lo, t1hi, ea, eb, ecxd, edd;
                    u64 dmin = ~0ull;
                    int it;
                    for (it = 0; it < 8; it++) {
                        __asm__ volatile("rdtsc" : "=a"(t0lo), "=d"(t0hi));
                        __asm__ volatile("cpuid" : "=a"(ea), "=b"(eb), "=c"(ecxd), "=d"(edd) : "a"(1));
                        __asm__ volatile("rdtsc" : "=a"(t1lo), "=d"(t1hi));
                        u64 d = (((u64)t1hi << 32) | t1lo) - (((u64)t0hi << 32) | t0lo);
                        if (d < dmin) dmin = d;
                    }
                    if (dmin > 10000ull) vm_poison(c);
#else
                    u32 t0lo, t0hi, t1lo, t1hi, ea, ecxd, edd;
                    u32 dmin = ~0u;
                    int it;
                    for (it = 0; it < 8; it++) {
                        __asm__ volatile("rdtsc" : "=a"(t0lo), "=d"(t0hi));
                        __asm__ volatile("pushl %%ebx\n\tcpuid\n\tpopl %%ebx"
                                         : "=a"(ea), "=c"(ecxd), "=d"(edd) : "a"(1u) : "memory");
                        __asm__ volatile("rdtsc" : "=a"(t1lo), "=d"(t1hi));
                        if (t1lo - t0lo < dmin) dmin = t1lo - t0lo;
                    }
                    if (dmin > 10000u) vm_poison(c);
#endif
                }
            }
            if (ud & 1) {
            /* 1.2.0-A8: K1..K9 TAM batarya (UO 1:1) */
            {
#if defined(VM_IS_X64)
            { u64 peb; __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
              u8* p = (u8*)u2p(peb);
              if (p[2] || (p[0xBC] & 0x70)) vm_poison(c); }
#else
            { u32 peb; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
              u8* p = (u8*)u2p((u64)peb);
              if (p[2] || (p[0x68] & 0x70)) vm_poison(c); }
#endif
            if (!c->done && (u32)c->scratch[3]) {
                if (mrd(c->base + (u64)(u32)c->scratch[3], 1) == 0xCC) vm_poison(c);
            }
#if defined(VM_IS_X64)
            if (!c->done) {
                u64 fl;
                __asm__ volatile("pushfq\n\t popq %0" : "=r"(fl));
                if (fl & 0x100) vm_poison(c);
            }
#else
            if (!c->done) {
                u32 fl;
                __asm__ volatile("pushfl\n\t popl %0" : "=r"(fl));
                if (fl & 0x100) vm_poison(c);
            }
#endif
            }
            /* (K3) DRx — GetThreadContext senkron okuma (0.8.5) */
            if (!c->done) {
                u64 gtc = xa_export(xa_module(XA_K32), XA_GTC);
                if (gtc) {
#if defined(VM_IS_X64)
                    u8 cbuf[XA_CTX_SIZE + 16];
                    u64 cal = ((u64)(unsigned long)cbuf + 15ull) & ~15ull;
                    mwr(cal + XA_CTX_FLAGS, 4, XA_CTX_DBGFL);
                    if (xa_call4(gtc, 0xFFFFFFFFFFFFFFFEull, cal, 0, 0)) {
                        u64 dr = mrd(cal + XA_CTX_DR0, 8) | mrd(cal + XA_CTX_DR1, 8)
                               | mrd(cal + XA_CTX_DR2, 8) | mrd(cal + XA_CTX_DR3, 8);
                        if (dr) vm_poison(c);
                    }
#else
                    u8 cbuf[XA_CTX_SIZE + 16];
                    u32 cal = ((u32)(unsigned long)cbuf + 3u) & ~3u;
                    mwr((u64)cal + XA_CTX_FLAGS, 4, XA_CTX_DBGFL);
                    if (xa_call2_86((u32)gtc, 0xFFFFFFFEu, cal)) {
                        u32 dr = (u32)mrd((u64)cal + XA_CTX_DR0, 4) | (u32)mrd((u64)cal + XA_CTX_DR1, 4)
                               | (u32)mrd((u64)cal + XA_CTX_DR2, 4) | (u32)mrd((u64)cal + XA_CTX_DR3, 4);
                        if (dr) vm_poison(c);
                    }
#endif
                }
            }
            /* (K4) ThreadHideFromDebugger — UO loader.cc 1:1 anti-aksiyon */
            if (!c->done) {
                u64 nsit = xa_export(xa_module(XA_NTD), XA_NSIT);
                if (nsit) {
#if defined(VM_IS_X64)
                    xa_call4(nsit, 0xFFFFFFFFFFFFFFFEull, 0x11, 0, 0);
#else
                    xa_call4_86(nsit, 0xFFFFFFFEu, 0x11, 0, 0);
#endif
                }
            }
            /* (K8) PROCESS DEBUG PORT/OBJECT — UO loader.cc:1810-1827 1:1:
               ProcessDebugPort(7): NT_SUCCESS && port != 0 -> debugger.
               ProcessDebugObjectHandle(30): NT_SUCCESS tek basina debugger
               (debug nesnesi yokken cagri BASARISIZDIR — PORT_NOT_SET). */
            if (!c->done) {
                u64 nqip = xa_export(xa_module(XA_NTD), XA_NQIP);
                if (nqip) {
                    u64 dbo = 0;
#if defined(VM_IS_X64)
                    /* 1.2.0-A8 KOK DUZELTME (NTSTATUS isaret-genisletme):
                       Win64 ABI'de 32-bit NTSTATUS RAX'ta SIFIR-GENISLEMIS
                       doner; (i64) u64 cast yanlis-pozitif uretir (0xC0000353
                       -> +3221227219!). Cozum: u32 kirp -> i32 isaret
                       genislet -> i64. (VMMIN K8b-kaniti: 0xDEAD0008.) */
                    i64 st = (i64)(int)(u32)xa_qip5(nqip, 7, (u64)(unsigned long)(void*)&dbo);
                    if (st >= 0 && dbo != 0) vm_poison(c);
                    dbo = 0;
                    st = (i64)(int)(u32)xa_qip5(nqip, 30, (u64)(unsigned long)(void*)&dbo);
                    if (st >= 0) vm_poison(c);
#else
                    i64 st = (i64)(long)xa_call5_86((u32)nqip, 0xFFFFFFFFu, 7,
                                              (u32)(unsigned long)(void*)&dbo, 8, 0);
                    if (st >= 0 && dbo != 0) vm_poison(c);
                    dbo = 0;
                    st = (i64)(long)xa_call5_86((u32)nqip, 0xFFFFFFFFu, 30,
                                          (u32)(unsigned long)(void*)&dbo, 8, 0);
                    if (st >= 0) vm_poison(c);
#endif
                }
            }
            /* (K9) CloseHandle(0xDEADC0DE) — UO loader.cc:2432 1:1 */
            if (!c->done) {
                u64 ch = xa_export(xa_module(XA_K32), XA_CLOSEH);
                if (ch) {
#if defined(VM_IS_X64)
                    if (xa_call4(ch, 0xDEADC0DEull, 0, 0, 0)) vm_poison(c);
#else
                    if (xa_call1_86((u32)ch, 0xDEADC0DEu)) vm_poison(c);
#endif
                }
            }
            }   /* if (ud & 1) */
            /* ===== 1.2.2-A15: KERNEL DEBUGGER bataryasi - cpCheckKernelDebugger
               ayri kutu. UO KURALI: Check Debugger acikken otomatik dahil
               (motor bit2 = antidebug || kerneldbg). Yalniz-kernel kipinde
               (ud&4, bit0 kapali) K5+K6 bagimsiz calisir. ===== */
            /* (K5) KERNEL DEBUGGER — SystemKernelDebuggerInformation (0x23) */
            if ((ud & 4) && !c->done) {   /* 1.2.2-A15: cpCheckKernelDebugger (bit2) */
                u64 nqsi = xa_export(xa_module(XA_NTD), XA_NQSI);
                if (nqsi) {
                    u8 ib[16];
                    u32 rl = 0;
#if defined(VM_IS_X64)
                    i64 st = (i64)(int)(u32)xa_call4(nqsi, 0x23, (u64)(unsigned long)(void*)ib, 2,
                                           (u64)(unsigned long)(void*)&rl);
#else
                    i64 st = (i64)(long)xa_call4_86((u32)nqsi, 0x23, (u32)(unsigned long)(void*)ib, 2,
                                              (u32)(unsigned long)(void*)&rl);
#endif
                    if (st >= 0 && ib[0] != 0 && ib[1] == 0) vm_poison(c);
                }
            }
            /* (K6) SURUCU TARAMASI — SystemModuleInformation (0x0B) */
            if ((ud & 4) && !c->done) {   /* 1.2.2-A15: cpCheckKernelDebugger (bit2) */
                u64 nqsi = xa_export(xa_module(XA_NTD), XA_NQSI);
                if (nqsi) {
#if defined(VM_IS_X64)
                    u8 mbuf[0x4000 + 16];
                    u64 mal = ((u64)(unsigned long)mbuf + 15ull) & ~15ull;
#else
                    u8 mbuf[0x4000 + 8];
                    u32 mal = ((u32)(unsigned long)mbuf + 3u) & ~3u;
#endif
                    u32 rl = 0;
#if defined(VM_IS_X64)
                    i64 st = (i64)(int)(u32)xa_call4(nqsi, 0x0B, mal, 0x4000,
                                           (u64)(unsigned long)(void*)&rl);
#else
                    i64 st = (i64)(long)xa_call4_86((u32)nqsi, 0x0B, (u32)mal, 0x4000,
                                              (u32)(unsigned long)(void*)&rl);
#endif
                    if (st >= 0 && rl >= 4 && rl <= 0x4000) {
                        u32 n = (u32)mrd(mal, 4);
                        u32 ent = (n > (0x4000 - 4) / 0x124) ? (0x4000 - 4) / 0x124 : n;
                        u32 mi;
                        for (mi = 0; mi < ent && !c->done; mi++) {
#if defined(VM_IS_X64)
                            u64 ebase = 4 + (u64)mi * 0x124 + 0x24;
                            u64 foff = mrd(mal + ebase - 2, 2);
#else
                            u32 ebase = 4 + mi * 0x116 + 0x16;
                            u32 foff = (u32)mrd((u64)mal + ebase - 2, 2);
#endif
                            if (foff >= 250) continue;
                            u64 w = mrd((u64)mal + (u64)ebase + (u64)foff, 8);
                            {
                                u64 t = 0; int kb;
                                for (kb = 0; kb < 8; kb++) {
                                    u8 ch = (u8)((w >> (8 * kb)) & 0xFF);
                                    if (ch >= 'A' && ch <= 'Z') ch += 32;
                                    t |= ((u64)ch) << (8 * kb);
                                }
                                w = t;
                            }
                            if (w == 0x0000000065636973ULL ||   /* sice   */
                                w == 0x0000646976776973ULL ||   /* siwvid */
                                w == 0x000000656369746EULL ||   /* ntice  */
                                w == 0x0000747865656369ULL ||   /* iceext */
                                w == 0x0000007265737973ULL)     /* syser  */
                                vm_poison(c);
                        }
                    }
                }
            }
#endif

                } else if (op == OP_BSWAP_R) {
            /* 0.8.0 komut genisletme: bswap r (yalniz 32/64) */
            sz = sf8(&s); r1 = sf8(&s);
            u64 v = rget(c, r1, sz), w = 0;
            int k2;
            for (k2 = 0; k2 < sz; k2++) w = (w << 8) | ((v >> (8 * k2)) & 0xFF);
            rset(c, r1, sz, w);

        } else if (op == OP_XCHG_RR) {
            /* 0.8.0 komut genisletme: xchg r1, r2 (bayrak etkisi yok) */
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            u64 va = rget(c, r1, sz), vb = rget(c, r2, sz);
            rset(c, r1, sz, vb);
            rset(c, r2, sz, va);

        /* ================= 0.9.0-DeepVM handler'lari =================
           UniversalObfuscator (VMProtect pub1 intel.cc CompileToVM)
           semantiğiyle ayni davranis: PUSHF/POPF/SAHF/LAHF/SETFLAG,
           MUL/DIV (unsigned, RDX:RAX), BT ailesi (yalniz CF),
           SHLD/SHRD, LOOP/JECXZ, XADD, string ops (rep + DF). */

        } else if (op == OP_PUSHF) {
            u64 f = c->flags;
            u64 img = 2ull                      /* bit1 rezerve = 1 (x86) */
                    | 0x200ull                  /* IF=1 (kesinti acik)   */
                    | ((f & FCF) ? 0x001ull : 0)
                    | ((f & FPF) ? 0x004ull : 0)
                    | ((f & FAF) ? 0x010ull : 0)
                    | ((f & FZF) ? 0x040ull : 0)
                    | ((f & FSF) ? 0x080ull : 0)
                    | ((f & FDF) ? 0x400ull : 0)
                    | ((f & FOF) ? 0x800ull : 0);
            renc(c, REG_RSP, rdec(c, REG_RSP) - (PUSHSZ));
            mwr(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ, img);

        } else if (op == OP_POPF) {
            u64 img = mrd(rdec(c, REG_RSP) - (u64)VM_DELTA, PUSHSZ);
            renc(c, REG_RSP, rdec(c, REG_RSP) + (PUSHSZ));
            c->flags = ((img & 0x001ull) ? FCF : 0)
                     | ((img & 0x004ull) ? FPF : 0)
                     | ((img & 0x010ull) ? FAF : 0)
                     | ((img & 0x040ull) ? FZF : 0)
                     | ((img & 0x080ull) ? FSF : 0)
                     | ((img & 0x400ull) ? FDF : 0)
                     | ((img & 0x800ull) ? FOF : 0);

        } else if (op == OP_SAHF) {
            u64 ah = (rdec(c, REG_RAX) >> 8) & 0xFF;
            c->flags = ((ah & 0x01) ? FCF : 0)
                     | ((ah & 0x04) ? FPF : 0)
                     | ((ah & 0x10) ? FAF : 0)
                     | ((ah & 0x40) ? FZF : 0)
                     | ((ah & 0x80) ? FSF : 0);

        } else if (op == OP_LAHF) {
            u64 f = c->flags;
            u64 ah = 2ull                       /* bit1 = 1 (x86) */
                   | ((f & FCF) ? 0x01 : 0)
                   | ((f & FPF) ? 0x04 : 0)
                   | ((f & FAF) ? 0x10 : 0)
                   | ((f & FZF) ? 0x40 : 0)
                   | ((f & FSF) ? 0x80 : 0);
            renc(c, REG_RAX, (rdec(c, REG_RAX) & ~0xFF00ULL) | (ah << 8));

        } else if (op == OP_SETFLAG) {
            ud = sf8(&s);
            if (ud == 0)      c->flags &= ~(u64)FCF;          /* CLC */
            else if (ud == 1) c->flags |= FCF;                /* STC */
            else if (ud == 2) c->flags ^= FCF;                /* CMC */
            else if (ud == 3) c->flags &= ~(u64)FDF;          /* CLD */
            else if (ud == 4) c->flags |= FDF;                /* STD */

        } else if (op == OP_MUL_R) {
            sz = sf8(&s); form = sf8(&s);
            if (form == 0) b = rget(c, sf8(&s), sz);
            else           b = mrd(mem_addr(&s, c), sz);
            a = rget(c, REG_RAX, sz);
            c->flags = 0;
            if (sz == 1) {
                /* AX = AL * r8 (x86) — rax'in ust bitleri korunur */
                u64 p = (a & 0xFF) * (b & 0xFF);
                renc(c, REG_RAX, (rdec(c, REG_RAX) & ~0xFFFFULL) | p);
                if (p & 0xFF00ULL) c->flags |= FCF | FOF;
            } else if (sz == 2) {
                u64 p = (a & 0xFFFF) * (b & 0xFFFF);
                renc(c, REG_RAX, (rdec(c, REG_RAX) & ~0xFFFFULL) | (p & 0xFFFF));
                renc(c, REG_RDX, (rdec(c, REG_RDX) & ~0xFFFFULL) | (p >> 16));
                if (p >> 16) c->flags |= FCF | FOF;
            } else if (sz == 4) {
                u64 p = (a & 0xFFFFFFFFULL) * (b & 0xFFFFFFFFULL);
                renc(c, REG_RAX, p & 0xFFFFFFFFULL);
                renc(c, REG_RDX, p >> 32);
                if (p >> 32) c->flags |= FCF | FOF;
            } else {
                u64 lo, hi;
                mulu64(a, b, &lo, &hi);
                renc(c, REG_RAX, lo);
                renc(c, REG_RDX, hi);
                if (hi) c->flags |= FCF | FOF;
            }

        } else if (op == OP_DIV_R) {
            sz = sf8(&s); form = sf8(&s);
            if (form == 0) b = rget(c, sf8(&s), sz);
            else           b = mrd(mem_addr(&s, c), sz);
            /* flags: DIV sonrasi TUM bayraklar tanimsiz (x86) — dokunma */
            if (sz == 1) {
                u32 n = (u32)(rdec(c, REG_RAX) & 0xFFFF);
                u32 d = (u32)(b & 0xFF);
                u32 q = d ? (n / d) : 0, rm = d ? (n % d) : 0;
                if (q > 0xFF) { q = 0; rm = 0; }          /* #DE -> guvenli sifir */
                renc(c, REG_RAX, (rdec(c, REG_RAX) & ~0xFFFFULL)
                                 | (u64)((q & 0xFF) | ((rm & 0xFF) << 8)));
            } else if (sz == 2) {
                u32 n = ((u32)(rdec(c, REG_RDX) & 0xFFFF) << 16)
                      |  (u32)(rdec(c, REG_RAX) & 0xFFFF);
                u32 d = (u32)(b & 0xFFFF);
                u32 q = d ? (n / d) : 0, rm = d ? (n % d) : 0;
                if (q > 0xFFFF) { q = 0; rm = 0; }
                renc(c, REG_RAX, (rdec(c, REG_RAX) & ~0xFFFFULL) | (u64)(q & 0xFFFF));
                renc(c, REG_RDX, (rdec(c, REG_RDX) & ~0xFFFFULL) | (u64)(rm & 0xFFFF));
            } else if (sz == 4) {
                u64 n = ((rdec(c, REG_RDX) & 0xFFFFFFFFULL) << 32)
                      |  (rdec(c, REG_RAX) & 0xFFFFFFFFULL);
                u32 d = (u32)(b & 0xFFFFFFFFULL);
                if (d == 0) { renc(c, 0, 0); renc(c, REG_RDX, 0); }
                else {
                    u32 rm;
                    u64 q = div64_32(n, d, &rm);   /* i386: __udivmoddi4 YASAK */
                    if (q > 0xFFFFFFFFULL) { q = 0; }     /* #DE -> guvenli sifir */
                    renc(c, REG_RAX, q & 0xFFFFFFFFULL);
                    renc(c, REG_RDX, (u64)rm);
                }
            } else {
                u64 q, r;
                if (b == 0) { renc(c, 0, 0); renc(c, REG_RDX, 0); }
                else {
                    div128_64(rdec(c, REG_RDX), rdec(c, 0), b, &q, &r);
                    if (q >> 32) { q = 0; r = 0; }        /* #DE */
                    renc(c, REG_RAX, q);
                    renc(c, REG_RDX, r);
                }
            }

        } else if (op == OP_BT_X) {
            ud = sf8(&s); sz = sf8(&s); form = sf8(&s);
            r1 = -1; addr = 0;
            if (form == 0) { r1 = sf8(&s); a = rget(c, r1, sz); }
            else           { addr = mem_addr(&s, c); a = mrd(addr, sz); }
            int sf2 = sf8(&s);
            u64 bit;
            if (sf2 == 0) bit = rget(c, sf8(&s), sz);
            else          bit = (u64)(u8)sf8(&s);
            bit &= (u64)(sz * 8 - 1);
            u64 val = (a >> bit) & 1;
            c->flags = (c->flags & ~(u64)FCF) | (val ? FCF : 0);
            if (ud == 1)      a |= (u64)1 << bit;         /* BTS */
            else if (ud == 2) a &= ~((u64)1 << bit);      /* BTR */
            else if (ud == 3) a ^= (u64)1 << bit;         /* BTC */
            if (ud) {
                if (form == 0) rset(c, r1, sz, a);
                else           mwr(addr, sz, a);
            }

        } else if (op == OP_SHLD) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            int nm = sf8(&s);
            int n = (nm == 1) ? (int)(rdec(c, REG_RCX) & (sz == 8 ? 63 : 31))
                              : (int)(u8)sf8(&s);
            n &= (sz == 8) ? 63 : 31;
            if (n > sz * 8) n = sz * 8;   /* 16-bit formda sayac > genislik */
            if (n) {
                int sbits = sz * 8;
                u64 d = rget(c, r1, sz), srcv = rget(c, r2, sz);
                u64 fl = 0;
                if (n <= sbits) { if ((d >> (sbits - n)) & 1) fl |= FCF; }
                r = ((d << n) | (((srcv << (64 - sbits)) >> (64 - sbits)) >> (sbits - n))) & szmask(sz);
                if (n == 1) { if ((((r >> (sbits-1)) & 1) ^ ((fl & FCF) ? 1u : 0u))) fl |= FOF; }
                if (r == 0) fl |= FZF;
                if ((r >> (sbits-1)) & 1) fl |= FSF;
                if (parity8(r)) fl |= FPF;
                c->flags = fl;
                rset(c, r1, sz, r);
            }

        } else if (op == OP_SHRD) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            int nm = sf8(&s);
            int n = (nm == 1) ? (int)(rdec(c, REG_RCX) & (sz == 8 ? 63 : 31))
                              : (int)(u8)sf8(&s);
            n &= (sz == 8) ? 63 : 31;
            if (n > sz * 8) n = sz * 8;
            if (n) {
                int sbits = sz * 8;
                u64 d = rget(c, r1, sz), srcv = rget(c, r2, sz);
                u64 fl = 0;
                if (n <= sbits) { if ((d >> (n - 1)) & 1) fl |= FCF; }
                r = ((d >> n) | (((srcv << (64 - sbits)) >> (64 - sbits)) << (sbits - n))) & szmask(sz);
                if (n == 1) { if (((d >> (sbits-1)) & 1)) fl |= FOF; }
                if (r == 0) fl |= FZF;
                if ((r >> (sbits-1)) & 1) fl |= FSF;
                if (parity8(r)) fl |= FPF;
                c->flags = fl;
                rset(c, r1, sz, r);
            }

        } else if (op == OP_LOOP) {
            cc = sf8(&s); sext32(&sv, sf32(&s));
            renc(c, REG_RCX, (rdec(c, REG_RCX) - 1) & szmask(PUSHSZ));  /* x86: ecx */
            int nz = (rdec(c, REG_RCX) != 0);
            int take = (cc == 0) ? nz : (cc == 1) ? (nz && ((c->flags & FZF) != 0))
                                                  : (nz && ((c->flags & FZF) == 0));
            if (take) s.ic = s.ic + (u64)sv;

        } else if (op == OP_JECXZ) {
            sext32(&sv, sf32(&s));
            if ((rdec(c, REG_RCX) & szmask(PUSHSZ)) == 0) s.ic = s.ic + (u64)sv;

        } else if (op == OP_XADD) {
            sz = sf8(&s); form = sf8(&s);
            if (form == 0) {
                r1 = sf8(&s); r2 = sf8(&s);
                a = rget(c, r1, sz); b = rget(c, r2, sz);
                r = do_alu(ALU_ADD, a, b, sz, &fl);
                c->flags = fl;
                rset(c, r1, sz, r);
                rset(c, r2, sz, a);
            } else {
                addr = mem_addr(&s, c);
                r2 = sf8(&s);
                a = mrd(addr, sz); b = rget(c, r2, sz);
                r = do_alu(ALU_ADD, a, b, sz, &fl);
                c->flags = fl;
                mwr(addr, sz, r);
                rset(c, r2, sz, a);
            }

        } else if (op == OP_STR) {
            ud = sf8(&s); sz = sf8(&s); int rp = sf8(&s);
            /* ud: 0=movs 1=stos 2=lods 3=scas 4=cmps | rp: 0=yok 1=repe 2=repne
               DF yonu; scas/cmps'ta ZF kosulu. Tamper-a'S tuzagi: ic dongu
               butcesi 1<<20 yineleme (meşru string op'larinin cok uzerinde). */
            {
                int dir = (c->flags & FDF) ? -1 : 1;
                u64 step = (u64)(dir * sz);
                u64 cmask = szmask(PUSHSZ == 8 ? 8 : 4);   /* x64: rcx, x86: ecx */
                u64 cap = (rp ? ((u64)1 << 20) : 1);
                u64 k;
                for (k = 0; k < cap; k++) {
                    if (rp && (rdec(c, REG_RCX) & cmask) == 0) break;
                    if (ud == 0) {            /* movs */
                        mwr(rdec(c, REG_RDI), sz, mrd(rdec(c, REG_RSI), sz));
                        renc(c, REG_RSI, rdec(c, REG_RSI) + (step)); renc(c, REG_RDI, rdec(c, REG_RDI) + (step));
                    } else if (ud == 1) {     /* stos */
                        mwr(rdec(c, REG_RDI), sz, rget(c, REG_RAX, sz));
                        renc(c, REG_RDI, rdec(c, REG_RDI) + (step));
                    } else if (ud == 2) {     /* lods */
                        rset(c, REG_RAX, sz, mrd(rdec(c, REG_RSI), sz));
                        renc(c, REG_RSI, rdec(c, REG_RSI) + (step));
                    } else if (ud == 3) {     /* scas: cmp rax, [rdi] */
                        r = do_alu(ALU_CMP, rget(c, REG_RAX, sz), mrd(rdec(c, REG_RDI), sz), sz, &fl);
                        c->flags = fl;
                        renc(c, REG_RDI, rdec(c, REG_RDI) + (step));
                    } else {                  /* cmps: cmp [rsi], [rdi] */
                        r = do_alu(ALU_CMP, mrd(rdec(c, REG_RSI), sz), mrd(rdec(c, REG_RDI), sz), sz, &fl);
                        c->flags = fl;
                        renc(c, REG_RSI, rdec(c, REG_RSI) + (step)); renc(c, REG_RDI, rdec(c, REG_RDI) + (step));
                    }
                    if (rp) renc(c, REG_RCX, (rdec(c, REG_RCX) - 1) & cmask);
                    if (rp && (ud == 3 || ud == 4)) {
                        if (rp == 1 && !(c->flags & FZF)) break;   /* repe */
                        if (rp == 2 &&  (c->flags & FZF)) break;   /* repne */
                    }
                }
            }

        } else if (op == OP_IMUL_RM) {
            sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            a = (u64)(i64)rget(c, r1, sz);
            b = mrd(addr, sz);
            if (sz == 4) {
                a = (u64)(i64)(int)(a & 0xFFFFFFFF);
                b = (u64)(i64)(int)(b & 0xFFFFFFFF);
            }
            r = (u64)((i64)a * (i64)b);
            {
                i64 pr = (i64)a * (i64)b;
                i64 tr = (sz == 8) ? pr : (i64)(int)(u32)((u64)pr & 0xFFFFFFFFULL);
                c->flags = (pr != tr) ? (FCF | FOF) : 0;
            }
            rset(c, r1, sz, r);

} else if (op == OP_STRDEC) {
            u32 strva = sf32(&s), stva = sf32(&s), k = sf32(&s), len = sf32(&s);
            u8* st = (u8*)u2p(c->base + (u64)stva);
            /* 0.8.0 sertlik: CFB tamper len'i 4G'ye cevirebilir -> handler
               ici 4G yineleme (bütce tek komutu sayar, ici döngüyü saymaz).
               Meşru strenc dizgesi bolge buyuklugu sinifinda (<1MB). */
            if (len > 0x100000u) len = 0;
            if (*st == 0) {
                u8* p = (u8*)u2p(c->base + (u64)strva);
                u32 i2;
                for (i2 = 0; i2 < len; i2++) p[i2] ^= (u8)(k + i2 * 31);
                *st = 1;
            }

        /* ---- 1.1.0-A4-FPU: UniversalObfuscator FPU paritesi ----
           UO intel.cc beyaz-listesinde VM icinde yurutulen FPU kumesi
           birebir + UST-KUME (UO'nun ltNative-ada biraktigi bellek-formlari
           dahil tam sanallastirma). x87 yigini GERCEK birimde kalir; VM'nin
           C kodu hicbir x87 kayit silmez (freestanding, float kod yok).
           AT&T->Intel esleme kaniti: scripts/a4_fpu_mnem_test.c (objdump). */

        } else if (op == OP_FPU_ST) {
            ud = sf8(&s); idx = sf8(&s);
            /* 8-yonlu reg-form makrolari (idx 0..7; gas st(i) derleme-zamani
               sabiti ister -> switch-makro; -fno-jump-tables ile karsilastirma
               zinciri, freestanding kurallara uygun). */
#define FP8_A(m) do { switch (idx) { \
    case 0: __asm__ volatile(m " %st(0), %st(0)"); break; \
    case 1: __asm__ volatile(m " %st(1), %st(0)"); break; \
    case 2: __asm__ volatile(m " %st(2), %st(0)"); break; \
    case 3: __asm__ volatile(m " %st(3), %st(0)"); break; \
    case 4: __asm__ volatile(m " %st(4), %st(0)"); break; \
    case 5: __asm__ volatile(m " %st(5), %st(0)"); break; \
    case 6: __asm__ volatile(m " %st(6), %st(0)"); break; \
    default: __asm__ volatile(m " %st(7), %st(0)"); break; \
} } while (0)
#define FP8_B(m) do { switch (idx) { \
    case 0: __asm__ volatile(m " %st(0), %st(0)"); break; \
    case 1: __asm__ volatile(m " %st(0), %st(1)"); break; \
    case 2: __asm__ volatile(m " %st(0), %st(2)"); break; \
    case 3: __asm__ volatile(m " %st(0), %st(3)"); break; \
    case 4: __asm__ volatile(m " %st(0), %st(4)"); break; \
    case 5: __asm__ volatile(m " %st(0), %st(5)"); break; \
    case 6: __asm__ volatile(m " %st(0), %st(6)"); break; \
    default: __asm__ volatile(m " %st(0), %st(7)"); break; \
} } while (0)
#define FP8_S(m) do { switch (idx) { \
    case 0: __asm__ volatile(m " %st(0)"); break; \
    case 1: __asm__ volatile(m " %st(1)"); break; \
    case 2: __asm__ volatile(m " %st(2)"); break; \
    case 3: __asm__ volatile(m " %st(3)"); break; \
    case 4: __asm__ volatile(m " %st(4)"); break; \
    case 5: __asm__ volatile(m " %st(5)"); break; \
    case 6: __asm__ volatile(m " %st(6)"); break; \
    default: __asm__ volatile(m " %st(7)"); break; \
} } while (0)
            /* ---- EFLAGS-KRITIK AILELER: TEK asm blogu ----
               FCOMI gercek EFLAGS yazar, FCMOV gercek EFLAGS okur;
               bayrak-kurulum ile talimat ARASINA gcc kodu (switch dispatch
               cmp/jcc) giremez — ayri asm ifadeleri arada bozar (T5-B kanit).
               VM flags ic-bit: FCF=1 FZF=2 FSF=4 FPF=16;
               gercek EFLAGS: CF=bit0 PF=bit2 ZF=bit6 (0x45 maskesi). */
            if ((ud >= FPU_FCOMI && ud <= FPU_FUCOMIP) ||
                (ud >= FPU_FCMOVB && ud <= FPU_FCMOVNU)) {
#if defined(VM_IS_X64)
                if (ud >= FPU_FCOMI && ud <= FPU_FUCOMIP) {
                    u64 f;
#define FP8_FC(m) do { switch (idx) { \
    case 0: __asm__ volatile(m " %%st(0)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 1: __asm__ volatile(m " %%st(1)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 2: __asm__ volatile(m " %%st(2)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 3: __asm__ volatile(m " %%st(3)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 4: __asm__ volatile(m " %%st(4)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 5: __asm__ volatile(m " %%st(5)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    case 6: __asm__ volatile(m " %%st(6)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
    default: __asm__ volatile(m " %%st(7)\n\tpushfq\n\tpopq %0" : "=r"(f) :: "cc","memory"); break; \
} } while (0)
                    if (ud == FPU_FCOMI)       { FP8_FC("fcomi"); }
                    else if (ud == FPU_FCOMIP) { FP8_FC("fcomip"); }
                    else if (ud == FPU_FUCOMI) { FP8_FC("fucomi"); }
                    else                       { FP8_FC("fucomip"); }
#undef FP8_FC
                    if (f & 0x001ULL) c->flags |= FCF;
                    if (f & 0x004ULL) c->flags |= FPF;
                    if (f & 0x040ULL) c->flags |= FZF;
                } else {
                    u64 fb = 0;
                    if (c->flags & FCF) fb |= 0x001ULL;
                    if (c->flags & FPF) fb |= 0x004ULL;
                    if (c->flags & FZF) fb |= 0x040ULL;
#define FP8_FCM(m) do { switch (idx) { \
    case 0: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(0), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 1: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(1), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 2: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(2), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 3: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(3), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 4: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(4), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 5: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(5), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    case 6: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(6), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
    default: __asm__ volatile("pushfq\n\tpopq %%rcx\n\tandq $-0x46,%%rcx\n\torq %1,%%rcx\n\tpushq %%rcx\n\tpopfq\n\t" m " %%st(7), %%st(0)" :: "r"(0), "r"(fb) : "rcx","cc","memory"); break; \
} } while (0)
                    if (ud == FPU_FCMOVB)       { FP8_FCM("fcmovb"); }
                    else if (ud == FPU_FCMOVE)   { FP8_FCM("fcmove"); }
                    else if (ud == FPU_FCMOVBE)  { FP8_FCM("fcmovbe"); }
                    else if (ud == FPU_FCMOVU)   { FP8_FCM("fcmovu"); }
                    else if (ud == FPU_FCMOVNB)  { FP8_FCM("fcmovnb"); }
                    else if (ud == FPU_FCMOVNE)  { FP8_FCM("fcmovne"); }
                    else if (ud == FPU_FCMOVNBE) { FP8_FCM("fcmovnbe"); }
                    else                         { FP8_FCM("fcmovnu"); }
#undef FP8_FCM
                }
#else
                if (ud >= FPU_FCOMI && ud <= FPU_FUCOMIP) {
                    u32 f;
#define FP8_FC(m) do { switch (idx) { \
    case 0: __asm__ volatile(m " %%st(0)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 1: __asm__ volatile(m " %%st(1)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 2: __asm__ volatile(m " %%st(2)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 3: __asm__ volatile(m " %%st(3)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 4: __asm__ volatile(m " %%st(4)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 5: __asm__ volatile(m " %%st(5)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    case 6: __asm__ volatile(m " %%st(6)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
    default: __asm__ volatile(m " %%st(7)\n\tpushfl\n\tpopl %0" : "=r"(f) :: "cc","memory"); break; \
} } while (0)
                    if (ud == FPU_FCOMI)       { FP8_FC("fcomi"); }
                    else if (ud == FPU_FCOMIP) { FP8_FC("fcomip"); }
                    else if (ud == FPU_FUCOMI) { FP8_FC("fucomi"); }
                    else                       { FP8_FC("fucomip"); }
#undef FP8_FC
                    if (f & 0x001u) c->flags |= FCF;
                    if (f & 0x004u) c->flags |= FPF;
                    if (f & 0x040u) c->flags |= FZF;
                } else {
                    u32 fb = 0;
                    if (c->flags & FCF) fb |= 0x001u;
                    if (c->flags & FPF) fb |= 0x004u;
                    if (c->flags & FZF) fb |= 0x040u;
#define FP8_FCM(m) do { switch (idx) { \
    case 0: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(0), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 1: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(1), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 2: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(2), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 3: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(3), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 4: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(4), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 5: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(5), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    case 6: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(6), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
    default: __asm__ volatile("pushfl\n\tpopl %%ecx\n\tandl $-0x46,%%ecx\n\torl %1,%%ecx\n\tpushl %%ecx\n\tpopfl\n\t" m " %%st(7), %%st(0)" :: "r"(0), "r"(fb) : "ecx","cc","memory"); break; \
} } while (0)
                    if (ud == FPU_FCMOVB)       { FP8_FCM("fcmovb"); }
                    else if (ud == FPU_FCMOVE)   { FP8_FCM("fcmove"); }
                    else if (ud == FPU_FCMOVBE)  { FP8_FCM("fcmovbe"); }
                    else if (ud == FPU_FCMOVU)   { FP8_FCM("fcmovu"); }
                    else if (ud == FPU_FCMOVNB)  { FP8_FCM("fcmovnb"); }
                    else if (ud == FPU_FCMOVNE)  { FP8_FCM("fcmovne"); }
                    else if (ud == FPU_FCMOVNBE) { FP8_FCM("fcmovnbe"); }
                    else                         { FP8_FCM("fcmovnu"); }
#undef FP8_FCM
                }
#endif
            } else
            switch (ud) {
            /* --- implicit (operand yok) --- */
            case FPU_FSQRT:   __asm__ volatile("fsqrt"); break;
            case FPU_FCHS:    __asm__ volatile("fchs"); break;
            case FPU_FABS:    __asm__ volatile("fabs"); break;
            case FPU_FSIN:    __asm__ volatile("fsin"); break;
            case FPU_FCOS:    __asm__ volatile("fcos"); break;
            case FPU_FSINCOS: __asm__ volatile("fsincos"); break;
            case FPU_FPTAN:   __asm__ volatile("fptan"); break;
            case FPU_FPATAN:  __asm__ volatile("fpatan"); break;
            case FPU_FYL2X:   __asm__ volatile("fyl2x"); break;
            case FPU_FYL2XP1: __asm__ volatile("fyl2xp1"); break;
            case FPU_F2XM1:   __asm__ volatile("f2xm1"); break;
            case FPU_FPREM:   __asm__ volatile("fprem"); break;
            case FPU_FPREM1:  __asm__ volatile("fprem1"); break;
            case FPU_FRNDINT: __asm__ volatile("frndint"); break;
            case FPU_FSCALE:  __asm__ volatile("fscale"); break;
            case FPU_FXTRACT: __asm__ volatile("fxtract"); break;
            case FPU_FTST:    __asm__ volatile("ftst"); break;
            case FPU_FXAM:    __asm__ volatile("fxam"); break;
            case FPU_FDECSTP: __asm__ volatile("fdecstp"); break;
            case FPU_FINCSTP: __asm__ volatile("fincstp"); break;
            case FPU_FINIT:   __asm__ volatile("finit"); break;   /* 9b db e3 */
            case FPU_FCLEX:   __asm__ volatile("fclex"); break;   /* 9b db e2 */
            case FPU_FNOP:    __asm__ volatile("fnop"); break;
            case FPU_FWAIT:   __asm__ volatile("fwait"); break;
            case FPU_FLD1:    __asm__ volatile("fld1"); break;
            case FPU_FLDZ:    __asm__ volatile("fldz"); break;
            case FPU_FLDPI:   __asm__ volatile("fldpi"); break;
            case FPU_FLDL2T:  __asm__ volatile("fldl2t"); break;
            case FPU_FLDL2E:  __asm__ volatile("fldl2e"); break;
            case FPU_FLDLG2:  __asm__ volatile("fldlg2"); break;
            case FPU_FLDLN2:  __asm__ volatile("fldln2"); break;
            case FPU_FCOMPP:  __asm__ volatile("fcompp"); break;  /* de d9 */
            case FPU_FUCOMPP: __asm__ volatile("fucompp"); break; /* da e9 */
            /* --- reg-form: Intel manasi yorumda; AT&T esleme makroda ---
               FP8_A: AT&T "m %st(i), %st(0)"  -> Intel m ST(0), ST(i)
               FP8_B: AT&T "m %st(0), %st(i)"  -> Intel m ST(i), ST(0)
                 (fsub/fsubr/fdiv/fdivr AT&T'de zaten ters -> Intel
                  SUB ST(i),ST(0) = AT&T fsubr; Intel SUBR = AT&T fsub)
               FP8_S: tek-operand st(i) */
            case FPU_FLD_ST:    FP8_S("fld"); break;
            case FPU_FXCH:      FP8_S("fxch"); break;
            case FPU_FADD_STI:  FP8_B("fadd"); break;   /* DC C0+i */
            case FPU_FMUL_STI:  FP8_B("fmul"); break;   /* DC C8+i */
            case FPU_FSUB_STI:  FP8_B("fsubr"); break;  /* DC E8+i: STi-=ST0 */
            case FPU_FSUBR_STI: FP8_B("fsub"); break;   /* DC E0+i: STi=ST0-STi */
            case FPU_FDIV_STI:  FP8_B("fdivr"); break;  /* DC F8+i: STi/=ST0 */
            case FPU_FDIVR_STI: FP8_B("fdiv"); break;   /* DC F0+i: STi=ST0/STi */
            case FPU_FADD_ST0:  FP8_A("fadd"); break;   /* D8 C0+i */
            case FPU_FMUL_ST0:  FP8_A("fmul"); break;   /* D8 C8+i */
            case FPU_FSUB_ST0:  FP8_A("fsub"); break;   /* D8 E0+i: ST0-=STi */
            case FPU_FSUBR_ST0: FP8_A("fsubr"); break;  /* D8 E8+i: ST0=STi-ST0 */
            case FPU_FDIV_ST0:  FP8_A("fdiv"); break;   /* D8 F0+i: ST0/=STi */
            case FPU_FDIVR_ST0: FP8_A("fdivr"); break;  /* D8 F8+i: ST0=STi/ST0 */
            case FPU_FCOM_STI:  FP8_S("fcom"); break;   /* D8 D0+i */
            case FPU_FCOMP_STI: FP8_S("fcomp"); break;  /* D8 D8+i */
            case FPU_FUCOM_STI: FP8_S("fucom"); break;  /* DD E0+i */
            case FPU_FUCOMP_STI: FP8_S("fucomp"); break;/* DD E8+i */
            case FPU_FST_STI:   FP8_S("fst"); break;    /* DD D0+i */
            case FPU_FSTP_STI:  FP8_S("fstp"); break;   /* DD D8+i */
            case FPU_FFREE:     FP8_S("ffree"); break;  /* DD C0+i */
            case FPU_FFREEP:    FP8_S("ffreep"); break; /* DF C0+i */
            case FPU_FADDP:     FP8_B("faddp"); break;  /* DE C0+i */
            case FPU_FMULP:     FP8_B("fmulp"); break;  /* DE C8+i */
            case FPU_FSUBP:     FP8_B("fsubrp"); break; /* DE E8+i (ters) */
            case FPU_FSUBRP:    FP8_B("fsubp"); break;  /* DE E0+i (ters) */
            case FPU_FDIVP:     FP8_B("fdivp"); break;  /* DE F8+i (ters) */
            case FPU_FDIVRP:    FP8_B("fdivrp"); break; /* DE F0+i (ters) */
            case FPU_FSTSW_AX: {
                /* FSTSW AX (9b df e0) = fwait + fnstsw; AX = VM regs[0].low16 */
                u16 sw;
                __asm__ volatile("fwait");
                __asm__ volatile("fnstsw %0" : "=m"(sw));
                rset(c, 0, 2, sw);
                break;
            }
            default: break; /* bilinmeyen subop -> etki yok (duru akis) */
            }
#undef FP8_A
#undef FP8_B
#undef FP8_S

        } else if (op == OP_FPU_MEM) {
            /* adres-formu: mem_addr ile cozulen GERCEK adrese gercek x87
               talimati (x86'da "r" 32-bit reg; x64'te 64-bit — u2p ayni). */
            ud = sf8(&s);
            addr = mem_addr(&s, c);
            {
                void* A = u2p(addr);
                switch (ud) {
                case FPU_M_FLD32:  __asm__ volatile("flds (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FLD64:  __asm__ volatile("fldl (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FLD80:  __asm__ volatile("fldt (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FST32:  __asm__ volatile("fsts (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FST64:  __asm__ volatile("fstl (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FSTP32: __asm__ volatile("fstps (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSTP64: __asm__ volatile("fstpl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSTP80: __asm__ volatile("fstpt (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FILD16: __asm__ volatile("filds (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FILD32: __asm__ volatile("fildl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FILD64: __asm__ volatile("fildll (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIST16: __asm__ volatile("fists (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIST32: __asm__ volatile("fistl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTP16: __asm__ volatile("fistps (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTP32: __asm__ volatile("fistpl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTP64: __asm__ volatile("fistpq (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTTP16: __asm__ volatile("fisttps (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTTP32: __asm__ volatile("fisttpl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISTTP64: __asm__ volatile("fisttpq (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FADD32: __asm__ volatile("fadds (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FADD64: __asm__ volatile("faddl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSUB32: __asm__ volatile("fsubs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSUB64: __asm__ volatile("fsubl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSUBR32: __asm__ volatile("fsubrs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSUBR64: __asm__ volatile("fsubrl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FMUL32: __asm__ volatile("fmuls (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FMUL64: __asm__ volatile("fmull (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FDIV32: __asm__ volatile("fdivs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FDIV64: __asm__ volatile("fdivl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FDIVR32: __asm__ volatile("fdivrs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FDIVR64: __asm__ volatile("fdivrl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FCOM32: __asm__ volatile("fcoms (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FCOM64: __asm__ volatile("fcoml (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FCOMP32: __asm__ volatile("fcomps (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FCOMP64: __asm__ volatile("fcompl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIADD16: __asm__ volatile("fiadds (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIADD32: __asm__ volatile("fiaddl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIMUL16: __asm__ volatile("fimuls (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIMUL32: __asm__ volatile("fimull (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FICOM16: __asm__ volatile("ficoms (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FICOM32: __asm__ volatile("ficoml (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FICOMP16: __asm__ volatile("ficomps (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FICOMP32: __asm__ volatile("ficompl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISUB16: __asm__ volatile("fisubs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISUB32: __asm__ volatile("fisubl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISUBR16: __asm__ volatile("fisubrs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FISUBR32: __asm__ volatile("fisubrl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIDIV16: __asm__ volatile("fidivs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIDIV32: __asm__ volatile("fidivl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIDIVR16: __asm__ volatile("fidivrs (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FIDIVR32: __asm__ volatile("fidivrl (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FSTSW: {
                    /* FSTSW m16 (9b dd /7 es-anlam): fwait + fnstsw */
                    u16 v;
                    __asm__ volatile("fwait");
                    __asm__ volatile("fnstsw %0" : "=m"(v));
                    mwr(addr, 2, v);
                    break;
                }
                case FPU_M_FSTCW: {
                    u16 v;
                    __asm__ volatile("fwait");
                    __asm__ volatile("fnstcw %0" : "=m"(v));
                    mwr(addr, 2, v);
                    break;
                }
                case FPU_M_FLDCW: __asm__ volatile("fldcw (%0)" :: "r"(A) : "memory"); break;
                case FPU_M_FBLD:  __asm__ volatile("fbld (%0)"  :: "r"(A) : "memory"); break;
                case FPU_M_FBSTP: __asm__ volatile("fbstp (%0)" :: "r"(A) : "memory"); break;
                default: break;
                }
            }

        } else if (op == OP_CHKRET) {
            /* 1.2.0-A8: UO AddCheckBreakpointSection (intel.cc:9305-9364) 1:1
               — DONUS ADRESI baytlari kontrolu. ctx->init_rsp = stub'un
               yazdigi donus-adresi slotu (x64: push_area+0x78 = 15*8,
               x86: push_area+0x20 = 8*4). Donus sitesinde 0xCC (kisa int3),
               CD 03 (uzun int3) veya 0F 0B (ud2) varsa debugger kirici
               koymustur -> zehir. Lifter, antidebug acikken her gercek
               ret (XP_RET/XP_RETI16) onune bu op'u yazar; UO ret-section
               enjeksiyonunun birebir karsiligi. */
            u64 ra = mrd(c->init_rsp, PUSHSZ);
            u8 b0 = (u8)mrd(ra, 1), b1 = (u8)mrd(ra + 1, 1);
            if (b0 == 0xCC || (b0 == 0xCD && b1 == 0x03)
                || (b0 == 0x0F && b1 == 0x0B)) vm_poison(c);

        } else {
            c->done = 1;   // bilinmeyen opcode -> guvenli dur
        }
    }
    }
    }

void vm_entry(VMContext* c) {
    int k;
    int map[NMAP];
#if defined(VM_IS_X64)
    /* 0.5.0 KOK-NEEN Duzeltmesi: eski {0,1,2,3,5,...} tablosunu GCC 14
    .rodata+memcpy'ye ceviriyordu -> blob PIC olmaktan cikiyordu (korunmis
    exe'de 0x103000 mutlak okuma = SIGSEGV). Tablo ARITMETIK yazilir:
    reg 4 (RSP) push edilmez -> atlanir. */
    for (k = 0; k < 15; k++) map[k] = (k < 4) ? k : (k + 1);
#else
    /* x86 pushad sirasi: EAX once push edilir -> EN YUKSEK adreste; EDI enson
       -> EN ALCAK adreste. push_area[k] ARTAN okundugu icin siralama ters:
       [0]=EDI(7), [1]=ESI(6), [2]=EBP(5), [3]=ESP_orig(atla), [4]=EBX(3),
       [5]=EDX(2), [6]=ECX(1), [7]=EAX(0). Eski map {0,1,2,3,..} reg'leri
       tamamen karistiriyordu (dir=copuk deger -> yanlis hareket). */
    for (k = 0; k < 8; k++) map[k] = (k == 3) ? (int)0xFFFFFFFFu : (7 - k);
#endif
#if defined(VM_IS_X64)
    u64* src = (u64*)u2p(c->push_area);          /* x64: 8B slot (push'lar) */
    #define SRC_LOAD(k)  src[k]
    #define SRC_STORE(k, v) (src[k] = (v))
#else
    u32* src = (u32*)u2p(c->push_area);          /* x86 pushad: 4B slot! */
    #define SRC_LOAD(k)  (u64)src[k]
    #define SRC_STORE(k, v) (src[k] = (u32)(v))
#endif

    /* 0.8.0 crypt_key: stub key^K2 tasiydi — gercek rolling anahtari geri
       coz. K2 = (bc_rva, bc_len) fonksiyonu (engine_stub ile ayni makro).
       1.2.0-A9 DUZEN: anahtar finalizasyonu regs yukleme ONCE yapilir —
       Encrypt Registers per-slot maskeleri FINAL anahtardan turetilir
       (yukleme/yazma ayni maskelerle eslesir). */
    {
        u32 bc_rva = (u32)(((const u8*)u2p(c->bc)) - (const u8*)u2p(c->base));
        c->key ^= VM_KEYXOR(bc_rva, c->bc_len);
        /* 1.2.0-B1 mult-VM: vm_id (scratch[7], stub yazar) anahtar-alani
           ayristirir — her VM instanci kendi bytecode anahtar uzayinda. */
        c->key ^= VM_VMK((u32)c->scratch[7]);
        c->regs_epoch = 0;   /* A20: deterministik baslangic (determinizm testleri) */
    }

    for (k = 0; k < NMAP; k++) {
        if (map[k] != (int)0xFFFFFFFFu) renc(c, map[k], SRC_LOAD(k));
    }
    renc(c, 4, c->init_rsp);
    c->flags = 0;
    c->done = 0;

    /* 0.9.0-DeepVM: TEB tabani yakala (scratch[4] — debug slotlari 0..2
       her adim ezilir, scratch[3] = perm tohumi (stub) — 4 serbest).
       x86: FS=TEB (fs:[0x18] self-ptr) | x64: GS=TEB (gs:[0x30] self-ptr).
       mem_addr MEMF_SEG bu tabani kullanir: x86 FS->TEB, x64 GS->TEB. */
#if defined(VM_IS_X64)
    { u64 teb; __asm__ volatile("movq %%gs:0x30, %0" : "=r"(teb)); c->scratch[4] = teb; }
#else
    { u32 teb; __asm__ volatile("movl %%fs:0x18, %0" : "=r"(teb)); c->scratch[4] = (u64)teb; }
#endif

    vm_run(c);

    if (c->done == 2) {
        renc(c, 0, 0xDEADBEEFDEADBEEFULL);   // debugger -> zehirli donus
        c->done = 1;
    }
    if (c->done == 3) {
        /* 1.2.2-A9FIX (JMPEXT x vmregs): stub'in .natgt blogu guest rsp'yi
           ctx'den HAM okur; A9 ile regs[REG_RSP] SIFRELI oldugundan eski
           okuma (x64 ctx+0x40 / x86 ctx+0x30) cop alirdi -> kuyruk-jmp
           bozuk stack'le abort (sdk_b1 rc=3 kaniti). RAW rsp artik burada
           init_rsp'ye (+0xB0, her iki mimaride ayni offset) yazilir; stub
           [ctx+0xB0] okur. init_rsp vm_run SONRASI hicbir yerde okunmaz. */
        c->init_rsp = rdec(c, REG_RSP);
    }
    for (k = 0; k < NMAP; k++) {
        if (map[k] != (int)0xFFFFFFFFu) SRC_STORE(k, rdec(c, map[k]));
    }
    (void)c->extra_pop;
}
