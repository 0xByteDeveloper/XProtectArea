// ============================================================
// xrt_core.c — XProtect Runtime (0.5.0)
// Korunmus PE'ye gomulen yerel koruma katmani:
//   - PEB gezintisi ile kernel32/user32 tabani bulma (IAT bagimsiz)
//   - Ihracat tablosu isim-hash cozumlemesi (FNV-1a)
//   - Self-CRC (motor kodu), .text CRC (reloc-farkindalikli),
//     dosya CRC (diskten okuyarak) butunluk kontrolleri
//   - Hata durumunda MessageBoxA + ExitProcess (runtime mesajlari)
//   - xrt_resolve: gecikmeli import cozumleyici (IAT thunk'lari icin)
// DERLEME (vm_core.c ile ayni yontem — pozisyon-bagimsiz duz ikili):
//   x64: gcc -O2 -ffreestanding -fno-stack-protector -fno-jump-tables
//        -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident
//        -DXRT_IS_X64 -c xrt_core.c
//        ld -Ttext=0x100000 -e xrt_entry xrt_core.o -o xrt64.elf
//        objcopy -O binary xrt64.elf xrt64.bin
//   x86: aynisi -DXRT_IS_X86 -m32
// KURAL: libc YOK, statik veri YOK (tum stringler yiginda kurulur),
// switch/jump-table YOK.
// Win32 API cagrilari: stdcall/Win64 ABI'yi inline asm sarmalayicilari
// ile yapariz (blob Linux gcc ile derlenir; cdecl/SysV ile Win32 API
// karisamaz).
// ============================================================
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

// ---- cfg yerlesimi (engine ile SOZLESME — engine_main.cpp'deki ayni tablo) ----
#define XCFG_MAGIC     0x31545258u   // 'XRT1'
#define XCFG_OFF_MAGIC 0x00
#define XCFG_OFF_FLAGS 0x04
#define XCFG_OFF_STATE 0x08
#define XCFG_OFF_SELFRVA 0x0C
#define XCFG_OFF_SELFLEN 0x10
#define XCFG_OFF_SELFCRC 0x14
#define XCFG_OFF_TEXTRVA 0x18
#define XCFG_OFF_TEXTSZ  0x1C
#define XCFG_OFF_TEXTCRC 0x20
#define XCFG_OFF_RELOCRVA 0x24
#define XCFG_OFF_RELOCSZ  0x28
#define XCFG_OFF_FILECRC 0x2C
#define XCFG_OFF_VMPRAW0 0x30
#define XCFG_OFF_VMPRAW1 0x34
#define XCFG_OFF_CKSUM   0x38
#define XCFG_OFF_CFGRVA  0x3C
#define XCFG_OFF_PACKRVA 0x40   // 0.6.0: XPK1 paket bilgi blok RVA (.vmp1)
#define XCFG_OFF_UNWRVA  0x44   // 0.8.0: dinamik unwind tablo RVA (.vmp0 icinde)
#define XCFG_OFF_UNWCNT  0x48   // 0.8.0: dinamik unwind kayit sayisi
// 0.8.0 SectionCryptor alanlari (xr_cipher.h ile ayni): flag 0x4C, anahtar 0x50/0x58
#define XCFG_SIZE        0x60
#include "xr_cipher.h"

#define XFLAG_SELFCRC 0x01
#define XFLAG_TEXTCRC 0x02
#define XFLAG_FILECRC 0x04
#define XFLAG_MSG     0x08
#define XFLAG_EXIT    0x10

// ---- yardimcilar ----
static u32 ld32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static u16 ld16(const u8* p) { return (u16)((u16)p[0] | ((u16)p[1] << 8)); }
static u64 ld64(const u8* p) { u64 v = 0; int i; for (i = 0; i < 8; i++) v |= ((u64)p[i]) << (8 * i); return v; }

// CRC32 (tablosuz, bitwise) — durum 0xFFFFFFFF ile baslar, sonuc ~durum.
static u32 crc_up(u32 c, u8 b) {
    int k;
    c ^= b;
    for (k = 0; k < 8; k++)
        c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    return c;
}

static u32 fnv_a(const char* s) {
    u32 h = 2166136261u;
    while (*s) { h ^= (u8)*s++; h *= 16777619u; }
    return h;
}
static u32 fnv_w(const u16* s, u32 n) {
    u32 h = 2166136261u; u32 i;
    for (i = 0; i < n; i++) {
        u16 c = s[i];
        if (c >= 'A' && c <= 'Z') c = (u16)(c + 32);
        h ^= (u32)c; h *= 16777619u;
    }
    return h;
}

// 0.5.0: API/modul isim hash'leri DERLEME SABITI (rodata tablosu YASAK —
// GCC stack-string'leri .rodata+memcpy'ye cevirip PIC'i boziyordu).
// fnv_a/fnv_lower("isim") ile birebir (motor tarafinda da ayni sabitler).
#define XH_KERNEL32      0xA3E6F6C3u   // "kernel32.dll"
#define XH_USER32        0xC0323159u   // "user32.dll"
#define XH_GETMODULEFNA  0x99FBC63Du
#define XH_CREATEFILEA   0xBDCAC9CEu
#define XH_READFILE      0x54FCC943u
#define XH_CLOSEHANDLE   0xFABA0065u
#define XH_EXITPROCESS   0x0E80FD3Au
#define XH_MESSAGEBOXA   0x23A979E4u
#define XH_LOADLIBRARYA  0x53B2070Fu
#define XH_VIRTUALALLOC  0x03285501u   // "VirtualAlloc"
#define XH_VIRTUALFREE   0x3A9ACC72u   // "VirtualFree"
#define XH_VIRTUALPROTECT 0x820621F3u  // "VirtualProtect"
#define XH_NTDLL          0xA62A3B3Bu  // "ntdll.dll" (wide, kucuk-harf)
#define XH_RTLADDFT       0x38791528u  // "RtlAddFunctionTable"

// volatile 4-karakter yazisi — GCC bunlari memcpy'ye cevireMEZ (PIC guvenli)
#define VP4(d, off, w) do { \
    volatile char* _p = (volatile char*)(d) + (off); \
    _p[0] = (char)((w) >> 24); _p[1] = (char)((w) >> 16); \
    _p[2] = (char)((w) >> 8);  _p[3] = (char)(w); \
} while (0)
#define A4(a,b,c,d) ((((u32)(a)) << 24) | (((u32)(b)) << 16) | (((u32)(c)) << 8) | ((u32)(d)))

// ---- PEB ----
// 0.5.0 DUZELTME: isaretci boyutu mimariye bagli — x86'da ld64 YANLIS
// (4 anlamlı + 4 cop bayt okuyup cop isaretciler uretiyordu -> crash).
#if defined(XRT_IS_X64)
  #define LDPTR(p) ld64(p)
#else
  #define LDPTR(p) ((u64)ld32(p))
#endif
#if defined(XRT_IS_X64)
static u64 peb_addr(void) { u64 v; __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(v)); return v; }
#define LDR_INMEM_OFF   0x20
#define ENT_INMEM_OFF   0x10
#define ENT_DLLBASE_OFF 0x30
#define ENT_NAMEBUF_OFF 0x60
#define ENT_NAMELEN_OFF 0x58
#define ENT_FULLBUF_OFF 0x50   /* 1.1.0: FullDllName.Buffer (DLL dosya yolu) */
#define ENT_FULLLEN_OFF 0x48   /*        FullDllName.Length          */
#define PEB_LDR_OFF     0x18
#else
static u32 peb_addr(void) { u32 v; __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(v)); return v; }
#define LDR_INMEM_OFF   0x14
#define ENT_INMEM_OFF   0x08
#define ENT_DLLBASE_OFF 0x18
#define ENT_NAMEBUF_OFF 0x30
#define ENT_NAMELEN_OFF 0x2C   // 0.5.0 DUZELTME: x86 BaseDllName.Length +0x2C
                               // (+0x28 = FullDllName.Buffer'di — yanlis alan)
/* 1.2.2-K9 KOK-DUZELTME (FileCRC cokmesi — metin2 ULTRA+FileCRC damage'te):
   x86 LDR_DATA_TABLE_ENTRY gercek yerlesimi:
     +0x24 FullDllName.Length (2B)  +0x26 FullDllName.MaximumLength (2B)
     +0x28 FullDllName.Buffer (4B)  +0x2C BaseDllName.Length (2B)...
   ESKI DEGER 0x2C, BaseDllName.Length+MaximumLength'i 4B LDPTR ile okuyordu:
   "metin2client_vmp.exe" icin Length=0x28, MaxLen=0x2A -> deger 0x002A0028
   = COP ISARETCI. Kullanici errorlog'u birebir: edx=0x002a0028, EIP =
   peb_path_for_base genis->ansi kopya dongusu (movzx ecx,word ptr [edx]),
   Exc 0xC0000005 @ RVA 0x55093D (.vmp0), ASLR base 0x00B90000. Dogru ofset:
   FullDllName.Buffer = +0x28. (Kanit: Unicorn A/B + wine regresyon R1-R4.) */
#define ENT_FULLBUF_OFF 0x2C
#define ENT_FULLLEN_OFF 0x24   /*        FullDllName.Length     */
#define PEB_LDR_OFF 0x0C
#endif

// ---- Win32 API cagri sarmalayicilari (tam arite) ----
// 0.5.1 KOK-DUZELTME: eski "rm"/"m" operand desenleri IKI GERCEK HATA
// tasidi: (1) GCC bellek operandi secince ofsetler asm-GIRISI rsp'ine
// gore derlenir; sablon rsp'yi kaydirinca (push/and/sub) operand YANLIS
// adresten okunur -> API'ya cop arguman gider (file-CRC'nin CreateFileA
// patlamasi tam buydu). (2) "rbx" clobber-liste disi oldugundan GCC
// operandi rbx'e atayabilirdi; "movq %%rsp,%%rbx" onu yok eder.
// YENI DESEN: argumanlar Once C tarafinda yerel diziye kopyalanir; asm
// icinde TEK kayit isaretcisi (r14/esi) uzerinden SABIT ofsetlerle
// okunur. GCC'nin rsp-goreli operandi asla asm icinde kullanilmaz.
#if defined(XRT_IS_X86)
// x86 stdcall: arglar yigina saga-sola push; CALLEE temizler (esp fix yok).
#define W1(NM) static u32 NM(u32 fn, u32 a0) { u32 ret; u32 ar_[1]; \
    ar_[0] = a0; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W2(NM) static u32 NM(u32 fn, u32 a0, u32 a1) { u32 ret; u32 ar_[2]; \
    ar_[0] = a0; ar_[1] = a1; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W3(NM) static u32 NM(u32 fn, u32 a0, u32 a1, u32 a2) { u32 ret; u32 ar_[3]; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 8(%%esi)\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W4(NM) static u32 NM(u32 fn, u32 a0, u32 a1, u32 a2, u32 a3) { u32 ret; u32 ar_[4]; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 12(%%esi)\n\tpushl 8(%%esi)\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W5(NM) static u32 NM(u32 fn, u32 a0, u32 a1, u32 a2, u32 a3, u32 a4) { u32 ret; u32 ar_[5]; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 16(%%esi)\n\tpushl 12(%%esi)\n\tpushl 8(%%esi)\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W7(NM) static u32 NM(u32 fn, u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6) { u32 ret; u32 ar_[7]; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; ar_[5] = a5; ar_[6] = a6; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 24(%%esi)\n\tpushl 20(%%esi)\n\tpushl 16(%%esi)\n\tpushl 12(%%esi)\n\tpushl 8(%%esi)\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
W1(api1)
W2(api2)
W3(api3)
W4(api4)
W5(api5)
W7(api7)
#else
// x64 Win64: rcx,rdx,r8,r9 + yigin (5.+ arg: 0x20'den itibaren) + golge alani.
// rbp cerceve cipasi; r14=argiman-dizi, r15=hedef fn (kayit-degiskeni PIN:
// GCC baska bir kayda atayamaz; Win64 callee r12-r15/rbx/rbp korur).
#define W1(NM) static u64 NM(u64 fn, u64 a0) { u64 ret; u64 ar_[1]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W2(NM) static u64 NM(u64 fn, u64 a0, u64 a1) { u64 ret; u64 ar_[2]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W3(NM) static u64 NM(u64 fn, u64 a0, u64 a1, u64 a2) { u64 ret; u64 ar_[3]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W4(NM) static u64 NM(u64 fn, u64 a0, u64 a1, u64 a2, u64 a3) { u64 ret; u64 ar_[4]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tmovq 24(%%r14), %%r9\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W5(NM) static u64 NM(u64 fn, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4) { u64 ret; u64 ar_[5]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x30, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tmovq 24(%%r14), %%r9\n\t" \
        "movq 32(%%r14), %%rax\n\tmovq %%rax, 32(%%rsp)\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W7(NM) static u64 NM(u64 fn, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6) { u64 ret; u64 ar_[7]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; ar_[5] = a5; ar_[6] = a6; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x40, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tmovq 24(%%r14), %%r9\n\t" \
        "movq 32(%%r14), %%rax\n\tmovq %%rax, 32(%%rsp)\n\tmovq 40(%%r14), %%rax\n\tmovq %%rax, 40(%%rsp)\n\t" \
        "movq 48(%%r14), %%rax\n\tmovq %%rax, 48(%%rsp)\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
W1(api1)
W2(api2)
W3(api3)
W4(api4)
W5(api5)
W7(api7)
#endif

// ---- modul ve ihracat cozumleme ----
static u64 peb_module(u32 want) {
    u64 peb = peb_addr();
    if (!peb) return 0;
    u64 ldr = LDPTR((const u8*)(unsigned long)(peb + PEB_LDR_OFF));
    if (!ldr) return 0;
    u64 head = ldr + LDR_INMEM_OFF;
    u64 cur = LDPTR((const u8*)(unsigned long)head);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent = cur - ENT_INMEM_OFF;
        u32 nlen = ld16((const u8*)(unsigned long)(ent + ENT_NAMELEN_OFF));
        u64 nbuf = LDPTR((const u8*)(unsigned long)(ent + ENT_NAMEBUF_OFF));
        if (nbuf && nlen && nlen < 128) {
            u32 h = fnv_w((const u16*)(unsigned long)nbuf, nlen >> 1);
            if (h == want) return LDPTR((const u8*)(unsigned long)(ent + ENT_DLLBASE_OFF));
        }
        cur = LDPTR((const u8*)(unsigned long)cur);
    }
    return 0;
}

/* 1.1.0-A4/DLL: VERILEN MODULE BASE'e AIT DOSYA YOLU (FullDllName).
   DLL senaryosunda file-CRC hedefi DLL'in KENDISIDIR; GetModuleFileNameA
   (h=NULL) HOST EXE'yi verir — yanlis hedef. PEB InLoadOrder listesinde
   DllBase==base eslesmesi aranir. Donus: ANSI uzunluk (0=bulunamadi). */
static u32 peb_path_for_base(const u8* base, char* out, u32 cap) {
    u64 peb = peb_addr();
    if (!peb || !base || cap < 4) return 0;
    u64 ldr = LDPTR((const u8*)(unsigned long)(peb + PEB_LDR_OFF));
    if (!ldr) return 0;
    u64 head = ldr + LDR_INMEM_OFF;
    u64 cur = LDPTR((const u8*)(unsigned long)head);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent = cur - ENT_INMEM_OFF;
        u64 db = LDPTR((const u8*)(unsigned long)(ent + ENT_DLLBASE_OFF));
        if (db == (u64)(unsigned long)base) {
            u32 nlen = ld16((const u8*)(unsigned long)(ent + ENT_FULLLEN_OFF));
            u64 nbuf = LDPTR((const u8*)(unsigned long)(ent + ENT_FULLBUF_OFF));
            u32 i, n;
            if (!nbuf || !nlen) return 0;
            n = nlen >> 1;
            if (n >= cap) n = cap - 1;
            for (i = 0; i < n; i++) {
                u16 w = ld16((const u8*)(unsigned long)(nbuf + 2 * i));
                out[i] = (char)(w & 0xFF);   /* ASCII dusus; uzayici yol -> CRC fallback exe */
                if (!out[i]) { n = i; break; }
            }
            out[n] = 0;
            return n;
        }
        cur = LDPTR((const u8*)(unsigned long)cur);
    }
    return 0;
}

static u64 find_export(u64 kbase, u32 want) {
    if (!kbase) return 0;
    const u8* d = (const u8*)(unsigned long)kbase;
    if (d[0] != 'M' || d[1] != 'Z') return 0;
    u32 lfa = ld32(d + 0x3C);
    if (lfa == 0 || lfa > 0x400) return 0;
    const u8* pe = d + lfa;
    if (ld32(pe) != 0x00004550u) return 0;
    u16 magic = ld16(pe + 24);
    u32 ddoff = (magic == 0x20B) ? 112 : 96;   // DD, OptionalHeader+112 (PE32+) / +96 (PE32)
    u32 erva = ld32(pe + 24 + ddoff);
    if (!erva) return 0;
    const u8* ex = d + erva;
    u32 nnames = ld32(ex + 24);   // +24 NumberOfNames
    u32 aofn = ld32(ex + 32);     // +32 AddressOfNames
    u32 aofo = ld32(ex + 28);     // +28 AddressOfFunctions   (0.5.0 DUZELTME:
    u32 aoo  = ld32(ex + 36);     // +36 AddressOfNameOrdinals  eskiden 28/36 takasti!)
    u32 i;
    if (nnames > 0x20000) return 0;
    for (i = 0; i < nnames; i++) {
        u32 nrva = ld32(d + aofn + 4 * i);
        if (!nrva) continue;
        u32 h = fnv_a((const char*)(unsigned long)(d + nrva));
        if (h == want) {
            u32 ord = (u32)ld16(d + aoo + 2 * i);
            u32 frva = ld32(d + aofo + 4 * ord);
            if (!frva) return 0;
            return kbase + frva;
        }
    }
    return 0;
}

// ---- .text CRC: reloc yamalarini atlayarak ----
static u32 crc_text(const u8* base, u32 text_rva, u32 text_sz,
                    const u8* reloc, u32 reloc_sz) {
    u8 flag[4096 + 16];
    u32 c = 0xFFFFFFFFu;
    u32 pg;
    u32 i;
    for (i = 0; i < sizeof flag; i++) flag[i] = 0;
    for (pg = 0; pg < text_sz; pg += 0x1000) {
        u32 pgrva = text_rva + pg;
        u32 plen = (text_sz - pg < 0x1000) ? (text_sz - pg) : 0x1000;
        for (i = 0; i < plen + 8; i++) flag[i] = 0;
        if (reloc && reloc_sz) {
            u32 ro = 0;
            while (ro + 8 <= reloc_sz) {
                u32 page_rva = ld32(reloc + ro);
                u32 bsz = ld32(reloc + ro + 4);
                if (bsz < 8 || ro + bsz > reloc_sz) break;
                if (page_rva == pgrva) {
                    u32 eo;
                    for (eo = 8; eo + 2 <= bsz; eo += 2) {
                        u16 e = ld16(reloc + ro + eo);
                        u32 typ = (u32)(e >> 12);
                        u32 off = (u32)(e & 0xFFF);
                        u32 len = 0;
                        if (typ == 3) len = 4;
                        else if (typ == 10) len = 8;
                        if (len && off < plen + 8) {
                            for (i = 0; i < len && off + i < sizeof flag; i++)
                                flag[off + i] = 1;
                        }
                    }
                }
                ro += bsz;
            }
        }
        {
            const u8* p = base + pgrva;
            for (i = 0; i < plen; i++)
                if (!flag[i]) c = crc_up(c, p[i]);
        }
    }
    return ~c;
}

// kucuk ondalik donusturucu
static void u32dec(u32 v, char* out) {
    char t[12]; int n = 0; int i;
    if (!v) { out[0] = '0'; out[1] = 0; return; }
    while (v && n < 10) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = 0; i < n; i++) out[i] = t[n - 1 - i];
    out[n] = 0;
}

// hata mesaji + cikis
static void rt_fatal(u64 k32, u32 code, u32 flags) {
    if (flags & XFLAG_MSG) {
        char un[16];
        VP4(un, 0, A4('u','s','e','r'));
        VP4(un, 4, A4('3','2','.','d'));
        VP4(un, 8, A4('l','l',0,0));
        {
            u64 ll = find_export(k32, XH_LOADLIBRARYA);
            if (ll) {
                u64 u32mod = api1(ll, (u64)(unsigned long)(void*)un);
                if (u32mod) {
                    u64 mb = find_export(u32mod, XH_MESSAGEBOXA);
                    if (mb) {
                        char ttl[16];
                        char msg[96];
                        char num[12];
                        int q;
                        VP4(ttl, 0, A4('X','P','r','o'));
                        VP4(ttl, 4, A4('t','e','c','t'));
                        ttl[8] = 0;
                        VP4(msg, 0,  A4('X','P','r','o'));
                        VP4(msg, 4,  A4('t','e','c','t'));
                        VP4(msg, 8,  A4(':',' ','b','u'));
                        VP4(msg, 12, A4('t','u','n','u'));
                        VP4(msg, 16, A4('l','u','k',' '));
                        VP4(msg, 20, A4('k','o','n','t'));
                        VP4(msg, 24, A4('r','o','l','u'));
                        VP4(msg, 28, A4(' ','k','o','d'));
                        VP4(msg, 32, A4(' ','=',' ','#'));
                        u32dec(code, num);
                        q = 0;
                        while (num[q] && 36 + q < 95) { msg[36 + q] = num[q]; q++; }
                        msg[36 + q] = 0;
                        api4(mb, 0, (u64)(unsigned long)(void*)msg,
                             (u64)(unsigned long)(void*)ttl, 0x10u);
                    }
                }
            }
        }
    }
    if (flags & XFLAG_EXIT) {
        u64 ep = find_export(k32, XH_EXITPROCESS);
        /* 0.5.1: cikis kodu 0x70+hatakodu (1=self, 2=text, 3=file, 4=k32)
        - teshiste hangi kontrolun patladigi net ayirt edilir */
        if (ep) { api1(ep, (u64)(0x70u + code)); }
        for (;;) {}
    }
}

// CRC tampon taramasi — iki atla araligi ile (dosya CRC icin)
static u32 crc_buf_skip(u32 c, const u8* p, u32 n, u32 base,
                        u32 s0, u32 s0n, u32 s1, u32 s1n) {
    u32 i;
    for (i = 0; i < n; i++) {
        u32 a = base + i;
        int skip = 0;
        if (s0n && a >= s0 && a < s0 + s0n) skip = 1;
        else if (s1n && a >= s1 && a < s1 + s1n) skip = 1;
        if (!skip) c = crc_up(c, p[i]);
    }
    return c;
}

// ============================================================
// xrt_entry(void* cfg) — her korumali fonksiyon girisinde BIR KEZ
// Donus: 0 = tamam; 1=self 2=text 3=file 4=ortam — stub zehir yolu
// ============================================================
u32 xrt_entry(void* cfgp) {
    u8* cfg = (u8*)cfgp;
    u32 flags;
    u64 cfgva;
    u32 cfg_rva;
    const u8* base;
    u64 k32;
    u32 err = 0;

    if (ld32(cfg + XCFG_OFF_MAGIC) != XCFG_MAGIC) return 0;
    flags = ld32(cfg + XCFG_OFF_FLAGS);
    if (ld32(cfg + XCFG_OFF_STATE)) return 0;
    cfg[XCFG_OFF_STATE]     = 1;
    cfg[XCFG_OFF_STATE + 1] = 0;
    cfg[XCFG_OFF_STATE + 2] = 0;
    cfg[XCFG_OFF_STATE + 3] = 0;

    cfgva = (u64)(unsigned long)cfg;
    cfg_rva = ld32(cfg + XCFG_OFF_CFGRVA);
    base = (const u8*)(unsigned long)(cfgva - cfg_rva);

    // --- kernel32 (hash sabiti — bkz. XH_* aciklamasi) ---
    k32 = peb_module(XH_KERNEL32);
    if (!k32) {
        if (flags & (XFLAG_SELFCRC | XFLAG_TEXTCRC | XFLAG_FILECRC)) return 4;
        return 0;
    }

    /* 0.8.0 SEH: dinamik unwind kaydi — dd[3]'e dokunmuyoruz (wine'da
       repoint istisna dagitimini bozuyor; olculu). .vmp0'daki tabloyu
       ntdll!RtlAddFunctionTable ile BIR KEZ kaydet (JIT modeli).
       CRC kontrolerinden ONCE: CRC patlasa bile kayitli kalsin. */
    {
        u32 urva = ld32(cfg + XCFG_OFF_UNWRVA);
        u32 ucnt = ld32(cfg + XCFG_OFF_UNWCNT);
        if (urva && ucnt) {
            u64 nt = peb_module(XH_NTDLL);
            if (nt) {
                u64 raft = find_export(nt, XH_RTLADDFT);
                if (raft) api3(raft, (u64)(unsigned long)(base + urva),
                               (u64)ucnt, (u64)(unsigned long)base);
            }
        }
    }

    // --- SELF CRC ---
    if ((flags & XFLAG_SELFCRC) && !err) {
        u32 sr = ld32(cfg + XCFG_OFF_SELFRVA);
        u32 sl = ld32(cfg + XCFG_OFF_SELFLEN);
        u32 sc = ld32(cfg + XCFG_OFF_SELFCRC);
        u32 c = 0xFFFFFFFFu;
        const u8* p = base + sr;
        u32 i;
        for (i = 0; i < sl; i++) c = crc_up(c, p[i]);
        if (~c != sc) err = 1;
    }

    // --- TEXT CRC (reloc atlama) ---
    if ((flags & XFLAG_TEXTCRC) && !err) {
        u32 tr = ld32(cfg + XCFG_OFF_TEXTRVA);
        u32 ts = ld32(cfg + XCFG_OFF_TEXTSZ);
        u32 tc = ld32(cfg + XCFG_OFF_TEXTCRC);
        u32 rr = ld32(cfg + XCFG_OFF_RELOCRVA);
        u32 rs = ld32(cfg + XCFG_OFF_RELOCSZ);
        if (ts) {
            u32 c = crc_text(base, tr, ts, rr ? (base + rr) : 0, rs);
            if (c != tc) err = 2;
        }
    }

    // --- FILE CRC (disk) ---
    if ((flags & XFLAG_FILECRC) && !err) {
        {
            u64 gmfn = find_export(k32, XH_GETMODULEFNA);
            u64 cfa  = find_export(k32, XH_CREATEFILEA);
            u64 rf   = find_export(k32, XH_READFILE);
            u64 ch   = find_export(k32, XH_CLOSEHANDLE);
            if (gmfn && cfa && rf && ch) {
                char path[1056];
                /* 1.1.0-A4/DLL: hedef = KORUMALI MODUL (base). DLL yukluyse
                   PEB FullDllName ile DLL'in KENDI yolu; bulunamazsa eski
                   GetModuleFileNameA(NULL) (host exe) davranisi. */
                u32 plen = peb_path_for_base(base, path, 1040);
                u32 r = plen;
                if (!r) r = api3(gmfn, 0, (u64)(unsigned long)(void*)path, 1040);
                if (r && r < 1040) {
                    // CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)
                    u64 h = api7(cfa, (u64)(unsigned long)(void*)path, 0x80000000u, 1, 0, 3, 0, 0);
                    if (h && h != (u64)(unsigned long)-1) {
                        u8 buf[4096];
                        u32 c = 0xFFFFFFFFu;
                        u32 foff = 0;
                        u32 ckoff = ld32(cfg + XCFG_OFF_CKSUM);
                        u32 vr0 = ld32(cfg + XCFG_OFF_VMPRAW0);
                        u32 vr1 = ld32(cfg + XCFG_OFF_VMPRAW1);
                        for (;;) {
                            u32 got = 0;
                            u32 okr = api5(rf, h, (u64)(unsigned long)(void*)buf, 4096,
                                           (u64)(unsigned long)(void*)&got, 0);
                            (void)okr;
                            if (!got) break;
                            c = crc_buf_skip(c, buf, got, foff, ckoff, 4,
                                             vr0, (vr1 > vr0) ? (vr1 - vr0) : 0);
                            foff += got;
                            if (got < 4096) break;
                        }
                        api1(ch, h);
#ifdef XRT_PROBE
                        /* PROBE-A: cfg alanlari dogru mu? (ckoff=0xD0, vr0=0x35C00, vr1=0x39600) */
                        { u64 ep2 = find_export(k32, XH_EXITPROCESS);
                          if (ep2) { api1(ep2, (u64)((ckoff == 0xD0 && vr0 == 0x35C00 && vr1 == 0x39600) ? 0x55 : 0x66)); } for(;;){} }
                        /* PROBE-B: toplam okunan bayt (foff>>8)&0xFF — beklenen 0x96 (918) */
                        { u64 ep2 = find_export(k32, XH_EXITPROCESS);
                          if (ep2) { api1(ep2, (u64)((foff >> 8) & 0xFF)); } for(;;){} }
#endif
                        if (~c != ld32(cfg + XCFG_OFF_FILECRC)) err = 3;
                    } else err = 3;
                } else err = 3;
            } else err = 3;
        }
    }

    if (err) {
        rt_fatal(k32, err, flags);   /* 0.5.1: cikis 0x70+hatakodu */
        return err;
    }
    return 0;
}

// ============================================================
// xrt_resolve(dllhash, namehash, fallback_abs) — gecikmeli import
// ============================================================
u64 xrt_resolve(u32 dllhash, u32 namehash, u64 fallback_abs) {
    u64 m = peb_module(dllhash);
    if (m) {
        u64 a = find_export(m, namehash);
        if (a) return a;
    }
    if (fallback_abs) {
#if defined(XRT_IS_X64)
        return ld64((const u8*)(unsigned long)fallback_abs);
#else
        return (u64)ld32((const u8*)(unsigned long)fallback_abs);
#endif
    }
    return 0;
}

// ============================================================
// 0.6.0 — xrt_unpack: LZMA paket acici (cpPack)
// EP stub'ı cagirir: .vmp1'deki XPK1 blok'taki akislari LZMA'dan
// cozer, bolum belleklerine yazar (VirtualProtect RW gecisi ile),
// sonra OEP'ye donulur (stub jmp). Referans: runtime/loader.cc
// "unpack regions" + third-party/lzma LzmaDecode (birebir port).
// Donus: 0 = tamam; 5 = acma hatasi (rt_fatal cagirildi)
// ============================================================
#define XPK_MAGIC 0x31504B58u   // 'XPK1'
// 0.8.0: kayit 12B -> 16B: {src_rva, dst_rva, dst_size, src_size}
#define XPK_REC_SZ      16
#define XPK_MAX_STREAM  0x08000000u   // tek akis icin saglam ust sinir (128MB)

#include "lzma/LzmaDecode.cc"   /* C olarak derlenir — statik veri yok (PIC kapisi) */

static void xcopy(u8* d, const u8* s, u32 n) { while (n--) *d++ = *s++; }

u32 xrt_unpack(void* cfgp) {
    u8* cfg = (u8*)cfgp;
    if (ld32(cfg + XCFG_OFF_MAGIC) != XCFG_MAGIC) return 0;
    u32 flags = ld32(cfg + XCFG_OFF_FLAGS);
    u32 packrva = ld32(cfg + XCFG_OFF_PACKRVA);
    if (!packrva) return 0;                     // paket yok — hizli cikis
    u64 cfgva = (u64)(unsigned long)cfg;
    u32 cfg_rva = ld32(cfg + XCFG_OFF_CFGRVA);
    u8* base = (u8*)(unsigned long)(cfgva - cfg_rva);

    u64 k32 = peb_module(XH_KERNEL32);
    if (!k32) return 5;                         // kernel32 yok: acilamaz
    u64 f_alloc = find_export(k32, XH_VIRTUALALLOC);
    u64 f_free  = find_export(k32, XH_VIRTUALFREE);
    u64 f_prot  = find_export(k32, XH_VIRTUALPROTECT);
    if (!f_alloc || !f_free || !f_prot) { rt_fatal(k32, 6, flags); return 6; }

    const u8* pk = base + packrva;
    if (ld32(pk) != XPK_MAGIC) { rt_fatal(k32, 7, flags); return 7; }
    u32 count = ld32(pk + 4);
    u32 props_rva = ld32(pk + 8);
    u32 xcflag = ld32(pk + XRC_HDR_FLAG);      // 0.8.0: 1 = akislar sifreli
    if (!count || count > 64 || !props_rva) { rt_fatal(k32, 8, flags); return 8; }

    // --- 0.8.0 SectionCryptor: anahtar cozumu (cfg'den maskeli okuma) ---
    u64 ck0 = 0, ck1 = 0;
    if (xcflag == 1 && ld32(cfg + XRC_CFG_FLAG) == 1) {
        u64 m = XRC_KEYMASK(ld32(cfg + XCFG_OFF_CFGRVA));
        ck0 = (u64)ld32(cfg + XRC_CFG_KEY0) | ((u64)ld32(cfg + XRC_CFG_KEY0 + 4) << 32);
        ck1 = (u64)ld32(cfg + XRC_CFG_KEY1) | ((u64)ld32(cfg + XRC_CFG_KEY1 + 4) << 32);
        ck0 ^= m; ck1 ^= m;
        if (!ck0 && !ck1) { rt_fatal(k32, 11, flags); return 11; }  // anahtar yok
    } else if (xcflag) {
        xcflag = 0;                                // bilinmeyen flag — sifresiz dene
    }

    CLzmaDecoderState st;
    if (LzmaDecodeProperties(&st.Properties, base + props_rva, LZMA_PROPERTIES_SIZE)
        != LZMA_RESULT_OK) { rt_fatal(k32, 9, flags); return 9; }
    {
        u64 probs = api4(f_alloc, 0, (u64)LzmaGetNumProbs(&st.Properties) * 2u, 0x3000u, 0x04u /*PAGE_READWRITE*/);
        if (!probs) { rt_fatal(k32, 10, flags); return 10; }
        st.Probs = (CProb*)(unsigned long)probs;
    }

    u32 bad = 0;
    u32 rec = packrva + 16;
    for (u32 i = 0; i < count; i++, rec += XPK_REC_SZ) {
        u32 src = ld32(base + rec);
        u32 dst = ld32(base + rec + 4);
        u32 dsz = ld32(base + rec + 8);
        u32 ssz = ld32(base + rec + 12);        // 0.8.0: sikistirilmis akis uzunlugu
        if (!src || !dst || !dsz || dst > 0xFFFF0000u) { bad = 1; break; }
        if (!ssz || ssz > XPK_MAX_STREAM) { bad = 5; break; }
        // 0.8.0 SectionCryptor: .vmp1 RWX mapli — yerinde CFB cozumu
        if (xcflag == 1)
            xr_cfb(ck0, ck1, XRC_NONCE(ck0, dst),
                   (unsigned char*)(unsigned long)(base + src), ssz, 1 /*coz*/);
        u64 tmp = api4(f_alloc, 0, (u64)dsz, 0x3000u, 0x04u /*PAGE_READWRITE*/);
        if (!tmp) { bad = 2; break; }
        SizeT sp = 0, dp = 0;
        int rc = LzmaDecode(&st, base + src, (SizeT)(0xFFFFFFFFu), &sp,
                            (unsigned char*)(unsigned long)tmp, (SizeT)dsz, &dp);
        if (rc != LZMA_RESULT_OK || dp != (SizeT)dsz) {
            bad = 3;
        } else {
            u8* dptr = base + dst;
            u32 oldp = 0, tmp2 = 0;
            u64 dva = (u64)(unsigned long)dptr;
            /* sayfa korumasini RW'ye al, yaz, eski haline don */
            if (!api4(f_prot, dva, (u64)dsz, 0x04u /*PAGE_READWRITE*/,
                      (u64)(unsigned long)&oldp)) { bad = 4; }
            if (!bad) {
                xcopy(dptr, (const u8*)(unsigned long)tmp, dsz);
                api4(f_prot, dva, (u64)dsz, oldp ? oldp : 0x20u /*EXEC_READ*/,
                     (u64)(unsigned long)&tmp2);
            }
        }
        api3(f_free, tmp, 0, 0x8000u /*MEM_RELEASE*/);
        if (bad) break;
    }
    api3(f_free, (u64)(unsigned long)st.Probs, 0, 0x8000u);
    /* 5+kod: 1=rec 2=alloc 3=decode 4=protect 5=akis-uzunluk 11=anahtar */
    if (bad) { rt_fatal(k32, 5, flags); return bad; }
    return 0;
}

// ---- 0.7.0: lisans cekirdegi (lic_sdk_core + xrt_sdk_entry asm kapilari) ----
#include "xrt_license.c"
