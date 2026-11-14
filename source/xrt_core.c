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
typedef long long i64;   /* 1.2.2-A20: NTSTATUS isaret-genisletme (A8 dersi) */

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
#define XCFG_OFF_STRENC 0x60   /* u32: strenc tablo RVA (A18; 0 = yok) */
#define XCFG_OFF_UNWCNT  0x48   // 0.8.0: dinamik unwind kayit sayisi
// 0.8.0 SectionCryptor alanlari (xr_cipher.h ile ayni): flag 0x4C, anahtar 0x50/0x58
#define XCFG_SIZE        0x60
#include "xr_cipher.h"

#define XFLAG_SELFCRC 0x01
#define XFLAG_TEXTCRC 0x02
#define XFLAG_FILECRC 0x04
#define XFLAG_MSG     0x08
#define XFLAG_EXIT    0x10
#define XFLAG_MEMPROT 0x20   /* 1.2.2-A11: IC memory protection (VEH yazma-guvesi) */
#define XFLAG_VFILES 0x40   /* 1.2.2-A16: Virtual Files (tek-kurulum kilidi) */
#define XFLAG_VREG   0x80   /* 1.2.2-A17: Virtual Registry (IAT kesmesi) */
#define XFLAG_STRENC 0x100  /* 1.2.2-A18: String Encryption (orijinal .rdata sifreli) */
#define XFLAG_ANTIDBG 0x200 /* 1.2.2-A20: GLOBAL Check Debugger (UO loader-parite) */
#define XFLAG_CHECKVM 0x400 /* 1.2.2-A20: GLOBAL Check Virtual Machine */
#define XFLAG_KDBG   0x800 /* 1.2.2-A20: GLOBAL Check Kernel Debugger */

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
/* A16-iz2: BÜYÜK/küçük duyarsız ANSI hash — PEB fnv_w ile ASCII'de birebir
   eşleşir (import "KERNEL32.dll" vs PEB "KERNEL32.dll" her yazımda bul). */
static u32 fnv_al(const char* s) {
    u32 h = 2166136261u;
    while (*s) { u32 c = (u8)*s++; if (c >= 'A' && c <= 'Z') c += 32u; h ^= c; h *= 16777619u; }
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
#define XH_ADDVECTEH      0xAFAC650Du  // "AddVectoredExceptionHandler" (1.2.2-A11)
#define XH_GETPROCADDRESS 0xF8F45725u  // "GetProcAddress" (1.2.2-A16)
#define XH_GETTEMPPATHA   0x5F59CFF1u  // "GetTempPathA" (1.2.2-A16)
#define XH_WRITEFILE      0x7F07C44Au  // "WriteFile" (1.2.2-A16)
#define XH_SETFILEPOINTER 0xB7F5E1C2u  // "SetFilePointer" (A16-iz)
/* 1.2.2-A20: GLOBAL batarya hash'leri (fnv_a case-sensitive) */
#define XH_NQIP   0xEA2DDA8Au  /* "NtQueryInformationProcess" (ntdll) */
#define XH_NQSI   0x7A43974Au  /* "NtQuerySystemInformation"  (ntdll) */
#define XH_NSIP   0x19ECB6CAu  /* "NtSetInformationProcess"   (ntdll) */

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
#define ENT_SIZE_OFF    0x40   /* 1.2.2-A11: LDR_DATA_TABLE_ENTRY.SizeOfImage */
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
#define ENT_FULLBUF_OFF 0x28   /* 1.2.2-K9: x86 FullDllName.Buffer */
#define ENT_FULLLEN_OFF 0x24   /*        FullDllName.Length     */
#define ENT_SIZE_OFF    0x20   /* 1.2.2-A11: LDR_DATA_TABLE_ENTRY.SizeOfImage */
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
/* A17.1: 0-arg stdcall cagri (DllRegisterServer — callee 0 arg temizler) */
#define W0(NM) static u32 NM(u32 fn) { u32 ret; \
    __asm__ volatile ("call *%[fn]" : "=a"(ret) : [fn] "r"(fn) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
W0(api0)
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
/* A17.1: 0-arg Win64 cagri (DllRegisterServer) — shadow alan + hizalama */
#define W0(NM) static u64 NM(u64 fn) { u64 ret; \
    register u64 rfn __asm__("r15") = fn; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "call *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
W0(api0)
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

/* A16-iz2: api-set (api-ms-win-*) DLL'ler PEB adıyla EŞLEŞMEZ (gerçek ad
   ucrtbase/kernelbase'tir) ve LoadLibraryA freestanding çerçeveden çağrıldı-
   ğında wine SEH-unwind'i (unwind-info'suz blob frame'leri) patlatıyor.
   ÇÖZÜM: import hash'ini TÜM yüklü modüllerin export tablolarında ara —
   ucrtbase zaten PEB'dedir (host api-ms-* import ediyorsa). */
static u64 find_export(u64 kbase, u32 want);
static u64 find_export_any(u32 want) {
    u64 peb = peb_addr();
    if (!peb) return 0;
    u64 ldr = LDPTR((const u8*)(unsigned long)(peb + PEB_LDR_OFF));
    if (!ldr) return 0;
    u64 head = ldr + LDR_INMEM_OFF;
    u64 cur = LDPTR((const u8*)(unsigned long)head);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent = cur - ENT_INMEM_OFF;
        u64 db = LDPTR((const u8*)(unsigned long)(ent + ENT_DLLBASE_OFF));
        if (db) {
            u64 a = find_export(db, want);
            if (a) return a;
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
// ---- 1.2.2-A11: IC MEMORY PROTECTION --------------------------------------
// Tasarim (UO "Internal Memory Protection" es-tanim + loader-parite):
//   Motor: memprot acikken .text (ve CRC-yoksa .vmp0) bolum charlari
//          EXECUTE_READ — loader sayfalari yazilamaz map eder.
//   Runtime: ILK-chance VEH — 0xC0000005 YAZMA (ExcInfo[0]==1) adresi
//          herhangi bir yuklu modulun KOD bolumundeyse (CNT_CODE) =
//          tamper -> ExitProcess(0x75). KOD bolumune normal yazma zaten
//          AV uretir (loader korur); bu katman VEH ile yakalanan her
//          yazma-girisimini keser. WPM/cekirdek-yolu yazimlar user-mode
//          kapsam disi (Check Debugger baglamsali).
//   Durumsuz tek-kurulum:
//     CRC kipi (cfg yazilabilir): gosterge = cfg state byte (0 -> ilk).
//     memprot-yalin (cfg YAZILAMAZ — .vmp0 EXECUTE_READ): gosterge =
//       VirtualProtect eski-koruma okumasi (old != EXEC_READ -> ilk).
//   xrt_unpack pack yazmalari kurulumdan ONCE (EP sirasi) ve kendi RW
//   gecisiyle yapilir — cakisma yok.
static u64 mp_module_of(u64 addr, u64* base_out, u32* imgsz_out) {
    u64 peb = peb_addr();
    if (!peb) return 0;
    u64 ldr = LDPTR((const u8*)(unsigned long)(peb + PEB_LDR_OFF));
    if (!ldr) return 0;
    u64 head = ldr + LDR_INMEM_OFF;
    u64 cur = LDPTR((const u8*)(unsigned long)head);
    int guard = 0;
    while (cur && cur != head && guard++ < 96) {
        u64 ent = cur - ENT_INMEM_OFF;
        u64 db = LDPTR((const u8*)(unsigned long)(ent + ENT_DLLBASE_OFF));
        u64 sz = LDPTR((const u8*)(unsigned long)(ent + ENT_SIZE_OFF));
        if (db && sz && addr >= db && addr < db + sz) {
            if (base_out) *base_out = db;
            if (imgsz_out) *imgsz_out = (u32)sz;
            return 1;
        }
        cur = LDPTR((const u8*)(unsigned long)cur);
    }
    return 0;
}

/* adres bir modulun KOD bolumunde mi? (bolum tablosu yuruyusu) */
static int mp_is_code(u64 addr) {
    u64 mb = 0; u32 msz = 0;
    if (!mp_module_of(addr, &mb, &msz)) return 0;
    {
        const u8* base = (const u8*)(unsigned long)mb;
        u32 e_lfanew = ld32(base + 0x3C);
        u16 nsec = ld16(base + e_lfanew + 6);
        u16 optsz = ld16(base + e_lfanew + 20);
        u32 sh = e_lfanew + 24 + optsz;
        u32 rva = (u32)(addr - mb);
        u32 i;
        if (nsec > 96) return 0;
        for (i = 0; i < nsec; i++) {
            u32 o = sh + i * 40;
            u32 va = ld32(base + o + 12);
            u32 vsz = ld32(base + o + 8);
            u32 ch = ld32(base + o + 36);
            if (rva >= va && rva < va + vsz) return (ch & 0x20000000u) ? 1 : 0;
        }
    }
    return 0;
}

#if defined(XRT_IS_X64)
static long __attribute__((stdcall)) mp_veh(u8* ep) {
    u8* er = (u8*)(unsigned long)LDPTR(ep + 0);       /* ExceptionRecord */
    if (er && ld32(er + 0) == 0xC0000005u && ld32(er + 0x18) >= 2) {
        u64 w = ld64(er + 0x20);   /* ExcInfo[0]: 0=oku 1=yaz 8=calistir */
        u64 fa = ld64(er + 0x28);  /* ExcInfo[1]: fault adresi          */
        if (w == 1 && fa && mp_is_code(fa)) {
            u64 k = peb_module(XH_KERNEL32);
            rt_fatal(k, 5, XFLAG_EXIT);                /* ExitProcess(0x75) tamper */
            for (;;) {}
        }
    }
    return 0;   /* EXCEPTION_CONTINUE_SEARCH */
}
#else
static long __attribute__((stdcall)) mp_veh(u8* ep) {
    u8* er = (u8*)(unsigned long)LDPTR(ep + 0);
    if (er && ld32(er + 0) == 0xC0000005u && ld32(er + 0x10) >= 2) {
        u32 w = ld32(er + 0x14);
        u32 fa = ld32(er + 0x18);
        if (w == 1 && fa && mp_is_code((u64)fa)) {
            u64 k = peb_module(XH_KERNEL32);
            rt_fatal(k, 5, XFLAG_EXIT);                /* ExitProcess(0x75) tamper */
            for (;;) {}
        }
    }
    return 0;
}
#endif

// ============================================================
// 1.2.2-A16 — VIRTUAL FILES (cpVirtualFiles): XVF1 bloğu = cfg + 0x60
// UO davranışı (core.cc InternalFile + runtime loader):
//   faLoad(1):     bellekte MANUEL PE haritası — VirtualAlloc + bölüm
//                  kopyala + reloc + import (hash/GetProcAddress) +
//                  DllMain(PROCESS_ATTACH). Diskte hiç iz yok.
//   faRegister(2): yükle + DllRegisterServer (A17'de tam)
//   faInstall(3):  %TEMP%\isim'e çöz + LoadLibraryA
// Anahtar/isim sözleşmesi: xr_cipher.h (xvf_k0/k1/nonce/namekey).
// ============================================================
static u32 xvf_rotl(u32 k, u32 i) {
    i &= 31;
    return (k << i) | (k >> ((32u - i) & 31));
}
static void xvf_wr32(u8* p, u32 v) {
    volatile u8* q = (volatile u8*)p;
    q[0] = (u8)v; q[1] = (u8)(v >> 8); q[2] = (u8)(v >> 16); q[3] = (u8)(v >> 24);
}
static void xvf_wr64(u8* p, u64 v) {
    volatile u8* q = (volatile u8*)p; int i;
    for (i = 0; i < 8; i++) q[i] = (u8)(v >> (8 * i));
}
static void xvf_memcpy(u8* d, const u8* s, u32 n) {
    volatile u8* dd = (volatile u8*)d; const volatile u8* ss = (const volatile u8*)s;
    while (n--) *dd++ = *ss++;
}
/* UO InternalFile::WriteName tersi: w[i] ^ (rotl32(key,i)+i) → ANSI */
static u32 xvf_name_dec(const u8* hdr, u32 name_off, u32 nk, char* out, u32 cap) {
    u32 n = 0;
    while (n + 1 < cap) {
        u16 e = (u16)((u16)hdr[name_off + n * 2] | ((u16)hdr[name_off + n * 2 + 1] << 8));
        u16 c = (u16)(e ^ (u16)((xvf_rotl(nk, n) + n) & 0xFFFF));
        if (!c) break;
        out[n] = (char)(c & 0xFF);
        n++;
    }
    out[n] = 0;
    return n;
}

/* --- manuel PE haritası (faLoad çekirdeği) --- */
/* A16-iz: APPEND modu — OPEN_ALWAYS + SetFilePointer(FILE_END); her işaret
   dosyaya EKLENİR (üstüne yazmaz), böylece tam crash konumu görünür.
   ÜRETİMDE XVF_TRACE tanımlı değilse NO-OP (hiç dosya-yazımı yok). */
#ifdef XVF_TRACE
static void xvf_dbg(u64 k32, char a, char b2, char c3) {
    char pn[16]; volatile char* pp = pn;
    pp[0]='C';pp[1]=':';pp[2]='\\';pp[3]='v';pp[4]='f';pp[5]='r';pp[6]='t';
    pp[7]='.';pp[8]='t';pp[9]='x';pp[10]='t';pp[11]=0;
    {
        u64 cfa_ = find_export(k32, XH_CREATEFILEA);
        u64 wf_ = find_export(k32, XH_WRITEFILE);
        u64 sf_ = find_export(k32, XH_SETFILEPOINTER);
        u64 ch_ = find_export(k32, XH_CLOSEHANDLE);
        if (cfa_ && wf_ && ch_) {
            u64 fh = api7(cfa_, (u64)(unsigned long)(void*)pn, 0x40000000u, 0, 0, 4, 0, 0);
            if (fh && fh != (u64)(unsigned long)-1) {
                char mk[4]; volatile char* mp = mk;
                mp[0]=a; mp[1]=b2; mp[2]=c3; mp[3]='\n';
                u32 wr = 0;
                if (sf_) api4(sf_, fh, 0, 0, 2 /*FILE_END*/);
                api5(wf_, fh, (u64)(unsigned long)(void*)mk, 4, (u64)(unsigned long)&wr, 0);
                api1(ch_, fh);
            }
        }
    }
}
#else
static void xvf_dbg(u64 k32, char a, char b2, char c3) { (void)k32; (void)a; (void)b2; (void)c3; }
#endif
static u64 xvf_map_pe2(const u8* raw, u32 rawsz, u64 k32, int call_dm);
static u64 xvf_map_pe(const u8* raw, u32 rawsz, u64 k32) {
    return xvf_map_pe2(raw, rawsz, k32, 1);
}
static u64 xvf_map_pe2(const u8* raw, u32 rawsz, u64 k32, int call_dm) {
    u32 pe_off, machine, nsec, optsz, ep_rva, img_sz, hdr_sz, ddir_off;
    u64 base, delta;
    u64 va_alloc, ep;
    const u8* sh;
    u32 i;

    if (rawsz < 0x100) return 0;
    if (ld16(raw) != 0x5A4D) return 0;                       /* 'MZ' */
    pe_off = ld32(raw + 0x3C);
    if ((u64)pe_off + 24 + 240 > rawsz) return 0;
    if (ld32(raw + pe_off) != 0x4550) return 0;               /* 'PE\0\0' */
    machine = ld16(raw + pe_off + 4);
#if defined(XRT_IS_X64)
    if (machine != 0x8664) return 0;
    ddir_off = pe_off + 24 + 112;                             /* PE32+ data-dizisi */
#else
    if (machine != 0x014C) return 0;
    ddir_off = pe_off + 24 + 96;                              /* PE32 data-dizisi */
#endif
    nsec  = ld16(raw + pe_off + 6);
    optsz = ld16(raw + pe_off + 20);
    if (!nsec || nsec > 96) return 0;
    ep_rva = ld32(raw + pe_off + 24 + 16);                    /* opt+16 girişi */
    img_sz = ld32(raw + pe_off + 24 + 56);                    /* opt+56 SizeOfImage */
    hdr_sz = ld32(raw + pe_off + 24 + 60);                    /* opt+60 SizeOfHeaders */
    if (img_sz < hdr_sz || img_sz > 0x40000000u || hdr_sz > rawsz) return 0;
    sh = raw + pe_off + 24 + optsz;                           /* bölüm tablosu */
    va_alloc = find_export(k32, XH_VIRTUALALLOC);
    if (!va_alloc) return 0;
    /* A16-iz3: RWX — manuel-map görseline KOD ÇALIŞTIRMA izni şart (yoksa
       DllMain ilk çalıştırmada NXfault; import veri-yazıları RW'de sorunsuzdu) */
    base = api4(va_alloc, 0, (u64)img_sz, 0x3000u, 0x40u);    /* RESERVE|COMMIT RWX */
    if (!base) return 0;
    xvf_dbg(k32, 'V', 'A', '.');
    xvf_memcpy((u8*)(unsigned long)base, raw, hdr_sz);
    xvf_dbg(k32, 'H', 'D', '.');
    for (i = 0; i < nsec; i++) {
        u32 so = (u32)(pe_off + 24 + optsz) + i * 40;
        u32 vsz = ld32(raw + so + 8);
        u32 vrva = ld32(raw + so + 12);
        u32 rsz = ld32(raw + so + 16);
        u32 rraw = ld32(raw + so + 20);
        if (!vsz || !vrva) continue;
        if ((u64)vrva + vsz > img_sz) continue;
        if ((u64)rraw + rsz > rawsz) continue;
        xvf_memcpy((u8*)(unsigned long)(base + vrva), raw + rraw, rsz);
    }
#if defined(XRT_IS_X64)
    delta = (u64)(unsigned long)base - ld64(raw + pe_off + 24 + 24);   /* opt+24 ImageBase */
#else
    delta = (u64)(unsigned long)base - (u64)ld32(raw + pe_off + 24 + 28); /* opt+28 ImageBase */
#endif
    xvf_dbg(k32, 'S', 'E', '.');
    {   /* --- reloc (data-dizisi 5) --- */
        u32 rel_rva = ld32(raw + ddir_off + 5 * 8);
        u32 rel_sz = ld32(raw + ddir_off + 5 * 8 + 4);
        if (rel_rva && rel_sz && delta) {
            u8* rp = (u8*)(unsigned long)(base + rel_rva);
            u32 ro = 0;
            while (ro + 8 <= rel_sz) {
                u32 page = ld32(rp + ro);
                u32 bsz = ld32(rp + ro + 4);
                u32 j;
                if (bsz < 8 || (u64)ro + bsz > rel_sz) break;
                for (j = 8; j < bsz; j += 2) {
                    u16 e = ld16(rp + ro + j);
                    u32 typ = (u32)(e >> 12);
                    u32 off = (u32)(e & 0xFFF);
                    u8* tgt;
                    if (!typ) continue;                        /* 0 = padding */
                    if ((u64)page + off + 8 > img_sz) continue;
                    tgt = (u8*)(unsigned long)(base + page + off);
#if defined(XRT_IS_X64)
                    if (typ == 10) {                          /* DIR64 */
                        u64 v = 0; int k2;
                        for (k2 = 0; k2 < 8; k2++) v |= ((u64)tgt[k2]) << (8 * k2);
                        xvf_wr64(tgt, v + delta);
                    }
#else
                    if (typ == 3) {                            /* HIGHLOW */
                        xvf_wr32(tgt, ld32(tgt) + (u32)delta);
                    }
#endif
                }
                ro += bsz;
            }
        }
    }
    xvf_dbg(k32, 'R', 'E', '.');
    {   /* --- import (data-dizisi 1) --- */
        u32 imp_rva = ld32(raw + ddir_off + 1 * 8);
        if (imp_rva) {
            u8* ip = (u8*)(unsigned long)(base + imp_rva);
            u32 di = 0;
            u64 gpa = find_export(k32, XH_GETPROCADDRESS);
            for (;;) {
                u32 oft, name_rva, ft;
                if (di >= 4096) break;
                oft = ld32(ip + di * 20 + 0);
                name_rva = ld32(ip + di * 20 + 12);
                ft = ld32(ip + di * 20 + 16);
                if (!oft && !name_rva && !ft) break;
                {
                    xvf_dbg(k32, 'I', 'D', (char)('0' + (di < 10 ? di : 9)));
                    char dll[128];
                    u32 q = 0;
                    u8* np = (u8*)(unsigned long)(base + name_rva);
                    while (q < 127 && np[q]) { dll[q] = (char)np[q]; q++; }
                    dll[q] = 0;
                    xvf_dbg(k32, 'N', '.', (char)('0' + (di < 10 ? di : 9)));
                    if (q) {
                        /* A16-iz2: 1) PEB case-insensitive eşleşme; 2) hmod yoksa
                           THUNK'LARI scan-all (find_export_any) ile çöz — api-ms-*
                           ucrtbase/kernelbase'te zaten var; LoadLibraryA SON ÇARE
                           (yalnız scan-all başarısızsa; freestanding çerçevede
                           wine SEH-unwind'ini bozabildiği için son adımda). */
                        u64 hmod = peb_module(fnv_al(dll));
                        xvf_dbg(k32, 'P', hmod ? '1' : '0', (char)('0' + (di < 10 ? di : 9)));
                        u32 nfail = 0;
                        u8* tsrc = (u8*)(unsigned long)(base + (oft ? oft : ft));
                        u8* tdst = (u8*)(unsigned long)(base + ft);
                        u32 ti = 0;
                        for (;;) {
                            u64 addr = 0;
#if defined(XRT_IS_X64)
                            u64 te = 0; int k2;
                            for (k2 = 0; k2 < 8; k2++) te |= ((u64)tsrc[(u64)ti * 8 + k2]) << (8 * k2);
                            if (!te) break;
                            if (te & 0x8000000000000000ull) {
                                if (hmod && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(te & 0xFFFFu));
                            } else {
                                u8* in = (u8*)(unsigned long)(base + (u32)te + 2);
                                u32 hh = fnv_a((const char*)in);
                                addr = hmod ? find_export(hmod, hh) : 0;
                                if (!addr) addr = find_export_any(hh);
                                if (!addr && hmod && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(unsigned long)(void*)in);
                            }
                            if (!addr) nfail++;
                            if (!addr) xvf_dbg(k32, 'Z', '!', (char)('0' + (ti < 10 ? ti : 9)));
                            xvf_wr64(tdst + (u64)ti * 8, addr);
#else
                            u32 te = ld32(tsrc + (u64)ti * 4);
                            if (!te) break;
                            if (te & 0x80000000u) {
                                if (hmod && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(te & 0xFFFFu));
                            } else {
                                u8* in = (u8*)(unsigned long)(base + te + 2);
                                u32 hh = fnv_a((const char*)in);
                                addr = hmod ? find_export(hmod, hh) : 0;
                                if (!addr) addr = find_export_any(hh);
                                if (!addr && hmod && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(unsigned long)(void*)in);
                            }
                            if (!addr) nfail++;
                            if (!addr) xvf_dbg(k32, 'Z', '!', (char)('0' + (ti < 10 ? ti : 9)));
                            xvf_wr32(tdst + (u64)ti * 4, (u32)addr);
#endif
                            ti++;
                            if (ti > 0x10000) break;
                        }
                        xvf_dbg(k32, 'S', (nfail ? 'F' : '0'), (char)('0' + (nfail < 10 ? nfail : 9)));
                        if (nfail && !hmod) {
                            /* SON ÇARE: gerçek LoadLibraryA (gerçek DLL/Windows
                             yolunda sorunsuz; scan-all çözemediyse) + yeniden */
                            u64 lla = find_export(k32, XH_LOADLIBRARYA);
                            if (lla) hmod = (u64)(unsigned long)api1(lla, (u64)(unsigned long)(void*)dll);
                            xvf_dbg(k32, 'L', hmod ? '1' : '0', (char)('0' + (di < 10 ? di : 9)));
                            if (hmod) {
                                ti = 0;
                                for (;;) {
                                    u64 addr = 0;
#if defined(XRT_IS_X64)
                                    u64 te = 0; int k2;
                                    for (k2 = 0; k2 < 8; k2++) te |= ((u64)tsrc[(u64)ti * 8 + k2]) << (8 * k2);
                                    if (!te) break;
                                    if (te & 0x8000000000000000ull) {
                                        if (gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(te & 0xFFFFu));
                                    } else {
                                        u8* in = (u8*)(unsigned long)(base + (u32)te + 2);
                                        addr = find_export(hmod, fnv_a((const char*)in));
                                        if (!addr && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(unsigned long)(void*)in);
                                    }
                                    xvf_wr64(tdst + (u64)ti * 8, addr);
#else
                                    u32 te = ld32(tsrc + (u64)ti * 4);
                                    if (!te) break;
                                    if (te & 0x80000000u) {
                                        if (gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(te & 0xFFFFu));
                                    } else {
                                        u8* in = (u8*)(unsigned long)(base + te + 2);
                                        addr = find_export(hmod, fnv_a((const char*)in));
                                        if (!addr && gpa) addr = (u64)(unsigned long)api2(gpa, hmod, (u64)(unsigned long)(void*)in);
                                    }
                                    xvf_wr32(tdst + (u64)ti * 4, (u32)addr);
#endif
                                    ti++;
                                    if (ti > 0x10000) break;
                                }
                            }
                        }
                    }
                }
                di++;
            }
        }
    }
    xvf_dbg(k32, 'I', 'M', '.');
    /* DllMain(base, DLL_PROCESS_ATTACH, NULL) — call_dm=0 (A21 ScyllaHide
       temiz-ntdll map) DllMain ATLANIR: temiz kopya yalnizca bayt-kaynagi */
    if (ep_rva && call_dm) {
        ep = (u64)(unsigned long)(base + ep_rva);
        api3(ep, (u64)(unsigned long)base, 1, 0);
    }
    xvf_dbg(k32, 'D', call_dm ? 'M' : 's', '.');
    return base;
}

/* ============================================================
   1.2.2-A17: VIRTUAL REGISTRY (XFLAG_VREG 0x80) — UO/VMP 1:1 semantik
   UO: ftRegistry runtime fonksiyonu + roRegistry (core.cc Prepare).
   XProtect: korumali process icinde Reg* API kesmesi — store'da TANIMLI
   anahtarlar bellek-icinden servis edilir; digerleri ORIJINAL API'ye gider.
   - Engine: act=4 (faRegStore) XVF girisi — "XVFR" store blogu.
   - Runtime: host IAT'u isim-hash ile taranir; Reg* thunk'lari handler'lara
     repoint, orijinaller kaydedilir. Tablo/store = VirtualAlloc scratch
     (memprot EXECUTE_READ .vmp0 ile cakisma yok).
   ============================================================ */
#define XH_REGOPENKEYEXA   0x0DF6A51Cu  /* "RegOpenKeyExA"   */
#define XH_REGOPENKEYEXW   0xFBF688C6u  /* "RegOpenKeyExW"   */
#define XH_REGQUERYVALUEEXA 0x9027EB7Cu /* "RegQueryValueExA"*/
#define XH_REGQUERYVALUEEXW 0x7E27CF26u /* "RegQueryValueExW"*/
#define XH_REGCLOSEKEY     0x1242154Au  /* "RegCloseKey"     */
#define XH_REGENUMKEYEXA   0xE5763A29u  /* "RegEnumKeyExA"   */
#define XH_REGENUMKEYEXW   0xD776241Fu  /* "RegEnumKeyExW"   */
#define XH_REGCREATEKEYEXA 0xF6ED1B50u  /* "RegCreateKeyExA" */
#define XH_REGCREATEKEYEXW 0xECED0B92u  /* "RegCreateKeyExW" */
#define XH_REGSETVALUEEXA  0xDA5113DCu  /* "RegSetValueExA"  */
#define XH_REGSETVALUEEXW  0xC850F786u  /* "RegSetValueExW"  */
#define XH_REGDELETEKEYA   0x429F0FB0u  /* "RegDeleteKeyA"   */
#define XH_REGQUERYINFOKEYA 0x95CB6FCDu /* "RegQueryInfoKeyA" (A17-iz2) */
#define XH_REGQUERYINFOKEYW 0x7FCB4D2Bu /* "RegQueryInfoKeyW" (A17-iz2) */
#define XH_REGDELETEKEYW   0x389EFFF2u  /* "RegDeleteKeyW"   */
#define XH_REGENUMVALUEA   0x7F1D5040u  /* "RegEnumValueA"   */
#define XH_REGENUMVALUEW   0x951D72E2u  /* "RegEnumValueW"   */

#define XVR_MAGIC   0x52465658u   /* 'XVFR' */
#define XVR_HKEY_BASE 0x58F00100u /* sahte HKEY araligi (pid tasiyici) */
#define XVR_MAXENT    64
#define XVR_MAXPATH   512

typedef struct {
    u32 pid;                                  /* path-table indeksi */
    u32 nlen; const u8* name;                 /* deger adi (ANSI) */
    u32 type; u32 dlen; const u8* data;
} XvrEnt;

typedef struct {
    u32 plen; u8 path[XVR_MAXPATH];           /* tam yol: "HKCU\Software\X" */
} XvrPath;

static u64*     xvr_orig = 0;                 /* orijinal API adresleri —
                                                 SCRATCH pointer (adres-alma
                                                 mutlak-imm32 YASAK) */
static XvrEnt*  xvr_ent = 0;                  /* SCRATCH icinde (memprot guvenli) */
static XvrPath* xvr_path = 0;                 /* SCRATCH icinde */
static u32      xvr_nent = 0, xvr_npath = 0;
static u64      xvr_mem = 0;                  /* scratch blok */
static u32      xvr_memsz = 0;
static int      xvr_iat_done = 0;

#define vr_is_fake(h) ((h) >= (u64)XVR_HKEY_BASE && ((h) - (u64)XVR_HKEY_BASE) < (u64)xvr_npath)
static u32 vr_plen(const u8* s) { u32 n = 0; while (n < XVR_MAXPATH && s[n]) n++; return n; }
static u32 vr_alen(const char* s) { u32 n = 0; while (s[n]) n++; return n; }

/* buyuk/kucuk duyarsiz karsilastirma (ANSI) */
static int vr_nicmp(const u8* a, const u8* b, u32 n) {
    u32 i;
    for (i = 0; i < n; i++) {
        u32 ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32u;
        if (cb >= 'A' && cb <= 'Z') cb += 32u;
        if (ca != cb) return (int)(ca - cb);
    }
    return 0;
}
/* wide -> ansi (ASCII dusus) */
static u32 vr_wtoa(const u16* w, u32 maxn, char* out, u32 cap) {
    u32 i;
    for (i = 0; i < maxn && i + 1 < cap; i++) {
        u16 c = w[i];
        if (!c) break;
        out[i] = (char)(c & 0xFF);
    }
    out[i] = 0;
    return i;
}

/* pid bul (yoksa 0xFFFFFFFF) */
static u32 vr_path_pid(const u8* path, u32 plen) {
    u32 i;
    for (i = 0; i < xvr_npath; i++)
        if (xvr_path[i].plen == plen && !vr_nicmp(xvr_path[i].path, path, plen))
            return i;
    return 0xFFFFFFFFu;
}
static u32 vr_path_add(const u8* path, u32 plen) {
    u32 p = vr_path_pid(path, plen);
    if (p != 0xFFFFFFFFu) return p;
    if (xvr_npath >= XVR_MAXENT || plen >= XVR_MAXPATH) return 0xFFFFFFFFu;
    {
        u32 i;
        for (i = 0; i < plen; i++) xvr_path[xvr_npath].path[i] = path[i];
        xvr_path[xvr_npath].path[plen] = 0;
        xvr_path[xvr_npath].plen = plen;
        xvr_npath++;
        return xvr_npath - 1;
    }
}
/* pid'e KOK yol dizisi (yalniz okuma) */
static const u8* vr_pid_path(u32 pid, u32* plen) {
    if (pid >= xvr_npath) return 0;
    *plen = xvr_path[pid].plen;
    return xvr_path[pid].path;
}

/* hKey (kok sabiti YA DA sahte HKEY) + subkey -> tam yol */
static u32 vr_join(u64 hKey, const char* sub, u8* out) {
    /* A17-iz FIX: statik-const dizi (hives[]) -fno-pie'da degisken-index'te
       mutlak-disp32 uretir -> YASAK (rodata kurali). Kok adi VP4 ile. */
    u32 n = 0, i;
    u32 root = (u32)(hKey & 0xFFFFFFFFull);      /* x64: gercek kok sabiti
                                                    0xFFFFFFFF80000001 —
                                                    alt-32 normalizasyonu */
    if (vr_is_fake(hKey)) {
        u32 pl = 0;
        const u8* pp = vr_pid_path((u32)(hKey - (u64)XVR_HKEY_BASE), &pl);
        if (!pp) return 0;
        for (i = 0; i < pl && n + 1 < XVR_MAXPATH; i++) out[n++] = pp[i];
    } else {
        char hn[8]; u32 hl = 0;
        switch (root) {
        case 0x80000000u: VP4(hn, 0, A4('H','K','C','R')); hn[4] = 0; hl = 4; break;
        case 0x80000001u: VP4(hn, 0, A4('H','K','C','U')); hn[4] = 0; hl = 4; break;
        case 0x80000002u: VP4(hn, 0, A4('H','K','L','M')); hn[4] = 0; hl = 4; break;
        case 0x80000003u: VP4(hn, 0, A4('H','K','U',0));   hn[4] = 0; hl = 3; break;
        case 0x80000005u: VP4(hn, 0, A4('H','K','C','C')); hn[4] = 0; hl = 4; break;
        default: return 0;
        }
        for (i = 0; i < hl && n + 1 < XVR_MAXPATH; i++) out[n++] = (u8)hn[i];
    }
    if (sub && sub[0]) {
        if (n + 1 < XVR_MAXPATH) out[n++] = '\\';
        for (i = 0; sub[i] && n + 1 < XVR_MAXPATH; i++) out[n++] = (u8)sub[i];
    }
    out[n] = 0;
    return n;
}

/* (pid, deger-adi) -> giris; defval: NULL/"" = varsayilan deger */
static u32 vr_find(u32 pid, const char* name) {
    u32 i;
    u32 nl = name ? vr_alen(name) : 0;
    for (i = 0; i < xvr_nent; i++) {
        if (xvr_ent[i].pid != pid) continue;
        if (xvr_ent[i].nlen != nl) continue;
        if (nl && vr_nicmp(xvr_ent[i].name, (const u8*)name, nl)) continue;
        return i;
    }
    return 0xFFFFFFFFu;
}

/* orijinal cagri (stdcall/x64 c-cast) */
#define VRCALL(idx, ...) ((u32 (*)(u64, ...))xvr_orig[idx])(__VA_ARGS__)

/* ---------- handler'lar ---------- */
static void vr_dbgq(u64 k32, u64 v) {
    xvf_dbg(k32, (char)('0' + ((v >> 4) & 15)), (char)('0' + (v & 15)), '.');
    xvf_dbg(k32, (char)('0' + ((v >> 36) & 15)), (char)('0' + ((v >> 32) & 15)), '.');
}
static u32 vr_RegOpenKeyExA(u64 hKey, const char* sub, u32 opt, u32 sam, u64 phk) {
    (void)opt; (void)sam;
    {   /* A17-iz3: sub pointer 32-36 bit nibble izi */
        u64 k32p = peb_module(XH_KERNEL32);
        if (k32p && sub) {
            xvf_dbg(k32p, 'Q', (char)('0' + (((unsigned long)(unsigned long long)sub >> 4) & 15)),
                    (char)('0' + (((unsigned long)(unsigned long long)sub >> 0) & 15)));
            xvf_dbg(k32p, 'Q', (char)('0' + (((unsigned long)(unsigned long long)sub >> 36) & 15)),
                    (char)('0' + (((unsigned long)(unsigned long long)sub >> 32) & 15)));
        }
    }
    if (xvr_mem && sub) {
        u8 fp[XVR_MAXPATH];
        u32 fl = vr_join(hKey, sub, fp);
        if (fl) {
            u32 pi = vr_path_pid(fp, fl);
            if (pi == 0xFFFFFFFFu) {
                /* alt anahtar tanimli mi? (path+\\ oneki) */
                u32 i, sl = fl;
                for (i = 0; i < xvr_npath; i++) {
                    if (xvr_path[i].plen > sl + 1 &&
                        !vr_nicmp(xvr_path[i].path, fp, sl) &&
                        xvr_path[i].path[sl] == '\\') { pi = vr_path_add(fp, fl); break; }
                }
            }
            if (pi != 0xFFFFFFFFu && phk) {
                *(u32*)(unsigned long)phk = (u32)(XVR_HKEY_BASE + pi);
                return 0;                                     /* ERROR_SUCCESS */
            }
        }
    }
    return (u32)VRCALL(0, hKey, (u64)(unsigned long)(void*)sub, (u64)opt, (u64)sam, phk);
}
static u32 vr_RegOpenKeyExW(u64 hKey, const u16* sub, u32 opt, u32 sam, u64 phk) {
    (void)opt; (void)sam;
    if (xvr_mem && sub) {
        char sa[256];
        if (vr_wtoa(sub, 255, sa, 256)) return vr_RegOpenKeyExA(hKey, sa, opt, sam, phk);
    }
    return (u32)VRCALL(1, hKey, (u64)(unsigned long)(void*)sub, (u64)opt, (u64)sam, phk);
}
static u32 vr_RegQueryValueExA(u64 hKey, const char* vname, u64 res, u64 ptype, u64 pdata, u64 pcb) {
    (void)res;
    if (xvr_mem && vr_is_fake(hKey)) {
        u32 pi = (u32)(hKey - (u64)XVR_HKEY_BASE);
        u32 ei = vr_find(pi, vname);
        if (ei != 0xFFFFFFFFu) {
            u32 t = xvr_ent[ei].type, d = xvr_ent[ei].dlen;
            if (ptype) *(u32*)(unsigned long)ptype = t;
            if (pcb) {
                u32 cap = *(u32*)(unsigned long)pcb;
                *(u32*)(unsigned long)pcb = d;
                if (pdata && cap >= d) {
                    u8* dst = (u8*)(unsigned long)pdata;
                    const u8* src = xvr_ent[ei].data;
                    u32 k;
                    for (k = 0; k < d; k++) dst[k] = src[k];
                    return 0;
                }
            }
            return 234u;                                       /* ERROR_MORE_DATA */
        }
        if (hKey >= (u64)XVR_HKEY_BASE && vname) return 2u;    /* ERROR_FILE_NOT_FOUND */
    }
    return (u32)VRCALL(2, hKey, (u64)(unsigned long)(void*)vname, res, ptype, pdata, pcb);
}
static u32 vr_RegQueryValueExW(u64 hKey, const u16* vname, u64 res, u64 ptype, u64 pdata, u64 pcb) {
    if (xvr_mem && vr_is_fake(hKey)) {
        char sa[256];
        vr_wtoa(vname, 255, sa, 256);
        return vr_RegQueryValueExA(hKey, sa, res, ptype, pdata, pcb);
    }
    return (u32)VRCALL(3, hKey, (u64)(unsigned long)(void*)vname, res, ptype, pdata, pcb);
}
static u32 vr_RegCloseKey(u64 hKey) {
    if (xvr_mem && vr_is_fake(hKey))
        return 0;
    return (u32)VRCALL(4, hKey);
}
static u32 vr_RegQueryInfoKeyA(u64 hKey, char* cls, u64 pc, u64 res, u64 pn, u64 pm, u64 pmx, u64 pv, u64 pvx, u64 pd, u64 pf) {
    (void)cls; (void)pc; (void)res; (void)pm; (void)pmx; (void)pvx; (void)pf;
    if (xvr_mem && vr_is_fake(hKey)) {
        u32 pi = (u32)(hKey - (u64)XVR_HKEY_BASE), pl = 0;
        const u8* pp = vr_pid_path(pi, &pl);
        u32 nsub = 0, nval = 0, i;
        if (pp) {
            for (i = 0; i < xvr_npath; i++) {
                u32 j;
                if (xvr_path[i].plen <= pl + 1) continue;
                if (vr_nicmp(xvr_path[i].path, pp, pl)) continue;
                if (xvr_path[i].path[pl] != '\\') continue;
                {   /* ayrik alt-segment sayimi */
                    int dup = 0;
                    for (j = 0; j < i; j++) {
                        u32 s2 = pl + 1;
                        if (xvr_path[j].plen <= pl + 1) continue;
                        if (vr_nicmp(xvr_path[j].path, pp, pl)) continue;
                        if (xvr_path[j].path[pl] != '\\') continue;
                        while (s2 < xvr_path[j].plen && xvr_path[j].path[s2] != '\\') s2++;
                        if (!vr_nicmp(xvr_path[j].path + pl + 1, xvr_path[i].path + pl + 1, s2 - pl - 1)) { dup = 1; break; }
                    }
                    if (!dup) nsub++;
                }
            }
            for (i = 0; i < xvr_nent; i++) if (xvr_ent[i].pid == pi) nval++;
            if (pn) *(u32*)(unsigned long)pn = nsub;
            if (pv) *(u32*)(unsigned long)pv = nval;
            return 0;
        }
        return 2u;
    }
    return (u32)VRCALL(15, hKey, (u64)(unsigned long)(void*)cls, pc, res, pn, pm, pmx, pv, pvx, pd, pf);
}
static u32 vr_RegQueryInfoKeyW(u64 hKey, u16* cls, u64 pc, u64 res, u64 pn, u64 pm, u64 pmx, u64 pv, u64 pvx, u64 pd, u64 pf) {
    if (xvr_mem && vr_is_fake(hKey)) {
        char ca[8];
        u32 r = vr_RegQueryInfoKeyA(hKey, ca, pc, res, pn, pm, pmx, pv, pvx, pd, pf);
        (void)ca;
        return r;
    }
    return (u32)VRCALL(16, hKey, (u64)(unsigned long)(void*)cls, pc, res, pn, pm, pmx, pv, pvx, pd, pf);
}
static u32 vr_RegCreateKeyExA(u64 hKey, const char* sub, u32 res, char* cls, u32 opt, u32 sam, u64 sa, u64 phk, u64 pd) {
    (void)res; (void)cls; (void)opt; (void)sam; (void)sa;
    if (xvr_mem && sub) {
        u8 fp[XVR_MAXPATH];
        u32 fl = vr_join(hKey, sub, fp);
        if (fl) {
            u32 pi = vr_path_add(fp, fl);                      /* sanal olustur */
            if (pi != 0xFFFFFFFFu) {
                if (phk) *(u32*)(unsigned long)phk = (u32)(XVR_HKEY_BASE + pi);
                if (pd) *(u32*)(unsigned long)pd = 1u;         /* REG_CREATED_NEW_KEY */
                return 0;
            }
        }
    }
    return (u32)VRCALL(5, hKey, (u64)(unsigned long)(void*)sub, (u64)res, (u64)(unsigned long)(void*)cls,
                       (u64)opt, (u64)sam, sa, phk, pd);
}
static u32 vr_RegCreateKeyExW(u64 hKey, const u16* sub, u32 res, u16* cls, u32 opt, u32 sam, u64 sa, u64 phk, u64 pd) {
    if (xvr_mem && sub) {
        char sa2[256];
        if (vr_wtoa(sub, 255, sa2, 256)) {
            char sc2[128];
            if (cls) vr_wtoa(cls, 127, sc2, 128);
            return vr_RegCreateKeyExA(hKey, sa2, res, cls ? sc2 : 0, opt, sam, sa, phk, pd);
        }
    }
    return (u32)VRCALL(6, hKey, (u64)(unsigned long)(void*)sub, (u64)res, (u64)(unsigned long)(void*)cls,
                       (u64)opt, (u64)sam, sa, phk, pd);
}
static u32 vr_RegSetValueExA(u64 hKey, const char* vname, u32 res, u32 type, u64 data, u32 cb) {
    (void)res;
    if (xvr_mem && vr_is_fake(hKey)) {
        u32 pi = (u32)(hKey - (u64)XVR_HKEY_BASE);
        u32 ei = vr_find(pi, vname);
        if (ei != 0xFFFFFFFFu && cb && cb <= xvr_ent[ei].dlen) {
            u8* dst = (u8*)(unsigned long)(void*)xvr_ent[ei].data;
            const u8* src = (const u8*)(unsigned long)data;
            u32 k;
            for (k = 0; k < cb; k++) dst[k] = src[k];
            xvr_ent[ei].type = type;
            xvr_ent[ei].dlen = cb;                             /* yerinde guncelle */
            return 0;
        }
        return 0;                                              /* sanal yazi yutulur */
    }
    return (u32)VRCALL(7, hKey, (u64)(unsigned long)(void*)vname, (u64)res, (u64)type, data, (u64)cb);
}
static u32 vr_RegSetValueExW(u64 hKey, const u16* vname, u32 res, u32 type, u64 data, u32 cb) {
    if (xvr_mem && vr_is_fake(hKey)) {
        char sa[256];
        vr_wtoa(vname, 255, sa, 256);
        return vr_RegSetValueExA(hKey, sa, res, type, data, cb);
    }
    return (u32)VRCALL(8, hKey, (u64)(unsigned long)(void*)vname, (u64)res, (u64)type, data, (u64)cb);
}
static u32 vr_RegEnumKeyExA(u64 hKey, u32 idx, char* name, u64 pcb, u64 res, char* cls, u64 pcbc, u64 ft) {
    (void)res; (void)cls; (void)pcbc; (void)ft;
    if (xvr_mem && vr_is_fake(hKey)) {
        u32 pi = (u32)(hKey - (u64)XVR_HKEY_BASE), pl = 0;
        const u8* pp = vr_pid_path(pi, &pl);
        if (pp) {
            /* pi yolunun ayrik alt-segmentleri */
            u32 i, cur = 0;
            for (i = 0; i < xvr_npath; i++) {
                u32 j;
                if (xvr_path[i].plen <= pl + 1) continue;
                if (vr_nicmp(xvr_path[i].path, pp, pl)) continue;
                if (xvr_path[i].path[pl] != '\\') continue;
                /* seg = path[pl+1 .. sonraki \\|son] */
                {
                    u32 seg = pl + 1, seglen;
                    while (seg < xvr_path[i].plen && xvr_path[i].path[seg] != '\\') seg++;
                    seglen = seg - (pl + 1);
                    /* ayriklik: ayni segment daha once mi? (mini tarama) */
                    {
                        int dup = 0;
                        for (j = 0; j < i; j++) {
                            u32 s2 = pl + 1, s2len;
                            if (xvr_path[j].plen <= pl + 1) continue;
                            if (vr_nicmp(xvr_path[j].path, pp, pl)) continue;
                            if (xvr_path[j].path[pl] != '\\') continue;
                            while (s2 < xvr_path[j].plen && xvr_path[j].path[s2] != '\\') s2++;
                            s2len = s2 - (pl + 1);
                            if (s2len == seglen && !vr_nicmp(xvr_path[j].path + pl + 1,
                                                             xvr_path[i].path + pl + 1, seglen)) { dup = 1; break; }
                        }
                        if (dup) continue;
                        if (cur == idx) {
                            if (name && pcb) {
                                u32 cap = *(u32*)(unsigned long)pcb;
                                *(u32*)(unsigned long)pcb = seglen;
                                if (cap > seglen) {
                                    u32 k;
                                    for (k = 0; k < seglen; k++) name[k] = (char)xvr_path[i].path[pl + 1 + k];
                                    name[seglen] = 0;
                                    return 0;
                                }
                                return 122u;                   /* ERROR_INSUFFICIENT_BUFFER */
                            }
                        }
                        cur++;
                    }
                }
            }
            return 259u;                                       /* ERROR_NO_MORE_ITEMS */
        }
    }
    return (u32)VRCALL(9, hKey, (u64)idx, (u64)(unsigned long)(void*)name, pcb, res,
                       (u64)(unsigned long)(void*)cls, pcbc, ft);
}
static u32 vr_RegEnumKeyExW(u64 hKey, u32 idx, u16* name, u64 pcb, u64 res, u16* cls, u64 pcbc, u64 ft) {
    if (xvr_mem && vr_is_fake(hKey)) {
        char sa[256];
        if (vr_RegEnumKeyExA(hKey, idx, sa, (u64)(unsigned long)(void*)&sa[250], res, 0, 0, 0) == 0) {
            u32 n = 0;
            while (sa[n] && n < 248) { name[n] = (u16)(u8)sa[n]; n++; }
            name[n] = 0;
            if (pcb) *(u32*)(unsigned long)pcb = n * 2u;
            return 0;
        }
        return 259u;
    }
    return (u32)VRCALL(10, hKey, (u64)idx, (u64)(unsigned long)(void*)name, pcb, res,
                       (u64)(unsigned long)(void*)cls, pcbc, ft);
}
static u32 vr_RegEnumValueA(u64 hKey, u32 idx, char* name, u64 pcb, u64 res, u64 ptype, u64 pdata, u64 pcbd) {
    (void)res;
    if (xvr_mem && vr_is_fake(hKey)) {
        u32 pi = (u32)(hKey - (u64)XVR_HKEY_BASE);
        /* pid'in degerleri sirala (giris ekleme sirasi) */
        u32 k = 0, i;
        for (i = 0; i < xvr_nent; i++) {
            if (xvr_ent[i].pid != pi) continue;
            if (k == idx) {
                if (name && pcb) {
                    u32 cap = *(u32*)(unsigned long)pcb;
                    *(u32*)(unsigned long)pcb = xvr_ent[i].nlen;
                    if (cap > xvr_ent[i].nlen) {
                        u32 q;
                        for (q = 0; q < xvr_ent[i].nlen; q++) name[q] = (char)xvr_ent[i].name[q];
                        name[xvr_ent[i].nlen] = 0;
                    } else return 122u;
                }
                if (ptype) *(u32*)(unsigned long)ptype = xvr_ent[i].type;
                if (pdata && pcbd) {
                    u32 cap = *(u32*)(unsigned long)pcbd;
                    u8* dst = (u8*)(unsigned long)pdata;
                    u32 q;
                    *(u32*)(unsigned long)pcbd = xvr_ent[i].dlen;
                    for (q = 0; q < xvr_ent[i].dlen && q < cap; q++) dst[q] = xvr_ent[i].data[q];
                }
                return 0;
            }
            k++;
        }
        return 259u;
    }
    return (u32)VRCALL(11, hKey, (u64)idx, (u64)(unsigned long)(void*)name, pcb, res, ptype, pdata, pcbd);
}
static u32 vr_RegEnumValueW(u64 hKey, u32 idx, u16* name, u64 pcb, u64 res, u64 ptype, u64 pdata, u64 pcbd) {
    if (xvr_mem && vr_is_fake(hKey)) {
        char sa[256];
        if (vr_RegEnumValueA(hKey, idx, sa, (u64)(unsigned long)(void*)&sa[250], res, ptype, pdata, pcbd) == 0) {
            u32 n = 0;
            while (sa[n] && n < 248) { name[n] = (u16)(u8)sa[n]; n++; }
            name[n] = 0;
            if (pcb) *(u32*)(unsigned long)pcb = n * 2u;
            return 0;
        }
        return 259u;
    }
    return (u32)VRCALL(12, hKey, (u64)idx, (u64)(unsigned long)(void*)name, pcb, res, ptype, pdata, pcbd);
}
static u32 vr_RegDeleteKeyA(u64 hKey, const char* sub) {
    if (xvr_mem && vr_is_fake(hKey))
        return 0;                                              /* sanal silme yutulur */
    return (u32)VRCALL(13, hKey, (u64)(unsigned long)(void*)sub);
}
static u32 vr_RegDeleteKeyW(u64 hKey, const u16* sub) {
    if (xvr_mem && vr_is_fake(hKey))
        return 0;
    return (u32)VRCALL(14, hKey, (u64)(unsigned long)(void*)sub);
}

#if defined(XRT_IS_X86)
#define VR_STDCALL __attribute__((stdcall))
typedef u32 vru;        /* x86: win32 stack-arg 4B — u64 param YANLIS okur */
/* A17-iz3 FIX: pointer arg x86'da 32-bit, x64'te 64-bit KALMALI —
   (unsigned int)(u32) cast'i x64'te pointer'i KESIYORDI (0x14002A0F0 ->
   0x2A0F0 -> kernelbase fault). */
#define VRPTR(v) ((unsigned long)(unsigned int)(u32)(v))
#else
#define VR_STDCALL
typedef u64 vru;
#define VRPTR(v) ((unsigned long)(unsigned long long)(v))
#endif
/* wrapper'lar VRPTR(...) kullanir */

/* app stdcall -> handler: yigin-duzeni mimariye gore (vru) */
static u32 VR_STDCALL vr_h_OpenA(vru h, vru s, vru o, vru m, vru p) { return vr_RegOpenKeyExA((u64)h, (const char*)(unsigned long)(unsigned long long)(s), (u32)o, (u32)m, (u64)p); }
static u32 VR_STDCALL vr_h_OpenW(vru h, vru s, vru o, vru m, vru p) { return vr_RegOpenKeyExW((u64)h, (const u16*)(unsigned long)(unsigned long long)(s), (u32)o, (u32)m, (u64)p); }
static u32 VR_STDCALL vr_h_QueryA(vru h, vru n, vru r, vru t, vru d, vru c) { return vr_RegQueryValueExA((u64)h, (const char*)(unsigned long)(unsigned long long)(n), (u64)r, (u64)t, (u64)d, (u64)c); }
static u32 VR_STDCALL vr_h_QueryW(vru h, vru n, vru r, vru t, vru d, vru c) { return vr_RegQueryValueExW((u64)h, (const u16*)(unsigned long)(unsigned long long)(n), (u64)r, (u64)t, (u64)d, (u64)c); }
static u32 VR_STDCALL vr_h_Close(vru h) { return vr_RegCloseKey((u64)h); }
static u32 VR_STDCALL vr_h_CreateA(vru h, vru s, vru r, vru c, vru o, vru m, vru sa, vru p, vru d) { return vr_RegCreateKeyExA((u64)h, (const char*)(unsigned long)(unsigned long long)(s), (u32)r, (char*)(unsigned long)(unsigned long long)(c), (u32)o, (u32)m, (u64)sa, (u64)p, (u64)d); }
static u32 VR_STDCALL vr_h_CreateW(vru h, vru s, vru r, vru c, vru o, vru m, vru sa, vru p, vru d) { return vr_RegCreateKeyExW((u64)h, (const u16*)(unsigned long)(unsigned long long)(s), (u32)r, (u16*)(unsigned long)(unsigned long long)(c), (u32)o, (u32)m, (u64)sa, (u64)p, (u64)d); }
static u32 VR_STDCALL vr_h_SetA(vru h, vru n, vru r, vru t, vru d, vru c) { return vr_RegSetValueExA((u64)h, (const char*)(unsigned long)(unsigned long long)(n), (u32)r, (u32)t, (u64)d, (u32)c); }
static u32 VR_STDCALL vr_h_SetW(vru h, vru n, vru r, vru t, vru d, vru c) { return vr_RegSetValueExW((u64)h, (const u16*)(unsigned long)(unsigned long long)(n), (u32)r, (u32)t, (u64)d, (u32)c); }
static u32 VR_STDCALL vr_h_EnumKeyA(vru h, vru i, vru n, vru c, vru r, vru cl, vru cc, vru f) { return vr_RegEnumKeyExA((u64)h, (u32)i, (char*)(unsigned long)(unsigned long long)(n), (u64)c, (u64)r, (char*)(unsigned long)(unsigned long long)(cl), (u64)cc, (u64)f); }
static u32 VR_STDCALL vr_h_EnumKeyW(vru h, vru i, vru n, vru c, vru r, vru cl, vru cc, vru f) { return vr_RegEnumKeyExW((u64)h, (u32)i, (u16*)(unsigned long)(unsigned long long)(n), (u64)c, (u64)r, (u16*)(unsigned long)(unsigned long long)(cl), (u64)cc, (u64)f); }
static u32 VR_STDCALL vr_h_EnumValA(vru h, vru i, vru n, vru c, vru r, vru t, vru d, vru dc) { return vr_RegEnumValueA((u64)h, (u32)i, (char*)(unsigned long)(unsigned long long)(n), (u64)c, (u64)r, (u64)t, (u64)d, (u64)dc); }
static u32 VR_STDCALL vr_h_EnumValW(vru h, vru i, vru n, vru c, vru r, vru t, vru d, vru dc) { return vr_RegEnumValueW((u64)h, (u32)i, (u16*)(unsigned long)(unsigned long long)(n), (u64)c, (u64)r, (u64)t, (u64)d, (u64)dc); }
static u32 VR_STDCALL vr_h_DelA(vru h, vru s) { return vr_RegDeleteKeyA((u64)h, (const char*)(unsigned long)(unsigned long long)(s)); }
static u32 VR_STDCALL vr_h_DelW(vru h, vru s) { return vr_RegDeleteKeyW((u64)h, (const u16*)(unsigned long)(unsigned long long)(s)); }
static u32 VR_STDCALL vr_h_InfoA(vru h, vru c, vru pc, vru r, vru pn, vru pm, vru mx, vru pv, vru px, vru pd, vru pf) { return vr_RegQueryInfoKeyA((u64)h, (char*)(unsigned long)(unsigned long long)(c), (u64)pc, (u64)r, (u64)pn, (u64)pm, (u64)mx, (u64)pv, (u64)px, (u64)pd, (u64)pf); }
static u32 VR_STDCALL vr_h_InfoW(vru h, vru c, vru pc, vru r, vru pn, vru pm, vru mx, vru pv, vru px, vru pd, vru pf) { return vr_RegQueryInfoKeyW((u64)h, (u16*)(unsigned long)(unsigned long long)(c), (u64)pc, (u64)r, (u64)pn, (u64)pm, (u64)mx, (u64)pv, (u64)px, (u64)pd, (u64)pf); }

/* ---------- store cozme (act=4 XVF girisi) ---------- */
static void xvr_load(const u8* blob, u32 blen, u64 k32) {
    u32 i, off;
    xvf_dbg(k32, 'L', '.', '.');
    if (blen < 8 || ld32(blob) != XVR_MAGIC) {
        xvf_dbg(k32, 'H', (char)('0' + ((blob[0] >> 4) & 15)), (char)('0' + (blob[0] & 15)));
        xvf_dbg(k32, 'H', (char)('0' + ((blob[1] >> 4) & 15)), (char)('0' + (blob[1] & 15)));
        xvf_dbg(k32, 'H', (char)('0' + ((blob[2] >> 4) & 15)), (char)('0' + (blob[2] & 15)));
        xvf_dbg(k32, 'H', (char)('0' + ((blob[3] >> 4) & 15)), (char)('0' + (blob[3] & 15)));
        xvf_dbg(k32, 'L', 'M', '!');
        return;
    }
    xvr_nent = ld32(blob + 4);
    if (xvr_nent > XVR_MAXENT) { xvf_dbg(k32, 'L', 'C', '!'); return; }
    {
        /* scratch: blob + isimler(256/giris) + tablolar — tek RWX blok */
        u32 need = blen + 256 * XVR_MAXENT + 24 * 8 +
                   sizeof(XvrEnt) * XVR_MAXENT + sizeof(XvrPath) * XVR_MAXENT + 64;
        u64 va = find_export(peb_module(XH_KERNEL32), XH_VIRTUALALLOC);
        if (!va) return;
        xvr_mem = api4(va, 0, (u64)((need + 0xFFF) & ~0xFFFu), 0x3000u, 0x40u);
        if (!xvr_mem) return;
        xvr_memsz = blen;
        {
            u8* sp = (u8*)(unsigned long)xvr_mem;
            u32 k;
            for (k = 0; k < blen; k++) sp[k] = blob[k];        /* blob kopyasi */
            for (k = 0; k < need - blen; k++) sp[blen + k] = 0;
            xvr_ent  = (XvrEnt*)(unsigned long)(xvr_mem + blen + 256 * XVR_MAXENT);
            xvr_path = (XvrPath*)(unsigned long)(xvr_mem + blen + 256 * XVR_MAXENT +
                                                 sizeof(XvrEnt) * XVR_MAXENT);
            xvr_orig = (u64*)(unsigned long)(xvr_mem + blen + 256 * XVR_MAXENT +
                                             sizeof(XvrEnt) * XVR_MAXENT +
                                             sizeof(XvrPath) * XVR_MAXENT);
            { u32 zq;
              for (zq = 0; zq < 24; zq++) xvr_orig[zq] = 0; }
        }
    }
    off = 8;
    for (i = 0; i < xvr_nent && off + 8 <= blen; i++) {
        u32 pl = ld32(blob + off); off += 4;
        if (off + pl > blen) return;
        {
            u32 nl, ty, dl;
            u32 pid = vr_path_add(blob + off, pl);
            off += pl;
            if (off + 4 > blen) return;
            nl = ld32(blob + off); off += 4;
            if (off + nl > blen) return;
            {
                u32 j, dpos = off;
                u8* np = (u8*)(unsigned long)(xvr_mem + blen);       /* isim alani */
                for (j = 0; j < nl && j < 250; j++) np[(unsigned long)i * 256 + j] = blob[off + j];
                np[(unsigned long)i * 256 + (nl < 250 ? nl : 249)] = 0;
                off += nl;
                if (off + 8 > blen) return;
                ty = ld32(blob + off); off += 4;
                dl = ld32(blob + off); off += 4;
                if (off + dl > blen) return;
                xvr_ent[i].pid = pid;
                xvr_ent[i].nlen = (nl < 250 ? nl : 249);
                xvr_ent[i].name = np + (unsigned long)i * 256;
                xvr_ent[i].type = ty;
                xvr_ent[i].dlen = dl;
                xvr_ent[i].data = (const u8*)(unsigned long)(xvr_mem + dpos);  /* scratch kopyasi */
                off += dl;
            }
        }
    }
    xvf_dbg(k32, 'V', 'R', (char)('0' + (xvr_nent < 10 ? xvr_nent : 9)));
    xvf_dbg(k32, 'V', 'P', (char)('0' + (xvr_npath < 10 ? xvr_npath : 9)));
}

/* ---------- host IAT repoint ---------- */
/* A17-iz FIX: statik-const tablo YASAK (mutlak-disp32). Hash + adres
   switch fonksiyonlari; adresler asm lea rip-relative ("p" constraint). */
static u32 vr_hook_hash(u32 k) {
    /* A17-iz FIX: switch -> GCC CSWTCH rodata tablosu (mutlak-disp32 YASAK).
       if-zinciri + derleyici-donusum engeli. */
    u32 h = 0;
    h ^= (k == 0)  ? XH_REGOPENKEYEXA   : 0;
    h ^= (k == 1)  ? XH_REGOPENKEYEXW   : 0;
    h ^= (k == 2)  ? XH_REGQUERYVALUEEXA : 0;
    h ^= (k == 3)  ? XH_REGQUERYVALUEEXW : 0;
    h ^= (k == 4)  ? XH_REGCLOSEKEY     : 0;
    h ^= (k == 5)  ? XH_REGCREATEKEYEXA : 0;
    h ^= (k == 6)  ? XH_REGCREATEKEYEXW : 0;
    h ^= (k == 7)  ? XH_REGSETVALUEEXA  : 0;
    h ^= (k == 8)  ? XH_REGSETVALUEEXW  : 0;
    h ^= (k == 9)  ? XH_REGENUMKEYEXA   : 0;
    h ^= (k == 10) ? XH_REGENUMKEYEXW   : 0;
    h ^= (k == 11) ? XH_REGENUMVALUEA   : 0;
    h ^= (k == 12) ? XH_REGENUMVALUEW   : 0;
    h ^= (k == 13) ? XH_REGDELETEKEYA   : 0;
    h ^= (k == 14) ? XH_REGDELETEKEYW   : 0;
    h ^= (k == 15) ? XH_REGQUERYINFOKEYA : 0;
    h ^= (k == 16) ? XH_REGQUERYINFOKEYW : 0;
    return h;
}
#define VRSYM(NM) __asm__ volatile ("lea %a1, %0" : "=r"(p) : "p"(&vr_h_##NM))
static u64 vr_hook_addr(u32 k) {
    u64 p = 0;
    switch (k) {
    case 0:  VRSYM(OpenA);    break;
    case 1:  VRSYM(OpenW);    break;
    case 2:  VRSYM(QueryA);   break;
    case 3:  VRSYM(QueryW);   break;
    case 4:  VRSYM(Close);    break;
    case 5:  VRSYM(CreateA);  break;
    case 6:  VRSYM(CreateW);  break;
    case 7:  VRSYM(SetA);     break;
    case 8:  VRSYM(SetW);     break;
    case 9:  VRSYM(EnumKeyA); break;
    case 10: VRSYM(EnumKeyW); break;
    case 11: VRSYM(EnumValA); break;
    case 12: VRSYM(EnumValW); break;
    case 13: VRSYM(DelA);     break;
    case 14: VRSYM(DelW);     break;
    case 15: VRSYM(InfoA);    break;
    case 16: VRSYM(InfoW);    break;
    }
    return p;
}

static u32 xvr_npatch = 0;
static void xrt_vreg_install(const u8* base, u64 k32) {
    u32 pe_off, nsec, optsz, ddir_off, imp_rva;
    u64 vp;
    if (xvr_iat_done || !xvr_mem) return;
    xvr_iat_done = 1;
    xvf_dbg(k32, 'I', 'N', '.');
    if (ld16(base) != 0x5A4D) { xvf_dbg(k32, 'G', '1', '.'); return; }
    pe_off = ld32(base + 0x3C);
    if (ld32(base + pe_off) != 0x4550) { xvf_dbg(k32, 'G', '2', '.'); return; }
#if defined(XRT_IS_X64)
    ddir_off = pe_off + 24 + 112;
#else
    ddir_off = pe_off + 24 + 96;
#endif
    nsec  = ld16(base + pe_off + 6);
    optsz = ld16(base + pe_off + 20);
    imp_rva = ld32(base + ddir_off + 1 * 8);
    vp = find_export(k32, XH_VIRTUALPROTECT);
    if (!imp_rva) { xvf_dbg(k32, 'G', '3', '.'); return; }
    if (!vp) { xvf_dbg(k32, 'G', '4', '.'); return; }
    {
        u8* ip = (u8*)(unsigned long)(base + imp_rva);
        u32 di = 0;
        xvf_dbg(k32, 'W', '.', '.');
        for (;;) {
            u32 oft, name_rva, ft;
            if (di >= 512) break;
            oft = ld32(ip + di * 20 + 0);
            name_rva = ld32(ip + di * 20 + 12);
            ft = ld32(ip + di * 20 + 16);
            if (!oft && !name_rva && !ft) break;
            {
                u8* tsrc = (u8*)(unsigned long)(base + (oft ? oft : ft));
                u8* tdst = (u8*)(unsigned long)(base + ft);
                u32 ti = 0;
                xvf_dbg(k32, 'W', (char)('0' + (di < 10 ? di : 9)), (char)('0' + (ti < 10 ? ti : 9)));
                for (;;) {
#if defined(XRT_IS_X64)
                    u64 te; int k2;
                    for (k2 = 0, te = 0; k2 < 8; k2++) te |= ((u64)tsrc[(u64)ti * 8 + k2]) << (8 * k2);
                    xvf_dbg(k32, 'R', (char)('0' + (ti < 10 ? ti : 9)), (char)('0' + ((te >> 8) & 15)));
                    if (!te) break;
                    if (!(te & 0x8000000000000000ull)) {
                        u32 hh = fnv_a((const char*)(unsigned long)(base + (u32)te + 2));
                        xvf_dbg(k32, 'T', '.', (char)('0' + (ti < 10 ? ti : 9)));
                        u32 k;
                        /* A17-iz FIX: degisken-indexli statik erisim mutlak-disp32
                           uretir (blob .vmp0'da unmapped AV) -> pointer-walk */
                        u64* op = xvr_orig;
                        for (k = 0; k < 17; k++, op++) {
                            if (vr_hook_hash(k) == hh) {
                                u32 oldp = 0;
                                u8* slot = tdst + (u64)ti * 8;
                                if (*op) break;                /* zaten kayitli */
                                /* orijinal adres IAT slotundan (cozulmus) —
                                   INT'teki te name-RVA'dir, ADRES DEGIL! */
                                { u64 cur = 0; int q2;
                                  for (q2 = 0; q2 < 8; q2++) cur |= ((u64)slot[q2]) << (8 * q2);
                                  *op = cur; }
                                if (api4(vp, (u64)(unsigned long)slot, 8, 0x40u, (u64)(unsigned long)&oldp)) {
                                    xvf_wr64(slot, (u64)(unsigned long)vr_hook_addr(k));
                                    if (oldp && oldp != 0x40u)
                                        api4(vp, (u64)(unsigned long)slot, 8, oldp, (u64)(unsigned long)&oldp);
                                    xvr_npatch++;
                                    xvf_dbg(k32, 'P', 'T', (char)('0' + (k < 10 ? k : 9)));
                                }
                                break;
                            }
                        }
                        xvf_dbg(k32, 'K', '.', (char)('0' + (ti < 10 ? ti : 9)));
                    }
#else
                    u32 te = ld32(tsrc + (u64)ti * 4);
                    if (!te) break;
                    if (!(te & 0x80000000u)) {
                        u32 hh = fnv_a((const char*)(unsigned long)(base + te + 2));
                        u32 k;
                        u64* op = xvr_orig;
                        for (k = 0; k < 17; k++, op++) {
                            if (vr_hook_hash(k) == hh) {
                                u32 oldp = 0;
                                u8* slot = tdst + (u64)ti * 4;
                                if (*op) break;
                                *op = ld32(slot);              /* cozulmus IAT degeri */
                                if (api4(vp, (u64)(unsigned long)slot, 4, 0x40u, (u64)(unsigned long)&oldp)) {
                                    xvf_wr32(slot, (u32)(unsigned long)vr_hook_addr(k));
                                    if (oldp && oldp != 0x40u)
                                        api4(vp, (u64)(unsigned long)slot, 4, oldp, (u64)(unsigned long)&oldp);
                                    xvr_npatch++;
                                }
                                break;
                            }
                        }
                    }
#endif
                    ti++;
                    if (ti > 0x8000) break;
                }
            }
            di++;
        }
    }
    xvf_dbg(k32, 'I', 'T', (char)('0' + (xvr_npatch < 10 ? xvr_npatch : 9)));
}


/* ============================================================
   1.2.2-A18: STRING ENCRYPTION (XFLAG_STRENC) — UO/VMP 1:1 semantik:
   korumali kodun TUM referanslari VM'de olan .rdata stringleri diskte
   CFB-sifreli; runtime ILK KAPIDA (CRC sonrasi) VirtualProtect RW +
   yerinde cozer. Motor: 'XSTR' tablosu (cfg+0x60 RVA; CFB k0/k1,
   nonce=tabloRVA): [u32 N][N x (u32 rva, u32 len)]. String anahtari:
   xr_cfb(k0,k1,nonce(rva)) — motor ile birebir.
   ============================================================ */
static void xrt_strenc(u8* cfg, u64 k32, const u8* base) {
    u32 trva = ld32(cfg + XCFG_OFF_STRENC);
    if (!trva) return;
    u32 cfg_rva = ld32(cfg + XCFG_OFF_CFGRVA);
    u64 va_alloc = find_export(k32, XH_VIRTUALALLOC);
    u64 vp = find_export(k32, XH_VIRTUALPROTECT);
    if (!va_alloc) return;
    {
        /* tabloyu scratch'te coz (.vmp0 yazilabilir olmayabilir) */
        u64 scratch = api4(va_alloc, 0, 0x1000u, 0x3000u, 0x04u);
        if (!scratch) return;
        u8* sp = (u8*)(unsigned long)scratch;
        u32 k;
        for (k = 0; k < 0x1000u; k++) sp[k] = base[trva + k];
        xr_cfb(xvf_k0(cfg_rva), xvf_k1(cfg_rva), xvf_nonce(trva), sp, 0x1000u, 1);
        u32 count = ld32(sp);
        if (count > 512u) { api1(find_export(k32, XH_VIRTUALFREE), scratch); return; }
        u32 i;
        /* A20-iz2: reloc kesismesi kontrolu — base != preferred yuklemelerde
           loader reloc yazar; string araligina dusen reloc varsa coZME */
        u32 rrva = ld32(cfg + XCFG_OFF_RELOCRVA);
        u32 rsz = ld32(cfg + XCFG_OFF_RELOCSZ);
        u32 i2;
        for (i = 0; i < count; i++) {
            u32 rva = ld32(sp + 4 + i * 8);
            u32 len = ld32(sp + 4 + i * 8 + 4);
            if (!len || len > 4096u) continue;
            if (rrva && rsz) {
                int overlaps = 0;
                const u8* rp = base + rrva;
                u32 ro = 0;
                while (ro + 8 <= rsz) {
                    u32 page = ld32(rp + ro);
                    u32 bsz = ld32(rp + ro + 4);
                    if (bsz < 8 || ro + bsz > rsz) break;
                    for (i2 = 8; i2 < bsz; i2 += 2) {
                        u16 e = ld16(rp + ro + i2);
                        u32 typ = e >> 12, off = e & 0xFFF;
                        if (!typ) continue;
                        u32 t2 = page + off, tlen = (typ == 10) ? 8u : 4u;
                        if (t2 + tlen > rva && t2 < rva + len) { overlaps = 1; break; }
                    }
                    if (overlaps) break;
                    ro += bsz;
                }
                if (overlaps) continue;   /* bu string dokunulmaz */
            }
            {
                u32 oldp = 0;
                if (vp && api4(vp, (u64)(unsigned long)(base + rva), (u64)len, 0x04u, (u64)(unsigned long)&oldp)) {
                    xr_cfb(xvf_k0(cfg_rva), xvf_k1(cfg_rva), xvf_nonce(rva),
                           (u8*)(unsigned long)(base + rva), len, 1);
                    { u32 tmp2 = 0;
                      api4(vp, (u64)(unsigned long)(base + rva), (u64)len,
                           oldp ? oldp : 0x20u, (u64)(unsigned long)&tmp2); }
                }
            }
        }
        { u64 vf2 = find_export(k32, XH_VIRTUALFREE);
          if (vf2) api1(vf2, scratch); }
    }
}

/* XVF1 blogunu işle — xrt_entry sonunda BİR KEZ çağrılır */
#ifdef XVF_TRACE
#define XVF_TRACE_ON 1
#else
#define XVF_TRACE_ON 0
#endif
static void xrt_vfiles(u8* cfg, u64 k32) {
    u8* hdr = cfg + 0x68;                                     /* VF blogu = cfg'den sonra (A18: cfg 0x68) */
    u32 count, i;
#if defined(XVF_TRACE)
    {   /* DEBUG-PROBE (A16) — ENTER işareti, stack-string (PIC-güvenli);
           YALNIZCA XVF_TRACE derlemesinde (üretimde dosya-yazımı YOK) */
        char pn[16]; volatile char* pp = pn;
        pp[0]='C';pp[1]=':';pp[2]='\\';pp[3]='v';pp[4]='f';pp[5]='r';pp[6]='t';
        pp[7]='.';pp[8]='t';pp[9]='x';pp[10]='t';pp[11]=0;
        {
            u64 cfa_ = find_export(k32, XH_CREATEFILEA);
            u64 wf_ = find_export(k32, XH_WRITEFILE);
            u64 ch_ = find_export(k32, XH_CLOSEHANDLE);
            if (cfa_ && wf_ && ch_) {
                u64 fh = api7(cfa_, (u64)(unsigned long)(void*)pn, 0x40000000u, 0, 0, 2, 0, 0);
                if (fh && fh != (u64)(unsigned long)-1) {
                    char mk[4]; volatile char* mp = mk;
                    mp[0]='E'; mp[1]='N'; mp[2]='\n'; mp[3]=0;
                    u32 wr = 0;
                    api5(wf_, fh, (u64)(unsigned long)(void*)mk, 3, (u64)(unsigned long)&wr, 0);
                    api1(ch_, fh);
                }
            }
        }
    }
#endif
    if (ld32(hdr) != XVF_HDR_MAGIC) { xvf_dbg(k32, 'M', 'X', '.'); return; }   /* 'XVF1' yok */
    count = ld32(hdr + 4);
    xvf_dbg(k32, 'M', 'C', (char)('0' + (count < 10 ? count : 9)));
    if (count > XVF_MAX_FILES) return;
    {
        u32 cfg_rva = ld32(cfg + XCFG_OFF_CFGRVA);
        u64 va_alloc = find_export(k32, XH_VIRTUALALLOC);
        u64 va_free  = find_export(k32, XH_VIRTUALFREE);
        if (!va_alloc) return;
        for (i = 0; i < count; i++) {
            u32 eno = 16 + i * 16;
            u32 name_off = ld32(hdr + eno + 0);
            u32 datao = ld32(hdr + eno + 4);
            u32 dsz = ld32(hdr + eno + 8);
            u32 act = ld32(hdr + eno + 12);
            char name[128];
            u32 nk = xvf_namekey(cfg_rva, i);
            u64 buf;
            xvf_name_dec(hdr, name_off, nk, name, 127);
            if (!dsz || dsz > (u32)XVF_MAX_SIZE) continue;
            buf = api4(va_alloc, 0, (u64)dsz, 0x3000u, 0x04u);
            if (!buf) continue;
            xvf_memcpy((u8*)(unsigned long)buf, hdr + datao, dsz);   /* şifreli ham kopya */
            xr_cfb(xvf_k0(cfg_rva), xvf_k1(cfg_rva), xvf_nonce(datao),
                   (u8*)(unsigned long)buf, dsz, 1);                 /* yerinde çöz */
            xvf_dbg(k32, 'D', (char)('0' + (act < 10 ? act : 9)), (char)('0' + (dsz < 10 ? dsz : (dsz > 99 ? 9 : (dsz / 10)))));
            if (act == 1 || act == 2) {
                /* faLoad (+ faRegister: A17.1 TAM — map edilen modulun
                   DllRegisterServer ihracati bağlanır VE çağrılır; COM
                   self-registration senaryosu UO faRegister 1:1) */
                u64 mapret = xvf_map_pe((const u8*)(unsigned long)buf, dsz, k32);
                xvf_dbg(k32, 'R', 'M', mapret ? '1' : '0');   /* 1.2.3-bisect: map donusu */
                if (act == 2 && mapret) {
                    /* A17.1: DllRegisterServer (fnv_a=0x38bf1ac1) bağla+çağır.
                       mapret = maplenen modul base (xvf_map_pe donusu);
                       find_export ihraç-tablosu yürütmesi PIC-guvenli. */
                    u64 drs = find_export(mapret, 0x38bf1ac1u);
                    xvf_dbg(k32, 'R', 'S', drs ? '1' : '0');  /* 1.2.3-bisect: export bulundu mu */
                    if (drs) {
#if defined(XRT_IS_X64)
                        (void)api0(drs);
#else
                        (void)api0((u32)drs);
#endif
                        xvf_dbg(k32, 'R', 'C', '.');          /* 1.2.3-bisect: cagri dondu */
                    }
                }
#if defined(XVF_TRACE)
                {   /* DEBUG-PROBE (A16) — stack-string (PIC-güvenli) */
                    char pn[16]; volatile char* pp = pn;
                    pp[0]='C';pp[1]=':';pp[2]='\\';pp[3]='v';pp[4]='f';pp[5]='r';pp[6]='t';
                    pp[7]='.';pp[8]='t';pp[9]='x';pp[10]='t';pp[11]=0;
                    u64 cfa_ = find_export(k32, XH_CREATEFILEA);
                    u64 wf_ = find_export(k32, XH_WRITEFILE);
                    u64 ch_ = find_export(k32, XH_CLOSEHANDLE);
                    if (cfa_ && wf_ && ch_) {
                        u64 fh = api7(cfa_, (u64)(unsigned long)(void*)pn,
                                      0x40000000u, 0, 0, 4, 0, 0);
                        if (fh && fh != (u64)(unsigned long)-1) {
                            char mk[4]; volatile char* mp = mk;
                            mp[0] = mapret ? 'K' : 'F'; mp[1] = 'M'; mp[2] = '\n'; mp[3] = 0;
                            u32 wr = 0;
                            api5(wf_, fh, (u64)(unsigned long)(void*)mk, 3,
                                 (u64)(unsigned long)&wr, 0);
                            api1(ch_, fh);
                        }
                    }
                }
#endif
                (void)mapret;
            } else if (act == 4) {
                /* 1.2.2-A17: VIRTUAL REGISTRY store — scratch'e kopyala+parse */
                xvr_load((const u8*)(unsigned long)buf, dsz, k32);
            } else if (act == 3) {                              /* faInstall */
                u64 gtp = find_export(k32, XH_GETTEMPPATHA);
                u64 cfa = find_export(k32, XH_CREATEFILEA);
                u64 wf  = find_export(k32, XH_WRITEFILE);
                u64 ch  = find_export(k32, XH_CLOSEHANDLE);
                u64 lla = find_export(k32, XH_LOADLIBRARYA);
                char path[300];
                if (gtp && cfa && wf && ch && lla) {
                    u32 tl = (u32)api3(gtp, 260, (u64)(unsigned long)(void*)path, 0);
                    if (tl && tl < 240) {
                        u32 q = 0;
                        while (q < 60 && name[q]) { path[tl + q] = name[q]; q++; }
                        path[tl + q] = 0;
                        {
                            u64 fh = api7(cfa, (u64)(unsigned long)(void*)path,
                                          0x40000000u, 0, 0, 2, 0, 0); /* CREATE_ALWAYS */
                            if (fh && fh != (u64)(unsigned long)-1) {
                                u32 written = 0;
                                api5(wf, fh, (u64)(unsigned long)buf, dsz,
                                     (u64)(unsigned long)(void*)&written, 0);
                                api1(ch, fh);
                                api1(lla, (u64)(unsigned long)(void*)path);
                            }
                        }
                    }
                }
            }
            if (va_free) api1(va_free, buf);                   /* ham tamponu bırak */
        }
    }
#ifdef XRT_PROBE
    xvf_dbg(k32, 'S', 'T', '.');   /* strenc bitti */
#endif
    /* 1.2.2-A17: Virtual Registry IAT kesmesi — store kurulduysa BIR KEZ */
    if (ld32(cfg + XCFG_OFF_FLAGS) & XFLAG_VREG)
        xrt_vreg_install((const u8*)(unsigned long)((u64)(unsigned long)cfg -
                         (u64)ld32(cfg + XCFG_OFF_CFGRVA)), k32);
#ifdef XRT_PROBE
    xvf_dbg(k32, 'V', 'R', '.');   /* vreg kuruldu */
#endif
}

/* ============================================================
   1.2.2-A21: SCYLLAHIDE-SEVIYESI TEMIZ-NTDLL KATMANI
   ============================================================
   Kullanici-modu ntdll hook'larina (InlineEAT/IAT hook, Vectored,
   Detours benzeri) karsi UO/ScyllaHide deseninin 1:1 uygulanisi:
     1. ntdll DISKTEN okunur (PEB FullDllName yolu — CreateFileA/ReadFile)
     2. temiz kopya xvf_map_pe2(call_dm=0) ile manuel map edilir
        (DllMain CALISMAZ — kopya yalnizca bayt-kaynagi)
     3. hassas 3 fonksiyonun (NtQueryInformationProcess,
        NtQuerySystemInformation, NtSetInformationProcess) ilk
        STUB_LEN bayti in-memory kopyaya geri yazilir (UNHOOK)
        — VirtualProtect(RWX) -> memcpy -> koruma geri
     4. K8 kontrolu (DebugPort 7 / DebugObjectHandle 30) artik TEMIZ
        kopya uzerinden yapilir — hook'lu API bir kez bile dokunulmaz
   Stub-imza guvesi: x64 "4C 8B D1 B8" (mov r10,rcx; mov eax,ssn) /
   x86 "B8" (mov eax,ssn) yoksa unhook YAPILMAZ (garbage-koruma).
   Donus: 0=temiz/kurulamadi, 1=unhook yapildi, 2=zaten temiz */
#define XH_VIRTUALPROTECT_A21 0x820621F3u
static u32 xrt_ad_scylla(u64 k32, u64* clean_nqip_out) {
    u64 nt = peb_module(XH_NTDLL);
    u64 cfa, rf, ch, va_alloc, vp;
    u64 buf = 0, total = 0, clean = 0;
    u32 i, st;

    *clean_nqip_out = 0;
    if (!nt) return 0;
    cfa = find_export(k32, XH_CREATEFILEA);
    rf  = find_export(k32, XH_READFILE);
    ch  = find_export(k32, XH_CLOSEHANDLE);
    va_alloc = find_export(k32, XH_VIRTUALALLOC);
    vp = find_export(k32, XH_VIRTUALPROTECT_A21);
    if (!cfa || !rf || !ch || !va_alloc || !vp) return 0;

    {   /* ntdll tam yolu (PEB InLoadOrder FullDllName -> ANSI dusus) */
        char path[1056];
        u32 plen;
        u64 h;
        plen = peb_path_for_base((const u8*)(unsigned long)nt, path, 1040);
        if (!plen || plen >= 1040) return 0;
        buf = api4(va_alloc, 0, 0x600000ull, 0x3000u, 0x04u);  /* 6MB RW */
        if (!buf) return 0;
        h = api7(cfa, (u64)(unsigned long)(void*)path, 0x80000000u, 1, 0, 3, 0, 0);
        if (!h || h == (u64)(unsigned long)-1) return 0;
        for (;;) {
            u32 got = 0;
            api5(rf, h, buf + total, 4096, (u64)(unsigned long)(void*)&got, 0);
            if (!got) break;
            total += got;
            if (total + 4096 > 0x600000ull) break;
            if (got < 4096) break;
        }
        api1(ch, h);
        if (total < 0x1000ull) return 0;
        clean = xvf_map_pe2((const u8*)(unsigned long)buf, (u32)total, k32, 0);
        if (!clean) return 0;
    }
    /* --- 3 hassas fonksiyon: unhook + temiz NQIP'i ver --- */
    {
        u32 hs[3]; u32 ni = 0;
        hs[ni++] = XH_NQIP;
        hs[ni++] = XH_NQSI;
        hs[ni++] = XH_NSIP;
        for (i = 0; i < ni; i++) {
            u8* fn = (u8*)(unsigned long)find_export(nt, hs[i]);
            u8* cf = (u8*)(unsigned long)find_export(clean, hs[i]);
            u32 k2, diff = 0;
            if (!fn || !cf) continue;
            /* stub-imza guvesi */
#if defined(XRT_IS_X64)
            if (cf[0] != 0x4C || cf[1] != 0x8B || cf[2] != 0xD1 || cf[3] != 0xB8) continue;
#else
            if (cf[0] != 0xB8) continue;
#endif
            /* A21-GUVE (2026-11-14): unhook YALNIZ gercek inline-hook deseninde
               (E9 jmp rel32 / FF25 jmp [imm]) — wine builtin ntdll diskten
               FARKLIDir (runtime-uretimli stub'lar); kosulsuz unhook wine
               ntdll'sini bozup sonsuz-recursion/stack-overflow verir
               (kanit: vreg_ctl + vreg_prot4). ScyllaHide da ayni deseni arar. */
            if (!(fn[0] == 0xE9 || (fn[0] == 0xFF && fn[1] == 0x25))) continue;
            for (k2 = 0; k2 < 32; k2++) if (fn[k2] != cf[k2]) { diff = 1; break; }
            if (!diff) {
                if (hs[i] == XH_NQIP) *clean_nqip_out = (u64)(unsigned long)cf;
                continue;
            }
            {   /* UNHOOK: PAGE_EXECUTE_READWRITE -> 32B -> geri */
                u32 oldp = 0;
                api4(vp, (u64)(unsigned long)fn, 64, 0x40u,
                     (u64)(unsigned long)(void*)&oldp);
                xvf_memcpy(fn, cf, 32);
                api4(vp, (u64)(unsigned long)fn, 64, oldp,
                     (u64)(unsigned long)(void*)&oldp);
                st = 1;
            }
            if (hs[i] == XH_NQIP) *clean_nqip_out = (u64)(unsigned long)cf;
        }
    }
    if (*clean_nqip_out) return st ? 1 : 2;
    return 0;
}

/* ============================================================
   1.2.2-A20: GLOBAL CHECK DEBUGGER / CHECK VM / CHECK KERNEL DEBUGGER
   ============================================================
   UO parite: UO'nun Check Debugger'i LOADER-seviyesinde GLOBALDIR —
   fonksiyon sanallastirma olmadan da calisir (loader.cc:1810-1827,
   2432). XProtect'te batarya simdiye kadar yalniz VM icindeydi
   (OP_ANTIDBG, fonksiyon-basina). Bu yukleyici-yan kopya xrt_entry
   tek-kurulum noktasinda calisir ve GLOBAL-only koruma saglar.
   UO teknik eslemesi:
     - K1  PEB.BeingDebugged + NtGlobalFlag      (loader.cc 1:1)
     - K8  ProcessDebugPort(7)/DebugObjectHandle(30) (loader.cc:1810)
     - K9  CloseHandle(0xDEADC0DE)               (loader.cc:2432)
     - K5  SystemKernelDebuggerInformation(0x23) (kernel-debugger)
     - K7  CPUID hipervizor bit + vendor dizeleri (checkvm)
   Donus: 0 temiz | 5 antidebug | 6 checkvm | 7 kerneldbg
   (xrt_entry err 1-4 kullanir; 5-7 burada — cikis 0x70+err) */
static u32 xrt_antidebug(u64 k32, u32 flags) {
    /* ---- (K7) CHECK VM: CPUID hipervizor-present + vendor dizeleri ---- */
    if (flags & XFLAG_CHECKVM) {
        u32 a, b, c, d;
#if defined(XRT_IS_X64)
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1));
#else
        __asm__ volatile("pushl %%ebx\n\tcpuid\n\tpopl %%ebx"
                         : "=a"(a), "=c"(c), "=d"(d) : "a"(1) : "memory");
#endif
        if (c & 0x80000000u) return 6;             /* hipervizor icinde */
        /* 1.2.2-A20: hypervisor leaf 0x40000000 vendor taramasi
           (VBOX/KVM/HyperV/Xen/Parallels/VMware — UO checkvm deseni).
           Sabitler LE-dword (ebx,ecx,edx) — rodata YASAK (PIC). */
#if defined(XRT_IS_X64)
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x40000000));
#else
        __asm__ volatile("pushl %%ebx\n\tcpuid\n\tpopl %%ebx"
                         : "=a"(a), "=c"(c), "=d"(d) : "a"(0x40000000) : "memory");
#endif
        if (a) {
            if (b == 0x4b4d564bu && c == 0x564b4d56u && d == 0x0000004du) return 6; /* KVMKVMKVM */
            if (b == 0x7263694du && c == 0x666f736fu && d == 0x76482074u) return 6; /* Microsoft Hv */
            if (b == 0x786f4256u && c == 0x786f4256u && d == 0x786f4256u) return 6; /* VBoxVBoxVBox */
            if (b == 0x206c7270u && c == 0x65707968u && d == 0x00002076u) return 6; /* prl hyperv  */
            if (b == 0x566e6558u && c == 0x65584d4du && d == 0x4d4d566eu) return 6; /* XenVMMXenVMM */
            if (b == 0x61774d56u && c == 0x4d566572u && d == 0x65726177u) return 6; /* VMwareVMware */
        }
    }
    /* ---- (K1) PEB.BeingDebugged + NtGlobalFlag ---- */
    {
        u64 peb = peb_addr();
        if (peb) {
            u8* p = (u8*)(unsigned long)peb;
#if defined(XRT_IS_X64)
            if (p[2] || (ld32(p + 0xBC) & 0x70)) return 5;
#else
            if (p[2] || (ld32(p + 0x68) & 0x70)) return 5;
#endif
        }
    }
    /* ---- (K8) ProcessDebugPort(7) + ProcessDebugObjectHandle(30) ----
       UO loader.cc:1810-1827 1:1; NTSTATUS isaret-genisletme (A8 dersi) */
    {
        u64 nt = peb_module(XH_NTDLL);
        /* A21: temiz-ntdll map + unhook; kontrol TEMIZ kopya uzerinden */
        {
            u64 cnq = 0;
            u32 sc = xrt_ad_scylla(k32, &cnq);
            if (cnq) {
                u64 dbo = 0;
#if defined(XRT_IS_X64)
                i64 st2 = (i64)(int)(u32)api5(cnq, 0xFFFFFFFFFFFFFFFEull, 7,
                                              (u64)(unsigned long)(void*)&dbo, 8, 0);
#else
                i64 st2 = (i64)(long)api5(cnq, 0xFFFFFFFFu, 7,
                                          (u32)(unsigned long)(void*)&dbo, 8, 0);
#endif
                if (st2 >= 0 && dbo != 0) return 5;
                dbo = 0;
#if defined(XRT_IS_X64)
                st2 = (i64)(int)(u32)api5(cnq, 0xFFFFFFFFFFFFFFFEull, 30,
                                          (u64)(unsigned long)(void*)&dbo, 8, 0);
#else
                st2 = (i64)(long)api5(cnq, 0xFFFFFFFFu, 30,
                                      (u32)(unsigned long)(void*)&dbo, 8, 0);
#endif
                if (st2 >= 0 && dbo != 0) return 5;
            }
            (void)sc;
        }
        if (nt) {
            u64 nqip = find_export(nt, XH_NQIP);
            if (nqip) {
                u64 dbo = 0;
#if defined(XRT_IS_X64)
                i64 st = (i64)(int)(u32)api5(nqip, 0xFFFFFFFFFFFFFFFEull, 7,
                                             (u64)(unsigned long)(void*)&dbo, 8, 0);
#else
                i64 st = (i64)(long)api5(nqip, 0xFFFFFFFFu, 7,
                                         (u32)(unsigned long)(void*)&dbo, 8, 0);
#endif
                if (st >= 0 && dbo != 0) return 5;
                dbo = 0;
#if defined(XRT_IS_X64)
                st = (i64)(int)(u32)api5(nqip, 0xFFFFFFFFFFFFFFFEull, 30,
                                         (u64)(unsigned long)(void*)&dbo, 8, 0);
#else
                st = (i64)(long)api5(nqip, 0xFFFFFFFFu, 30,
                                     (u32)(unsigned long)(void*)&dbo, 8, 0);
#endif
                if (st >= 0) return 5;
            }
            /* ---- (K5) SystemKernelDebuggerInformation (0x23) ---- */
            if (flags & XFLAG_KDBG) {
                u64 nqsi = find_export(nt, XH_NQSI);
                if (nqsi) {
                    u8 ib[16];
                    u32 rl = 0;
                    i64 st;
                    ib[0] = 0; ib[1] = 0;
#if defined(XRT_IS_X64)
                    st = (i64)(int)(u32)api4(nqsi, 0x23, (u64)(unsigned long)(void*)ib, 2,
                                             (u64)(unsigned long)(void*)&rl);
#else
                    st = (i64)(long)api4(nqsi, 0x23, (u32)(unsigned long)(void*)ib, 2,
                                         (u32)(unsigned long)(void*)&rl);
#endif
                    if (st >= 0 && ib[0] != 0 && ib[1] == 0) return 7;
                }
            }
        }
    }
    /* ---- (K9) CloseHandle(0xDEADC0DE) — UO loader.cc:2432 1:1 ---- */
    if (flags & XFLAG_ANTIDBG) {
        u64 ch = find_export(k32, XH_CLOSEHANDLE);
        if (ch) {
#if defined(XRT_IS_X64)
            if (api1(ch, 0xDEADC0DEull)) return 5;
#else
            if (api1(ch, 0xDEADC0DEu)) return 5;
#endif
        }
        /* ---- A21-uzanti: ProcessInstrumentationCallback sifirlama
           (UO teknik-2: NtSetInformationProcess(-1, 0x40, NULL, 0)) —
           KALDIRILDI (2026-11-14 kanit: wine 10.0'da NtSetInformationProcess
           (0x40) fixme-stub x3 + virtual_setup_exception STACK OVERFLOW
           (vreg_ctl rc=3, vreg_kanit full-scan) — wine'in callback
           mekanizmasi cagriyi yeniden tetikliyor. Gercek Windows'ta
           A21+2 olarak planlandi; wine-guvenli yol: temiz-ntdll unhook
           yeterli (xrt_ad_scylla). */
    }
    return 0;
}

u32 xrt_entry(void* cfgp) {
    u8* cfg = (u8*)cfgp;
    u32 flags;
    u64 cfgva;
    u32 cfg_rva;
    const u8* base;
    u64 k32;
    u32 err = 0;
#ifdef XRT_PROBE
    { u64 kk = peb_module(XH_KERNEL32); xvf_dbg(kk, 'E', '1', '.'); }
#endif

#if defined(XVF_TRACE)
    {   /* DEBUG-PROBE-ENTRY (A16): xrt_entry cagrildi mi? stack-string PIC;
           YALNIZCA XVF_TRACE derlemesinde — üretimde dosya-yazımı YOK */
        u64 k32p = peb_module(XH_KERNEL32);
        if (k32p) {
            char pn[16]; volatile char* pp = pn;
            pp[0]='C';pp[1]=':';pp[2]='\\';pp[3]='v';pp[4]='f';pp[5]='r';pp[6]='t';
            pp[7]='.';pp[8]='t';pp[9]='x';pp[10]='t';pp[11]=0;
            u64 cfa_ = find_export(k32p, XH_CREATEFILEA);
            u64 wf_ = find_export(k32p, XH_WRITEFILE);
            u64 ch_ = find_export(k32p, XH_CLOSEHANDLE);
            if (cfa_ && wf_ && ch_) {
                u64 fh = api7(cfa_, (u64)(unsigned long)(void*)pn, 0x40000000u, 0, 0, 4, 0, 0);
                if (fh && fh != (u64)(unsigned long)-1) {
                    u64 poslo = 0; /* OPEN_ALWAYS + WriteFile at FILE_END atlanir — kisaca yazi */
                    char mk[4]; volatile char* mp = mk;
                    mp[0]='X'; mp[1]='R'; mp[2]='T'; mp[3]=0;
                    u32 wr = 0;
                    (void)poslo;
                    api5(wf_, fh, (u64)(unsigned long)(void*)mk, 3, (u64)(unsigned long)&wr, 0);
                    api1(ch_, fh);
                }
            }
        }
    }
#endif
    if (ld32(cfg + XCFG_OFF_MAGIC) != XCFG_MAGIC) return 0;
    flags = ld32(cfg + XCFG_OFF_FLAGS);
    if (ld32(cfg + XCFG_OFF_STATE)) return 0;
    /* 1.2.2-A11-v3: state yazimi ASAGIDAKI MEMPROT penceresinde yapilir —
       memprot-yalin kipte cfg (.vmp0 EXECUTE_READ, loader) yazilamazdir;
       cfg sayfasi gecici RW'ye alinir (VirtualProtect), state=1 yazilir,
       eski koruma dondurulur. Stub'in state kilidi sonraki cagrilarida
       xrt_entry'yi tamamen atlar (tek-kurulum garantisini STUB verir). */

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

    // --- 1.2.2-A11: IC MEMORY PROTECTION kurulumu (tek-sefer, pencere) ---
    /* Tasarim: memprot-yalin kipte .vmp0 LOADER tarafindan EXECUTE_READ
       map edilir (engine chars 0x60000020) — kullanici raporundaki
       "jmp'in gotturdugu yer" (.vmp0 stub) disk-seviyesinde korumali.
       Runtime: cfg sayfasi gecici RW'ye alinir; state==0 ise (a) ilk-chance
       VEH kurulur (kod-bolumune YAZMA AV = tamper -> ExitProcess(0x75)),
       (b) .text sayfalari VirtualProtect ile guclenir, (c) state=1 yazilir,
       eski koruma dondurulur. Stub state kilidi sonraki cagrilarda
       xrt_entry'yi hic cagirmaz (sifir-maliyet, tek-kurulum garantisi). */
    if (flags & XFLAG_MEMPROT) {
        u64 vp0 = find_export(k32, XH_VIRTUALPROTECT);
        u32 mp_old = 0;
        int mp_window = 0;
        if (vp0) {
            mp_window = (int)api4(vp0, cfgva & ~(u64)0xFFFULL, 0x1000,
                                  0x04u /*PAGE_READWRITE*/,
                                  (u64)(unsigned long)&mp_old);
        }
        /* 1.2.2-A11 NOT: VEH kaydi wine-dispatch etkilesiminde patolojik
           (noop handler ile de VM akisi exit-1 — v5 bisect kaniti);
           GERCEK WINDOWS'ta beklentiler farkli olabilir -> cfg gate:
           cfg[XCFG_OFF_STATE+1]=1 yalniz motor --mpveh ile yazilir. */
        if (ld32(cfg + XCFG_OFF_STATE) == 0 && cfg[XCFG_OFF_STATE + 1] == 1) {
            u64 av = find_export(k32, XH_ADDVECTEH);
            if (av) api2(av, 1u, (u64)(unsigned long)(void*)mp_veh);
            {
                u64 vp = find_export(k32, XH_VIRTUALPROTECT);
                if (vp) {
                    u32 oldp = 0;
                    u32 tr = ld32(cfg + XCFG_OFF_TEXTRVA);
                    u32 ts = ld32(cfg + XCFG_OFF_TEXTSZ);
                    if (tr && ts)
                        api4(vp, (u64)(unsigned long)(base + tr), (u64)ts, 0x20u,
                             (u64)(unsigned long)&oldp);
                }
            }
        }
        cfg[XCFG_OFF_STATE]     = 1;
        cfg[XCFG_OFF_STATE + 1] = 0;
        cfg[XCFG_OFF_STATE + 2] = 0;
        cfg[XCFG_OFF_STATE + 3] = 0;
        if (mp_window && vp0) {
            u32 tmp2 = 0;
            api4(vp0, cfgva & ~(u64)0xFFFULL, 0x1000,
                 mp_old ? mp_old : 0x20u, (u64)(unsigned long)&tmp2);
        }
    }
    else if (flags & (XFLAG_SELFCRC | XFLAG_TEXTCRC | XFLAG_FILECRC | XFLAG_VFILES)) {
        /* 1.2.2-A16: VF de tek-kurulum — her kapida yeniden map edilmesin */
        cfg[XCFG_OFF_STATE]     = 1;
        cfg[XCFG_OFF_STATE + 1] = 0;
        cfg[XCFG_OFF_STATE + 2] = 0;
        cfg[XCFG_OFF_STATE + 3] = 0;
    }

    /* 1.2.2-A20: GLOBAL Check Debugger / Check VM / Check Kernel Debugger —
       tek-kurulum noktasinda LOADER-seviyesi batarya (UO loader-parite:
       UO'da Check Debugger fonksiyon-sanallastirmasi OLMADAN da globaldir).
       CRC'lerden ONCE calisir (UO: loader once debugger'i arar).
       err: 5=antidebug | 6=checkvm | 7=kerneldbg -> rt_fatal(0x70+err). */
    if ((flags & (XFLAG_ANTIDBG | XFLAG_CHECKVM | XFLAG_KDBG)) && !err) {
        err = xrt_antidebug(k32, flags);
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

#ifdef XRT_PROBE
    xvf_dbg(k32, 'A', 'D', '.');   /* antidebug/scylla geri döndü */
#endif
    /* 1.2.2-A18: STRING ENCRYPTION — CRC'ler disk-gorseli uzerinden
       dogrulandi (sifreli); SIMDI yerinde coz (tum kullanici kodundan once) */
    if (flags & XFLAG_STRENC) xrt_strenc(cfg, k32, base);

    /* 1.2.2-A16: VIRTUAL FILES — ilk kurulumda yükle (XVF1 cfg+0x68) */
    xrt_vfiles(cfg, k32);
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
