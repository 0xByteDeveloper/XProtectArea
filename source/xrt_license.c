// ============================================================
// xrt_license.c — XProtect 0.7.0 Lisans Çekirdeği (XRT tarafı)
// ============================================================
// xrt_core.c'nin SONUNA include edilir (aynı PIC/freestanding kurallar).
// VMProtect 3.5.1 runtime/licensing_manager.cc + hwid.cc birebir port:
//   - Serial: base64 -> RSA-2048 pub-op -> 00 02 NN..NN 00 <bloklar>
//   - Bloklar: 0x01 version, 0x02 user name, 0x03 email, 0x04 HWID,
//     0x05 exp date (0xYYYYMMDD LE), 0x06 running-time (dk),
//     0x07 product code (8B, zorunlu), 0x08 user data, 0x09 max build,
//     0xFF checksum = SHA-1 ilk kelime (birebir: LE deposu p[3-i])
//   - State bayrakları: sdk.h birebir (0x01 CORRUPTED ... 0x40 MAXBUILD)
//   - HWID: [volser_le | fnv32(hostname)] 8B -> base64
//   - Tarih/saat: KUSER_SHARED_DATA (0x7FFE0000) — API'siz, PIC-güvenli
// LSD bloğu (motor gömer, stub'lara RVA pişirilir):
//   modulus + e + build_date + product_code + watermark +
//   yazılabilir lic_state/start_tick + crc.
// ============================================================
#ifndef XRT_LICENSE_C
#define XRT_LICENSE_C

// ---- serial state bayrakları (sdk.h birebir) ----
#define XS_CORRUPTED     0x00000001u
#define XS_INVALID       0x00000002u
#define XS_BLACKLISTED   0x00000004u
#define XS_DATE_EXPIRED  0x00000008u
#define XS_TIME_OVER     0x00000010u
#define XS_BAD_HWID      0x00000020u
#define XS_MAXBUILD      0x00000040u

// ---- LSD düzeni ----
#define LSD_MAGIC      0x44534C58u   // 'XLSD' (LE: 58 4C 53 44)
#define LSD_SIZE       0x12C
#define LSD_OFF_MOD    0x08
#define LSD_OFF_EXP    0x108
#define LSD_OFF_BDATE  0x10C
#define LSD_OFF_PC     0x110
#define LSD_OFF_WM     0x118
#define LSD_OFF_STATE  0x120
#define LSD_OFF_URL    0x150   /* cp273 PORT E: ASCII NUL-sonlu aktivasyon URL'i (max 0x1F bayt; CRC-disi; wm-metni 0x130..0x14F) */
#define LSD_OFF_TICK   0x124
#define LSD_OFF_CRC    0x128
#define LSD_OFF_KEYLEN 0x12E
/* cp293/V293-1b: modulus LSD sabit kisminin sonrasinda, DEGISKEN uzunlukta.
   Ofset sabit 0x170; bayt sayisi keylen/8 (128..896). 2048'de eski 0x08
   alaniyla ayni icerik (uyumluluk kopyasi — eski runtime'lar 0x08 okur). */
#define LSD_OFF_MOD2   0x170
/* cp291/P0-c: RSA anahtar uzunlugu (bit) — CRC-disi (0x12E..0x12F, kullanimsiz
   alan; wl 0x12C-0x12D'ye dokunmaz). 0 = default 2048. Runtime dogrulamada
   modulus boyutu ile caprazlanir; 2048 disi uzunluklar 'belirtilmis' gorunur. */
// 0.7.0-final FIX: LSD CRC SADECE 0x000..0x11F (salt-okunur yapi) uzerinden
// hesaplanir. Eskiden 0x128'e kadar KAPSİYORDU -> runtime'in yazdigi
// state(0x120)/tick(0x124) ilk SetSerial'da CRC'yi bozuyor, sonraki TUM
// lic_lsd() taramalari false-CRC ile LSD'yi bulamiyor -> butun lisans
// API'leri CORRUPTED'a dusuyor (probe kaniti: post1=1 set_serial=1).
#define LSD_CRC_LEN    0x120
// 0.7.0-final: serial em onbellegi — LSD'nin hemen sonunda (lsd+0x12C),
// motor 0x104 bayt rezerve eder: [0]=0xAD gecerli flag, [4..0x103]=em(256B)
#define LSD_CACHE_OFF  LSD_SIZE
#define LSD_CACHE_FLAG 0xADu

// ---- SDK fonksiyon kimlikleri (xprotect_sdk.h + motor birebir) ----
#define XPAPI_SETSERIAL      1u
#define XPAPI_GETSTATE       2u
#define XPAPI_GETDATA        3u
#define XPAPI_GETHWID        4u
#define XPAPI_ISPROTECTED    5u
#define XPAPI_ISDEBUGGER     6u
#define XPAPI_ISIMAGECRC     7u
#define XPAPI_DECSTRA        8u
#define XPAPI_DECSTRW        9u
#define XPAPI_FREESTRING    10u
#define XPAPI_ACTIVATE      11u
#define XPAPI_DEACTIVATE    12u
#define XPAPI_OFFACT        13u
#define XPAPI_OFFDEACT      14u
#define XPAPI_ISVM          15u
/* ---- 0.7.0-final SDK-40: core/files.h APIType tam yuzeyi (atNone haric) ----
   atBegin/atEnd = BOLGE isaretleri (fnid'siz); atIsProtected=5, atIsVM=15,
   atDebugger=6, atImageCRC=7, atDecryptStr=8/9, atFreeString=10, atActivate=11,
   atDeactivate=12, atOffline=13/14, atSerial=1/2/3/4 zaten yukarida. */
#define XPAPI_LOADRESOURCE  16u   /* atLoadResource */
#define XPAPI_FINDRESA      17u   /* atFindResourceA */
#define XPAPI_FINDRESEXA    18u   /* atFindResourceExA */
#define XPAPI_FINDRESW      19u   /* atFindResourceW */
#define XPAPI_FINDRESEXW    20u   /* atFindResourceExW */
#define XPAPI_LOADSTRA      21u   /* atLoadStringA */
#define XPAPI_LOADSTRW      22u   /* atLoadStringW */
#define XPAPI_ENUMNAMESA    23u   /* atEnumResourceNamesA */
#define XPAPI_ENUMNAMESW    24u
#define XPAPI_EXENULANGA    25u   /* atEnumResourceLanguagesA */
#define XPAPI_EXENULANGW    26u
#define XPAPI_EXENUTYPESA   27u   /* atEnumResourceTypesA */
#define XPAPI_EXENUTYPESW   28u
#define XPAPI_DECBUF        29u   /* atDecryptBuffer */
#define XPAPI_RTINIT        30u   /* atRuntimeInit  (ic) */
#define XPAPI_LOADERDATA    31u   /* atLoaderData   (ic) */
#define XPAPI_SETUPIMAGE    32u   /* atSetupImage   (ic) */
#define XPAPI_FREEIMAGE     33u   /* atFreeImage    (ic) */
#define XPAPI_CALCCRC       34u   /* atCalcCRC      (ic) */
#define XPAPI_RANDOM        35u   /* atRandom */
#define XPAPI_BOXPTR        36u   /* atBoxPointer */
#define XPAPI_UNBOXPTR      37u   /* atUnboxPointer */

// kernel32 hash'leri (FNV-1a; motor tarafındaki sabitlerle birebir)
#define XH_GETWINDOWSDIR   0xDF670872u   // GetWindowsDirectoryA
#define XH_GETVOLINFO      0xC6DD0460u   // GetVolumeInformationA
#define XH_GETCOMPUTERNAME 0x446EAA3Cu   // GetComputerNameA
#define XH_TERMINATE       0xF84EEE59u   // TerminateProcess (cp273 PORT A)
/* ---- 0.7.0-final SDK-40 kaynak API hash'leri (fnv_a ile ayni algoritma,
        python dogrulamali: kernel32/user32 bilinen sabitleriyle eslesti) ---- */
#define XH_FINDRESOURCEA          0x3D905489u   // "FindResourceA"
#define XH_FINDRESOURCEW          0x2F903E7Fu   // "FindResourceW"
#define XH_FINDRESOURCEEXA        0xD1C53CA2u   // "FindResourceExA"
#define XH_FINDRESOURCEEXW        0xBBC51A00u   // "FindResourceExW"
#define XH_LOADRESOURCE           0xAA8CA8F9u   // "LoadResource"
#define XH_SIZEOFRESOURCE         0x694FD8FDu   // "SizeofResource"
#define XH_LOCKRESOURCE           0x081E23EAu   // "LockResource"
#define XH_ENUMRESOURCENAMESA     0xA599888Fu   // "EnumResourceNamesA"
#define XH_ENUMRESOURCENAMESW     0x93996C39u   // "EnumResourceNamesW"
#define XH_ENUMRESOURCELANGUAGESA 0x68B9D642u   // "EnumResourceLanguagesA"
#define XH_ENUMRESOURCELANGUAGESW 0x52B9B3A0u   // "EnumResourceLanguagesW"
#define XH_ENUMRESOURCETYPESA     0xB9D7B534u   // "EnumResourceTypesA"
#define XH_ENUMRESOURCETYPESW     0xA7D798DEu   // "EnumResourceTypesW"
#define XH_LOADSTRINGA            0x0A4DCC5Fu   // "LoadStringA" (user32)
#define XH_LOADSTRINGW            0x184DE269u   // "LoadStringW" (user32)

// ---- libc-yok yardımcıları (xrt_core'da yok — burada) ----
static u32 crc_up_byte(u32 c, u8 by) {
    c ^= by;
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    return c;
}
static void lmset(u8* d, u8 v, u32 n) { while (n--) *d++ = v; }
static void lcopy(u8* d, const u8* s, u32 n) { while (n--) *d++ = *s++; }

// ---- 2- ve 8-argümanlı sarmalayıcılar (aynı desen: sabit ofset) ----
#if defined(XRT_IS_X86)
#define W2(NM) static u32 NM(u32 fn, u32 a0, u32 a1) { u32 ret; u32 ar_[2]; \
    ar_[0] = a0; ar_[1] = a1; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#define W8(NM) static u32 NM(u32 fn, u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5, u32 a6, u32 a7) { u32 ret; u32 ar_[8]; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; \
    ar_[4] = a4; ar_[5] = a5; ar_[6] = a6; ar_[7] = a7; \
    __asm__ volatile ("movl %[ar], %%esi\n\tpushl 28(%%esi)\n\tpushl 24(%%esi)\n\tpushl 20(%%esi)\n\tpushl 16(%%esi)\n\tpushl 12(%%esi)\n\tpushl 8(%%esi)\n\tpushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]" \
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_) \
        : "ecx", "edx", "esi", "memory", "cc"); return ret; }
#else
#define W2(NM) static u64 NM(u64 fn, u64 a0, u64 a1) { u64 ret; u64 ar_[2]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x20, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#define W8(NM) static u64 NM(u64 fn, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7) { u64 ret; u64 ar_[8]; \
    register u64 rfn __asm__("r15") = fn; \
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_; \
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; \
    ar_[4] = a4; ar_[5] = a5; ar_[6] = a6; ar_[7] = a7; \
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x48, %%rsp\n\t" \
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tmovq 24(%%r14), %%r9\n\t" \
        "movq 32(%%r14), %%r10\n\tmovq %%r10, 0x20(%%rsp)\n\t" \
        "movq 40(%%r14), %%r10\n\tmovq %%r10, 0x28(%%rsp)\n\t" \
        "movq 48(%%r14), %%r10\n\tmovq %%r10, 0x30(%%rsp)\n\t" \
        "movq 56(%%r14), %%r10\n\tmovq %%r10, 0x38(%%rsp)\n\tcall *%%r15\n\t" \
        "movq %%rbp, %%rsp\n\tpopq %%rbp" \
        : "=a"(ret) : "r"(rfn), "r"(rar) \
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret; }
#endif
/* W2(api2) — 0.7.0-final: xrt_core.c'te tanimli */
W8(api8)
/* cp273 PORT E: api6 — WinHttpQueryHeaders (6 arguman); xrt_core api1-5/7,
   burada 6-argumanli yapi her arch icin acik yazilir */
#if defined(XRT_IS_X64)
static u64 api6(u64 fn, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5) {
    u64 ret; u64 ar_[6];
    register u64 rfn __asm__("r15") = fn;
    register u64 rar __asm__("r14") = (u64)(unsigned long)(void*)ar_;
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; ar_[5] = a5;
    __asm__ volatile ("pushq %%rbp\n\tmovq %%rsp, %%rbp\n\tandq $-16, %%rsp\n\tsubq $0x38, %%rsp\n\t"
        "movq 0(%%r14), %%rcx\n\tmovq 8(%%r14), %%rdx\n\tmovq 16(%%r14), %%r8\n\tmovq 24(%%r14), %%r9\n\t"
        "movq 32(%%r14), %%r10\n\tmovq %%r10, 0x20(%%rsp)\n\t"
        "movq 40(%%r14), %%r10\n\tmovq %%r10, 0x28(%%rsp)\n\tcall *%%r15\n\t"
        "movq %%rbp, %%rsp\n\tpopq %%rbp"
        : "=a"(ret) : "r"(rfn), "r"(rar)
        : "rcx", "rdx", "r8", "r9", "r10", "r11", "memory", "cc"); return ret;
}
#else
static u32 api6(u32 fn, u32 a0, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5) {
    u32 ret; u32 ar_[6];
    ar_[0] = a0; ar_[1] = a1; ar_[2] = a2; ar_[3] = a3; ar_[4] = a4; ar_[5] = a5;
    __asm__ volatile ("movl %[ar], %%esi\n\t"
        "pushl 20(%%esi)\n\tpushl 16(%%esi)\n\tpushl 12(%%esi)\n\tpushl 8(%%esi)\n\t"
        "pushl 4(%%esi)\n\tpushl 0(%%esi)\n\tcall *%[fn]\n\t"
        "addl $24, %%esp"
        : "=a"(ret) : [fn] "r"(fn), [ar] "r"(ar_)
        : "ecx", "edx", "esi", "memory", "cc"); return ret;
}
#endif

// ---- exe tabanı: PEB InLoadOrder ilk girdi (exe kendisi) ----
static u64 lic_exe_base(void) {
    u64 peb = peb_addr();
    if (!peb) return 0;
    u64 ldr = LDPTR((const u8*)(unsigned long)(peb + PEB_LDR_OFF));
    if (!ldr) return 0;
    u64 head = ldr + LDR_INMEM_OFF;
    u64 first = LDPTR((const u8*)(unsigned long)head);
    if (!first || first == head) return 0;
    /* first = InMemoryOrderLinks dugumu; giris = first - ENT_INMEM_OFF;
       DllBase = giris + ENT_DLLBASE_OFF  =>  first + (0x30 - 0x10) */
    return LDPTR((const u8*)(unsigned long)(first + (ENT_DLLBASE_OFF - ENT_INMEM_OFF)));
}

// ---- SHA-1 (checksum) ----
typedef struct { u32 h[5]; u32 k[4]; u64 len; u8 buf[64]; u32 buflen; } sha1_ctx;
static void sha1_init(sha1_ctx* c) {
    c->h[0]=0x67452301u; c->h[1]=0xEFCDAB89u; c->h[2]=0x98BADCFEu;
    c->h[3]=0x10325476u; c->h[4]=0xC3D2E1F0u; c->len=0; c->buflen=0;
    /* K sabitleri ctx icinde (const dizi = .rodata = PIC kapisi) */
    c->k[0]=0x5A827999u; c->k[1]=0x6ED9EBA1u; c->k[2]=0x8F1BBCDCu; c->k[3]=0xCA62C1D6u;
}
static void sha1_block(sha1_ctx* c, const u8* p) {
    u32 w[80]; int i;
    for (i = 0; i < 16; i++)
        w[i] = ((u32)p[i*4] << 24) | ((u32)p[i*4+1] << 16) | ((u32)p[i*4+2] << 8) | (u32)p[i*4+3];
    for (i = 16; i < 80; i++) {
        u32 v = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (v << 1) | (v >> 31);
    }
    u32 a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4];
    for (i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & cc) | ((~b) & d);         k = c->k[0]; }
        else if (i < 40) { f = b ^ cc ^ d;                    k = c->k[1]; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = c->k[2]; }
        else             { f = b ^ cc ^ d;                    k = c->k[3]; }
        u32 t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = cc; cc = (b << 30) | (b >> 2); b = a; a = t;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e;
}
static void sha1_update(sha1_ctx* c, const u8* p, u32 n) {
    c->len += n;
    while (n) {
        u32 take = 64 - c->buflen; if (take > n) take = n;
        lcopy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
    }
}
static void sha1_final(sha1_ctx* c, u8 out[20]) {
    u64 bits = c->len * 8ull;
    u8 pad = 0x80; int i;
    sha1_update(c, &pad, 1);
    u8 z = 0;
    while (c->buflen != 56) sha1_update(c, &z, 1);
    u8 lb[8];
    for (i = 0; i < 8; i++) lb[i] = (u8)(bits >> (56 - 8*i));
    lcopy(c->buf + 56, lb, 8);
    sha1_block(c, c->buf);
    c->buflen = 0;
    for (i = 0; i < 5; i++) {
        out[i*4]   = (u8)(c->h[i] >> 24);
        out[i*4+1] = (u8)(c->h[i] >> 16);
        out[i*4+2] = (u8)(c->h[i] >> 8);
        out[i*4+3] = (u8)(c->h[i]);
    }
}

// ---- base64 ----
// 0.7.0-final FIX: lic_div64 EKSIKTI (oturum-8'de xrt_license.c 09:53'te
// duzenlendi ama blob 09:43'te kaldi; tanim hicbir dosyada yoktu -> blob
// derlenemiyor, motor ESKI blob tasiyor -> exe icinde modexp YANLIS ->
// SetSerial INVALID). Freestanding C: shift-subtract (libgcc'siz).
static u64 lic_div64(u64 a, u64 b, u64* rem) {
    u64 q = 0, r = 0; int i;
    if (!b) { if (rem) *rem = 0; return 0; }
    for (i = 63; i >= 0; i--) {
        r = (r << 1) | ((a >> i) & 1ull);
        if (r >= b) { r -= b; q |= (1ull << i); }
    }
    if (rem) *rem = r;
    return q;
}

static int lic_b64dec(const u8* in, u32 n, u8* out, u32* outn) {
    u32 acc = 0, accb = 0, o = 0; u32 i;
    for (i = 0; i < n; i++) {
        u8 c = in[i]; int v;
        if (c == '=') break;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else return 0;
        acc = (acc << 6) | (u32)v; accb += 6;
        if (accb >= 8) { accb -= 8; out[o++] = (u8)(acc >> accb); }
    }
    *outn = o;
    return o ? 1 : 0;
}
static void lic_b64enc(const u8* in, u32 n, char* out, u32* outn) {
    /* ENC tablosu volatile-dizi yazımla kurulur (rodata kapanı: taban =
       ld32'lerle okunur; const dizi = .rodata = PIC kapısı hatası) */
    char ENC[64];
    { u32 i; for (i = 0; i < 26; i++) { ENC[i] = (char)('A' + i); ENC[26+i] = (char)('a' + i); }
      for (i = 0; i < 10; i++) ENC[52+i] = (char)('0' + i);
      ENC[62] = '+'; ENC[63] = '/'; }
    u32 o = 0, i;
    for (i = 0; i + 2 < n; i += 3) {
        u32 v = ((u32)in[i] << 16) | ((u32)in[i+1] << 8) | in[i+2];
        out[o++] = ENC[(v >> 18) & 63]; out[o++] = ENC[(v >> 12) & 63];
        out[o++] = ENC[(v >> 6) & 63];  out[o++] = ENC[v & 63];
    }
    if (i < n) {
        u32 v = (u32)in[i] << 16;
        if (i + 1 < n) v |= (u32)in[i+1] << 8;
        out[o++] = ENC[(v >> 18) & 63]; out[o++] = ENC[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? ENC[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    *outn = o;
}

// ---- RSA-2048 (e=65537) public-op ----
// Duzeltme gecmisi: (1) mod_dbl dongusu base*65537 hesapliyordu (kare yok);
// (2) Montgomery REDC carry-tasmasi (129. limb) dusuluyordu. 0.7.0 FINAL:
// 4096-bit kare + bit-bit long-division mod — yavas ama tasınsız/bulunmaz
// (verify basina ~10ms; dogrulama seyrek cagri — kabul).
/* cp292/V292-2: LIC_LIMBS artik 224 — 7168-bit (896B) moda kadar dinamik
   RSA. Eski 64'luk sabit 2048-bit'e sabitler; aktif limb sayisi (L) her
   isleme parametre olarak gecer, boylece 1024..7168 arasi her uzunluk
   ayni kodla islenir. 224 limb * 4B = 896B; lbn stack'te 3 adet ~2.7KB. */
#define LIC_LIMBS 224
/* aktif limb sayisi; 0 = henuez setlenmedi (ilk kullanimda 64'e cekilir).
   baslaticsiz: .data'ya dusmesin (freestanding loader .text+.bss tasir) */
static int g_lic_L = 0;
static int lic_L(void) { if (g_lic_L == 0) g_lic_L = 64; return g_lic_L; }
typedef struct { u32 l[LIC_LIMBS]; } lbn;
static void lbn_zero(lbn* a) { int i; for (i = 0; i < LIC_LIMBS; i++) a->l[i] = 0; }
static int  lbn_ge(const lbn* a, const lbn* b) {
    int i;
    for (i = lic_L() - 1; i >= 0; i--)
        if (a->l[i] != b->l[i]) return a->l[i] > b->l[i];
    return 1;
}
static void lbn_sub(lbn* a, const lbn* b) {
    int i; u64 borrow = 0;
    for (i = 0; i < lic_L(); i++) {
        u64 cur = (u64)a->l[i] - (u64)b->l[i] - borrow;
        a->l[i] = (u32)cur;
        borrow = (cur >> 32) & 1ull;
    }
}
static void lbn_be_load(lbn* a, const u8 be[256]) {   /* cp292: L'ye gore */
    int i; lbn_zero(a);
    for (i = 0; i < lic_L() * 4; i++)
        a->l[g_lic_L - 1 - (i >> 2)] |= (u32)be[i] << ((3 - (i & 3)) * 8);
}
static void lbn_be_store(const lbn* a, u8 be[256]) {
    int i;
    for (i = 0; i < lic_L() * 4; i++)
        be[i] = (u8)(a->l[g_lic_L - 1 - (i >> 2)] >> ((3 - (i & 3)) * 8));
}
/* a*a -> 4096-bit (128 limb, LE) */
static void lic_sq(u32 out[2 * LIC_LIMBS], const lbn* a) {
    int i, j;
    for (i = 0; i < 2 * lic_L(); i++) out[i] = 0;
    for (i = 0; i < lic_L(); i++) {
        u64 carry = 0;
        for (j = 0; j < g_lic_L; j++) {
            u64 cur = (u64)out[i + j] + (u64)a->l[i] * a->l[j] + carry;
            out[i + j] = (u32)cur;
            carry = cur >> 32;
        }
        { int k = i + g_lic_L;
          while (carry && k < 2 * g_lic_L) {
              u64 cur = (u64)out[k] + carry;
              out[k] = (u32)cur; carry = cur >> 32; k++;
          } }
    }
}
/* a*b -> 4096-bit (128 limb, LE) */
static void lic_mul(u32 out[2 * LIC_LIMBS], const lbn* a, const lbn* b) {
    int i, j;
    for (i = 0; i < 2 * lic_L(); i++) out[i] = 0;
    for (i = 0; i < lic_L(); i++) {
        u64 carry = 0;
        for (j = 0; j < g_lic_L; j++) {
            u64 cur = (u64)out[i + j] + (u64)a->l[i] * b->l[j] + carry;
            out[i + j] = (u32)cur;
            carry = cur >> 32;
        }
        { int k = i + g_lic_L;
          while (carry && k < 2 * g_lic_L) {
              u64 cur = (u64)out[k] + carry;
              out[k] = (u32)cur; carry = cur >> 32; k++;
          } }
    }
}
/* r (129 limb, LE) karsilastir/subtract n (64 limb) */
static int lic_ge129(const u32* r, const lbn* n) {
    int i;
    for (i = lic_L(); i >= 0; i--) {
        u32 rv = r[i];
        u32 nv = (i < g_lic_L) ? n->l[i] : 0;
        if (rv != nv) return rv > nv;
    }
    return 1;
}
static void lic_sub129(u32* r, const lbn* n) {
    int i; u64 borrow = 0;
    for (i = 0; i <= lic_L(); i++) {
        u64 cur = (u64)r[i] - ((i < g_lic_L) ? n->l[i] : 0u) - borrow;
        r[i] = (u32)cur;
        borrow = (cur >> 32) & 1ull;
    }
}
/* x (128 limb) mod n (64 limb) — bit-bit long division */
static void lic_mod128(u32* x, const lbn* n) {
    u32 r[LIC_LIMBS + 1];
    int i, b, j;
    for (i = 0; i <= lic_L(); i++) r[i] = 0;
    for (i = 2 * lic_L() - 1; i >= 0; i--) {
        for (b = 31; b >= 0; b--) {
            u32 bit = (x[i] >> b) & 1u;
            /* r = r*2 + bit */
            { u32 c = bit;
              for (j = 0; j <= lic_L(); j++) {
                  u32 nc = r[j] >> 31;
                  r[j] = (r[j] << 1) | c;
                  c = nc;
              } }
            if (lic_ge129(r, n)) lic_sub129(r, n);
        }
    }
    for (i = 0; i < lic_L(); i++) x[i] = r[i];
}
/* cp292/V292-2: g_lic_L'yi LSD'deki Key Length (0x12E) belirler. 2048-bit
   (L=64) eski davranisla ayni; 1024..7168 desteklenir. LSD yoksa/bozulussa
   default 2048. Uzunluk L'yi asarsa kisaltilir (güvenli: modulus yuksek
   baytlari 0 olur, imza gecersiz kabul edilir). */
static int lic_setlen_from_lsd(const u8* lsd) {
    u16 kb = (u16)(lsd[LSD_OFF_KEYLEN] | (lsd[LSD_OFF_KEYLEN + 1] << 8));
    if (kb < 1024) kb = 2048;            /* alan yok/bos -> default */
    if (kb > 7168) kb = 7168;
    g_lic_L = kb / 32;                   /* bit -> limb (32b/limb) */
    if (g_lic_L < 4) g_lic_L = 4;
    if (g_lic_L > LIC_LIMBS) g_lic_L = LIC_LIMBS;
    return g_lic_L;
}
static void lic_modexp65537(const u8 s_be[256], const u8 n_be[256], u8 out[256]) {
    lbn base, nn, acc; int i;
    lbn_be_load(&base, s_be);
    lbn_be_load(&nn, n_be);
    if (lbn_ge(&base, &nn)) {           /* imza >= n: gecersiz */
        lbn_zero(&base);
        lbn_be_store(&base, out);
        return;
    }
    acc = base;
    /* 65537 = 2^16 + 1 → 16 kare + 1 carpim */
    { int q;
      for (q = 0; q < 16; q++) {
          u32 prod[2 * LIC_LIMBS];
          lic_sq(prod, &acc);
          lic_mod128(prod, &nn);
          for (i = 0; i < lic_L(); i++) acc.l[i] = prod[i];
      } }
    /* acc = base^65536; son adim: × base (mod n) */
    { u32 prod[2 * LIC_LIMBS];
      lic_mul(prod, &acc, &base);
      lic_mod128(prod, &nn);
      for (i = 0; i < lic_L(); i++) acc.l[i] = prod[i]; }
    lbn_be_store(&acc, out);
}

// ---- KUSER_SHARED_DATA (API'siz tarih/saat) ----
// +0x08 InterruptTime (KSYSTEM_TIME: low@0x08, high1@0x0C)
// +0x14 SystemTime   (low@0x14, high1@0x18)
static u32 lic_tick_ms(void) {
    u32 lo = ld32((const u8*)(unsigned long)(0x7FFE0000ull + 0x08));
    u32 hi = ld32((const u8*)(unsigned long)(0x7FFE0000ull + 0x0C));
    return (u32)lic_div64((((u64)hi << 32) | lo), 10000ull, 0);
}
static u32 lic_now_date(void) {
    u32 lo = ld32((const u8*)(unsigned long)(0x7FFE0000ull + 0x14));
    u32 hi = ld32((const u8*)(unsigned long)(0x7FFE0000ull + 0x18));
    u64 ft = ((u64)hi << 32) | lo;
    /* FILETIME 1601-epoch — 1970 dongusu icin offset cikar (cp273 FIX):
       1601->1970 = 369 yil + 89 artik = 134774 gun */
    u64 days = lic_div64(ft, 864000000000ull, 0);
    days = (days > 134774ull) ? (days - 134774ull) : 0ull;
    u64 rem = days;
    u32 yy = 1970;
    while (1) {
        u64 dy = ((yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0) ? 366 : 365;
        if (rem < dy) break;
        rem -= dy; yy++;
    }
    u32 mm = 1;
    int leap = ((yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0);
    while (mm <= 12) {
        u32 dm = (mm == 2) ? (u32)(28 + leap) :
                 (mm == 4 || mm == 6 || mm == 9 || mm == 11) ? 30u : 31u;
        if (rem < dm) break;
        rem -= dm; mm++;
    }
    return ((yy & 0xFFFF) << 16) | ((mm & 0xFF) << 8) | ((u32)(rem + 1) & 0xFF);
}


// ---- 0.7.0 HWID (env-temelli, yalniz PEB okumasi — API'siz) ----
// PEB->ProcessParameters(+0x20 x64 / +0x10 x86)->Environment(+0x80 x64 / +0x48 x86)
// UTF-16 girisleri: "COMPUTERNAME=..." ve "PROCESSOR_IDENTIFIER=..." -> fnv_w
// (volser/GetVolumeInformation yolu 0.8.0'da: api2/api8 cagri yigin
//  kalibrasyonu wine'da ayrica dogrulanacakti — 0.7.0'da guvenli yol.)
#if defined(XRT_IS_X64)
  #define PP_OFF   0x20
  #define ENV_OFF  0x80
#else
  #define PP_OFF   0x10
  #define ENV_OFF  0x48
#endif
static int lic_hwid_env(u32 b[2]) {
    u64 peb = peb_addr();
    if (!peb) return 0;
    u64 pp = LDPTR((const u8*)(unsigned long)(peb + PP_OFF));
    if (!pp) return 0;
    u64 env = LDPTR((const u8*)(unsigned long)(pp + ENV_OFF));
    if (!env) return 0;
    const u16* p = (const u16*)(unsigned long)env;
    u32 got = 0;
    b[0] = 0; b[1] = 0;
    u32 i = 0, guard = 0;
    while (got < 2 && guard++ < 4096) {
        /* tek giris: NUL'a kadar; bitis: cift NUL */
        u32 len = 0;
        while (p[i + len] && len < 512) len++;
        if (!len) break;
        /* "NAME=" oneki */
        const u16* q = p + i;
        if (len > 14 && q[0] == 'C' && q[1] == 'O' && q[2] == 'M' && q[3] == 'P' &&
            q[4] == 'U' && q[5] == 'T' && q[6] == 'E' && q[7] == 'R' && q[8] == 'N' &&
            q[9] == 'A' && q[10] == 'M' && q[11] == 'E' && q[12] == '=') {
            b[0] = (fnv_w(q + 13, len - 13) & ~3u) | 1u; got++;   /* HOST type=1 */
        } else if (len > 21 && q[0] == 'P' && q[1] == 'R' && q[2] == 'O' &&
                   q[3] == 'C' && q[4] == 'E' && q[5] == 'S' && q[6] == 'S' &&
                   q[7] == 'O' && q[8] == 'R' && q[9] == '_' && q[10] == 'I' &&
                   q[11] == 'D' && q[12] == 'E' && q[13] == 'N' && q[14] == 'T' &&
                   q[15] == 'I' && q[16] == 'F' && q[17] == 'I' && q[18] == 'E' &&
                   q[19] == 'R' && q[20] == '=') {
            b[1] = (fnv_w(q + 21, len - 21) & ~3u); got++;        /* CPU type=0 */
        }
        i += len + 1;
    }
    return (b[0] && b[1]) ? 1 : 0;
}

// ---- HWID: [volser_le | fnv32(hostname)] ----
static u32 lic_volser(u64 k32) {
    u32 vol = 0;
    char wdir[264]; u32 i;
    for (i = 0; i < 264; i++) wdir[i] = 0;
    u32 fn_wd = find_export(k32, XH_GETWINDOWSDIR);
    if (!fn_wd) return 0;
    api2(fn_wd, (u64)(unsigned long)wdir, 260);
    if (wdir[0] == 0 || wdir[1] != ':') return 0;
    wdir[2] = '\\'; wdir[3] = 0;
    u32 fn_vi = find_export(k32, XH_GETVOLINFO);
    if (!fn_vi) return 0;
    api8(fn_vi, (u64)(unsigned long)wdir, 0, 0,
         (u64)(unsigned long)&vol, 0, 0, 0, 0);
    return vol;
}
static u32 lic_host_hash(u64 k32) {
    char name[64]; u32 i; u32 sz = 63;
    for (i = 0; i < 64; i++) name[i] = 0;
    u32 fn_cn = find_export(k32, XH_GETCOMPUTERNAME);
    if (!fn_cn) return 0;
    api2(fn_cn, (u64)(unsigned long)name, (u64)(unsigned long)&sz);
    if (!name[0]) return 0;
    return fnv_a(name) | 1u;
}
static int lic_cur_hwid(u32 b[2], u64 k32) {
    b[0] = lic_volser(k32);
    b[1] = lic_host_hash(k32);
    return (b[0] && b[1]) ? 1 : 0;
}

// ---- VMProtectSerialNumberData (sdk.h birebir; wchar=2B) ----
typedef struct { u16 wYear; u8 bMonth; u8 bDay; } lic_date_t;
typedef struct __attribute__((packed)) {
    int nState;
    u16 wUserName[256];
    u16 wEMail[256];
    lic_date_t dtExpire;
    lic_date_t dtMaxBuild;
    int bRunningTime;
    u8 nUserDataLength;
    u8 bUserData[255];
} lic_snd_t;

// 0.7.0-final: em bloklarindan SerialNumberData doldurma (ParseSerial'in
// ayni blok haritasi: 02=name 03=email 05=expire 06=runtime 08=userdata
// 09=maxbuild; UTF-8 -> UTF-16).
static void lic_utf8_to_utf16(const u8* s, u32 n, u16* out, u32 cap) {
    u32 o = 0, i = 0;
    while (i < n && o + 1 < cap) {
        u8 c = s[i];
        u32 cp = c; i += 1;
        if (c >= 0xC0 && c < 0xE0 && i < n) { cp = ((u32)(c & 0x1F) << 6) | (s[i] & 0x3F); i += 1; }
        else if (c >= 0xE0 && c < 0xF0 && i + 1 < n) {
            cp = ((u32)(c & 0x0F) << 12) | ((u32)(s[i] & 0x3F) << 6) | (s[i+1] & 0x3F); i += 2;
        }
        else if (c >= 0x80) { cp = '?'; }   /* bozuk dizi */
        if (cp == 0) break;
        out[o++] = (u16)cp;
    }
    out[o] = 0;
}
static void lic_fill_data(lic_snd_t* d, const u8* em, u32 start, u32 state) {
    u32 pos = start;
    lmset((u8*)d, 0, sizeof(lic_snd_t));
    d->nState = (int)state;
    while (pos < 256) {
        u8 b = em[pos++];
        if (b == 0xFF) break;
        switch (b) {
        case 0x01: pos += 1; break;
        case 0x02: { u8 s2 = em[pos++]; lic_utf8_to_utf16(em + pos, s2, d->wUserName, 256); pos += s2; break; }
        case 0x03: { u8 s2 = em[pos++]; lic_utf8_to_utf16(em + pos, s2, d->wEMail, 256); pos += s2; break; }
        case 0x04: { u8 s2 = em[pos++]; pos += s2; break; }
        case 0x05: { u32 v = em[pos] | (em[pos+1] << 8) | (em[pos+2] << 16) | ((u32)em[pos+3] << 24);
                     d->dtExpire.wYear = (u16)(v >> 16); d->dtExpire.bMonth = (u8)(v >> 8); d->dtExpire.bDay = (u8)v;
                     pos += 4; break; }
        case 0x06: { d->bRunningTime = (int)em[pos]; pos += 1; break; }
        case 0x07: pos += 8; break;
        case 0x08: { u8 s2 = em[pos++]; u32 cp2 = (s2 > 255) ? 255 : s2;
                     d->nUserDataLength = s2; lcopy(d->bUserData, em + pos, cp2); pos += s2; break; }
        case 0x09: { u32 v = em[pos] | (em[pos+1] << 8) | (em[pos+2] << 16) | ((u32)em[pos+3] << 24);
                     d->dtMaxBuild.wYear = (u16)(v >> 16); d->dtMaxBuild.bMonth = (u8)(v >> 8); d->dtMaxBuild.bDay = (u8)v;
                     pos += 4; break; }
        case 0x0A: case 0x0B: { u8 s2 = em[pos++]; pos += s2; break; }
        default: return;
        }
    }
}

// ---- LSD erişimi: imaj taraması ('XLSD' + ver=1 + CRC doğrulaması) ----
// Stub'lara RVA pişirmek yerine dispatch imajda bulur (stub 11B/10B olur;
// 15B'lik işaret bloklarına sığar). Tarama bir-kez: sonucu statik-yazılabilir
// alanda TUTAMAYIZ (PIC) — her çağrıda taranır (5MB imaj ~ms).
static const u8* lic_lsd(void) {
    u64 base = lic_exe_base();
    const u8* b = (const u8*)(unsigned long)base;
    u32 e = ld32(b + 0x3C);
    u32 imgsz = ld32(b + e + 0x50);
    if (!imgsz || imgsz > 0x20000000u) return 0;
    for (u32 rva = 0x1000; rva + LSD_SIZE < imgsz; rva += 4) {
        const u8* p = b + rva;
        if (ld32(p) == LSD_MAGIC && p[4] == 1) {
            /* CRC doğrulaması — yanlış-pozitif engeli. 0.7.0-final: yalnız
               0x120 bayt (state/tick HARİÇ — runtime yazılabilir). */
            u32 lcrc = 0xFFFFFFFFu;
            for (u32 i = 0; i < LSD_CRC_LEN; i++) lcrc = crc_up_byte(lcrc, p[i]);
            lcrc = ~lcrc;
            if (ld32(p + LSD_OFF_CRC) == lcrc) return p;
        }
    }
    return 0;
}

static void lic_wr32(u8* p, u32 v) { p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }

/* cp273 PORT A: VMProtect DecryptBuffer rotl yardimcisi */
static u32 lic_rotl(u32 v, u32 r) { return (v << r) | (v >> (32u - r)); }

/* cp273 PORT A: cevrimdisi aktivasyon/deaktivasyon string'i (UO 1:1 semantik):
   "type=activation&code=CODE&hwid=BASE64&hash=BASE64" -> base64(SHA1(modulus) ile
   ayni sira). sunucu tarafina gidecek URL parametrelerini URLEscape eder ve
   tamami base64'e kodlar (BuildUrl+EncodeUrl birebir).
   NOT: stringler stack'te VP4 ile kurulur (.rodata YASAK — PIC blob). */
static u32 lic_url_escape(char* dst, u32 cap, const char* src) {
    u32 o = 0;
    for (; *src; src++) {
        u8 c = (u8)*src;
        int plain = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~');
        if (c == ' ' && o + 1 < cap) dst[o++] = '+';
        else if (plain && o + 1 < cap) dst[o++] = (char)c;
        else if (o + 3 < cap) {
            dst[o++] = '%';
            dst[o++] = (char)('0' + (c >> 4) + ((c >> 4) > 9 ? 39 : 0));
            dst[o++] = (char)('0' + (c & 15) + ((c & 15) > 9 ? 39 : 0));
        }
        else break;
    }
    dst[o] = 0;
    return o;
}
static u32 lic_offline_str(char* out, u32 cap, int is_deact, const char* code,
                           const u8* lsd, u64 k32) {
    /* hwid -> base64 (mevcut 2-blok) */
    u32 cur[2];
    if (!lic_hwid_env(cur)) return 0;
    u8 raw[8]; u32 r;
    for (r = 0; r < 4; r++) raw[r]     = (u8)(cur[0] >> (8 * r));
    for (r = 0; r < 4; r++) raw[4 + r] = (u8)(cur[1] >> (8 * r));
    char str_hwid[24]; u32 hn = 0;
    lic_b64enc(raw, 8, str_hwid, &hn);
    /* hash -> base64: SHA1(modulus 256B) ilk 20B */
    u8 h[20];
    {
        sha1_ctx c; sha1_init(&c);
        sha1_update(&c, lsd + LSD_OFF_MOD, 256);
        sha1_final(&c, h);
    }
    char str_hash[32]; u32 sn = 0;
    lic_b64enc(h, 20, str_hash, &sn);
    /* birlesik: type=...&code=...&hwid=...&hash=... (stack-stringler) */
    char body[512]; u32 o = 0;
    char s_pre1[8];  char s_act[12]; char s_deact[16];
    char s_pre2[8];  char s_pre3[8];  char s_pre4[8];
    VP4(s_pre1, 0, A4('t','y','p','e')); VP4(s_pre1, 4, A4('=','&','c','o') >> 8); s_pre1[5] = 0;
    VP4(s_act, 0, A4('a','c','t','i')); VP4(s_act, 4, A4('v','a','t','i')); VP4(s_act, 8, A4('o','n',0,0));
    VP4(s_deact, 0, A4('d','e','a','c')); VP4(s_deact, 4, A4('t','i','v','a')); VP4(s_deact, 8, A4('t','i','o','n')); VP4(s_deact, 12, 0);
    VP4(s_pre2, 0, A4('&','c','o','d')); VP4(s_pre2, 4, A4('e','=',0,0));
    VP4(s_pre3, 0, A4('&','h','w','i')); VP4(s_pre3, 4, A4('d','=',0,0));
    VP4(s_pre4, 0, A4('&','h','a','s')); VP4(s_pre4, 4, A4('h','=',0,0));
    const char* parts[8]; u32 pi;
    parts[0] = s_pre1;            parts[1] = is_deact ? s_deact : s_act;
    parts[2] = s_pre2;            parts[3] = code ? code : "";
    parts[4] = s_pre3;            parts[5] = str_hwid;
    parts[6] = s_pre4;            parts[7] = str_hash;
    for (pi = 0; pi < 8 && o + 1 < sizeof body; pi++) {
        const char* s = parts[pi];
        if (pi & 1) o += lic_url_escape(body + o, (u32)(sizeof body - o - 1), s);
        else while (*s && o + 1 < sizeof body) body[o++] = *s++;
    }
    body[o] = 0;
    /* EncodeUrl: tamami base64 */
    u32 on = 0;
    lic_b64enc((const u8*)body, o, out, &on);
    (void)k32;
    return (on && on < cap) ? on + 1 : 0;
}

static int lic_check_hwid(const u8* em, u32 pos, u8 s, u64 k32, u32* state) {
    /* VMProtect hwid.cc IsCorrect birebir (cp273 PORT B):
       - bloklar 4B hizali; her blok alt-2 biti TIP (0=CPU 1=HOST 2=MAC 3=HDD)
       - kural: CPU tipli blok ESLESMELI + bulunan tiplerin TUMU ya >=3 tip eslesmeli
       (ag donanimi degisse de makul esneklik — UO 1:1 semantik) */
    if (s == 0 || (s & 3) || pos + s > 256) { *state = XS_BAD_HWID; return 0; }
    u32 cur[2];
    if (!lic_hwid_env(cur)) { *state = XS_BAD_HWID; return 0; }
    /* mevcut makinenin bloklari: [0]=env-host (HOST tipi=1), [1]=env-cpu (CPU tipi=0)
       lic_hwid_env: b[0]=COMPUTERNAME-hash, b[1]=PROCESSOR_IDENTIFIER-hash */
    u32 cur_blocks[2]; u32 cur_types[2];
    cur_blocks[0] = cur[0]; cur_types[0] = 1u;   /* HOST  */
    cur_blocks[1] = cur[1]; cur_types[1] = 0u;   /* CPU   */
    int equals[4]; int found[4];
    u32 t;
    for (t = 0; t < 4; t++) { equals[t] = 0; found[t] = 0; }
    u32 nblocks = s / 4u;
    u32 j;
    for (j = 0; j < nblocks; j++) {
        u32 d = em[pos+j*4] | (em[pos+j*4+1] << 8) | (em[pos+j*4+2] << 16) | ((u32)em[pos+j*4+3] << 24);
        found[d & 3u] = 1;
        u32 c;
        for (c = 0; c < 2u; c++)
            if (d == cur_blocks[c]) { equals[cur_types[c]] = 1; break; }
    }
    /* CPU zorunlu (hwid.cc: if (!equals[0]) return false) */
    if (!equals[0]) { *state = XS_BAD_HWID; return 0; }
    /* n == c || n >= 3 */
    {
        int n = 0, c2 = 0;
        for (t = 0; t < 4; t++) { if (found[t]) c2++; if (equals[t]) n++; }
        if (!(n == c2 || n >= 3)) { *state = XS_BAD_HWID; return 0; }
    }
    return 1;
}

// ---- serial blok taraması (licensing_manager.cc ParseSerial birebir) ----
static u32 lic_parse_serial(const u8* em, u32 start, const u8* lsd, u64 k32) {
    u32 state = ld32(lsd + LSD_OFF_STATE) & (XS_MAXBUILD | XS_DATE_EXPIRED | XS_TIME_OVER);
    u32 pos = start;
    u32 bd = ld32(lsd + LSD_OFF_BDATE);
    while (pos < 256) {
        u8 b = em[pos++];
        switch (b) {
        case 0x01:
            if (pos >= 256 || em[pos] != 1) return XS_INVALID;
            pos += 1; break;
        case 0x05: {
            if (pos + 4 > 256) return XS_INVALID;
            u32 d = em[pos] | (em[pos+1] << 8) | (em[pos+2] << 16) | ((u32)em[pos+3] << 24);
            if (!(state & XS_DATE_EXPIRED) && (bd > d || lic_now_date() > d))
                state |= XS_DATE_EXPIRED;
            pos += 4; break; }
        case 0x06: {
            if (pos >= 256) return XS_INVALID;
            u8 s = em[pos];
            u32 start_tick = ld32(lsd + LSD_OFF_TICK);
            u32 now = lic_tick_ms();
            if (!(state & XS_TIME_OVER) && start_tick && (now - start_tick) / 60000u > s)
                state |= XS_TIME_OVER;
            pos += 1; break; }
        case 0x07: {
            if (pos + 8 > 256) return XS_INVALID;
            u64 pc = ld64(em + pos);
            if (pc != ld64(lsd + LSD_OFF_PC)) return XS_INVALID;
            pos += 8; break; }
        case 0x09: {
            if (pos + 4 > 256) return XS_INVALID;
            u32 d = em[pos] | (em[pos+1] << 8) | (em[pos+2] << 16) | ((u32)em[pos+3] << 24);
            if (!(state & XS_MAXBUILD) && bd > d) state |= XS_MAXBUILD;
            pos += 4; break; }
        case 0x04: {
            if (pos >= 256) return XS_INVALID;
            u8 s = em[pos++];
            if (!lic_check_hwid(em, pos, s, k32, &state)) return state;
            pos += s; break; }
        case 0x02: case 0x03: case 0x08: {
            if (pos >= 256) return XS_INVALID;
            u8 s = em[pos++];
            if (pos + s > 256) return XS_INVALID;
            pos += s; break; }
        case 0xFF: {
            if (pos + 4 > 256) return XS_INVALID;
            sha1_ctx c; u8 h[20]; int i;
            sha1_init(&c);
            sha1_update(&c, em + start, pos - 1 - start);   /* FF hariç (birebir) */
            sha1_final(&c, h);
            for (i = 0; i < 4; i++)
                if (em[pos + i] != h[3 - i]) return XS_INVALID;
            return state; }
        default:
            return XS_INVALID;
        }
    }
    return XS_INVALID;
}

// ---- cp273 PORT E: ONLINE AKTIVASYON (licensing_manager.cc Send/Process 1:1) ----
// WinHTTP ailesi LoadLibraryA + PEB-hash ile cozulur (IAT yok, PIC-guvenli).
// URL LSD 0x130'dan okunur (motor --lic-url ile gomer). CrackUrl yerine
// birebir URL parse (VMProtect CrackUrl es-deger: scheme/host/port/path).
#define XH_WINHTTP_DLL    0x91BD45A3u   // "winhttp.dll"
#define XH_WINHTTP_OPEN   0xAEBC83A5u   // "WinHttpOpen"
#define XH_WINHTTP_READ   0x943A5129u   // "WinHttpReadData"
#define XH_WINHTTP_CLOSE  0xD2053A99u   // "WinHttpCloseHandle"
#define XH_WINHTTP_CONN   0xB0B51A4Du   // "WinHttpConnect"
#define XH_WINHTTP_OREQ   0x1552DF72u   // "WinHttpOpenRequest"
#define XH_WINHTTP_SEND   0xE0CFB564u   // "WinHttpSendRequest"
#define XH_WINHTTP_RECV   0xEC3C8021u   // "WinHttpReceiveResponse"
#define XH_WINHTTP_SETOPT 0xA64F42FAu   // "WinHttpSetOption"
#define XH_WINHTTP_QHDRS  0x437AA28Fu   // "WinHttpQueryHeaders"
// VMProtectActivationFlags (VMProtectDDK.h birebir)
#define ACT_OK            0u
#define ACT_SMALL_BUFFER  1u
#define ACT_NO_CONNECTION 2u
#define ACT_BAD_REPLY     3u
#define ACT_BANNED        4u
#define ACT_CORRUPTED     5u
#define ACT_BAD_CODE      6u
#define ACT_ALREADY_USED  7u
#define ACT_SERIAL_UNK    8u
#define ACT_EXPIRED       9u
#define ACT_NOT_AVAIL     10u

static u32 lic_widen(u16* out, u32 cap, const char* s) {
    u32 n = 0;
    for (; *s && n + 1 < cap; s++) out[n++] = (u16)(u8)*s;
    out[n] = 0;
    return n;
}

/* LSD URL'i parse eder: "http(s)://host[:port][/base]"
   donus: 1 = OK; *is_https, host_w, port, base_w doldurulur */
static int lic_parse_url(const char* url, int* is_https, u16* host_w, u16* base_w,
                         u32* port, u32* base_len) {
    const char* p = url;
    *is_https = 0;
    if (p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p') {
        if (p[4] == 's') { *is_https = 1; p += 5; }
        else p += 4;
    } else return 0;
    if (p[0] != ':' || p[1] != '/' || p[2] != '/') return 0;
    p += 3;
    /* host */
    u32 hn = 0;
    while (*p && *p != ':' && *p != '/' && hn < 63) host_w[hn++] = (u16)(u8)*p++;
    host_w[hn] = 0;
    if (!hn) return 0;
    /* port */
    *port = *is_https ? 443u : 80u;
    if (*p == ':') {
        p++;
        u32 v = 0;
        while (*p >= '0' && *p <= '9') { v = v * 10u + (u32)(*p - '0'); p++; }
        if (v) *port = v;
    }
    /* base path ("-" yoksa "/") */
    u32 bl = 0;
    base_w[bl++] = '/';
    if (*p == '/') {
        p++;
        while (*p && bl < 200) base_w[bl++] = (u16)(u8)*p++;
    }
    base_w[bl] = 0;
    *base_len = bl;
    return 1;
}

/* HTTP GET: VMProtect Send() birebir akis (open->connect->open_request->
   send->receive->read loop->query date->close). donus: okunan bayt; 0 = baglanti yok */
static u32 lic_http_get(const u8* lsd, u64 k32, const char* lsd_url,
                        const char* path_query, u8* resp, u32 cap, u32* srv_date) {
    int is_https = 0;
    u16 host_w[64], base_w[208], agent_w[64], path_w[320];
    u32 port = 0, base_len = 0;
    if (!lic_parse_url(lsd_url, &is_https, host_w, base_w, &port, &base_len)) return 0;

    u64 ll = find_export(k32, XH_LOADLIBRARYA);
    if (!ll) return 0;
    char dllname[16];
    VP4(dllname, 0, A4('w','i','n','h')); VP4(dllname, 4, A4('t','t','p','.'));
    VP4(dllname, 8, A4('d','l','l',0));
    u64 dll = api1(ll, (u64)(unsigned long)dllname);
    if (!dll) return 0;
    u64 f_open = find_export(dll, XH_WINHTTP_OPEN);
    u64 f_read = find_export(dll, XH_WINHTTP_READ);
    u64 f_close = find_export(dll, XH_WINHTTP_CLOSE);
    u64 f_conn = find_export(dll, XH_WINHTTP_CONN);
    u64 f_oreq = find_export(dll, XH_WINHTTP_OREQ);
    u64 f_send = find_export(dll, XH_WINHTTP_SEND);
    u64 f_recv = find_export(dll, XH_WINHTTP_RECV);
    u64 f_setopt = find_export(dll, XH_WINHTTP_SETOPT);
    u64 f_qhdrs = find_export(dll, XH_WINHTTP_QHDRS);
    if (!f_open || !f_read || !f_close || !f_conn || !f_oreq ||
        !f_send || !f_recv || !f_setopt || !f_qhdrs) return 0;

    /* agent: VMProtectDecryptStringW("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)")
       PIC: stack kurulum (literal rodata'a dusemez) */
    {
        char agb[52];
        u32 i = 0;
        VP4(agb, 0,  A4('M','o','z','i')); VP4(agb, 4,  A4('l','l','a','/'));
        VP4(agb, 8,  A4('4','.','0',' ')); VP4(agb, 12, A4('(','c','o','m'));
        VP4(agb, 16, A4('p','a','t','i')); VP4(agb, 20, A4('b','l','e',';'));
        VP4(agb, 24, A4(' ','M','S','I')); VP4(agb, 28, A4('E',' ','6','.'));
        VP4(agb, 32, A4('0',';',' ','W')); VP4(agb, 36, A4('i','n','d','o'));
        VP4(agb, 40, A4('w','s',' ','N')); VP4(agb, 44, A4('T',' ','5','.'));
        VP4(agb, 48, A4('1',')',0,0));
        for (; i < 52; i++) { if (!agb[i]) break; }
        lic_widen(agent_w, 64, agb);
    }
    /* dwAccessType: PEB OSBuildNumber >= 9600 (WIN8_1) -> 4 (AUTOMATIC), yoksa 0 */
    u32 access = 0;
    {
        u64 peb = peb_addr();
        if (peb) {
#if defined(XRT_IS_X64)
            u16 build = ld16((const u8*)(unsigned long)(peb + 0x120));
#else
            u16 build = ld16((const u8*)(unsigned long)(peb + 0xAC));
#endif
            if (build >= 9600u) access = 4;
        }
    }
    u64 inet = api5(f_open, (u64)(unsigned long)agent_w, access, 0, 0, 0);
    if (!inet) return 0;
    u64 conn = api4(f_conn, inet, (u64)(unsigned long)host_w, port, 0);
    if (!conn) { api2(f_close, inet, 0); return 0; }
    /* path_query base'in ucune eklenir; open_request'e kopya gecer */
    u16 verb[4];
    u32 bl = base_len, q = 0;
    while (path_query[q] && bl < 300) base_w[bl++] = (u16)(u8)path_query[q++];
    base_w[bl] = 0;
    verb[0] = 'G'; verb[1] = 'E'; verb[2] = 'T'; verb[3] = 0;
    {
        u32 i2;
        for (i2 = 0; i2 <= bl; i2++) path_w[i2] = base_w[i2];
    }
    u64 req = api7(f_oreq, conn,
                   (u64)(unsigned long)verb,
                   (u64)(unsigned long)path_w, 0, 0, 0,
                   0x00000100u /*BYPASS_CACHE*/ | (u32)(is_https ? 0x00800000u : 0u));
    if (!req) { api2(f_close, conn, 0); api2(f_close, inet, 0); return 0; }
    if (is_https && f_setopt) {
        u32 flags = 0x100u | 0x2000u | 0x8000u;   /* UNKNOWN_CA|DATE|CN ignore */
        api4(f_setopt, req, 31u /*OPTION_SECURITY_FLAGS*/,
             (u64)(unsigned long)&flags, 4u);
    }
    u32 ok = api7(f_send, req, 0, 0, 0, 0, 0, 0);
    if (!ok) { api2(f_recv, req, 0); }
    ok = api2(f_recv, req, 0);
    u32 total = 0;
    if (ok) {
        while (total + 1 < cap) {
            u32 n = 0;
            if (!api4(f_read, req, (u64)(unsigned long)(resp + total),
                      (u64)(cap - 1 - total), (u64)(unsigned long)&n) || !n) break;
            total += n;
        }
    }
    resp[total] = 0;
    /* Date header -> server_date (VMProtect QueryHeaders birebir) */
    if (srv_date && ok) {
        u32 st[8]; u32 len = 32;   /* SYSTEMTIME: 8 x u16 */
        if (api6(f_qhdrs, req, 9u /*QUERY_DATE*/ | 0x40000000u /*FLAG_SYSTEMTIME*/,
                 0xFFFFFFFFull /*HEADER_NAME_BY_INDEX*/, (u64)(unsigned long)st,
                 (u64)(unsigned long)&len, 0)) {
            u16 y = (u16)st[0], mo = (u16)st[1], d = (u16)st[3];
            *srv_date = ((u32)y << 16) | ((u32)(u8)mo << 8) | (u32)(u8)d;
        }
    }
    api2(f_close, req, 0);
    api2(f_close, conn, 0);
    api2(f_close, inet, 0);
    return total;
}

/* ActivationRequest::VerifyCode birebir: alphabet 0-9a-z-, max 33 kar */
static int lic_verify_code(const char* code) {
    if (!code || !code[0]) return 0;
    for (const char* p = code; *p; p++) {
        char c = *p;
        int okc = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') || c == '-';
        if (!okc) return 0;
        if (p - code > 32) return 0;
    }
    return 1;
}

/* XPAPI_ACTIVATE govdesi: BuildUrl(online)+Send+Process birebir.
   donus: ACTIVATION_* ; basarida serial_buf'a serial yazilir. */
static u32 lic_activate(const u8* lsd, u64 k32, const char* code,
                        char* serial_buf, u32 size) {
    if (!lic_verify_code(code)) return ACT_BAD_CODE;
    const char* url = (const char*)(unsigned long)(lsd + LSD_OFF_URL);
    if (!url[0]) return ACT_NOT_AVAIL;
    /* hwid + hash parametreleri (offline yol ile ayni uretim) */
    u32 cur[2];
    if (!lic_hwid_env(cur)) return ACT_BAD_REPLY;
    u8 raw[8]; u32 r;
    for (r = 0; r < 4; r++) raw[r]     = (u8)(cur[0] >> (8 * r));
    for (r = 0; r < 4; r++) raw[4 + r] = (u8)(cur[1] >> (8 * r));
    char str_hwid[24]; u32 hn = 0;
    lic_b64enc(raw, 8, str_hwid, &hn);
    u8 h[20];
    { sha1_ctx c; sha1_init(&c); sha1_update(&c, lsd + LSD_OFF_MOD, 256); sha1_final(&c, h); }
    char str_hash[32]; u32 sn = 0;
    lic_b64enc(h, 20, str_hash, &sn);
    /* path: activation.php?code=<code>&hwid=<hwid>&hash=<hash>
       (ActivationRequest::BuildUrl online formu birebir; stack-stringler) */
    char path[512]; u32 o = 0;
    char s_pre[24], s_p3[8], s_p4[8];
    VP4(s_pre, 0,  A4('a','c','t','i')); VP4(s_pre, 4,  A4('v','a','t','i'));
    VP4(s_pre, 8,  A4('o','n','.','p')); VP4(s_pre, 12, A4('h','p','?','c'));
    VP4(s_pre, 16, A4('o','d','e','='));
    s_pre[20] = 0;
    VP4(s_p3, 0, A4('&','h','w','i')); VP4(s_p3, 4, A4('d','=',0,0));
    VP4(s_p4, 0, A4('&','h','a','s')); VP4(s_p4, 4, A4('h','=',0,0));
    const char* parts[6]; u32 pi;
    parts[0] = s_pre;    parts[1] = code;
    parts[2] = s_p3;     parts[3] = str_hwid;
    parts[4] = s_p4;     parts[5] = str_hash;
    for (pi = 0; pi < 6 && o + 1 < sizeof path; pi++) {
        const char* s = parts[pi];
        if (pi & 1) o += lic_url_escape(path + o, (u32)(sizeof path - o - 1), s);
        else while (*s && o + 1 < sizeof path) path[o++] = *s++;
    }
    path[o] = 0;
    u8 resp[2048]; u32 srv_date = 0;
    u32 n = lic_http_get(lsd, k32, url, path, resp, sizeof resp, &srv_date);
    (void)srv_date;   /* GetCurrentDate max'ine 0.9.0'da baglanir (LSD alan izi var) */
    if (!n) return ACT_NO_CONNECTION;
    /* reply: OK\n<serial> | BAD | BANNED | USED | EXPIRED (birebir) */
    if (resp[0] == 'B' && resp[1] == 'A' && resp[2] == 'D') return ACT_BAD_CODE;
    if (resp[0] == 'B' && resp[1] == 'A' && resp[2] == 'N') return ACT_BANNED;
    if (resp[0] == 'U' && resp[1] == 'S' && resp[2] == 'E') return ACT_ALREADY_USED;
    if (resp[0] == 'E' && resp[1] == 'X' && resp[2] == 'P') return ACT_EXPIRED;
    if (!(resp[0] == 'O' && resp[1] == 'K' && resp[2] == '\n')) return ACT_BAD_REPLY;
    const char* s2 = (const char*)resp + 3;
    u32 need = 0;
    while (s2[need]) need++;
    if (need + 1 > size) return ACT_SMALL_BUFFER;
    { u32 i2; for (i2 = 0; i2 <= need; i2++) serial_buf[i2] = s2[i2]; }
    return ACT_OK;
}

/* XPAPI_DEACTIVATE govdesi: DeactivationRequest::BuildUrl/Process birebir.
   reply: OK | ERROR | UNKNOWN */
static u32 lic_deactivate(const u8* lsd, u64 k32, const char* serial) {
    /* VerifySerial: base64 + minimum boyut */
    if (!serial || !serial[0]) return ACT_BAD_CODE;
    u32 slen = 0;
    while (serial[slen]) slen++;
    u8 bin[512]; u32 bl = 0;
    if (!lic_b64dec((const u8*)(unsigned long)serial, slen, bin, &bl) || bl < 16)
        return ACT_BAD_CODE;
    const char* url = (const char*)(unsigned long)(lsd + LSD_OFF_URL);
    if (!url[0]) return ACT_NOT_AVAIL;
    u8 h[20];
    { sha1_ctx c; sha1_init(&c); sha1_update(&c, bin, bl); sha1_final(&c, h); }
    char str_hash[32]; u32 sn = 0;
    lic_b64enc(h, 20, str_hash, &sn);
    char path[128]; u32 o = 0;
    char s_pre[16], s_p2[8];
    VP4(s_pre, 0, A4('d','e','a','c')); VP4(s_pre, 4, A4('t','i','v','a'));
    VP4(s_pre, 8, A4('t','i','o','n')); VP4(s_pre, 12, A4('.','p','h','p'));
    VP4(s_p2, 0, A4('?','h','a','s')); VP4(s_p2, 4, A4('h','=',0,0));
    for (u32 pi = 0; pi < 4 && o + 1 < sizeof path; pi++) {
        const char* s = (pi == 0) ? s_pre : (pi == 1) ? s_p2 :
                        (pi == 2) ? str_hash : "";
        while (*s && o + 1 < sizeof path) path[o++] = *s++;
    }
    path[o] = 0;
    u8 resp[256];
    u32 n = lic_http_get(lsd, k32, url, path, resp, sizeof resp, 0);
    if (!n) return ACT_NO_CONNECTION;
    if (resp[0] == 'O' && resp[1] == 'K') return ACT_OK;
    if (resp[0] == 'E' && resp[1] == 'R') return ACT_CORRUPTED;
    if (resp[0] == 'U' && resp[1] == 'N') return ACT_SERIAL_UNK;
    return ACT_BAD_REPLY;
}

// ---- cp273 PORT F: ISVM GERÇEK TESPİT (runtime/core.cc ExportedIsVirtualMachinePresent 1:1) ----
#define XH_ENUMFIRM     0xA0DA901Du   // "EnumSystemFirmwareTables"
#define XH_GETSYSFIRM   0xC74E7819u   // "GetSystemFirmwareTable"

/* InternalFindFirmwareVendor (Windows dalı birebir): VirtualBox/VMware/Parallels */
static int lic_find_vendor(const u8* data, u32 size) {
    for (u32 i = 0; i < size; i++) {
        if (i + 9 < size && data[i]=='V' && data[i+1]=='i' && data[i+2]=='r' &&
            data[i+3]=='t' && data[i+4]=='u' && data[i+5]=='a' && data[i+6]=='l' &&
            data[i+7]=='B' && data[i+8]=='o' && data[i+9]=='x') return 1;
        if (i + 5 < size && data[i]=='V' && data[i+1]=='M' && data[i+2]=='w' &&
            data[i+3]=='a' && data[i+4]=='r' && data[i+5]=='e') return 1;
        if (i + 8 < size && data[i]=='P' && data[i+1]=='a' && data[i+2]=='r' &&
            data[i+3]=='a' && data[i+4]=='l' && data[i+5]=='l' && data[i+6]=='e' &&
            data[i+7]=='l' && data[i+8]=='s') return 1;
    }
    return 0;
}

static void lic_cpuid(u32 leaf, u32 out[4]) {
    __asm__ volatile (
        "xorl %%ebx, %%ebx\n\txorl %%ecx, %%ecx\n\tcpuid"
        : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
        : "a"(leaf));
}

/* IsVirtualMachinePresent birebir:
   1) CPUID(1) ECX bit31 (hipervizor) ->
      Hyper-V root-partition ayristirmasi (0x40000000 "Microsoft Hv",
      0x40000003 EBX bit0) — root partition ise VM DEGIL.
   2) yazilim yolu: EnumSystemFirmwareTables('FIRM') -> GetSystemFirmwareTable
      -> vendor taramasi */
static u32 lic_isvm(u64 k32) {
    u32 ci[4];
    lic_cpuid(1, ci);
    if ((ci[2] >> 31) & 1u) {
        /* Hyper-V root partition kontrolu */
        lic_cpuid(0x40000000u, ci);
        if (ci[1] == 0x7263694Du && ci[2] == 0x666F736Fu && ci[3] == 0x76482074u) {
            lic_cpuid(0x40000003u, ci);
            if (ci[1] & 1u) return 0;
        }
        return 1;
    }
    /* firmware tablosu taramasi */
    {
        u64 f_enum = find_export(k32, XH_ENUMFIRM);
        u64 f_get = find_export(k32, XH_GETSYSFIRM);
        if (f_enum && f_get) {
            u32 firm = 0x4D524946u;   /* 'FIRM' (LE) */
            u32 tables_size = (u32)api3(f_enum, firm, 0, 0);
            if (tables_size && tables_size <= 256u) {
                u32 tables[64];
                api3(f_enum, firm, (u64)(unsigned long)tables, tables_size);
                u32 n = tables_size / 4u;
                for (u32 i = 0; i < n && i < 64u; i++) {
                    u32 dsz = (u32)api4(f_get, firm, tables[i], 0, 0);
                    if (dsz && dsz <= 4096u) {
                        u8 data[4096];
                        api4(f_get, firm, tables[i], (u64)(unsigned long)data, dsz);
                        if (lic_find_vendor(data, dsz)) return 1;
                    }
                }
            }
        }
    }
    return 0;
}

// ---- çekirdek (arch-bağımsız) ----
static u64 lic_sdk_core(u64 fnid, u64 a1, u64 a2, u64 a3, u64 a4) {
    (void)a3; (void)a4;
    const u8* lsd = lic_lsd();
    u64 k32 = peb_module(XH_KERNEL32);
    switch (fnid) {
    case XPAPI_SETSERIAL: {
        if (!lsd) return XS_CORRUPTED;
        const char* serial = (const char*)(unsigned long)a1;
        if (!serial) return XS_INVALID;
        u32 n = 0;
        while (serial[n]) n++;
        if (!n || n > 1216) return XS_INVALID;   /* cp293: 7168-bit = 896B -> b64 ~1216 */
        u8 bin[896]; u32 bl = 0;   /* cp293: 7168-bit'e kadar */
        if (!lic_b64dec((const u8*)(unsigned long)serial, n, bin, &bl) || bl < 16)
            return XS_INVALID;
        lic_wr32((u8*)(unsigned long)(lsd + LSD_OFF_STATE), XS_INVALID);
        u8 em[896];                                  /* cp293: 7168-bit'e kadar */
        int L2 = lic_setlen_from_lsd(lsd);           /* cp292: dinamik RSA */
        u32 emb = (u32)L2 * 4;                       /* aktif modulus bayti */
        lic_modexp65537(bin, lsd + LSD_OFF_MOD2, em);

        if (em[0] != 0 || em[1] != 2) return XS_INVALID;
        u32 pos;
        for (pos = 2; pos < emb; pos++)
            if (!em[pos]) { pos++; break; }
        if (pos == emb) return XS_INVALID;
        lic_wr32((u8*)(unsigned long)(lsd + LSD_OFF_TICK), lic_tick_ms());
        u32 st = lic_parse_serial(em, pos, lsd, k32);
        lic_wr32((u8*)(unsigned long)(lsd + LSD_OFF_STATE), st);
        /* 0.7.0-final: em'yi onbellege yaz (GetSerialNumberData bunu okur) */
        if (st != XS_INVALID) {
            /* cp293/V293-1b: cache modulus'tan SONRA (eski 0x12C ofseti
               keylen alaniyla cakisiyordu — ikinci SetSerial keylen'i eziyordu) */
            u8* cache = (u8*)(unsigned long)(lsd + LSD_OFF_MOD2 + emb);
            cache[0] = (u8)LSD_CACHE_FLAG; cache[1] = 0; cache[2] = 0; cache[3] = 0;
            lcopy(cache + 4, em, emb);   /* FIX: lcopy(d,s,n) — hedef once */
        }
        return st;
    }
    case XPAPI_GETSTATE: {
        if (!lsd) return XS_CORRUPTED;
        return ld32(lsd + LSD_OFF_STATE);
    }
    case XPAPI_GETDATA: {
        if (!lsd) return 0;
        lic_snd_t* d = (lic_snd_t*)(unsigned long)a1;
        if (!d || (int)a2 != (int)sizeof(lic_snd_t)) return 0;
        {
            /* cp293/V293-1b: cache ofseti dinamik (modulus uzunluguna gore) */
            int L3 = lic_setlen_from_lsd(lsd);
            const u8* cache = (const u8*)(unsigned long)(lsd + LSD_OFF_MOD2 + (u32)L3 * 4);
            u32 state = ld32(lsd + LSD_OFF_STATE);
            if (cache[0] == (u8)LSD_CACHE_FLAG) {
                /* em yeniden-pozisyonla: blok baslangicina git */
                const u8* em = cache + 4;
                u32 emb3 = (u32)L3 * 4;
                u32 pos = 2;
                while (pos < emb3 && em[pos]) pos++;
                pos++;
                lic_fill_data(d, em, pos, state);
            } else {
                lmset((u8*)d, 0, sizeof(lic_snd_t));
                d->nState = (int)state;
            }
        }
        return 1;
    }
    case XPAPI_GETHWID: {
        char* buf = (char*)(unsigned long)a1;
        int size = (int)a2;
        if (!buf || size == 0) return 0;
        u32 cur[2];
        if (!lic_hwid_env(cur)) return 0;
        u8 raw[8];
        raw[0]=(u8)cur[0]; raw[1]=(u8)(cur[0]>>8); raw[2]=(u8)(cur[0]>>16); raw[3]=(u8)(cur[0]>>24);
        raw[4]=(u8)cur[1]; raw[5]=(u8)(cur[1]>>8); raw[6]=(u8)(cur[1]>>16); raw[7]=(u8)(cur[1]>>24);
        char out[16]; u32 on = 0;
        lic_b64enc(raw, 8, out, &on);
        u32 copy = (u32)size - 1; if (copy > on) copy = on;
        { u32 i2; for (i2 = 0; i2 < copy; i2++) buf[i2] = out[i2]; }
        buf[copy] = 0;
        return copy + 1;
    }
    case XPAPI_ISPROTECTED:  return 1;
    case XPAPI_ISDEBUGGER: {
        u8* p = (u8*)(unsigned long)peb_addr();
        return p[2] ? 1 : 0;
    }
    case XPAPI_ISIMAGECRC: return lic_lsd() ? 1 : 0;   /* cp273 PORT F: LSD-CRC + self-CRC gate'i icinden gecmis demektir */
    case XPAPI_DECSTRA: return a1;        /* MVP: dizgeler şifresiz */
    case XPAPI_DECSTRW: return a1;
    case XPAPI_FREESTRING: return 1;
    case XPAPI_ACTIVATE: {
        /* cp273 PORT E: online aktivasyon — Send/Process 1:1 */
        if (!lsd) return ACT_CORRUPTED;
        return lic_activate(lsd, k32, (const char*)(unsigned long)a1,
                            (char*)(unsigned long)a2, (u32)a3);
    }
    case XPAPI_DEACTIVATE: {
        if (!lsd) return ACT_CORRUPTED;
        return lic_deactivate(lsd, k32, (const char*)(unsigned long)a1);
    }
    case XPAPI_OFFACT: case XPAPI_OFFDEACT: {
        /* cp273 PORT A: cevrimdisi aktivasyon/deaktivasyon string'i —
           ActivationRequest::BuildUrl(offline=true) + EncodeUrl birebir */
        char* buf = (char*)(unsigned long)a1;
        int size = (int)a2;
        const char* code = (const char*)(unsigned long)a3;
        if (!lsd || !buf || size <= 0) return 0;
        char tmp[512];
        char empty[1]; empty[0] = 0;    /* PIC: "" literal'i .rodata'ya dusmez */
        u32 n = lic_offline_str(tmp, sizeof tmp,
                                (fnid == XPAPI_OFFDEACT) ? 1 : 0,
                                code ? code : empty, lsd, k32);
        if (!n || (int)n > size) return 0;
        { u32 i2; for (i2 = 0; i2 < n; i2++) buf[i2] = tmp[i2]; }
        return 1;
    }
    case XPAPI_ISVM:     return lic_isvm(k32);   /* cp273 PORT F: CPUID + firmware taraması (core.cc 1:1) */

    /* ---------- 0.7.0-final SDK-40: kaynak ailesi (gercek API delege) ----
       .rsrc runtime-decrypt (0.6.0) sonrasi gecerli oldugundan FindResource/
       LoadResource/Enum ailesi gercel Windows API'sine yonlenir (PEB hash,
       IAT'siz). Kanit: shell32 uzerinden types=13, icon-names=1840. */
    case XPAPI_FINDRESA: case XPAPI_FINDRESW: {
        u64 f = find_export(k32, (fnid == XPAPI_FINDRESA) ? XH_FINDRESOURCEA : XH_FINDRESOURCEW);
        return f ? api3(f, a1, a2, a3) : 0;
    }
    case XPAPI_FINDRESEXA: case XPAPI_FINDRESEXW: {
        u64 f = find_export(k32, (fnid == XPAPI_FINDRESEXA) ? XH_FINDRESOURCEEXA : XH_FINDRESOURCEEXW);
        return f ? api4(f, a1, a2, a3, a4) : 0;
    }
    case XPAPI_LOADRESOURCE: {
        u64 f = find_export(k32, XH_LOADRESOURCE);
        return f ? api2(f, a1, a2) : 0;
    }
    case XPAPI_LOADSTRA: case XPAPI_LOADSTRW: {
        u64 um = peb_module(XH_USER32);
        if (!um) {
            u64 ll = find_export(k32, XH_LOADLIBRARYA);
            char un[16];
            VP4(un, 0, A4('u','s','e','r')); VP4(un, 4, A4('3','2','.','d')); VP4(un, 8, A4('l','l',0,0));
            if (!ll) return 0;
            um = api1(ll, (u64)(unsigned long)(void*)un);
            if (!um) return 0;
        }
        u64 f = find_export(um, (fnid == XPAPI_LOADSTRA) ? XH_LOADSTRINGA : XH_LOADSTRINGW);
        return f ? api4(f, a1, a2, a3, a4) : 0;
    }
    case XPAPI_ENUMNAMESA: case XPAPI_ENUMNAMESW: {
        u64 f = find_export(k32, (fnid == XPAPI_ENUMNAMESA) ? XH_ENUMRESOURCENAMESA : XH_ENUMRESOURCENAMESW);
        return f ? api4(f, a1, a2, a3, a4) : 0;
    }
    case XPAPI_EXENULANGA: case XPAPI_EXENULANGW: {
        u64 f = find_export(k32, (fnid == XPAPI_EXENULANGA) ? XH_ENUMRESOURCELANGUAGESA : XH_ENUMRESOURCELANGUAGESW);
        return f ? api5(f, a1, a2, a3, a4, 0) : 0;
    }
    case XPAPI_EXENUTYPESA: case XPAPI_EXENUTYPESW: {
        u64 f = find_export(k32, (fnid == XPAPI_EXENUTYPESA) ? XH_ENUMRESOURCETYPESA : XH_ENUMRESOURCETYPESW);
        return f ? api3(f, a1, a2, a3) : 0;
    }

    /* ---------- 0.7.0-final: buffer/rastgele/kutu ---------- */
    case XPAPI_DECBUF: {
        /* cp273 PORT A — licensing_manager.cc DecryptBuffer birebir:
           p[0..3] = rotl((p+session)^key0, 7/11/17/23) + key1
           dogrulama: p0+p1+p2+p3 == session*4 degilse lisans mesaji +
           TerminateProcess(0xDEADC0DE). Anahtar uretimi:
           key0 = lo64(product_code), key1 = hi64(product_code)+session_key.
           SDK'dan key argumaninda [lo32 key0 | hi32 session] gelir —
           uyumluluk: eski splitmix yolu 16B'den KUCUK tamponlarda kalir
           (test cagrilari bozulmasin); VMProtect yolu >=16B'de. */
        u8* buf = (u8*)(unsigned long)a1;
        u32 n = (u32)a2;
        u64 key = a3;
        if (!buf || !n) return 0;
        if (n >= 16 && lsd && ((u32)1u << 0)) {
            u32 session = (u32)key;
            u32 key0 = ld32(lsd + LSD_OFF_PC);
            u32 key1 = ld32(lsd + LSD_OFF_PC + 4) + session;
            u32* p = (u32*)(unsigned long)buf;
            u32 q0 = p[0], q1 = p[1], q2 = p[2], q3 = p[3];
            p[0] = lic_rotl((q0 + session) ^ key0,  7) + key1;
            p[1] = lic_rotl((q1 + session) ^ key0, 11) + key1;
            p[2] = lic_rotl((q2 + session) ^ key0, 17) + key1;
            p[3] = lic_rotl((q3 + session) ^ key0, 23) + key1;
            if (p[0] + p[1] + p[2] + p[3] != session * 4u) {
                /* VMProtect: lisans-gerekli mesaji + sonlandir (0xDEADC0DE) */
                u64 kp = find_export(k32, XH_TERMINATE);
                if (kp) api1(kp, 0xDEADC0DEull);
                return 0;
            }
            /* kalan baytlar: splitmix akisi (VMProtect yalniz ilk 16B'yi
               sifreler; uzun tamponlar icin geri kalan bize kalmis) */
            {
                u64 s = key ^ 0xC2B2AE3D27D4EB4Full;
                u32 i;
                for (i = 16; i < n; i++) {
                    s += 0x9E3779B97F4A7C15ull;
                    { u64 z = s;
                      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
                      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
                      z ^= z >> 31;
                      buf[i] ^= (u8)(z >> 24); }
                }
            }
            return a1;
        }
        u64 s = key ^ 0xC2B2AE3D27D4EB4Full;
        u32 i;
        for (i = 0; i < n; i++) {
            s += 0x9E3779B97F4A7C15ull;
            { u64 z = s;
              z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
              z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
              z ^= z >> 31;
              buf[i] ^= (u8)(z >> 24); }
        }
        return a1;
    }
    case XPAPI_RANDOM: {
        /* rdtsc + KUSER interrupt time karışımı (API'siz, PIC-güvenli) */
        u32 t1, t2;
        __asm__ volatile ("rdtsc" : "=a"(t1), "=d"(t2));
        u64 r = ((u64)t2 << 32) | t1;
        u32 lo = ld32((const u8*)(unsigned long)(0x7FFE0000ull + 0x08));
        r ^= ((u64)lo << 17) ^ lic_exe_base();
        r *= 0x2545F4914F6CDD1Dull;
        r ^= r >> 29;
        r *= 0xBF58476D1CE4E5B9ull;
        r ^= r >> 32;
        return r;
    }
    case XPAPI_BOXPTR: case XPAPI_UNBOXPTR: {
        /* simetrik kutu: p' = p ^ K(load); K imaj-bazlı (aynı süreçte çift
           işlemler kendini götürür) */
        u64 k = lic_exe_base() * 0x9E3779B97F4A7C15ull ^ 0x51ED270B4C5A3D0Full;
        return a1 ^ k;
    }
    case XPAPI_RTINIT:     return 1;
    case XPAPI_LOADERDATA: return (u64)(unsigned long)(void*)lic_lsd();
    case XPAPI_SETUPIMAGE: return 1;
    case XPAPI_FREEIMAGE:  return 1;
    case XPAPI_CALCCRC:    return 1;
    default: return 0;
    }
}

#if defined(XRT_IS_X64)
u64 xrt_sdk_dispatch(u64 fnid, u64 a1, u64 a2, u64 a3, u64 a4) {
    return lic_sdk_core(fnid, a1, a2, a3, a4);
}
#else
u32 xrt_sdk_dispatch86(u32 fnid, u32 args_ptr) {
    const u8* ar = (const u8*)(unsigned long)args_ptr;
    u32 a1 = ld32(ar), a2 = ld32(ar + 4), a3 = ld32(ar + 8), a4 = ld32(ar + 12);
    return (u32)lic_sdk_core(fnid, a1, a2, a3, a4);
}
#endif

// ---- asm giriş kapıları (Win32 ABI -> SysV C) ----
#if defined(XRT_IS_X64)
__asm__(
".text\n"
".globl xrt_sdk_entry\n"
"xrt_sdk_entry:\n"
"  subq $0xE8, %rsp\n"
"  movq %rcx, 0x00(%rsp)\n"
"  movq %rdx, 0x08(%rsp)\n"
"  movq %r8,  0x10(%rsp)\n"
"  movq %r9,  0x18(%rsp)\n"
"  movq %rsi, 0x20(%rsp)\n"
"  movq %rdi, 0x28(%rsp)\n"
"  movdqu %xmm6,  0x30(%rsp)\n"
"  movdqu %xmm7,  0x40(%rsp)\n"
"  movdqu %xmm8,  0x50(%rsp)\n"
"  movdqu %xmm9,  0x60(%rsp)\n"
"  movdqu %xmm10, 0x70(%rsp)\n"
"  movdqu %xmm11, 0x80(%rsp)\n"
"  movdqu %xmm12, 0x90(%rsp)\n"
"  movdqu %xmm13, 0xA0(%rsp)\n"
"  movdqu %xmm14, 0xB0(%rsp)\n"
"  movdqu %xmm15, 0xC0(%rsp)\n"
"  movq %rcx, %rsi\n"           /* a1 (SysV rsi) */
"  movq %r8,  %rcx\n"           /* a3 (SysV rcx) */
"  movq %r9,  %r8\n"           /* a4 (SysV r8)  */
"  xorl %r9d, %r9d\n"          /* a5 yok */
"  movl %r10d, %edi\n"         /* fnid (SysV rdi) */
"  call xrt_sdk_dispatch\n"    /* a2 = Win rdx = SysV rdx dogrudan */
"  movq 0x00(%rsp), %rcx\n"
"  movq 0x08(%rsp), %rdx\n"
"  movq 0x10(%rsp), %r8\n"
"  movq 0x18(%rsp), %r9\n"
"  movq 0x20(%rsp), %rsi\n"
"  movq 0x28(%rsp), %rdi\n"
"  movdqu 0x30(%rsp), %xmm6\n"
"  movdqu 0x40(%rsp), %xmm7\n"
"  movdqu 0x50(%rsp), %xmm8\n"
"  movdqu 0x60(%rsp), %xmm9\n"
"  movdqu 0x70(%rsp), %xmm10\n"
"  movdqu 0x80(%rsp), %xmm11\n"
"  movdqu 0x90(%rsp), %xmm12\n"
"  movdqu 0xA0(%rsp), %xmm13\n"
"  movdqu 0xB0(%rsp), %xmm14\n"
"  movdqu 0xC0(%rsp), %xmm15\n"
"  addq $0xE8, %rsp\n"
"  ret\n"
);
#else
__asm__(
".text\n"
".globl xrt_sdk_entry86\n"
"xrt_sdk_entry86:\n"
"  pusha\n"                      /* 32B: eax@28 ecx@24 edx@20 ... edi@0 */
"  leal 0x24(%esp), %edx\n"     /* args_ptr (API arg1) */
"  pushl %edx\n"               /* 2. arg: args_ptr */
"  pushl %ecx\n"               /* 1. arg: fnid */
"  call xrt_sdk_dispatch86\n"
"  addl $8, %esp\n"
"  movl %eax, 0x1C(%esp)\n"    /* eax yuvasina donus */
"  popa\n"
"  ret\n"
);
#endif

#endif // XRT_LICENSE_C
