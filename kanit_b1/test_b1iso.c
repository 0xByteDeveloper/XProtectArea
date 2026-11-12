/* test_b1iso.c — B1 izolasyon testi: her yeni ozellik AYRI bolgede.
 * P1 plain-V (R5 deseni — bilinen-iyi)      -> saglamsin kontrol
 * P2 ncall VM->VM (tek cagri)               -> mult-VM izolasyonu
 * P3 njcc rel8 negatif (T3 aynisi, V-mark)  -> gateway izolasyonu
 * P4 njcc rel32 pozitif (ext SONRA gelsin)  -> yon izolasyonu
 * P5 test+jnz FALL-ONLY (disari hedef asla alinmaz ama lifter NJCC uretir)
 * rc: 42 = hepsi dogru
 */
#include <stdio.h>
#include <stdint.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

static volatile uint32_t g1;

/* P1 */
__attribute__((noinline)) uint32_t p1_v(uint32_t n) {
    XP_SDK_BEG(1);
    uint32_t s = n * 3 + 7;
    if (s > 100) s -= 100;
    g1 = s;
    XP_SDK_END();
    return s;
}

/* P2: VM->VM tek cagri */
__attribute__((noinline)) uint32_t p2_sub(uint32_t n) {
    XP_SDK_BEG(1);
    g1 = n ^ 0x5A5A;
    XP_SDK_END();
    return n + 1;
}
__attribute__((noinline)) uint32_t p2_call(uint32_t n) {
    XP_SDK_BEG(1);
    uint32_t a = p2_sub(n);
    g1 = a;
    XP_SDK_END();
    return a * 2;
}
/* cift-ncall: ardardik iki VM->VM cagrisi (multvm teshisi) */
static volatile uint32_t g1, g2, g3;
__attribute__((noinline)) uint32_t p2_double(uint32_t n) {
    XP_SDK_BEG(1);
    uint32_t a = p2_sub(n);
    g3 = a;                              /* g1 DEGIL — p2_sub g1'e yazar */
    uint32_t b = p2_sub(n + 1);
    g2 = b;
    XP_SDK_END();
    return a ^ (b * 2654435761u);
}

/* dongulu VM bolgesi (f2_inner'in ayni dongusu) — dogrudan cagiri */
__attribute__((noinline)) uint32_t p2_loop(uint32_t n) {
    XP_SDK_BEG(1);
    uint32_t s = 2166136261u;
    for (uint32_t i = 0; i < (n & 63u); i++) { s = (s ^ i) * 16777619u; s ^= s >> 7; }
    g2 = s;
    XP_SDK_END();
    return s;
}
/* cift-ncall + DONGULU callee (test_b1 multvm'nin birebir sekli) */
__attribute__((noinline)) uint32_t p2d2(uint32_t n) {
    XP_SDK_BEG(1);
    uint32_t a = p2_loop(n);
    uint32_t b = p2_loop(n + 1);
    XP_SDK_END();
    return a ^ (b * 2654435761u);
}
/* P3/P4: njcc asm bolgeleri */
#if defined(__x86_64__)
static void rlog(const char* s);
/* rel8 negatif: ext bolgeden ONCE — C fonksiyonu (natcall hedefi) */
__attribute__((noinline)) uint32_t p3_ext(uint32_t x) {
    /* rlog KAPALI (bisect): derin cagri zinciri suphesi */
    return x ^ 0xBEEF;
}
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    ".globl p3_main\n"
    "p3_main:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  test ecx, ecx\n"
    "  jnz p3_ext\n"
    "  mov eax, 111\n"
    "  ret\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
);
extern uint32_t p3_main(uint32_t);
/* rel32 pozitif: ext bolgeden SONRA (linker ileriye yazar) */
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    ".globl p4_main\n"
    "p4_main:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  test ecx, ecx\n"
    "  jz 1f\n"
    "  jmp p4_ext\n"          /* taken-yol: jmp disari (kuyruk — NCALL yolu) */
    "1:\n"
    "  mov eax, 222\n"
    "  ret\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
    ".globl p4_ext\n"
    "p4_ext:\n"
    "  mov eax, ecx\n"
    "  xor eax, 0xBEEF\n"
    "  ret\n"
);
extern uint32_t p4_main(uint32_t);
#elif defined(__i386__)
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    ".globl _p3_entry\n"
    "_p3_entry:\n"
    "  mov eax, [esp+4]\n"
    "  jmp _p3_main\n"
    ".globl _p3_ext\n"
    "_p3_ext:\n"
    "  xor eax, 0xBEEF\n"
    "  ret\n"
    ".globl _p3_main\n"
    "_p3_main:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  test eax, eax\n"
    "  jnz _p3_ext\n"
    "  mov eax, 111\n"
    "  ret\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
);
extern uint32_t __cdecl p3_main(uint32_t);
#define p3_entry p3_main
#endif

static void rlog_addr(const char* tag, unsigned long long rip) {
    FILE* f = fopen("Z:\\home\\z\\my-project\\scripts\\kanit_b1\\iso_sonuc.txt", "a");
    if (f) { fprintf(f, "%s rip=0x%016llX\n", tag, rip); fclose(f); }
}
typedef unsigned long long u64v;
/* VEH: istisna RIP'ini dosyaya yaz (wine crash teshisi) */
__attribute__((dllimport)) void* __stdcall AddVectoredExceptionHandler(unsigned long first, void* handler);
static long __stdcall my_veh(void* eps) {
    u64v* er = *(u64v**)eps;              /* EXCEPTION_RECORD* */
    unsigned int ecode = (unsigned int)er[0];
    u64v eaddr = er[2];                   /* ExceptionAddress (offset 16) */
    if (ecode & 0x80000000u) {
        FILE* f = fopen("Z:\\home\\z\\my-project\\scripts\\kanit_b1\\iso_sonuc.txt", "a");
        if (f) { fprintf(f, "EXC %08X rip=0x%016llX\n", ecode, eaddr); fclose(f); }
    }
    return 0;                             /* EXCEPTION_CONTINUE_SEARCH */
}

static void rlog(const char* s) {
    FILE* f = fopen("Z:\\home\\z\\my-project\\scripts\\kanit_b1\\iso_sonuc.txt", "a");
    if (f) { fputs(s, f); fputc('\n', f); fclose(f); }
}

int main(void) {
    int r = 0;
    uint32_t got, want;
    AddVectoredExceptionHandler(1, (void*)my_veh);
    printf("basla\n"); fflush(stdout);
    FILE* rf = fopen("Z:\\home\\z\\my-project\\scripts\\kanit_b1\\iso_sonuc.txt", "w");
    if (rf) fclose(rf);

    got = p1_v(11); want = 11 * 3 + 7;
    if (got != want) { rlog("FAIL p1"); r |= 1; }
    else rlog("OK p1");

    got = p2_call(9); want = (9 + 1) * 2;
    if (got != want) { rlog("FAIL p2"); r |= 2; }
    else rlog("OK p2");

    {
        uint32_t a = 9 + 1, b = 9 + 2;
        got = p2_double(9); want = a ^ (b * 2654435761u);
        if (got != want) { rlog("FAIL p2d"); r |= 256; }
        else rlog("OK p2d");
        if (g3 != a) { rlog("FAIL p2d-g3"); r |= 512; }
        if (g2 != b) { rlog("FAIL p2d-g2"); r |= 1024; }
    }

    {
        uint32_t s = 2166136261u;
        for (uint32_t i = 0; i < (21u & 63u); i++) { s = (s ^ i) * 16777619u; s ^= s >> 7; }
        got = p2_loop(21); want = s;
        if (got != want) {
            char bfr[64]; static const char* hx = "0123456789ABCDEF";
            for (int q = 0; q < 8; q++) bfr[q] = hx[(got >> ((7 - q) * 4)) & 0xF];
            bfr[8] = ' '; bfr[9] = 'w'; bfr[10] = '='; bfr[11] = ' ';
            for (int q = 0; q < 8; q++) bfr[12 + q] = hx[(want >> ((7 - q) * 4)) & 0xF];
            bfr[20] = 0;
            rlog(bfr);
            r |= 2048;
        }
        else rlog("OK p2loop");
        uint32_t s2 = 2166136261u;
        for (uint32_t i = 0; i < (22u & 63u); i++) { s2 = (s2 ^ i) * 16777619u; s2 ^= s2 >> 7; }
        uint32_t s3 = 2166136261u;
        for (uint32_t i = 0; i < (23u & 63u); i++) { s3 = (s3 ^ i) * 16777619u; s3 ^= s3 >> 7; }
        got = p2d2(22); want = s2 ^ (s3 * 2654435761u);
        if (got != want) {
            FILE* f = fopen("Z:\\home\\z\\my-project\\scripts\\kanit_b1\\iso_sonuc.txt", "a");
            if (f) { fprintf(f, "p2d2 got=%08X want=%08X s2=%08X s3=%08X\n", got, want, s2, s3); fclose(f); }
            r |= 4096;
        }
        else rlog("OK p2d2");
    }

    rlog("p3t-oncesi");
    got = p3_main(5); want = 5 ^ 0xBEEF;
    if (got != want) { rlog("FAIL p3t"); r |= 4; }
    else rlog("OK p3t");
    got = p3_main(0); want = 111;
    if (got != want) { rlog("FAIL p3f"); r |= 8; }
    else rlog("OK p3f");

    got = p4_main(5); want = 5 ^ 0xBEEF;
    if (got != want) { rlog("FAIL p4t"); r |= 16; }
    else rlog("OK p4t");
    got = p4_main(0); want = 222;
    if (got != want) { rlog("FAIL p4f"); r |= 32; }
    else rlog("OK p4f");

    rlog(r ? "HATALI" : "OK hepsi");
    printf(r ? "HATALI r=%d\n" : "OK hepsi\n", r);
    return r ? 7 : 42;
}
