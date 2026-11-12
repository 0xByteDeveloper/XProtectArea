/* test_b1.c — 1.2.0-B1 kanit testi: UniversalObfuscator "Advanced (rel32)"
 * parite bloklari:
 *   T1 MULT-VM   : f1 (Ultra) icinden f2 (Virtualization) stub'ina ncall
 *                  -> VM->VM ic-ice giris (kendi VM'i calisirken digeri).
 *   T2 OP_RETI   : dinamik ret-imm (x86 stdcall) — ret 8 / ret 4 / MIXED
 *                  (iki farkli imm AYNI bolgede: eski lifter RED'di).
 *   T3 OP_NJCC   : bolge-disari jcc (rel32 gateway) — kuyruk natcall.
 * Beklenti: tum "OK" satirlari, rc=42.
 * Derleme: python3 -m ziglang cc -O2 -target x86_64-windows-gnu|windows-gnu
 */
#include <stdio.h>
#include <stdint.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

/* ---------- T1: MULT-VM ---------- */
/* DERS (sdk_ornek_test_rt3'ten): saf hesap markerlarin DISINA tasinir —
   bolge icinde volatile-global erisimi ZORUNLU (memory clobber duzeni). */
static volatile uint32_t g_out;

__attribute__((noinline)) uint32_t f2_inner(uint32_t n) {
    XP_SDK_BEG(1);                       /* Virtualization */
    uint32_t s = 2166136261u;
    for (uint32_t i = 0; i < (n & 63u); i++) { s = (s ^ i) * 16777619u; s ^= s >> 7; }
    g_out = s;                           /* bolge govdesini yerinde tutar */
    XP_SDK_END();
    return s;
}
__attribute__((noinline)) uint32_t f1_outer(uint32_t n) {
    XP_SDK_BEG(3);                       /* Ultra (mutasyon+VM) */
    uint32_t a = f2_inner(n);            /* VM icinden VM stub'ina ncall */
    uint32_t b = f2_inner(n + 1);        /* ikinci cagri (durum tazeligi) */
    g_out = a ^ (b * 2654435761u);
    XP_SDK_END();
    return g_out;
}
/* korumasiz ayna — beklenti uretimi */
static uint32_t m2_inner(uint32_t n) {
    uint32_t s = 2166136261u;
    for (uint32_t i = 0; i < (n & 63u); i++) { s = (s ^ i) * 16777619u; s ^= s >> 7; }
    return s;
}
static uint32_t m1_outer(uint32_t n) {
    uint32_t a = m2_inner(n);
    uint32_t b = m2_inner(n + 1);
    return a ^ (b * 2654435761u);
}

/* ---------- T2: OP_RETI dinamik ret-imm (x86 yalniz) ----------
   Bolge-govdelerinde ESP-goreli erisim YOK (0.6.2 kurali): argumanlar
   kapida ECX/EDX'e alinir, govde gercek yiginda ret-imm temizligi yapar. */
#if defined(__i386__)
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    /* kapı (korunsuz, cdecl): ecx/edx'a yukle, yigina stdcall duzeni kur */
    ".globl _t_reti8e\n"
    "_t_reti8e:\n"
    "  mov ecx, [esp+4]\n"
    "  mov edx, [esp+8]\n"
    "  add esp, 8\n"
    "  push edx\n"
    "  push ecx\n"
    "  call _t_reti8c\n"
    "  ret\n"
    /* bolge: ret 8 (dinamik OP_RETI) */
    ".globl _t_reti8c\n"
    "_t_reti8c:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  lea eax, [ecx+ecx*2]\n"
    "  add eax, edx\n"
    "  ret 8\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
    /* kapı: tek arg */
    ".globl _t_reti4e\n"
    "_t_reti4e:\n"
    "  mov ecx, [esp+4]\n"
    "  add esp, 4\n"
    "  push ecx\n"
    "  call _t_reti4c\n"
    "  ret\n"
    /* bolge: ret 4 (dinamik OP_RETI) */
    ".globl _t_reti4c\n"
    "_t_reti4c:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  mov eax, ecx\n"
    "  xor eax, 0xABCD\n"
    "  ret 4\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
    /* kapı: mix — edx kalan temizligi tasiyor */
    ".globl _t_mixe\n"
    "_t_mixe:\n"
    "  mov ecx, [esp+4]\n"
    "  mov edx, [esp+8]\n"
    "  add esp, 8\n"
    "  push edx\n"
    "  push ecx\n"
    "  call _t_mixc\n"
    "  add esp, edx\n"
    "  ret\n"
    /* MIXED bolge: AYNI bolgede ret 8 + ret 4 (eski lifter: 'farkli ret
       imm' RED — 1.2.0-B1 ile KALDIRILDI). edx = kalan temizlik. */
    ".globl _t_mixc\n"
    "_t_mixc:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x01, 0x00, 0x00, 0x00\n"
    "  mov eax, ecx\n"
    "  test eax, 1\n"
    "  jz 2f\n"
    "  add eax, edx\n"
    "  xor edx, edx\n"
    "  ret 8\n"
    "2:\n"
    "  sub eax, edx\n"
    "  mov edx, 4\n"
    "  ret 4\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
);
/* x86 kapı externleri (asm etiketleriyle eslesir) — eski isimlere makro */
extern uint32_t __cdecl t_reti8e(uint32_t, uint32_t);
extern uint32_t __cdecl t_reti4e(uint32_t);
extern uint32_t __cdecl t_mixe(uint32_t, uint32_t);
#define t_reti8  t_reti8e
#define t_reti4  t_reti4e
#define t_mixcall t_mixe
#endif

/* ---------- T3: OP_NJCC disari-jcc gateway ---------- */
#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    ".globl t_njcc_ext\n"
    "t_njcc_ext:\n"
    "  mov eax, ecx\n"
    "  xor eax, 0xBEEF\n"
    "  ret\n"
    ".globl t_njcc_main\n"
    "t_njcc_main:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"   /* SDK BEG */
    "  .byte 0xB8, 0x03, 0x00, 0x00, 0x00\n"   /* Ultra */
    "  test ecx, ecx\n"
    "  jnz t_njcc_ext\n"                        /* bolge-disari jcc -> NJCC */
    "  mov eax, 111\n"
    "  ret\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"   /* SDK END */
);
extern uint32_t t_njcc_main(uint32_t);
#elif defined(__i386__)
__asm__(
    ".text\n"
    ".intel_syntax noprefix\n"
    /* kapı (korunsuz, cdecl): arg'i eax'a alir, kuyruk-jmp ile bolgeye */
    ".globl _t_njcc_entry\n"
    "_t_njcc_entry:\n"
    "  mov eax, [esp+4]\n"
    "  jmp _t_njcc_core\n"
    ".globl _t_njcc_ext\n"
    "_t_njcc_ext:\n"
    "  xor eax, 0xBEEF\n"
    "  ret\n"
    /* bolge: esp-goreli erisim YOK (0.6.2); disari jcc -> NJCC */
    ".globl _t_njcc_core\n"
    "_t_njcc_core:\n"
    "  .byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C\n"
    "  .byte 0xB8, 0x03, 0x00, 0x00, 0x00\n"
    "  test eax, eax\n"
    "  jnz _t_njcc_ext\n"                       /* bolge-disari jcc -> NJCC */
    "  mov eax, 111\n"
    "  ret\n"
    "  .byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D\n"
);
extern uint32_t __cdecl t_njcc_entry(uint32_t);
#define t_njcc_main t_njcc_entry
#endif

/* ---------- Unicorn fark-koşusu için cdecl ihrac sarmalayıcılar ----------
   (t_ öneki = unic_deepvm_x86 şema'daki isim kuralı; x86 koşusu wine32
   olmadığı için Unicorn'da yapılır. Sabit-arg sarmalayıcılar — ARGS tablosu
   boş tuple.) */
#if defined(__i386__) || defined(__x86_64__)
__attribute__((dllexport)) uint32_t t_multvm(void) { return f1_outer(20); }
__attribute__((dllexport)) uint32_t t_multvm2(void) { return f1_outer(0x2A); }
__attribute__((dllexport)) uint32_t t_njcc1(void)   { return t_njcc_main(5); }
__attribute__((dllexport)) uint32_t t_njcc0(void)   { return t_njcc_main(0); }
#if defined(__i386__)
__attribute__((dllexport)) uint32_t t_reti8w(void) { return t_reti8(3, 4); }
__attribute__((dllexport)) uint32_t t_reti4w(void) { return t_reti4(7); }
__attribute__((dllexport)) uint32_t t_mixa(void)    { return t_mixcall(5, 9); }
__attribute__((dllexport)) uint32_t t_mixb(void)    { return t_mixcall(4, 9); }
#endif
#endif

int main(void) {
    int r = 0;
    uint32_t got, want;

    /* T1 */
    got = f1_outer(20); want = m1_outer(20);
    if (got != want) { printf("FAIL multvm got=%u want=%u\n", got, want); r |= 1; }
    else printf("OK multvm %u\n", got);
    got = f1_outer(0x2A); want = m1_outer(0x2A);
    if (got != want) { printf("FAIL multvm2 got=%u want=%u\n", got, want); r |= 2; }
    else printf("OK multvm2 %u\n", got);

#if defined(__i386__)
    /* T2 */
    if (t_reti8(3, 4) != 13) { printf("FAIL reti8 %u\n", t_reti8(3, 4)); r |= 4; }
    else printf("OK reti8 13\n");
    if (t_reti4(7) != (uint32_t)(7 ^ 0xABCD)) { printf("FAIL reti4 %u\n", t_reti4(7)); r |= 8; }
    else printf("OK reti4 %u\n", (uint32_t)(7 ^ 0xABCD));
    if (t_mixcall(5, 9) != 14) { printf("FAIL retimix-a %u\n", t_mixcall(5, 9)); r |= 16; }
    else printf("OK retimix-a 14\n");
    if (t_mixcall(4, 9) != (uint32_t)(4 - 9)) { printf("FAIL retimix-b %u\n", t_mixcall(4, 9)); r |= 32; }
    else printf("OK retimix-b %u\n", (uint32_t)(4 - 9));
#endif

    /* T3 */
    if (t_njcc_main(5) != (uint32_t)(5 ^ 0xBEEF)) { printf("FAIL njcc-taken %u\n", t_njcc_main(5)); r |= 64; }
    else printf("OK njcc-taken %u\n", (uint32_t)(5 ^ 0xBEEF));
    if (t_njcc_main(0) != 111) { printf("FAIL njcc-fall %u\n", t_njcc_main(0)); r |= 128; }
    else printf("OK njcc-fall 111\n");

    printf(r ? "HATALI r=%d\n" : "OK hepsi\n", r);
    return r ? 7 : 42;
}
