// test_calli_rt.c — 1.2.2-A10 OP_NCALLI runtime kanit testi (x86)
// Kullanicinin E96D0 raporu birebir: "call dword ptr [eax+00000088]"
// (FF 90 88000000) — vtable-dolayli cagri. Bu test:
//   T-A: SDK-V bolgesi icinde FF 90 88000000 ile natcall -> dogru hedef,
//        dogru donus degeri (777) -> rc=42
//   T-B: NEGATIF kontrol — ayni kod baska vtable slotu (0x8C) -> 888 doner
//        (VM'in hedefi bellekten okudugunu kanitlar; sabit degil)
// Derleme: zig cc -target x86-windows-gnu
#include <stdio.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

static void* g_vt[0x90 / 4];   /* sahte vtable — slot 0x22 => offset 0x88 */

static int __attribute__((noinline)) vtcall(void) { return 777; }   /* slot 0x88 */
static int __attribute__((noinline)) vtcall2(void) { return 888; }  /* slot 0x8C */

/* Kullanicinin E96D0 gogusunun birebir kopyasi: push esi, mov esi,ecx,
   mov eax,[eax-tabani], call dword ptr [eax+00000088] (FF 90 88000000) */
static int __attribute__((noinline)) do_calli(unsigned vt) {
    volatile int out = 0;
    XP_SDK_BEG(1);                    /* Virtualization bolgesi */
    __asm__ volatile(
        "pushl %%esi\n\t"
        "movl %%ecx, %%esi\n\t"       /* E96D8: mov esi,ecx (this) */
        "call *0x88(%%eax)\n\t"       /* E96E4: FF 90 88000000 */
        "movl %%eax, %0\n\t"
        "popl %%esi\n\t"
        : "=a"(out)
        : "a"(vt)
        : "ecx", "edx", "esi", "memory"
    );
    XP_SDK_END();
    return out;
}

static int __attribute__((noinline)) do_calli2(unsigned vt) {
    volatile int out = 0;
    XP_SDK_BEG(1);
    __asm__ volatile(
        "pushl %%esi\n\t"
        "movl %%ecx, %%esi\n\t"
        "call *0x8C(%%eax)\n\t"       /* FF 90 8C000000 — NEGATIF kontrol */
        "movl %%eax, %0\n\t"
        "popl %%esi\n\t"
        : "=a"(out)
        : "a"(vt)
        : "ecx", "edx", "esi", "memory"
    );
    XP_SDK_END();
    return out;
}

int main(void) {
    g_vt[0x88 / 4] = (void*)vtcall;
    g_vt[0x8C / 4] = (void*)vtcall2;

    int a = do_calli((unsigned)g_vt);
    int b = do_calli2((unsigned)g_vt);
    printf("OK ncalli a=%d (beklenen 777) b=%d (beklenen 888)\n", a, b);
    if (a != 777) return 7;           /* hatali hedef/akis */
    if (b != 888) return 8;           /* slot kaymasi/hardcode */
    printf("OK ncAllI TAMAM — dolayli natcall iki-slot dogru\n");
    return 42;
}
