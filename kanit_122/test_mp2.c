// test_mp2.c — 1.2.2-A11 kombine kanit (x64):
//   1) SDK-V bolgesi cagrilir — VM stub .vmp0 EXECUTE_READ'ten calisir
//      (memprot-yalin dogru-calisma yolu)
//   2) main .text'e yazma dener (trainer simülasyonu) — A11 VEH -> 0x75
//   Temiz varyant (MP_WRITE_KAPALI): yazma yok -> rc=42
#include <stdio.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

static int __attribute__((noinline)) sdk_v(int a, int b) {
    volatile int r = 0;
    XP_SDK_BEG(1);
    r = a * 3 + b;
    r = r ^ 0x55;
    r = (r << 2) | (r >> 30);
    r = r + 0x1234;
    r = r - (a | 1) * 2;
    XP_SDK_END();
    return r;
}

static int __attribute__((noinline)) mp_target(void) { return 42; }

int main(void) {
    int u = sdk_v(13, 3);            /* 5142 — VM .vmp0 RX'ten calisir */
    printf("OK sdk_v=%d (beklenen 5142)\n", u);
    if (u != 5142) return 5;
#ifdef MP_WRITE_KAPALI
    printf("OK temiz-son (yazma yok)\n");
    return 42;
#else
    {
        volatile unsigned char* q =
            (volatile unsigned char*)(void*)&mp_target;
        printf("MP yazma denemesi: %p\n", (void*)q);
        fflush(stdout);
        *q = 0x90;                   /* KOD SAYFASINA YAZMA — A11 VEH -> 0x75 */
        printf("OK yazma gecti (koruma calismadi!)\n");
        return 42;
    }
#endif
}
