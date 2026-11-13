// test_mp.c — 1.2.2-A11 IC Memory Protection runtime kanit testi (x86)
// Davranis: main -> kendi .text'ine KULLANICI-MODU YAZMASI (trainer
// simülasyonu: *(u8*)funcAddr = 0x90).
//   memprot=YOK  -> AV handled-degil (wine crash kodu)
//   memprot=ACIK -> A11 VEH yakalar -> ExitProcess(0x75) -> rc=117
// Bölge yok — yazma SDK bolgesi DISINDAN (gerçek saldırı modeli).
#include <stdio.h>

static int __attribute__((noinline)) mp_target(void) { return 42; }

int main(void) {
    volatile unsigned char* q =
        (volatile unsigned char*)(unsigned long)&mp_target;
    printf("MP yazma denemesi: %p\n", (void*)q);
    *q = 0x90;                       /* KOD SAYFASINA YAZMA — A11 VEH burada keser */
    printf("OK yazma gecti (koruma yok) — mp_target=%d\n", mp_target());
    return 42;                       /* memprot-yok yolu */
}
