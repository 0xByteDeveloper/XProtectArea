// test_rt.c — 0.5.1 runtime + SDK + IAT otomatik test exe'si
// Derleme: zig cc -target x86_64-windows-gnu / x86-windows-gnu
// Davranis: dogru calisirsa "OK ..." satirlari + exit 42.
// 0.5.1 NOT: volatile duvarlari — derleyici (yeni zig -O2) saf yazmac
// hesabini SDK isaretlerinin USTUNE tasirmasin (eski kanit exe'sinde
// bolge tam govdeyi kapsiyordu; bugunku derlemede cmp/cmov kalinti
// kaliyordu -> bolge yarim hesap -> yanlis sonuc).
#include <stdio.h>
#include <string.h>

// ---- XProtect SDK isaretleri (xprotect_sdk.h ile ayni sozlesme) ----
// B8 <BEG_MAGIC> B8 <tip 1..3> ... kod ... B8 <END_MAGIC>
#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

static int sdk_v(int a, int b) {
    volatile int r = 0;                  /* yazmac-tasima engeli */
    XP_SDK_BEG(1);                       // Virtualization
    r = a + b;
    r = r * 3 + 7;
    if (r > 100) r -= 100;
    XP_SDK_END();
    return r;
}

static int sdk_m(int a) {
    volatile int r = 0;
    XP_SDK_BEG(2);                       // Mutation
    r = a ^ 0x55;
    r = r + (r >> 2);
    XP_SDK_END();
    return r;
}

static int sdk_u(int a) {
    volatile int r = 0;
    XP_SDK_BEG(3);                       // Ultra (mutation+virtualization)
    r = a * 2;
    r = r ^ 0x58;
    r = (unsigned)r >> 1;
    r = r + 9;
    XP_SDK_END();
    return r;
}

static int sdk_print(int a, int b, int c, int d) {
    printf("OK sdk_print %d\n", a);
    if (a != 78) return 1;   /* 19+38=57; 57*3+7=178; -100=78 */
    if (b != ((0x1234 ^ 0x55) + ((0x1234 ^ 0x55) >> 2))) return 2;
    if (d != 81) return 3;   /* 19+39=58; 58*3+7=181; -100=81 */
    printf("OK hepsi dogru\n");
    return 42;
}

int main(void) {
    int a = sdk_v(19, 38);               /* 57; 57*3+7=168; -100=68 */
    int b = sdk_m(0x1234);
    int c = sdk_u(0x1234);
    int d = sdk_v(19, 39);               /* 58; 58*3+7=181; -100=81 */
    printf("OK main a=%d b=%#x c=%#x d=%d\n", a, b, c, d);
    return sdk_print(a, b, c, d);
}
