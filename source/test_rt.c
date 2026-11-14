// test_rt.c — 0.5.0 runtime + SDK + IAT otomatik test exe'si
// Derleme: zig cc -target x86_64-windows-gnu / x86-windows-gnu
// Davranis: dogru calisirsa "OK ..." satirlari + exit 42.
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
    XP_SDK_BEG(1);                       // Virtualization
    int r = a + b;
    r = r * 3 + 7;
    if (r > 100) r -= 100;
    XP_SDK_END();
    return r;
}

static int sdk_m(int a) {
    XP_SDK_BEG(2);                       // Mutation
    int r = a ^ 0x55;
    r = r + (r >> 2);
    XP_SDK_END();
    return r;
}

static int sdk_u(const char* s) {
    XP_SDK_BEG(3);                       // Ultra
    int r = 0;
    while (*s) { r = r * 31 + (unsigned char)*s++; }
    XP_SDK_END();
    return r & 0xFFFF;
}

// IAT testi: printf cagrisi ISARETLI bolgenin icinde —
// --iat ile cagri noktasi thunk'a cevrilir ve VM ncall ile thunk'u cagirir.
static int sdk_print(int v) {
    XP_SDK_BEG(1);
    printf("OK sdk_print %d\n", v);
    XP_SDK_END();
    return v + 1;
}

int main(int argc, char** argv) {
    volatile int A = 20 + (argc & 0), B = 30 + (argc & 0);   // sabit-katlama engeli
    volatile int C = 0x1234 + (argc & 0);
    char buf[32]; int q;
    for (q = 0; q < 10; q++) buf[q] = (char)("XProtect"[q] + (argc & 0));
    buf[10] = 0;
    int a = sdk_v(A, B);            // (50*3+7)=157 -> 57
    int b = sdk_m(C);
    int c = sdk_u(buf);
    int d = sdk_print(a);
    printf("OK main a=%d b=0x%x c=0x%x d=%d\n", a, b, c, d);
    if (a != 57) return 1;
    if (b != ((0x1234 ^ 0x55) + ((0x1234 ^ 0x55) >> 2))) return 2;
    if (d != 58) return 3;
    printf("OK hepsi dogru\n");
    return 42;
}
