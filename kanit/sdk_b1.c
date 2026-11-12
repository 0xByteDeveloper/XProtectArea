// sdk_b1.c v5 — 1.2.0-B1: JMPEXT + JCCEXT kabul testi
// DERSler: (v1) musttail sonrasi END ölü kod -> LLVM atar.
//          (v2/v4) if-dali musttail: LLVM blok KOPYALAR -> mükerrer isaret.
//          (v3) ham-asm jmp: cagri-konvansiyonu kiriliyor.
//          (v4) arg-okuma marker-disina tasiniyor (rt3 dersi tekrari):
//               cozum = argümanlar bölge ONCESI volatile globale; bölge
//               içinde riprel okuma (derleyici disari tasıyamaz).
// v5: musttail yalniz-kuyruk blogunda + END if-dalinda erisilebilir +
//     girdiler volatile global uzerinden.
#include <stdio.h>
#include <stdlib.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

static volatile int g_r;
static volatile int g_in;    /* bolge girdileri (riprel ile okunur) */

__attribute__((noinline)) static int b1_t3(int x) { return x * 3 + 1; }

__attribute__((noinline)) static int b1_jmpext(int a) {
    g_in = a;                                   /* bolge disinda */
    XP_SDK_BEG(1);
    g_r = g_in * 2 + 7;                         /* bolge icinde riprel */
    if (g_r <= 1000) {
        int r = b1_t3(g_r + 5);                 /* normal yol: disari CALL (ncall) */
        XP_SDK_END();
        return r;
    }
    __attribute__((musttail)) return b1_t3(g_r); /* JMPEXT yolu (kuyruk-jmp) */
}

__attribute__((noinline)) static int b1_jccext(int a) {
    g_in = a;
    XP_SDK_BEG(1);
    g_r = g_in ^ 0x5A;
    if (g_r > 1000) goto out;                   /* JCCEXT (disari sartli jcc) */
    g_r = g_r + (g_r >> 1);
    XP_SDK_END();
out:
    return g_r + 1;
}

__attribute__((noinline)) static int b1_normal(int a) {
    g_in = a;
    XP_SDK_BEG(1);
    g_r = g_in + 5;
    g_r = g_r * 2 - 3;
    XP_SDK_END();
    return g_r;
}

int main(int argc, char** argv) {
    int k = (argc > 1) ? atoi(argv[1]) : 0;
    int i1 = 9 + k, i2 = 600 + k, ib = 0x1234 + k, ic = 3 + k, id_ = 10 + k;
    int a = b1_jmpext(i1);
    printf("trace a: g_r=%d\n", g_r); fflush(stdout);
    int a2 = b1_jmpext(i2);
    printf("trace a2: g_r=%d\n", g_r); fflush(stdout);
    int b = b1_jccext(ib);
    printf("trace b: g_r=%d ret=%d\n", g_r, b); fflush(stdout);
    int c = b1_jccext(ic);
    printf("trace c: g_r=%d ret=%d\n", g_r, c); fflush(stdout);
    int d = b1_normal(id_);
    printf("trace d: g_r=%d\n", g_r); fflush(stdout);
    int ea, ea2, eb, ec, ed;
    { int gr = i1 * 2 + 7; ea = (gr <= 1000) ? b1_t3(gr + 5) : b1_t3(gr); }
    { int gr = i2 * 2 + 7; ea2 = (gr <= 1000) ? b1_t3(gr + 5) : b1_t3(gr); }
    { int gr = ib ^ 0x5A; eb = (gr > 1000) ? (gr + 1) : (gr + (gr >> 1) + 1); }
    { int gr = ic ^ 0x5A; ec = (gr > 1000) ? (gr + 1) : (gr + (gr >> 1) + 1); }
    ed = ((id_ + 5) * 2) - 3;
    printf("B1 a=%d a2=%d b=%d c=%d d=%d\n", a, a2, b, c, d);
    if (a == ea && a2 == ea2 && b == eb && c == ec && d == ed) {
        printf("B1 OK hepsi (jmpext=%d jccext=%d)\n", ea2, ec);
        return 42;
    }
    printf("B1 HATALI beklenti a=%d a2=%d b=%d c=%d d=%d\n", ea, ea2, eb, ec, ed);
    return 3;
}
