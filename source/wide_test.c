/* wide_test.c — A18.2 dogrulama: wide string kullanan SDK-bolgeli fonksiyon
   Derleme: zig cc -target x86_64-windows-gnu wide_test.c xprotect_sdk.c -o wide_test.exe */
#include <stdio.h>
#include <windows.h>

#define XP_SDK_BEG(t) \
    __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
#define XP_SDK_END() \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

/* volatile uzerinden okuma: -O2 sabit-katlamayi engeller (lea + gercek
   .rdata referansi kalmali; yoksa derleyici toplamai derleme-aninda
   hesaplar ve string exe'den silinir — ilk denemede oldu) */
const wchar_t g_wide[] = L"XProtectWide2026";

static int wide_sum(void) {
    volatile int s = 0;                 /* yazmac-tasima engeli */
    XP_SDK_BEG(1);                      // Virtualization
    for (const volatile wchar_t* wp = g_wide; *wp; wp++) s += (int)*wp;
    XP_SDK_END();
    return s;
}

int main(void) {
    int v = wide_sum();
    printf("wide_sum=%d\n", v);
    return v & 0xFF;
}
