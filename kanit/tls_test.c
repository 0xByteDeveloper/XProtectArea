// tls_test.c — 1.2.0-B2 kapisi: TLS callback + pack birlikte
// zig/clang: GCC section-attribute (mingw CRT _tls_used ile .CRT$XLB zinciri)
#include <stdio.h>
#include <windows.h>

static volatile long g_tls_ran = 0;
static volatile long g_tls_val = 0;

static void NTAPI my_tls_callback(PVOID h, DWORD reason, PVOID pv) {
    (void)h; (void)pv;
    if (reason == DLL_PROCESS_ATTACH) {
        g_tls_ran = 1;
        g_tls_val = 0x5A5A;
    }
}

__attribute__((section(".CRT$XLB"), used))
static const PIMAGE_TLS_CALLBACK tls_cb_entry = my_tls_callback;

int main(void) {
    printf("main: tls_ran=%ld tls_val=%lx\n", g_tls_ran, g_tls_val);
    if (g_tls_ran == 1 && g_tls_val == 0x5A5A) {
        printf("TLS OK: callback EP'den once calisti\n");
        return 42;
    }
    printf("TLS HATALI: callback calismadi\n");
    return 3;
}
