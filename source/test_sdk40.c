// ============================================================
// test_sdk40.c — SDK-40 yuzey testi (korumali exe)
// FindResource/LoadResource/LoadString/Random/Box/Unbox/DecryptBuffer
// Derleme: x86_64-w64-mingw32-gcc -O2 test_sdk40.c xprotect_sdk.c -o sdk40.exe
// Beklenen (korumali): RC=42, tum satirlar OK
// ============================================================
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "xprotect_sdk.h"

static int CALLBACK etype_cb(HMODULE h, LPSTR type, LONG_PTR param) {
    (void)h; (void)type;
    (*(int*)param)++;
    return TRUE;
}
static int CALLBACK ename_cb(HMODULE h, LPCTSTR type, LPTSTR name, LONG_PTR param) {
    (void)h; (void)type; (void)name;
    (*(int*)param)++;
    return TRUE;
}

int main(void) {
    int fail = 0;
    printf("Prot=%d\n", XProtectIsProtected());

    /* 1) Random: iki cagri farkli olmali */
    unsigned long long r1 = XProtectRandom();
    unsigned long long r2 = XProtectRandom();
    printf("rand: %016llx %016llx %s\n", r1, r2, (r1 != r2) ? "OK" : "FAIL");
    if (r1 == r2) fail++;

    /* 2) Box/Unbox: cift islem kimligi korumali */
    volatile int v = 0x1234;
    void* p = (void*)(unsigned long)&v;
    void* b = XProtectBoxPointer(p);
    void* u = XProtectUnboxPointer(b);
    printf("box: boxed=%s unboxed=%s\n", (b != p) ? "degisti" : "AYNI(FAIL)",
           (u == p) ? "OK" : "FAIL");
    if (b == p || u != p) fail++;

    /* 3) DecryptBuffer: kendini-goturen XOR akisi */
    {
        unsigned char buf[16]; unsigned char ref[16];
        for (int i = 0; i < 16; i++) { buf[i] = (unsigned char)(0xA0 + i); ref[i] = buf[i]; }
        XProtectDecryptBuffer(buf, 16, 0xDEADBEEFCAFEF00Dull);
        int diff = memcmp(buf, ref, 16) != 0;
        XProtectDecryptBuffer(buf, 16, 0xDEADBEEFCAFEF00Dull);
        int back = memcmp(buf, ref, 16) == 0;
        printf("decbuf: sifrelendi=%s geri=%s\n", diff ? "OK" : "FAIL", back ? "OK" : "FAIL");
        if (!diff || !back) fail++;
    }

    /* 4) kaynak ailesi: shell32'nin GERCEK kaynaklari uzerinden delegasyon
       kaniti (korunan imajda SDK cagrisi IAT'siz PEB-hash ile gider) */
    {
        HMODULE sh = LoadLibraryA("shell32.dll");
        int cnt = 0, cnt2 = 0;
        int e = 0, e2 = 0;
        if (sh) {
            e = XProtectEnumResourceTypesA((void*)sh, (void*)etype_cb, (LONG_PTR)(long long)&cnt);
            e2 = XProtectEnumResourceNamesA((void*)sh, (void*)RT_ICON, (void*)ename_cb, (LONG_PTR)(long long)&cnt2);
        }
        printf("enum: types rc=%d adet=%d | icon-names rc=%d adet=%d %s\n",
               e, cnt, e2, cnt2, (e != 0 && cnt >= 1 && e2 != 0 && cnt2 >= 1) ? "OK" : "FAIL");
        if (!(e != 0 && cnt >= 1 && e2 != 0 && cnt2 >= 1)) fail++;
    }
    printf(fail ? "SDK40 FAIL=%d\n" : "SDK40 TUM OK\n", fail);
    return fail ? 7 : 42;
}
