/* vreg_kanit.c — A17.2 Virtual Registry wine-kanit ailesi (x64)
   Baseline (korumasiz): anahtar gercek registry'de YOK -> rc=7
   Korumali (--vreg): sanal store yanit verir -> rc=42 + degerler */
#include <windows.h>
#include <stdio.h>

int main(void) {
    HKEY h = 0;
    LONG st = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\XProtectSaha\\Test", 0, KEY_READ, &h);
    printf("openA st=%ld hk=%p\n", st, (void*)h);
    if (st != 0 || !h) { printf("NEGATIF: anahtar yok (beklenen baseline)\n"); return 7; }
    char buf[128]; DWORD sz = 128, ty = 0;
    st = RegQueryValueExA(h, "Surum", 0, &ty, (BYTE*)buf, &sz);
    printf("queryA-Surum st=%ld ty=%lu val=%s\n", st, (unsigned long)ty, (st == 0) ? buf : "-");
    DWORD dw = 0, sz2 = 4;
    st = RegQueryValueExA(h, "SahaDegeri", 0, &ty, (BYTE*)&dw, &sz2);
    printf("queryA-dword st=%ld ty=%lu val=%lu\n", st, (unsigned long)ty,
           (st == 0) ? (unsigned long)dw : 0ul);
    {   /* W yolu */
        wchar_t wname[64];
        DWORD wsz = 120;
        for (int i = 0; i < 63 && "Surum"[i]; i++) wname[i] = (wchar_t)("Surum"[i]);
        wname[63] = 0;
        char ab[128]; DWORD asz = 128;
        st = RegQueryValueExW(h, wname, 0, &ty, (BYTE*)ab, &wsz);
        printf("queryW st=%ld val=%s\n", st, (st == 0) ? ab : "-");
    }
    {   /* enum */
        char nm[64]; DWORD nmsz = 64;
        st = RegEnumValueA(h, 0, nm, &nmsz, 0, 0, 0, 0);
        printf("enumA-0 st=%ld name=%s\n", st, (st == 0) ? nm : "-");
    }
    {   /* negatif: olmayan deger */
        char nb[64]; DWORD nsz = 64;
        st = RegQueryValueExA(h, "YokBoyleBirDeger", 0, &ty, (BYTE*)nb, &nsz);
        printf("negatif-deger st=%ld (2=yok)\n", st);
    }
    RegCloseKey(h);
    printf("TAM\n");
    return 42;
}
