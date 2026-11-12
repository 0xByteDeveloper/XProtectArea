/* res_test.c — B3 cpResourceProtection kanit testi
 * Gomulu RCDATA kaynagi (ID=1) okur; icerigi "XPROTECT-RES-GIZLI-042" ile
 * karsilastirir. Dogruysa rc=42; yanlissa 111; API basarisizsa 110.
 * FindResourceA/LoadResource/LockResource/SizeofResource — RAM-map yolu
 * (.rsrc pack sonrasi unpack'ta geri yazilir; statikte sifreli gorunur).
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    HRSRC hr = FindResourceA(NULL, MAKEINTRESOURCEA(1), RT_RCDATA);
    if (!hr) return 110;
    HGLOBAL hg = LoadResource(NULL, hr);
    if (!hg) return 110;
    const void* p = LockResource(hg);
    DWORD sz = SizeofResource(NULL, hr);
    if (!p || sz == 0) return 110;
    printf("RES OK: %u bayt\n", (unsigned)sz);
    static const char beklenen[] = "XPROTECT-RES-GIZLI-042";
    size_t nb = sizeof(beklenen) - 1;
    if ((size_t)sz >= nb && memcmp(p, beklenen, nb) == 0) {
        printf("RES DOGRU: gizli metin saglam\n");
        return 42;
    }
    printf("RES HATALI icerik\n");
    return 111;
}
