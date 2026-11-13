// test_e96d0.cpp — 1.2.2-A10 XP_CALLI kanit testi
// Kullanicinin coklu-fonksiyon RED raporu: "sub_e96d0: lifter bilinmeyen islem"
// Kok-neden: FF 90 88000000 (call dword ptr [eax+88h], vtable-thiscall) ->
// lifter XP_CALLI case'i YOKTU. Fix: OP_NCALLI (VM form 0/1/2).
// Bu harness E96D0'nun GERCEK baytlarini lifter'dan gecirir.
#include "engine.hpp"
#include <cstdio>

// metin2client.exe 0xE96D0..0xE9710 (boyut=0x40, kullanicinin ChatDrn listesi)
static const unsigned char E96D0[] = {
    0x55,                                   // E96D0 push ebp
    0x8B, 0xEC,                             // E96D1 mov ebp,esp
    0x53,                                   // E96D3 push ebx
    0x8A, 0x5D, 0x08,                       // E96D4 mov bl,[ebp+8]
    0x56,                                   // E96D7 push esi
    0x8B, 0xF1,                             // E96D8 mov esi,ecx
    0x84, 0xDB,                             // E96DA test bl,bl
    0x74, 0x28,                             // E96DC je E9706
    0x8B, 0x46, 0x04,                       // E96DE mov eax,[esi+4]
    0x8D, 0x4E, 0x04,                       // E96E1 lea ecx,[esi+4]
    0xFF, 0x90, 0x88, 0x00, 0x00, 0x00,     // E96E4 call dword ptr [eax+00000088]  <-- CALLI
    0x85, 0xC0,                             // E96EA test eax,eax
    0x74, 0x18,                             // E96EC je E9706
    0x8B, 0xC8,                             // E96EE mov ecx,eax
    0xE8, 0x8B, 0x2F, 0xF8, 0xFF,           // E96F0 call 0x6C680
    0x85, 0xC0,                             // E96F5 test eax,eax
    0x74, 0x0D,                             // E96F7 je E9706
    0x8B, 0xCE,                             // E96F9 mov ecx,esi
    0xE8, 0x90, 0xF7, 0xFF, 0xFF,           // E96FB call 0xE8E90
    0x5E,                                   // E9700 pop esi
    0x5B,                                   // E9701 pop ebx
    0x5D,                                   // E9702 pop ebp
    0xC2, 0x04, 0x00,                       // E9703 ret 4
    0x88, 0x5E, 0x64,                       // E9706 mov [esi+64],bl
    0x5E,                                   // E9709 pop esi
    0x5B,                                   // E970A pop ebx
    0x5D,                                   // E970B pop ebp
    0xC2, 0x04, 0x00,                       // E970C ret 4
    0xCC,                                   // E970F int3 (dolgu)
};

int main() {
    const u32 RVA = 0xE96D0, SZ = (u32)sizeof(E96D0);
    printf("[test] sub_e96d0 RVA=0x%X boyut=0x%X bayt\n", RVA, SZ);

    // metin2 senaryosu birebir: x86, ImageBase=0x400000,
    // rdata RVA=0x3B5000 VSz=0x98865E (kullanicinin PE logu),
    // ULTRA(M+V) = junk(mutation) + V, allow_call=true, fonksiyon-kipi
    VFn F = lift_function(E96D0, RVA, SZ, false,
                          0x400000, 0x520000, true,
                          0x3B5000, 0x09865E,
                          2 /*junk=mutation (Ultra M+V)*/, 0x12345678,
                          true /*pad_terminates*/, false /*region_mode*/);
    printf("[sonuc] ok=%s bc=%u bayt retimm=0x%X\n",
           F.ok ? "EVET" : "HAYIR", (unsigned)F.plain.size(), F.retimm);
    if (!F.ok) { printf("[RED] why=%s\n", F.why.c_str()); return 3; }
    for (size_t i = 0; i < F.notes.size(); i++) printf("  %s\n", F.notes[i].c_str());

    // ncalli opcode yayimi kanit: plain icinde OP_NCALLI(0x44) ara
    int ncalli = 0, ncall = 0;
    for (size_t i = 0; i < F.plain.size(); i++) {
        // perm yok — plain duz bayt-kod (sifreleme son asamada); junk oldugu
        // icin 0x44'ler junk da olabilir -> baglam kontrolu yerine sayim raporu
        if (F.plain[i] == 0x44) ncalli++;
        if (F.plain[i] == 0x19) ncall++;
    }
    printf("[kanit] plain icinde 0x44(=OP_NCALLI) olasi=%d, 0x19(=OP_NCALL) olasi=%d\n",
           ncalli, ncall);
    printf("[PASS] E96D0 lifter ARTIK geciyor (coklu-fonksiyon koruma yolu acik)\n");
    return 42;
}
