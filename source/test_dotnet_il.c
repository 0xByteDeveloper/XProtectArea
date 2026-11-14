// test_dotnet_il.c — xprotect_dotnet + xprotect_il uçtan-uca test (host)
// 1) minidn.exe parse -> MethodDef keşfi (Class1::Method1, RVA, satır-ofsetleri)
// 2) IL gövde decode -> komut listesi kontrol
// 3) IL->x86 derle -> mmap'de çağır -> 21+21 = 42 dönmeli
// 4) RED yolu: ldstr'li gövde -> RED mesajı
#include "xprotect_dotnet.h"
#include "xprotect_il.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

typedef int (*fn2)(int a, int b);

static u8* load(const char* p, size_t* n) {
    FILE* f = fopen(p, "rb");
    if (!f) { printf("FAIL: acilamadi %s\n", p); return 0; }
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    u8* d = (u8*)malloc(*n);
    fread(d, 1, *n, f); fclose(f);
    return d;
}

static int fails = 0;
#define CHECK(cond, msg) do { if (cond) printf("PASS: %s\n", msg); else { printf("FAIL: %s\n", msg); fails++; } } while (0)

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "/tmp/minidn.exe";
    size_t n = 0;
    u8* d = load(path, &n);
    if (!d) return 1;
    printf("[1] parse %s (%zu bayt)\n", path, n);
    xpdotnet::Image img;
    bool ok = xpdotnet::parse(d, n, &img);
    if (!ok) { printf("FAIL: parse: %s\n", img.err.c_str()); return 1; }
    printf("PASS: is_dotnet=%d typedefs=%zu methods=%zu\n", img.is_dotnet, img.typedefs.size(), img.methods.size());
    CHECK(img.methods.size() == 1, "1 MethodDef");
    xpdotnet::Method& m = img.methods[0];
    printf("  metot: %s::%s rva=0x%X token=0x%08X params=%u fat=%d body_len=%u\n",
           m.type_name.c_str(), m.name.c_str(), m.rva, m.token, m.param_count, m.fat_header, m.body_len);
    CHECK(m.name == "Method1", "metot adi Method1");
    CHECK(m.type_name == "Class1", "tip adi Class1");
    CHECK(m.body_len == 6, "IL govde 6 bayt");
    CHECK(m.row_rva_off != 0 && m.row_impl_off != 0, "satir ofsetleri var");

    printf("[2] IL govde decode\n");
    std::vector<u8> il;
    CHECK(xpdotnet::read_body(d, n, m, &il), "govde okundu");
    std::vector<xpil::Cmd> cmds;
    std::string err;
    CHECK(xpil::decode(il.data(), il.size(), &cmds, &err), err.c_str());
    printf("  komut sayisi: %zu\n%s", cmds.size(), xpil::disasm(cmds, il.size(), 0).c_str());
    CHECK(cmds.size() == 4, "4 IL komutu");

    printf("[3] IL -> x86 derle + calistir\n");
    xpil::X86Fn x;
    CHECK(xpil::to_x86(cmds, 0, true /*has ret*/, true /*static*/, 0, &x), x.why_red.c_str());
    printf("  x86 boyut: %zu bayt\n", x.code.size());
    // çalıştır: mmap RWX + çağır (cdecl: args yok -> ret 0)
    void* buf = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(buf, x.code.data(), x.code.size());
    fn2 f = (fn2)buf;
    int r = f(0, 0);
    printf("  donus: %d\n", r);
    CHECK(r == 42, "IL 21+21 -> 42");

    printf("[4] RED yolu: ldstr iceren govde\n");
    std::vector<u8> il2 = {0x72, 0x01, 0x00, 0x00, 0x70, 0x2A}; // ldstr tok; ret
    std::vector<xpil::Cmd> c2; std::string e2;
    xpil::decode(il2.data(), il2.size(), &c2, &e2);
    xpil::X86Fn x2;
    bool rok = xpil::to_x86(c2, 0, true, true, 0, &x2);
    CHECK(!rok && x2.why_red.find("ldstr") != std::string::npos, "ldstr -> RED (net mesaj)");

    printf("[5] dal fixup: dongu (br geri-dalis)\n");
    // locals=1: i<3 dongusu: ldc.i4.0; stloc.0; br IL_1E? yerine basit: 3x arttir
    // IL: ldc.i4.0(16) stloc.0(0A) ldc.i4.3(1D) stloc.1(s 11 01) ...
    // basit geri-dal: ldc.i4.0, stloc.0, ldloc.0, ldc.i4.1, add, stloc.0,
    //                 ldloc.0, ldc.i4.3, blt.s IL_04, ldloc.0
    u8 loop_il[] = {0x16,                     // IL_00 ldc.i4.0
                    0x0A,                     // IL_01 stloc.0
                    0x06,                     // IL_02 ldloc.0
                    0x17,                     // IL_03 ldc.i4.1
                    0x58,                     // IL_04 add
                    0x0A,                     // IL_05 stloc.0
                    0x06,                     // IL_06 ldloc.0
                    0x1D,                     // IL_07 ldc.i4.3
                    0x32, 0xF7,               // IL_08 blt.s IL_02 (rel = 2 - 10 = -9 = 0xF7)
                    0x06,                     // IL_0A ldloc.0
                    0x2A};                    // IL_0B ret
    std::vector<xpil::Cmd> c3; std::string e3;
    bool d3 = xpil::decode(loop_il, sizeof loop_il, &c3, &e3);
    printf("  decode: %d %s\n", d3, e3.c_str());
    xpil::X86Fn x3;
    bool l3 = d3 && xpil::to_x86(c3, 1, true, true, 0, &x3);
    if (l3) {
        void* b3 = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memcpy(b3, x3.code.data(), x3.code.size());
        int r3 = ((fn2)b3)(0, 0);
        printf("  dongu donus: %d\n", r3);
        CHECK(r3 == 3, "IL dongu -> 3");
    } else { printf("FAIL: dongu derlenmedi %s\n", x3.why_red.c_str()); fails++; }

    printf("\n%s (fails=%d)\n", fails ? "BAZI TESTLER BASARISIZ" : "TUM TESTLER PASSED", fails);
    return fails ? 1 : 0;
}
