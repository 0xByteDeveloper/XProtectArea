// ============================================================
// engine_main.cpp — koruma orkestrasyonu
// Akis: PE yukle -> fonksiyonlari bul (export+COFF+PDB/MAP) ->
//       sec -> TIP SEVKI (0.3.0: V=sanallastirma, M=mutasyon,
//       U=mutasyon+sanallastirma) -> STRDEC/state planla ->
//       sifrele -> .vmp0 kur (blob+bc+stub+mut+state) -> .text yamala ->
//       secenekler (antidebug/strenc/memprot) -> checksum -> kaydet
// ============================================================
#include "engine.hpp"
#include "engine_sym.hpp"
#include "xr_cipher.h"   // 0.8.0 SectionCryptor (runtime ile ortak sozlesme)
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <map>
#include <string>
#include <vector>

// 0.8.0 SEH: küçük LE yardımcıları (engine_pe.cpp'dekiler static)
static u32 rdv32(const std::vector<u8>& b, size_t o) {
    return (u32)b[o] | ((u32)b[o+1] << 8) | ((u32)b[o+2] << 16) | ((u32)b[o+3] << 24);
}
static void wrv32(std::vector<u8>& b, size_t o, u32 v) {
    b[o] = (u8)v; b[o+1] = (u8)(v >> 8); b[o+2] = (u8)(v >> 16); b[o+3] = (u8)(v >> 24);
}

struct RStr { u32 rva, len; };

// ============================================================
// 0.5.0 — XProtect Runtime yardimcilari (xrt_core.c ile SOZLESME)
// ============================================================
// FNV-1a 32 — xrt_core.c fnv_a ile birebir (export isim hash'i)
static u32 xfnv_a(const char* s, size_t n) {
    u32 h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= (u8)s[i]; h *= 16777619u; }
    return h;
}
// FNV-1a 32 kucuk-harf — xrt fnv_w ile ayni sonucu veren ANSI surumu
// (modul adi: PEB BaseDllName kucuk-harfe indirilir)
static u32 xfnv_lower(const std::string& s) {
    u32 h = 2166136261u;
    for (char c : s) {
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        h ^= (u8)c; h *= 16777619u;
    }
    return h;
}
// CRC32 bitwise — xrt crc_up ile birebir
static u32 xcrc_up(u32 c, u8 by) {
    c ^= by;
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    return c;
}

// ---- 1.2.2-A13: Watermark — UO core.cc Watermark::Compile 1:1 ----
// Deger hex dizisi: ciftler bayt olur ('5''8' -> 0x58). Hex OLMAYAN karakter
// = JOKER: maske 0, bayt rastgele (her cagride yeniden). Orn. "585072??" =
// 0x58,0x72 + 1 joker bayt. Sürün dicek arama (SearchByte) maskeli eslesir.
static void wm_compile(const std::string& value, std::vector<u8>& dump, std::vector<u8>& mask) {
    dump.clear(); mask.clear();
    if (value.empty()) return;
    for (size_t i = 0; i < value.size(); i++) {
        size_t p = i / 2;
        if (p >= dump.size()) { dump.push_back(0); mask.push_back(0); }
        u8 m = 0xff, b2;
        char c = value[i];
        if (c >= '0' && c <= '9') b2 = (u8)(c - '0');
        else if (c >= 'A' && c <= 'F') b2 = (u8)(c - 'A' + 0x0a);
        else if (c >= 'a' && c <= 'f') b2 = (u8)(c - 'a' + 0x0a);
        else { m = 0; b2 = (u8)(rand() & 0xff); }
        if ((i & 1) == 0) { dump[p] = (u8)((dump[p] & 0x0f) | (b2 << 4)); mask[p] = (u8)((mask[p] & 0x0f) | (m << 4)); }
        else               { dump[p] = (u8)((dump[p] & 0xf0) | (b2 & 0x0f)); mask[p] = (u8)((mask[p] & 0xf0) | (m & 0x0f)); }
    }
}
// IC SURUM WATERMARK: "XProtect1.2.2" ASCII -> hex dizisi (UO version_watermark karsiligi;
// her korumali dosyaya otomatik gomulur — Search Watermarks ile tespit edilebilir)
static const char* WM_VERSION_VALUE = "5850726F74656374312E322E32";  // "XProtect1.2.2"

// ---- import tablosu (IAT yuvalari) ----
struct ImpSlot {
    u32 iat_rva = 0;
    u32 dll_hash = 0, name_hash = 0;
    bool ordinal = false;
    std::string dll, name;
};
static bool parse_imports(const PEFile& pe, std::vector<ImpSlot>& out) {
    if (pe.e_lfanew == 0 || (size_t)pe.e_lfanew + 24 + 160 > pe.buf.size()) return false;
    const u8* base = pe.buf.data();
    u16 magic; memcpy(&magic, base + pe.e_lfanew + 24, 2);
    u32 ddoff = (magic == 0x20B) ? 112 : 96;   // OptionalHeader'e gore
    u32 imp_rva, imp_sz;
    memcpy(&imp_rva, base + pe.e_lfanew + 24 + ddoff + 8, 4);
    memcpy(&imp_sz,  base + pe.e_lfanew + 24 + ddoff + 12, 4);
    if (!imp_rva || !imp_sz) return false;
    u32 psz = pe.is64 ? 8 : 4;
    bool okc;
    u32 raw = pe.rva2raw(imp_rva, &okc);
    if (!okc) return false;
    for (u32 d = 0; d < 0x10000 && raw + d * 20 + 20 <= pe.buf.size(); d++) {
        u32 doff = raw + d * 20;
        u32 oft, name_rva, ft;
        memcpy(&oft, base + doff, 4);
        memcpy(&name_rva, base + doff + 12, 4);
        memcpy(&ft, base + doff + 16, 4);
        if (!oft && !name_rva && !ft) break;   // sonlandirici descriptor
        std::string dll;
        {
            bool ok2; u32 nr = pe.rva2raw(name_rva, &ok2);
            if (ok2 && nr + 2 < pe.buf.size()) {
                const char* p = (const char*)base + nr; u32 q = 0;
                while (q < 64 && nr + q < pe.buf.size() && p[q]) { dll.push_back(p[q]); q++; }
            }
        }
        u32 thunk_rva = oft ? oft : ft;
        if (!thunk_rva) continue;
        bool okt; u32 traw = pe.rva2raw(thunk_rva, &okt);
        if (!okt) continue;
        for (u32 k = 0; k < 0x20000; k++) {
            u64 th = 0;
            u32 toff = traw + k * psz;
            if (toff + psz > pe.buf.size()) break;
            memcpy(&th, base + toff, psz);
            if (!th) break;
            ImpSlot s;
            s.dll = dll;
            s.iat_rva = ft + k * psz;
            if (th & (pe.is64 ? 0x8000000000000000ull : 0x80000000u)) {
                s.ordinal = true;
            } else {
                bool okn; u32 hn = pe.rva2raw((u32)th, &okn);
                if (okn && hn + 2 < pe.buf.size()) {
                    const char* p = (const char*)base + hn + 2;   // hint (2 bayt) atla
                    u32 q = 0;
                    while (q < 128 && hn + 2 + q < pe.buf.size() && p[q]) { s.name.push_back(p[q]); q++; }
                }
            }
            s.dll_hash = xfnv_lower(dll);
            s.name_hash = s.ordinal ? 0 : xfnv_a(s.name.c_str(), s.name.size());
            out.push_back(s);
        }
    }
    return !out.empty();
}

// ---- SDK isaret taramasi (xprotect_sdk.h sozlesmesi) ----
// B8 <BEG_MAGIC> B8 <tip 1..3> [kullanici kodu] B8 <END_MAGIC>
static const u32 SDK_BEG_MAGIC = 0x9C37E1B5u;
static const u32 SDK_END_MAGIC = 0x3D7A2C8Eu;
static void scan_sdk(const PEFile& pe, std::vector<ManFn>& out, std::vector<std::string>& log) {
    const Section* t = pe.secbyname_c(".text");
    if (!t) return;
    bool ok; u32 raw = pe.rva2raw(t->va, &ok);
    if (!ok) return;
    u32 maxn = t->vsz;
    if (raw + maxn > pe.buf.size()) maxn = (u32)(pe.buf.size() - raw);
    if (maxn < 16) return;
    const u8* p = pe.buf.data() + raw;
    u32 i = 0;
    int found = 0;
    while (i + 10 <= maxn) {
        if (p[i] == 0xB8) {
            u32 mg; memcpy(&mg, p + i + 1, 4);
            if (mg == SDK_BEG_MAGIC && p[i + 5] == 0xB8) {
                u32 ty; memcpy(&ty, p + i + 6, 4);
                if (ty >= 1 && ty <= 3) {
                    // kapanis isaretini ara
                    u32 j = i + 10;
                    u32 end_at = 0;
                    while (j + 5 <= maxn) {
                        if (p[j] == 0xB8) {
                            u32 me; memcpy(&me, p + j + 1, 4);
                            if (me == SDK_END_MAGIC) { end_at = j; break; }
                        }
                        j++;
                    }
                    if (end_at) {
                        u32 beg = t->va + i + 10;
                        u32 endr = t->va + end_at;
                        if (endr > beg + 7 && endr - beg <= 0x40000) {
                            ManFn m;
                            m.rva = beg; m.size = endr - beg; m.ty = (int)ty - 1;
                            m.is_region = true;   /* 0.5.1: SDK isareti = bolge */
                            m.name = (ty == 1 ? "SDK_V" : (ty == 2 ? "SDK_M" : "SDK_U"));
                            m.name += "_0x" + hex32(beg);
                            out.push_back(m);
                            found++;
                            log.push_back("[SDK] isaret bulundu: " + m.name +
                                          " boyut=0x" + hex32(m.size) +
                                          " tip=" + (ty == 1 ? "V" : (ty == 2 ? "M" : "U")));
                        }
                        i = end_at + 5;
                        continue;
                    }
                    // kapanis yok: bu magic yanlis pozitif olabilir — normal devam
                }
            }
        }
        i++;
    }
    (void)found;
}

// ---- 0.7.0: SDK LISANS API tarayicisi ----
// xprotect_sdk.h API fonksiyonlari: B8 <APIMAGIC> B8 <fnid> ...govde... B8 <END>
// Bulunan blogun TAMAMI (BEG basi -> END sonu) lisans dispatch'ine yamanir.
struct ApiSite { u32 beg_rva; u32 span; u32 fnid; };
static void scan_sdk_api(const PEFile& pe, std::vector<ApiSite>& out,
                         std::vector<std::string>& log) {
    const Section* t = pe.secbyname_c(".text");
    if (!t) return;
    bool ok; u32 raw = pe.rva2raw(t->va, &ok);
    if (!ok) return;
    u32 maxn = t->vsz;
    if (raw + maxn > pe.buf.size()) maxn = (u32)(pe.buf.size() - raw);
    if (maxn < 16) return;
    static const u32 API_MAGIC = 0x4C415058u;   // 'XAPL' (B8 58 50 41 4C)
    const u8* p = pe.buf.data() + raw;
    u32 i = 0;
    while (i + 10 <= maxn) {
        if (p[i] == 0xB8) {
            u32 mg; memcpy(&mg, p + i + 1, 4);
            if (mg == API_MAGIC && p[i + 5] == 0xB8) {
                u32 fnid; memcpy(&fnid, p + i + 6, 4);
                if (fnid >= 1 && fnid <= 37) {   /* 0.7.0-final SDK-40: 1..37 */
                    u32 j = i + 10;
                    u32 end_at = 0;
                    while (j + 5 <= maxn) {
                        if (p[j] == 0xB8) {
                            u32 me; memcpy(&me, p + j + 1, 4);
                            if (me == SDK_END_MAGIC) { end_at = j; break; }
                        }
                        j++;
                    }
                    /* 0.7.0: API bloklari GOVDESIZDIR (yalniz 3 mov):
                       END tam i+10'da olmali — ortadaki govde boslugu
                       sahte-pozitifi imkansiz kilar (CRT rastgele
                       baytlarinda B8 58 50 41 4C ... B8 8E 2C 7A 3D
                       dizisi gorulebilir; araya govde giren eseyseler
                       gercek degildir). */
                    if (end_at == i + 10) {
                        ApiSite st;
                        st.beg_rva = t->va + i;
                        st.span    = (end_at + 5) - i;
                        st.fnid    = fnid;
                        out.push_back(st);
                        log.push_back("[SDK-API] fnid=" + std::to_string(fnid) +
                                      " @0x" + hex32(st.beg_rva) +
                                      " span=" + std::to_string(st.span) + "B");
                        i = end_at + 5;
                        continue;
                    }
                }
            }
        }
        i++;
    }
}

// ---- IAT dolayli-cagri noktasi tarayicisi ----
struct IatSite {
    u32 site_rva, iat_rva, insn_len;
    int kind = 0;    /* 0=call/jmp thunk (FF15/FF25), 1=mov r,[IAT] yukleme */
    bool is_jmp = false;
    int reg = -1;    /* kind=1: hedef reg (REX.R dahil); -1 = islenmez */
    bool rex = false;
};
static void scan_iat_sites(const PEFile& pe, const std::vector<FnInfo>& fns,
                            const std::map<u32, ImpSlot>& by_rva,
                            std::vector<IatSite>& out, u32& n_func_skip) {
    for (auto& f : fns) {
        /* 1.1.0-A6 VMProtect semantigi: import cagrilari YALNIZ korunan
           (sanallastirilan) fonksiyonlarda thunk'a cevrilir. Korunmayan
           kodun (CRT, exit yolu) cagrilari dogrudan IAT'ten devam eder —
           CRT kapanisinda thunk-resolve ile kirisma yok (49-site kaniti:
           main calisiyor, DETACH'ta base+0'a ziplama). */
        if (!f.selected) continue;
        if (f.size < 8) continue;
        bool ok; u32 raw = pe.rva2raw(f.rva, &ok);
        if (!ok || raw + f.size > pe.buf.size()) continue;
        u32 pc = f.rva, end = f.rva + f.size;
        bool aborted = false;
        while (pc < end) {
            Insn I = disasm(&pe.buf[raw + (pc - f.rva)], (int)(end - pc), pe.is64, pc,
                            (u64)pe.imagebase, pe.sizeofimage);
            if (I.op == XP_UNKNOWN || I.len == 0) { aborted = true; break; }
            /* 1.1.0-A6: kind=1 mov r,[IAT] — derleyicilerin 'mov rax,[__imp_X]'
               + 'call rax' deseni; eski tarayici yalniz FF15/FF25 yiyordu.
               Yama: x64 lea r,[rip+thunk] (ayni uzunluk; thunk adi-ilkinde
               API'ye atlar), x86 mov r32, imm32=thunk-VA + nop. */
            u32 slot_rva = 0;
            if (I.op == XP_CALLI || I.op == XP_JMPI || I.op == XP_MOV_RM) {
                if (I.mem.riprel)
                    slot_rva = pc + I.len + (u32)(i32)(u32)I.mem.disp;
                else if (I.mem.absimage) {
                    u64 va = I.mem.absval;
                    if (va >= pe.imagebase && va < (u64)pe.imagebase + pe.sizeofimage)
                        slot_rva = (u32)(va - pe.imagebase);
                }
            }
            if (slot_rva && by_rva.count(slot_rva)) {
                IatSite s;
                s.site_rva = pc; s.iat_rva = slot_rva; s.insn_len = I.len;
                s.is_jmp = (I.op == XP_JMPI);
                if (I.op == XP_MOV_RM && I.mem.present) {
                    /* mov r <- em] : r1 hedef reg; tam-genislik (4/8) yalniz */
                    if (I.sz == 4 || I.sz == 8) {
                        s.kind = 1;
                        s.reg = I.r1;
                        s.rex = I.r1 >= 8;
                    }
                }
                /* beklenmedik kalip — dokunma (x64: 7B REX'li / 6B r32;
                   x86: 6B 8B /r [abs32]) */
                if (s.kind == 1 && pe.is64 && s.insn_len != 7 && s.insn_len != 6) s.kind = 0;
                if (s.kind == 1 && !pe.is64 && s.insn_len != 6) s.kind = 0;
                out.push_back(s);
            }
            pc += I.len;
        }
        if (aborted) n_func_skip++;
    }
}

// Fonksiyonun GERCEK sonunu tara: ret + dolgu (int3/nop) -> dur.
// COFF sembolu olmayan son fonksiyonlarda 0xCC firtinasi onlenir.
static u32 est_func_size(const u8* p, u32 max, bool is64, u64 ib, u32 isz) {
    u32 pc = 0; bool sawret = false;
    while (pc < max) {
        Insn I = disasm(p + pc, (int)(max - pc), is64, pc, ib, isz);
        if (I.op == XP_UNKNOWN || I.len == 0 || I.op == XP_INT3)
            return sawret ? pc : max;
        if (I.op == XP_NOP && sawret) return pc;
        if (I.op == XP_NOP && !sawret) { pc += I.len; continue; }
        pc += I.len;
        if (I.op == XP_RET || I.op == XP_RETI16) sawret = true;
    }
    return pc;
}

// .pdata (x64): RUNTIME_FUNCTION tablosundan fonksiyonun KESIN sonunu bul.
// Donus: fonksiyon sonu RVA'si (bulunamazsa 0).
static u32 pdata_func_end(const PEFile& pe, u32 rva) {
    const Section* pd = pe.secbyname_c(".pdata");
    if (!pd || pd->vsz < 12) return 0;
    bool ok; u32 raw = pe.rva2raw(pd->va, &ok);
    if (!ok) return 0;
    u32 n = pd->vsz / 12;
    // RUNTIME_FUNCTION dizisi BeginAddress'e gore siralidir -> ikili arama
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        u32 o = raw + mid * 12;
        if (o + 12 > pe.buf.size()) return 0;
        u32 beg; memcpy(&beg, &pe.buf[o], 4);
        if (beg == rva) {
            u32 end; memcpy(&end, &pe.buf[o + 4], 4);
            return (end > beg) ? end : 0;
        }
        if (beg < rva) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static void scan_strings(const PEFile& pe, std::vector<RStr>& out) {
    const Section* rd = pe.secbyname_c(".rdata");
    if (!rd) return;
    bool ok; u32 raw = pe.rva2raw(rd->va, &ok);
    if (!ok) return;
    u32 run = 0;
    for (u32 i = 0; i < rd->vsz && raw + i < pe.buf.size(); i++) {
        u8 c = pe.buf[raw + i];
        if (c >= 0x20 && c < 0x7F) { run++; continue; }
        if (run >= 4 && c == 0) out.push_back({ rd->va + i - run, run });
        run = 0;
    }
}

int protect(const std::string& in, const std::string& out, const Options& opt,
            std::vector<std::string>& log) {
    auto L = [&](const std::string& s) { log.push_back(s); };
    char b[300];

    PEFile pe; std::string err;
    if (!pe.load(in, err)) { L("[HATA] " + err); return 1; }
    snprintf(b, sizeof b, "[PE] %s | Machine=0x%04X | %s | ImageBase=0x%llX | GirisRVA=0x%X",
             in.c_str(), pe.machine, pe.is64 ? "PE32+(x64)" : "PE32(x86)",
             (unsigned long long)pe.ib64, pe.entry_rva);
    L(b);
    for (auto& s : pe.secs) {
        snprintf(b, sizeof b, "  sec %-8s RVA=0x%06X VSz=0x%06X Raw=0x%06X Chars=0x%08X",
                 s.name, s.va, s.vsz, s.rawoff, s.chars);
        L(b);
    }

    // --- fonksiyon kesfi: export + COFF sembolleri ---
    std::map<u32, std::string> fnames;
    std::vector<std::pair<std::string, u32>> ex, cs;
    pe.exports(ex);
    pe.coff_symbols(cs);
    for (auto& e : ex) fnames[e.second] = e.first;
    for (auto& c : cs) if (!fnames.count(c.second)) fnames[c.second] = c.first;
    L("[KESIF] export=" + std::to_string(ex.size()) + " coff-fonksiyon=" + std::to_string(cs.size()));

    // --- 0.3.0: PDB / MAP fonksiyon isimleri (VMProtect davranisi) ---
    // Hedefin yaninda <ad>.pdb/.map varsa veya debug dizini gecerli bir PDB
    // gosteriyorsa isimler keşfe eklenir. HICBIRI yoksa bu blogun hicbir
    // etkisi yoktur — 0.2.0'nin kullanici-dogrulanmis cikti davranisi
    // bayt bayt korunur (Test.exe pakette pdb'siz birlikte gelir).
    size_t sym_added = 0;
    {
        SymSections ss;
        for (auto& s : pe.secs)
            ss.secs.push_back({s.va, s.vsz, s.rawsz, s.rawoff, s.chars, std::string(s.name)});
        auto slurp_n = [](const std::string& p, std::vector<u8>& out) -> bool {
            FILE* f = fopen(p.c_str(), "rb");
            if (!f) return false;
            fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
            if (n <= 0) { fclose(f); return false; }
            out.resize((size_t)n);
            size_t rd = fread(out.data(), 1, (size_t)n, f);
            fclose(f);
            return rd == (size_t)n;
        };
        // hedef klasoru + ad (dar yol)
        std::string dir = ".", base;
        {
            size_t q = in.find_last_of("\\/");
            if (q != std::string::npos) { dir = in.substr(0, q); base = in.substr(q + 1); }
            else base = in;
            size_t d = base.find_last_of('.');
            if (d != std::string::npos && d > 0) base.resize(d);
        }
        std::vector<std::string> cands;
        cands.push_back(dir + "\\" + base + ".pdb");
        std::vector<DbgPdbRef> dbg_names;
        pe_debug_pdb_names(pe.buf.data(), pe.buf.size(), ss, dbg_names);
        const su8* want_guid = NULL; su32 want_age = 0;
        if (!dbg_names.empty() && dbg_names[0].has_guid) {
            want_guid = dbg_names[0].guid; want_age = dbg_names[0].age;
        }
        for (auto& r : dbg_names) {
            const std::string& n = r.name;
            bool abs_ = (n.size() > 1 && (n[1] == ':' || n[0] == '\\' || n[0] == '/'));
            if (abs_) cands.push_back(n);
            size_t q = n.find_last_of("\\/");
            cands.push_back(dir + "\\" + (q != std::string::npos ? n.substr(q + 1) : n));
        }
        // dedupe
        for (size_t i = 0; i < cands.size(); i++)
            for (size_t j = i + 1; j < cands.size(); )
                if (cands[j] == cands[i]) cands.erase(cands.begin() + j); else j++;
        std::vector<SymEntry> sfns; std::string serr;
        for (auto& c : cands) {
            std::vector<u8> pd;
            if (!slurp_n(c, pd)) continue;
            if (want_guid && !pdb_matches(pd.data(), pd.size(), want_guid, want_age))
                continue;   // bayat/eslesmeyen PDB — ele
            if (pdb_parse(pd.data(), pd.size(), ss, sfns, serr)) break;
            sfns.clear();
        }
        // MAP
        {
            std::vector<u8> md;
            if (slurp_n(dir + "\\" + base + ".map", md)) {
                std::vector<SymEntry> mfns;
                if (map_parse((const char*)md.data(), md.size(), ss, pe.imagebase, mfns, serr))
                    for (auto& e : mfns) sfns.push_back(e);
            }
        }
        for (auto& e : sfns) {
            if (fnames.count(e.rva)) continue;
            fnames[e.rva] = e.name;
            sym_added++;
        }
        if (sym_added)
            L("[KESIF] +PDB/MAP=" + std::to_string(sym_added) + " (pdb/map yaninda/hata-ayiklama dizininde)");
    }

    std::vector<FnInfo> fns;
    {
        Section* text0 = pe.secbyname(".text");
        u32 textend = text0 ? text0->va + text0->vsz : 0;
        std::vector<u32> rv;
        for (auto& kv : fnames) rv.push_back(kv.first);
        std::sort(rv.begin(), rv.end());
        for (size_t i = 0; i < rv.size(); i++) {
            u32 r = rv[i];
            if (!text0 || r < text0->va || r >= textend) continue;
            u32 next_bound = (i + 1 < rv.size() ? rv[i + 1] : textend);
            u32 sz = next_bound - r;
            if (sz > 0x8000) sz = 0x8000;
            // x64: .pdata'daki RUNTIME_FUNCTION KESIN siniri verir —
            // (BU, onceki surumdeki "est+16 tasma -> sonraki fonksiyonu
            //  int3 ile ezip acilista crash" hatasini kokten engeller)
            if (pe.is64) {
                u32 pend = pdata_func_end(pe, r);
                if (pend > r && pend <= next_bound) sz = pend - r;
            }
            // sembol araligi zenginse guven; genis aralikta gercek kod sonunu tara
            {
                bool okraw; u32 raw = pe.rva2raw(r, &okraw);
                if (okraw && raw + sz <= pe.buf.size() && sz > 16) {
                    u32 est = est_func_size(&pe.buf[raw], sz, pe.is64, pe.imagebase, pe.sizeofimage);
                    if (est + 64 < sz) sz = est + 16;   // tarayici daha erken bitirdi
                }
            }
            // KESIN GUVENLIK: sonraki sembolun icine asla tasma (x86 + pdata'siz durumlar)
            if (r + sz > next_bound) sz = next_bound - r;
            if (sz < 8) continue;
            FnInfo f; f.rva = r; f.size = sz; f.name = fnames[r];
            f.exported = std::any_of(ex.begin(), ex.end(), [&](auto& e) { return e.second == r; });
            fns.push_back(f);
        }
    }
    snprintf(b, sizeof b, "[FONKSIYON] %zu aday (.text)", fns.size());
    L(b);

    // --- 0.4.1: MANUEL fonksiyonlar (UI Manual Address Base/End) ---
    // 0.5.0: opt.manual + SDK isaretleri birlesik liste (manual_all)
    std::vector<ManFn> manual_all = opt.manual;
    if (opt.sdk_scan) scan_sdk(pe, manual_all, log);
    // Kullanici Base/End ile kesin {rva, boyut, tip} verir. 0.4.0'a kadar bu
    // liste motora hic ulasmadigindan (yalnizca tarayici adaylari eslestirilirdi)
    // ULTRA (M+V) secilse bile fonksiyona DOKUNULMIYORDU (.vmp0 yalnizca VM blob
    // tasiyordu). Artik aday-aramadan bagimsiz derlenir; ayni RVA'daki tarayici
    // adayi kesin boyut lehine cikarilir.
    for (auto& m : manual_all) {
        Section* ms = NULL;
        for (auto& s : pe.secs)
            if ((s.chars & 0x20000000) && m.rva >= s.va && m.rva < s.va + s.vsz) { ms = &s; break; }
        if (!ms) { L("[MANUEL] RED: 0x" + hex32(m.rva) + " yurutulebilir bolumde degil"); continue; }
        u32 sz = m.size;
        if (!sz || sz > 0x100000) { L("[MANUEL] RED: gecersiz boyut 0x" + hex32(sz)); continue; }
        if (m.rva + sz > ms->va + ms->vsz) {
            sz = (ms->va + ms->vsz) - m.rva;
            L("[MANUEL] uyari: End bolum sonunu asti -> 0x" + hex32(sz) + " kirpildi");
        }
        bool replaced = false;
        for (size_t i = 0; i < fns.size(); ) {
            if (fns[i].rva == m.rva) { fns.erase(fns.begin() + i); replaced = true; }
            else i++;
        }
        FnInfo f; f.rva = m.rva; f.size = sz;
        f.name = m.name.empty() ? ("MANUAL_0x" + hex32(m.rva)) : m.name;
        f.selected = true;
        fns.push_back(f);
        snprintf(b, sizeof b, "[MANUEL] %s @RVA=0x%06X boyut=0x%X tip=%s%s",
                 f.name.c_str(), f.rva, sz,
                 m.ty == 0 ? "V" : (m.ty == 1 ? "M" : "U"),
                 replaced ? " (tarayici adayi degisti)" : "");
        L(b);
    }

    // --- secim ---
    std::set<u32> man_rva; std::map<u32,int> man_ty;   // 0.4.1: manuel fonksiyonlar
    for (auto& m : manual_all) { man_rva.insert(m.rva); man_ty[m.rva] = m.ty; }
    std::set<u32> sdk_rva;
    for (auto& m : manual_all) if (m.is_region) sdk_rva.insert(m.rva);
    for (auto& f : fns) {
        if (man_rva.count(f.rva)) continue;   // manuel: kesin secili (asla ezilmez)
        if (opt.sdk_only) continue;           // 0.5.0: yalniz SDK/manual bolgeleri koru
        if (opt.manual.empty() && (opt.all || opt.funcs.empty())) { f.selected = (f.size >= 24 && f.size <= 8192); continue; }
        for (auto& want : opt.funcs) {
            if (want == f.name) { f.selected = true; break; }
            u32 rv = (u32)strtoul(want.c_str(), nullptr, 16);
            if (rv && rv == f.rva) { f.selected = true; break; }
        }
    }

    // --- 0.3.0: TIP SEVKI (V/M/U) — ftypes anahtarlari opt.funcs
    // ile ayni formattadir (isim ya da buyuk-harf RVA-hex) ---
    auto ftype_of = [&](const FnInfo& f) -> int {
        auto itm = man_ty.find(f.rva);          // 0.4.1: manuel tip onceligi
        if (itm != man_ty.end()) return itm->second;
        auto it = opt.ftypes.find(f.name);
        if (it != opt.ftypes.end()) return it->second;
        char rb[24]; snprintf(rb, sizeof rb, "%X", f.rva);
        it = opt.ftypes.find(rb);
        if (it != opt.ftypes.end()) return it->second;
        return opt.default_type;
    };

    Section* text = pe.secbyname(".text");
    Section* rdata = pe.secbyname(".rdata");
    u32 rdata_rva = rdata ? rdata->va : 0;
    u32 rdata_sz  = rdata ? rdata->vsz : 0;
    std::vector<RStr> strings;
    if (opt.strenc) {
        scan_strings(pe, strings);
        snprintf(b, sizeof b, "[STRENC] .rdata'da %zu string tespit", strings.size());
        L(b);
    }

    // ============================================================
    // 0.5.0 — ERKEN YERLESIM + IMPORT KORUMASI (derleme ONCESI)
    // .vmp0 duzeni: [vm blob][xrt kod][cfg][IAT thunklar][bc][stublar]
    //               [M kapi+govde][state][IAT cache]
    // IAT yamalari derlemeden once yapilir: boylece mutasyon/lifter
    // FF15 yerine E8 (dogrudan cagri) gorur -> API cagiran fonksiyonlar
    // da sanallastirilabilir hale gelir (VMProtect davranisi).
    // ============================================================
    const u8* blob; int blob_len;
    if (pe.is64) { blob = VM_BLOB64; blob_len = VM_BLOB64_LEN; }
    else         { blob = VM_BLOBX86; blob_len = VM_BLOBX86_LEN; }

    u32 newva_guess = 0;
    {
        u32 lastva = 0, lastvsz = 0;
        for (auto& s : pe.secs) if (s.va + s.vsz > lastva + lastvsz) { lastva = s.va; lastvsz = s.vsz; }
        newva_guess = (lastva + lastvsz + pe.secalign - 1) & ~(pe.secalign - 1);
    }

    bool rt_any  = opt.rt_selfcrc || opt.rt_textcrc || opt.rt_filecrc || opt.memprot;   /* 1.2.2-A11: memprot runtime bagli */
    // 0.7.0: lisans API'leri xrt dispatch ister
    bool lic_any = !opt.lic_pubkey.empty() || !opt.lic_watermark.empty();
    // 0.6.0: paketleme xrt_unpack ister (EP stub cagirir)
    bool rt_blob = rt_any || opt.iat_prot || opt.pack || lic_any
                || (opt.vfiles && !opt.vfile_paths.empty());   /* 1.2.2-A16: VF runtime ister */
    u32 xrt_len      = pe.is64 ? (u32)XRT_BLOB64_LEN : (u32)XRT_BLOBX86_LEN;
    u32 xrt_code_off = 0, cfg_off = 0;
    u32 xrt_entry_rva = 0, xrt_resolve_rva = 0, cfg_rva = 0, xrt_unpack_rva = 0;
    u32 xrt_sdk_rva = 0, lsd_rva = 0;
    if (rt_blob) {
        xrt_code_off = ((u32)blob_len + 15) & ~15u;
        cfg_off      = (xrt_code_off + xrt_len + 15) & ~15u;
        u32 xrt_rva  = newva_guess + xrt_code_off;
        xrt_entry_rva   = xrt_rva + (pe.is64 ? XRT_BLOB64_ENTRY_OFF : XRT_BLOBX86_ENTRY_OFF);
        xrt_resolve_rva = xrt_rva + (pe.is64 ? XRT_BLOB64_RESOLVE_OFF : XRT_BLOBX86_RESOLVE_OFF);
        xrt_unpack_rva  = xrt_rva + (pe.is64 ? XRT_BLOB64_UNPACK_OFF : XRT_BLOBX86_UNPACK_OFF);
        xrt_sdk_rva     = xrt_rva + (pe.is64 ? XRT_BLOB64_SDK_OFF  : XRT_BLOBX86_SDK_OFF);
        cfg_rva         = newva_guess + cfg_off;
    }

    // ---- 0.7.0: LSD (License SeDiketi) — cfg sonrasi rezerve edilir ----
    // Duzen: [cfg 0x48][LSD 0x12C][bytecode...]
    /* 1.1.0-A7: 0x130..0x16F = watermark metni (64B), 0x12C..0x12D = uzunluk.
       CRC alani (0x000..0x11F) degismedi — runtime uyumlu. */
    #define LSD_SIZE_E 0x170
    #define LSD_CACHE_E 0x104   /* 0.7.0-final: serial em önbelleği (flag+256B) */
    std::vector<u8> lsd;
    if (!opt.lic_pubkey.empty()) {
        if (opt.lic_pubkey.size() != 512) {
            L("[HATA] --pubkey 512 hex (256 bayt modulus BE) olmali — cikti YAZILMADI");
            return 2;
        }
        if (opt.lic_prodcode.size() != 16) {
            L("[HATA] --prodcode 16 hex (8 bayt urun kodu) olmali — cikti YAZILMADI");
            return 2;
        }
    }

    // ---- IAT korumasi: tarama + thunk planlama + cagri noktasi yamasi ----
    std::vector<ImpSlot> imps;
    std::vector<u32> thunk_rvas;          // benzersiz IAT yuvasi basina bir thunk
    std::vector<ImpSlot> thunk_slots;     // thunk ile eslesen slot
    // 0.6.1 DÜZELTME (kullanıcı bulgusu: metin2 ULTRA+loaderCRC'te sessiz
    // no-op): 0.6.0'da XCFG 0x40 -> 0x48 büyüdü (XCFG_OFF_PACKRVA) ama
    // rezerv 0x40'ta kaldı -> cfg'nin son 8B (pack_rva+reserved=0)
    // İLK bytecode'un ilk 8 baytını EZİYORDU -> VM çöp opcode okuyor,
    // fonksiyon sessizce no-op'a düşüyor (crash YOK, yanlış sonuç VAR).
    u32 lsd_area = (lic_any && rt_blob) ? (LSD_SIZE_E + LSD_CACHE_E) : 0;

    // ============================================================
    // 1.2.2-A16: VIRTUAL FILES — cfg'den sonra XVF1 blogu (xr_cipher.h sozlesmesi)
    // Gomulu dosyalar: isim UO InternalFile::WriteName 1:1 rotl/xor; veri CFB-64.
    // cpVirtualFiles kutusu + --vfile <yol> (faLoad) / reg:<yol> / install:<yol>.
    // Runtime: ilk korumali kapida xrt_vfiles bellekte manuel-PE yukler.
    // ============================================================
    std::vector<u8> vf_block;
    u32 vf_area = 0;
    if (opt.vfiles && rt_blob && !opt.vfile_paths.empty()) {
        size_t vf_n = opt.vfile_paths.size() > (size_t)XVF_MAX_FILES ? (size_t)XVF_MAX_FILES : opt.vfile_paths.size();
        if (vf_n < opt.vfile_paths.size())
            L("[VF] en fazla 64 dosya — fazlasi atlandi");
        struct VfRaw { std::vector<u8> data; u32 action; std::string name; std::string src; };
        std::vector<VfRaw> vfs;
        for (size_t vfi = 0; vfi < vf_n; vfi++) {
            const std::string& p = opt.vfile_paths[vfi];
            u32 act = 1;                                  // faLoad varsayilan
            std::string path = p;
            if (path.size() > 5 && path.compare(0, 5, "reg:") == 0) { act = 2; path = path.substr(5); }
            else if (path.size() > 8 && path.compare(0, 8, "install:") == 0) { act = 3; path = path.substr(8); }
            FILE* fp = fopen(path.c_str(), "rb");
            if (!fp) { L(std::string("[VF] acilamadi (atlandi): ") + path); continue; }
            fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
            if (sz < 0 || (unsigned long long)sz > XVF_MAX_SIZE) {
                L(std::string("[VF] boyut siniri (atlandi): ") + path);
                fclose(fp); continue;
            }
            VfRaw v; v.data.resize((size_t)sz);
            if (sz && fread(v.data.data(), 1, (size_t)sz, fp) != (size_t)sz) {
                L(std::string("[VF] okunamadi (atlandi): ") + path);
                fclose(fp); continue;
            }
            fclose(fp);
            size_t sl = path.find_last_of("/\\");
            v.name = (sl == std::string::npos) ? path : path.substr(sl + 1);
            v.action = act;
            v.src = path;
            vfs.push_back(std::move(v));
        }
        if (!vfs.empty()) {
            u32 names_off = 16 + (u32)vfs.size() * 16;
            std::vector<u8> names_blob;
            std::vector<u32> name_offs;
            for (size_t fi = 0; fi < vfs.size(); fi++) {
                // UTF-16 isim + L'\0'; UO WriteName 1:1: w[i] ^ (rotl32(key,i)+i)
                std::wstring w(vfs[fi].name.begin(), vfs[fi].name.end());  // ASCII guvenli
                u32 nk = xvf_namekey(cfg_rva, (u32)fi);
                name_offs.push_back(names_off + (u32)names_blob.size());
                for (size_t i = 0; i <= w.size(); i++) {
                    u16 c = (i == w.size()) ? 0 : (u16)w[i];
                    u32 ro = ((nk << ((u32)(i & 31))) | (nk >> ((32u - (u32)(i & 31)) & 31)));
                    u16 e = (u16)(c ^ (u16)((ro + (u32)i) & 0xFFFF));
                    names_blob.push_back((u8)(e & 0xFF));
                    names_blob.push_back((u8)(e >> 8));
                }
            }
            // 1.2.2-A16 duzeltildi: yerlesim hatasi — veri isimlerden SONRA
            // hizalanir (names_off degil blok-sonu); hdr data_off = ILK veri
            // baslangici (dongu sonu degil); data_blob ici padding YOK —
            // hizalama blok resize ile yapilir.
            u32 blk_end = names_off + (u32)names_blob.size();
            u32 first_data_off = (blk_end + 15) & ~15u;
            std::vector<u8> data_blob;
            std::vector<u32> data_offs;
            for (size_t fi = 0; fi < vfs.size(); fi++) {
                data_offs.push_back(first_data_off + (u32)data_blob.size());
                std::vector<u8> enc = vfs[fi].data;
                xr_cfb(xvf_k0(cfg_rva), xvf_k1(cfg_rva),
                       xvf_nonce(data_offs[fi]), enc.data(), (u32)enc.size(), 0);
                data_blob.insert(data_blob.end(), enc.begin(), enc.end());
                while (data_blob.size() & 15u) data_blob.push_back(0);
            }
            // blok kur: [hdr 16][entries][isimler][pad][veri]
            vf_block.resize(16 + vfs.size() * 16, 0);
            wrv32(vf_block, 0, XVF_HDR_MAGIC);
            wrv32(vf_block, 4, (u32)vfs.size());
            wrv32(vf_block, 8, names_off);
            wrv32(vf_block, 12, first_data_off);
            for (size_t fi = 0; fi < vfs.size(); fi++) {
                wrv32(vf_block, 16 + (u32)fi * 16 + 0, name_offs[fi]);
                wrv32(vf_block, 16 + (u32)fi * 16 + 4, data_offs[fi]);
                wrv32(vf_block, 16 + (u32)fi * 16 + 8, (u32)vfs[fi].data.size());
                wrv32(vf_block, 16 + (u32)fi * 16 + 12, vfs[fi].action);
            }
            vf_block.insert(vf_block.end(), names_blob.begin(), names_blob.end());
            if (vf_block.size() < (size_t)first_data_off) vf_block.resize(first_data_off, 0);
            vf_block.insert(vf_block.end(), data_blob.begin(), data_blob.end());
            vf_area = (u32)vf_block.size();
            for (auto& v : vfs) {
                snprintf(b, sizeof b, "[VF] gomuldu: %s (%uB, fa%s)",
                         v.name.c_str(), (u32)v.data.size(),
                         v.action == 1 ? "Load" : (v.action == 2 ? "Register" : "Install"));
                L(b);
            }
        }
    }

    if (lsd_area) lsd_rva = cfg_rva + XCFG_SIZE_E + vf_area;   // 1.2.2-A16: VF blogu cfg ile LSD arasinda
    u32 thunk_area_end = rt_blob ? (cfg_off + XCFG_SIZE_E + vf_area + lsd_area) : (u32)blob_len;
    u32 n_iat_sites = 0, n_iat_funcs_skip = 0;
    if (opt.iat_prot) {
        std::map<u32, ImpSlot> by_rva;
        if (parse_imports(pe, imps))
            for (auto& s : imps) by_rva[s.iat_rva] = s;
        if (by_rva.empty()) {
            L("[IAT] import tablosu bos/okunamadi — koruma atlandi");
        } else {
            std::vector<IatSite> sites;
            scan_iat_sites(pe, fns, by_rva, sites, n_iat_funcs_skip);
            // benzersiz yuvalar
            std::map<u32, ImpSlot> uniq;
            std::vector<u32> order;
            for (auto& st : sites)
                if (!uniq.count(st.iat_rva)) { uniq[st.iat_rva] = by_rva[st.iat_rva]; order.push_back(st.iat_rva); }
            std::vector<u8> probe = pe.is64
                ? build_thunk_x64(0, 0, 0, 0, 0, 0)
                : build_thunk_x86(0, 0, 0, 0, 0, 0);
            const u32 thlen = (u32)probe.size();
            u32 tcur = (thunk_area_end + 15) & ~15u;
            for (u32 r : order) {
                thunk_rvas.push_back(newva_guess + tcur);
                thunk_slots.push_back(uniq[r]);
                tcur += thlen;
            }
            thunk_area_end = tcur;
            // cagri noktalarini yamala: FF15->E8 (call), FF25->E9 (jmp) + nop dolgu
            // (ayni site birden fazla fonksiyon araliginda olabilir — dedupe)
            std::set<u32> done;
            for (auto& st : sites) {
                if (done.count(st.site_rva)) continue;
                done.insert(st.site_rva);
                bool okr; u32 sraw = pe.rva2raw(st.site_rva, &okr);
                if (!okr || sraw + st.insn_len > pe.buf.size()) continue;
                // thunk rvasini bul
                u32 thr = 0;
                for (size_t q = 0; q < thunk_slots.size(); q++)
                    if (thunk_slots[q].iat_rva == st.iat_rva) { thr = thunk_rvas[q]; break; }
                if (!thr) continue;
                if (st.kind == 1 && st.reg >= 0) {
                    /* mov r,[IAT] -> thunk adresi yukle */
                    if (pe.is64) {
                        /* [REX] 8B /r [rip+disp32] -> [REX] 8D /r [rip+thunk]
                           8B konumu = insn_len-6 (7B:1, 6B:0); disp32 sonda */
                        u32 rel = (u32)(thr - (st.site_rva + st.insn_len));
                        pe.buf[sraw + st.insn_len - 6] = 0x8D;  /* mov->lea */
                        u32 doff = sraw + st.insn_len - 4;
                        pe.buf[doff + 0] = (u8)rel; pe.buf[doff + 1] = (u8)(rel >> 8);
                        pe.buf[doff + 2] = (u8)(rel >> 16); pe.buf[doff + 3] = (u8)(rel >> 24);
                    } else {
                        /* 6B: 8B /r [abs32] -> B8+r imm32(thunk VA) + 90 */
                        u32 va = pe.imagebase + thr;
                        pe.buf[sraw + 0] = (u8)(0xB8 + (st.reg & 7));
                        pe.buf[sraw + 1] = (u8)va; pe.buf[sraw + 2] = (u8)(va >> 8);
                        pe.buf[sraw + 3] = (u8)(va >> 16); pe.buf[sraw + 4] = (u8)(va >> 24);
                        pe.buf[sraw + 5] = 0x90;
                    }
                    n_iat_sites++;
                    continue;
                }
                i32 rel = (i32)(thr - (st.site_rva + 5));
                u8 jb[16];
                jb[0] = st.is_jmp ? 0xE9 : 0xE8;   // jmp / call thunk
                jb[1] = (u8)(u32)rel; jb[2] = (u8)((u32)rel >> 8);
                jb[3] = (u8)((u32)rel >> 16); jb[4] = (u8)((u32)rel >> 24);
                for (u32 q = 5; q < st.insn_len; q++) jb[q] = 0x90;  // nop dolgu
                memcpy(&pe.buf[sraw], jb, st.insn_len);
                n_iat_sites++;
            }
            snprintf(b, sizeof b, "[IAT] %zu import (benzersiz yuva=%zu) | %u cagri noktasi thunk'a cevrildi | %u fonksiyon atlandi (cozumlenemeyen bayt)",
                     imps.size(), order.size(), n_iat_sites, n_iat_funcs_skip);
            L(b);
            for (size_t q = 0; q < thunk_slots.size() && q < 12; q++)
                L("  [IAT] thunk[" + std::to_string(q) + "] " + thunk_slots[q].dll + "!" +
                  (thunk_slots[q].ordinal ? ("#" + std::to_string(thunk_slots[q].name_hash)) : thunk_slots[q].name) +
                  " IAT=0x" + hex32(thunk_slots[q].iat_rva) + " RVA=0x" + hex32(thunk_rvas[q]));
            if (thunk_slots.size() > 12)
                L("  [IAT] ... +" + std::to_string(thunk_slots.size() - 12) + " thunk daha");
        }
    }

    // 0.7.0: SDK lisans API yamasi (.text icindeki isaret govdeyi degistirir).
    // CRC hesaplarindan ONCE yapilmali (text-CRC yamali .text uzerinden).
    {
        std::vector<ApiSite> apis;
        if (opt.sdk_scan) scan_sdk_api(pe, apis, log);
        u32 n_apis = 0;
        for (auto& st : apis) {
            u32 stub_len = pe.is64 ? 11u : 10u;
            if (st.span < stub_len) {
                L("[SDK-API] UYARI: span kisa (" + std::to_string(st.span) + "B) — atlandi");
                continue;
            }
            bool okr; u32 sraw = pe.rva2raw(st.beg_rva, &okr);
            if (!okr || sraw + st.span > pe.buf.size()) continue;
            std::vector<u8> sb = pe.is64
                ? build_api_stub_x64(st.beg_rva, st.fnid, lsd_rva, xrt_sdk_rva, st.span)
                : build_api_stub_x86(st.beg_rva, st.fnid, lsd_rva, xrt_sdk_rva, st.span);
            memcpy(&pe.buf[sraw], sb.data(), st.span);
            n_apis++;
        }
        if (!apis.empty()) {
            snprintf(b, sizeof b, "[SDK-API] %zu isaret / %u API lisans dispatch'ine yamandi (fnid 1..37; LSD imaj taramasi)",
                     apis.size(), n_apis, lsd_rva, xrt_sdk_rva);
            L(b);
        }
    }

    // --- lift / mutasyon ---
    struct Compiled {
        FnInfo* f; VFn v; std::vector<u8> plain, enc;
        u64 key = 0; u32 bc_rva = 0, stub_rva = 0;
        u32 stub_len = 0;                    // 0.8.0 SEH: .vmp0 kayit genisligi
        bool tramp = false;
        int  ty = 0;                          // 0=V 1=M 2=U
        MutFn mut;                           // M: olcum gecisi; U: kaynak mutasyon
        u32  mut_rva = 0;                    // M: .vmp0 icindeki yerlesim
        u32  mut_gate_rva = 0;               // 0.5.0: M onundeki runtime kapisI
        std::vector<u32> state_sites;         // plain icinde state rva u32 pozisyonlari
        std::vector<u32> state_strva;         // sirasiyla string rva'lari
        std::vector<std::pair<u32,u32>> dec_sites; // 0.8.1: (plain-ofset, orig str rva) — strRva=kopya yamasi
        u32 prefix_len = 0;                   // 0.8.1: govde oncesi STRDEC/ANTIDBG oneki (ref-site kaydirmasi)
        u32 vm_id = 0;                        // 1.2.0-B1 mult-VM gostergesi
        u32 perm_seed = 0;                    // 1.2.0-B1 opcode harita tohumu
    };
    std::vector<Compiled> comps;
    int nV = 0, nM = 0, nU = 0, nUf = 0;
    // 0.8.0 SEH: eski .pdata SizeOfProlog haritasi (mutator unwind haritasi
    // prologu buna kadar izler; .xdata'daki UNWIND_INFO byte1)
    std::map<u32,u32> prolog_of;
    if (pe.is64) {
        u32 fh2 = pe.e_lfanew + 4;
        u32 dd3b = fh2 + 20 + 112 + 3 * 8;
        u32 pr_rva = 0, pr_sz = 0;
        memcpy(&pr_rva, &pe.buf[dd3b], 4);
        memcpy(&pr_sz, &pe.buf[dd3b + 4], 4);
        if (pr_rva && pr_sz) {
            bool oko = false; u32 praw2 = pe.rva2raw(pr_rva, &oko);
            if (oko && (u64)praw2 + pr_sz <= pe.buf.size()) {
                for (u32 o = 0; o + 12 <= pr_sz; o += 12) {
                    u32 bg = rdv32(pe.buf, praw2 + o), ui = rdv32(pe.buf, praw2 + o + 8);
                    if (!bg) continue;
                    bool oki = false; u32 uiraw = pe.rva2raw(ui, &oki);
                    if (oki && (u64)uiraw + 2 <= pe.buf.size())
                        prolog_of[bg] = pe.buf[uiraw + 1];
                }
            }
        }
    }
    for (auto& f : fns) {
        if (!f.selected) continue;
        bool okraw; u32 raw = pe.rva2raw(f.rva, &okraw);
        if (!okraw || raw + f.size > pe.buf.size()) { f.note = "ham veri yok"; continue; }
        int ty = ftype_of(f);
        bool is_region = sdk_rva.count(f.rva) != 0;   // 0.5.1: yalniz SDK bolgesi
        if (ty == 1) {
            // --- MUTASYON (native): makine kodu kalir, yeniden uretilir ---
            MutFn m = mutate_function(&pe.buf[raw], f.rva, f.size, pe.is64,
                                      pe.imagebase, pe.sizeofimage,
                                      true /* 0.4.1: x86 dis-cagri rel32 fixup zaten destekli */,
                                      opt.mut_strength,
                                      f.rva ^ 0x9E3779B9u, 0 /*olcum gecisi*/, is_region,
                                      prolog_of.count(f.rva) ? prolog_of[f.rva] : 0);
            if (!m.ok) { f.note = "RED: mutasyon " + m.why; continue; }
            Compiled c; c.f = &f; c.ty = 1; c.mut = m;
            comps.push_back(c);
            nM++;
            continue;
        }
        // --- V / U: lifter kaynagi (U'da mutasyon on gecisi) ---
        std::vector<u8> mbuf;
        const u8* lcode = &pe.buf[raw];
        u32 lsize = f.size;
        int jl;
        MutFn mkeep;                            // U: istatistik/kayit tut
        if (ty == 2) {
            MutFn m = mutate_function(&pe.buf[raw], f.rva, f.size, pe.is64,
                                      pe.imagebase, pe.sizeofimage,
                                      true /* 0.4.1: x86 dis-cagri rel32 fixup zaten destekli */,
                                      opt.mut_strength,
                                      f.rva ^ 0x9E3779B9u, f.rva /*base=fonksiyon RVA*/,
                                      false /* U kaynak mutasyonu: bolge kuyrugu YOK — lifter yapay OP_RET ile cikar */,
                                      prolog_of.count(f.rva) ? prolog_of[f.rva] : 0);
            if (m.ok) {
                mbuf = m.code; lcode = mbuf.data(); lsize = (u32)mbuf.size();
                mkeep = m;
                nU++;
            } else {
                // mutasyon mumkun degil: 0.2.0 U davranisina dus (VM junk)
                L("[ULTRA] on-mutasyon RED: " + m.why + " -> saf V ye dusuluyor" + (is_region ? " (bolge)" : ""));
                ty = 0; nUf++; nV++;   /* 0.6.2: OZET sayaci — dusus bir V derlemesidir */
            }
            jl = 2;
        } else {
            // V: acik tip 0 => saf sanallastirma (junk yok).
            // ftypes yoksa 0.2.0 CLI uyumu: level>=2 -> VM junk
            jl = opt.ftypes.empty() ? (opt.level >= 2 ? 2 : 0) : 0;
            nV++;
        }
        // 0.5.0: x86 VM'de dogal cagri (OP_NCALL) hala kirik (vm_natcall86
        // Unicorn testinde yigin bozumu) — x86'ta cagri iceren fonksiyonlar
        // V/U reddedilir (duru RED, sessiz yanlis SONUC yerine). M modu
        // native calistigi icin cagrilar sorunsuz. x64'te natcall CALISIYOR
        // (wine test_rt64 kaniti). 0.5.1'de x86 natcall duzeltmesi planli.
        bool lift_allow_call = true; /* EXPERIMENT */
        /* 1.2.0-B1 mult-VM: vmn>1 -> ayni VM'in fonksiyonlari AYNI opcode
           haritasini tasir (VMP VirtualMachineList semantigi); vmn=1 ->
           fonksiyon-basi tohum (1.1.0 davranisi birebir). */
        u32 vm_id = (opt.vmn > 1) ? (u32)(f.rva % (u32)opt.vmn) : 0u;
        u32 perm_seed = (opt.vmn > 1)
            ? ((((vm_id + 1u) * 0x9E3779B9u) ^ 0x51ED270Bu) | 1u)
            : f.rva;
        VFn v = lift_function(lcode, f.rva, lsize, pe.is64,
                              pe.imagebase, pe.sizeofimage,
                              lift_allow_call,
                              rdata_rva, rdata_sz,
                              jl, f.rva ^ 0x9E3779B9u,
                              mbuf.empty() /* 0.4.1: mutant girdide dolgu akisi kesmez */,
                              is_region, perm_seed /* 0.8.0/B1 tohum */,
                              opt.antidebug /* 1.2.0-A8: OP_CHKRET yayimi */);
        if (!v.ok) { f.note = "RED: " + v.why; continue; }
        Compiled c; c.f = &f; c.ty = ty; c.v = v;
        c.vm_id = vm_id; c.perm_seed = perm_seed;   /* 1.2.0-B1 */
        if (ty == 2) c.mut = mkeep;
        comps.push_back(c);
    }
    {
        u32 n_sel = 0;
        for (auto& f2 : fns) if (f2.selected) n_sel++;
        snprintf(b, sizeof b, "[LIFT] %zu/%u secili fonksiyon | V=%d M=%d U=%d (U-mutdus=%d)",
                 comps.size(), n_sel, nV, nM, nU, nUf);
        if (n_sel > (u32)comps.size())
            snprintf(b + strlen(b), sizeof b - strlen(b),
                     " | UYARI: %u fonksiyon RED edildi (asagida)", n_sel - (u32)comps.size());
    }
    L(b);
    for (auto& f : fns) {
        if (f.selected && !f.virtualized && !f.note.empty() && f.note.rfind("RED", 0) == 0)
            L("[RED] " + f.name + " @0x" + hex32(f.rva) + ": " + f.note);
    }

    // --- plain olustur: STRDEC + ANTIDBG + govde ---
    // (blob/newva_guess 0.5.0'da derleme ONCESINE tasindi — IAT thunk plani)
    // 0.8.1: strenc ozel kopyalari — lifter'in referans verdigi TUM stringler
    // (tekil; kopya basina PAYLASILAN state). Orijinal string diske
    // DOKUNULMAZ -> M/native kodun kendi referanslari her zaman dogru kalir.
    std::vector<RStr> encstr;
    std::map<u32, u32> str_state_idx;     // orig rva -> state index (kopya basina)
    std::map<u32, u32> str_copy;          // orig rva -> kopya RVA (yerlesim sonrasi dolar)

    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: bayt-kod yok
        std::vector<u8> plain;
        /* 0.8.1 KRITIK FIX (anti-debug olumu): STRDEC/ANTIDBG opcode'lari
           lifter ile AYNI perm tablosundan gecmeli (tohum = f.rva).
           0.8.0'da ham push ediliyordu; interpreter itab[sf8] ile cozdugu
           icin ham bayt BASKA op'a dusuyordu:
             ham 0x1E (ANTIDBG) -> itab[0x1E]=OP_CQO -> kontrol HIC calismiyor
             (CE/winedbg altinda fonksiyon calismaya devam ediyordu)
             ham 0x1F (STRDEC)  -> rastgele op (strenc bozuk). */
        u8 ptab[VM_OPN];
        vm_perm_tab(c.perm_seed ? c.perm_seed : c.f->rva, ptab, 0);  // gercek->raw (lift_function ile ayni tohum)
        if (opt.strenc) {
            std::vector<RStr> used;
            for (u32 ref : c.v.str_refs)
                for (auto& s : strings)
                    if (ref >= s.rva && ref < s.rva + s.len)
                        if (std::find_if(used.begin(), used.end(), [&](RStr& r) { return r.rva == s.rva; }) == used.end())
                            used.push_back(s);
            for (auto& s : used) {
                if (str_state_idx.find(s.rva) == str_state_idx.end()) {
                    str_state_idx[s.rva] = (u32)encstr.size();
                    encstr.push_back(s);
                }
                plain.push_back(ptab[OP_STRDEC]);
                /* 0.8.1 FIX (0.3.0'dan beri latent): VM handler 4xu32 okur
                   (strRva, stateRva, key, len) — encoder yalniz 2xu32
                   yaziyordu -> akis 8 bayt kayiyor, govde op'lari yanlis
                   cozuluyor, ANTIDBG de yutuluyordu.
                   strRva = SIFRELI OZEL KOPYA (yerlesim sonrasi yamalanir). */
                c.dec_sites.push_back({(u32)plain.size(), s.rva});
                for (int k = 0; k < 4; k++) plain.push_back(0);   // strRva (kopya) placeholder
                c.state_sites.push_back((u32)plain.size());
                for (int k = 0; k < 4; k++) plain.push_back(0);   // state rva placeholder
                u32 k2 = (s.rva * 2654435761u) | 1u;
                for (int k = 0; k < 4; k++) plain.push_back((u8)(k2 >> (8 * k)));    // key
                for (int k = 0; k < 4; k++) plain.push_back((u8)(s.len >> (8 * k))); // len
                c.state_strva.push_back(s.rva);
                c.v.notes.push_back("  [STRDEC] str=0x" + hex32(s.rva) + " len=" + std::to_string(s.len) + " key=0x" + hex32(k2));
            }
        }
        /* 1.1.0-A7 + 1.2.2-A15: ANTIDBG maske bayti — bit0=anti-debug bataryasi
           (PEB/K1..K4,K8,K9), bit1=Check VM (K7 CPUID hipervizor), bit2=KERNEL
           DEBUGGER (K5 SystemKernelDebuggerInformation + K6 SoftICE surucu
           taramasi). UO KURALI: Check Debugger acikken kernel-debugger kontrolu
           OTOMATIK dahil -> bit2 = (antidebug || kerneldbg). */
        if (opt.antidebug || opt.checkvm || opt.kerneldbg) {
            plain.push_back(ptab[OP_ANTIDBG]);
            plain.push_back((u8)((opt.antidebug ? 1 : 0)
                               | (opt.checkvm ? 2 : 0)
                               | ((opt.antidebug || opt.kerneldbg) ? 4 : 0)));
        }
        c.prefix_len = (u32)plain.size();     // 0.8.1: govde ref-site kaydirmasi
        plain.insert(plain.end(), c.v.plain.begin(), c.v.plain.end());
        c.plain = plain;
#ifdef XPROTECT_BC_DUMP
        {   /* HATA AYIKLAMA: duz plain akisi dosyaya (bcwalk dogrulamasi) */
            char db[96]; snprintf(db, sizeof db, "/tmp/bcdump_%X.bin", c.f->rva);
            FILE* df = fopen(db, "wb"); if (df) { fwrite(plain.data(), 1, plain.size(), df); fclose(df); }
        }
#endif
    }

    // --- section icinde RVAlari planla ---
    // 0.5.0: vm blob + (xrt + cfg + thunklar erken planlandi) sonrasindan devam
    u32 cur = thunk_area_end;
    u32 xrt_after = cur;   // xrt kodu + cfg zaten secimg'in basina yazilacak
    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: bc yerlesimi yok
        cur = (cur + 7) & ~7u;
        c.bc_rva = newva_guess + cur;
        cur += (u32)c.plain.size();
    }
    u32 vent_guess = newva_guess + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF);
    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: stub yok (native govde)
        cur = (cur + 15) & ~15u;
        c.stub_rva = newva_guess + cur;
        std::vector<u8> st;
        bool isreg = sdk_rva.count(c.f->rva) != 0;
        u32 cont = isreg ? (c.f->rva + c.f->size) : 0;
        if (pe.is64) st = build_stub_x64(c.stub_rva, vent_guess, c.key, c.bc_rva, (u32)c.plain.size(),
                                         (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont,
                                         c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
        else         st = build_stub_x86(c.stub_rva, vent_guess, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm,
                                         (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont,
                                         c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
        c.tramp = st.size() > c.f->size;
        c.stub_len = (u32)st.size();
        cur += (u32)st.size();
    }
    // --- mutasyon bloklari (tip M): runtime kapisI + olcum gecisi boyutu ---
    for (auto& c : comps) if (c.ty == 1) {
        cur = (cur + 15) & ~15u;
        u32 gate_rva = newva_guess + cur;
        u32 glen = 0;
        if (rt_any) {
            std::vector<u8> g = pe.is64
                ? build_mgate_x64(gate_rva, xrt_entry_rva, cfg_rva, 0)
                : build_mgate_x86(gate_rva, xrt_entry_rva, cfg_rva, 0);
            glen = (u32)g.size();
        }
        c.mut_gate_rva = gate_rva;
        c.mut_rva = gate_rva + glen;          // govde kapiya bitisik
        cur += glen + (u32)c.mut.code.size();
    }
    // --- 0.8.1: sifreli string kopyalari (M-blok/bc/stub SONRASI, state ONCESI;
    //     M-bolge cakisma korumasi: kopya alani hicbir kod bloguyla paylasmaz) ---
    {
        u32 sc = (cur + 7) & ~7u;
        for (auto& s : encstr) {
            str_copy[s.rva] = newva_guess + sc;
            sc += (s.len + 7) & ~7u;          // kopya basina 8 bayt hizali
        }
        cur = sc;
    }
    u32 state_off = cur;
    u32 nstate = (u32)encstr.size();          // 0.8.1: state KOPYA basina PAYLASILIR
                                              // (eski: site basina — ayni stringi
                                              // kullanan 2. fonksiyon TEKRAR
                                              // cozecek ve stringi bozacakti)
    // 0.5.0: IAT cache hucreleri (thunk basina isaretci genisligi)
    u32 psz = pe.is64 ? 8 : 4;
    u32 cache_off = state_off + nstate;
    std::vector<u32> cache_rvas;
    for (size_t q = 0; q < thunk_slots.size(); q++)
        cache_rvas.push_back(newva_guess + cache_off + (u32)q * psz);

    // --- 0.8.1 yamalari: strRva(kopya) + state RVA + bytecode .rdata ref siteleri ---
    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: plain yok
        // (a) STRDEC strRva -> sifreli kopya RVA
        for (auto& ds : c.dec_sites) {
            auto it2 = str_copy.find(ds.second);
            if (it2 == str_copy.end()) continue;   // kopya yoksa yerinde kalsin (plain)
            u32 cs = it2->second;
            u32 at = ds.first;
            for (int k = 0; k < 4; k++) c.plain[at + k] = (u8)(cs >> (8 * k));
        }
        // (b) state RVA -> kopyanin PAYLASILAN state byte'i
        for (size_t i = 0; i < c.state_sites.size(); i++) {
            u32 stva = newva_guess + state_off + str_state_idx[c.state_strva[i]];
            u32 at = c.state_sites[i];
            for (int k = 0; k < 4; k++) c.plain[at + k] = (u8)(stva >> (8 * k));
        }
        // (c) lifter .rdata ref siteleri -> kopyaya yonlendir (string-ici delta korunur;
        //     string disi .rdata verisi — tablo vb — DOKUNULMAZ)
        for (auto& st2 : c.v.str_sites) {
            const RStr* sp = 0;
            for (auto& s2 : encstr)
                if (st2.second >= s2.rva && st2.second < s2.rva + s2.len) { sp = &s2; break; }
            if (!sp) continue;
            u32 cs = str_copy[sp->rva] + (st2.second - sp->rva);
            u32 at = st2.first + c.prefix_len;
            if ((u64)at + 4 > c.plain.size()) continue;
            for (int k = 0; k < 4; k++) c.plain[at + k] = (u8)(cs >> (8 * k));
        }
    }

    // --- sifrele ---
    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: sifreleme yok (native kod)
        u64 key = 0;
        if (opt.vmenc) {
            key = ((u64)(u32)(c.f->rva * 2654435761u + 0x9E3779B9u) << 32)
                | (u32)((u32)c.plain.size() * 0x2545F491u + 1u) | 1ull;
        }
        c.key = key;
        c.enc.resize(c.plain.size());
        {
            /* 0.8.0 crypt_command: CFB geribesleme — enc[i], enc[i-1]'e
               bagli (vm_core sf8 ile birebir ayni VM_KSC). */
            u8 prev = 0;
            /* 1.2.0-B1: decoder anahtar = (stub tasiyan) ^ K2 ^ VM_VMK(vm_id).
               Encoder ayni etkin anahtari kullanir: base ^ VM_VMK(vm_id).
               vm_id=0 -> VM_VMK=0 -> 1.1.0 davranisi bayt-bayt. */
            u64 ekey = key ^ VM_VMK(c.vm_id);
            /* 1.2.0-B1 vtAdvanced: VM_KSCA (4-byte periyot ailesi) — decoder
               scratch[5] ile ayni secimi yapar. */
            for (size_t i = 0; i < c.plain.size(); i++) {
                c.enc[i] = (u8)(c.plain[i] ^ (opt.vm_adv
                    ? VM_KSCA(ekey, prev, (u32)i)
                    : VM_KSC(ekey, prev, (u32)i)));
                prev = c.enc[i];
            }
        }
    }

    // --- section goruntusunu kur ---
    std::vector<u8> secimg;
    secimg.insert(secimg.end(), blob, blob + blob_len);
    // 0.5.0: xrt blob (kod) — self-CRC bu bolgeyi kapsar (cfg haric)
    if (rt_blob) {
        secimg.resize(xrt_code_off, 0);
        const u8* xblob = pe.is64 ? XRT_BLOB64 : XRT_BLOBX86;
        secimg.insert(secimg.end(), xblob, xblob + xrt_len);
        secimg.resize(cfg_off + XCFG_SIZE_E, 0);   // cfg (0.6.1: 0x48 — 0x40 rezervi bc ezdi!)
        if (vf_area)   // 1.2.2-A16: XVF1 blogu — cfg'den hemen sonra (LSD oncesi)
            secimg.insert(secimg.end(), vf_block.begin(), vf_block.end());
    }
    while (secimg.size() < (size_t)state_off - (nstate ? 0 : 0)) secimg.push_back(0);
    secimg.resize(cache_off + (u32)thunk_slots.size() * psz, 0);
    // --- 0.8.1: sifreli string kopyalari DISKTE (STRDEC ilk erisimde yerinde
    //     cozer; keystream = (u8)(k2 + i*31) — vm_core OP_STRDEC ile birebir) ---
    for (auto& s : encstr) {
        u32 cs = str_copy[s.rva];
        u32 k2 = (s.rva * 2654435761u) | 1u;
        u32 so = cs - newva_guess;
        bool oko = false;
        u32 praw = pe.rva2raw(s.rva, &oko);
        if (!oko || (u64)praw + s.len > pe.buf.size()) continue;
        for (u32 i = 0; i < s.len; i++)
            secimg[so + i] = (u8)(pe.buf[praw + i] ^ (u8)(k2 + i * 31));
    }
    // 0.7.0: LSD (lisans sedeti) — cfg'nin hemen sonrasi
    if (lsd_area) {
        size_t lsd_off = (size_t)(lsd_rva - newva_guess);
        if (secimg.size() < lsd_off + LSD_SIZE_E + LSD_CACHE_E)
            secimg.resize(lsd_off + LSD_SIZE_E + LSD_CACHE_E, 0);
        lsd.assign(LSD_SIZE_E, 0);
        lsd[0] = 'X'; lsd[1] = 'L'; lsd[2] = 'S'; lsd[3] = 'D'; lsd[4] = 1;
        if (!opt.lic_pubkey.empty()) {
            for (u32 i = 0; i < 256; i++)
                lsd[0x08 + i] = (u8)std::stoul(opt.lic_pubkey.substr(i * 2, 2), nullptr, 16);
            for (u32 i = 0; i < 8; i++)
                lsd[0x110 + i] = (u8)std::stoul(opt.lic_prodcode.substr(i * 2, 2), nullptr, 16);
            lsd[0x108] = 0x01; lsd[0x109] = 0x00; lsd[0x10A] = 0x01; lsd[0x10B] = 0x00;  // e=65537
        }
        u32 bd = opt.lic_builddate ? opt.lic_builddate : 0x07EA0B09u; /* 2026-11-09 */
        lsd[0x10C] = (u8)bd; lsd[0x10D] = (u8)(bd >> 8);
        lsd[0x10E] = (u8)(bd >> 16); lsd[0x10F] = (u8)(bd >> 24);
        if (!opt.lic_watermark.empty()) {
            u64 w = 0xCBF29CE484222325ull;
            for (size_t wi = 0; wi < opt.lic_watermark.size(); wi++) {
                w ^= (u64)(u8)opt.lic_watermark[wi];
                w *= 0x100000001B3ull;
            }
            for (int wi = 0; wi < 8; wi++) lsd[0x118 + wi] = (u8)(w >> (8 * wi));
            /* 1.1.0-A7: watermark METNI gomulu (UO cpIncludeWatermark 1:1:
               sizinti izleme — korunan dosyada metin okunur bulunur).
               LSD_CRC (0x000..0x11F) DISINDA — runtime etkisi yok. */
            u32 wl = (u32)opt.lic_watermark.size();
            if (wl > 64) wl = 64;
            for (u32 wi = 0; wi < wl; wi++) lsd[0x130 + wi] = (u8)opt.lic_watermark[wi];
            lsd[0x12C] = (u8)wl;
            lsd[0x12D] = (u8)(wl >> 8);
        }
        /* 0.7.0-final FIX: CRC SADECE 0x000..0x11F (LSD_CRC_LEN) — state(0x120)
           /tick(0x124) runtime-yazılabilir; CRC'ye dahil edilirse ilk SetSerial
           CRC'yi bozup tüm lisans API'lerini CORRUPTED'a düşürüyordu. */
        u32 lcrc = 0xFFFFFFFFu;
        for (u32 wi = 0; wi < 0x120; wi++) lcrc = xcrc_up(lcrc, lsd[wi]);
        lcrc = ~lcrc;
        lsd[0x128] = (u8)lcrc; lsd[0x129] = (u8)(lcrc >> 8);
        lsd[0x12A] = (u8)(lcrc >> 16); lsd[0x12B] = (u8)(lcrc >> 24);
        memcpy(&secimg[lsd_off], lsd.data(), LSD_SIZE_E);
        snprintf(b, sizeof b, "[LSD] lisans blok: modulus=%s urun=%s watermark=%s build_date=0x%X lsd_rva=0x%X",
                 opt.lic_pubkey.empty() ? "yok" : "256B",
                 opt.lic_prodcode.empty() ? "yok" : opt.lic_prodcode.c_str(),
                 opt.lic_watermark.empty() ? "yok" : "var", bd, lsd_rva);
        L(b);
    }
    for (auto& c : comps) {
        if (c.ty == 1) continue;              // M: bc/stub kopyasi yok
        u32 o = c.bc_rva - newva_guess;
        memcpy(&secimg[o], c.enc.data(), c.enc.size());
        u32 so = c.stub_rva - newva_guess;
        u32 vent = vent_guess;
        std::vector<u8> st;
        bool isreg2 = sdk_rva.count(c.f->rva) != 0;
        u32 cont2 = isreg2 ? (c.f->rva + c.f->size) : 0;
        if (pe.is64) st = build_stub_x64(c.stub_rva, vent, c.key, c.bc_rva, (u32)c.plain.size(),
                                         (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont2,
                                         c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
        else         st = build_stub_x86(c.stub_rva, vent, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm,
                                         (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont2,
                                         c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
        memcpy(&secimg[so], st.data(), st.size());
    }
    // 0.5.0: IAT thunklari (gecikmeli import cozumleyicileri)
    for (size_t q = 0; q < thunk_slots.size(); q++) {
        std::vector<u8> th = pe.is64
            ? build_thunk_x64(thunk_rvas[q], xrt_resolve_rva, cache_rvas[q],
                              thunk_slots[q].dll_hash, thunk_slots[q].name_hash, thunk_slots[q].iat_rva)
            : build_thunk_x86(thunk_rvas[q], xrt_resolve_rva, cache_rvas[q],
                              thunk_slots[q].dll_hash, thunk_slots[q].name_hash, thunk_slots[q].iat_rva);
        std::vector<u8> probe2 = pe.is64 ? build_thunk_x64(0, 0, 0, 0, 0, 0) : build_thunk_x86(0, 0, 0, 0, 0, 0);
        u32 expected = (u32)probe2.size();
        if (th.size() != expected) {
            snprintf(b, sizeof b, "[HATA] IAT thunk boyut %zu != %u (yerlesim bozulur)", th.size(), expected);
            L(b); return 1;
        }
        u32 o = thunk_rvas[q] - newva_guess;
        memcpy(&secimg[o], th.data(), th.size());
    }
    // mutasyon bloklari: GERCEK base_rva ile yeniden uret (deterministik LCG
    // ayni seed'i verir; boyutlar bayt bayt eslesmeli)
    for (auto& c : comps) if (c.ty == 1) {
        bool okraw2; u32 raw2 = pe.rva2raw(c.f->rva, &okraw2);
        if (!okraw2) { L("[HATA] mutasyon yeniden uretim raw yok"); return 1; }
        // 0.4.3 FIX (kullanici x4: Mutation ciktisi V ile ayni cikiyordu):
        // ikinci geciste allow_call YANLISLIKLA pe.is64 yollaniyordu — x86'da
        // (is64=false) yeniden-uretim "call desteklenmiyor" diyerek dusuyor,
        // olcum gecisi ise true ile govde uretip tutarsizlik tetikliyor ->
        // [HATA] + rc=1 -> CIKTI DOSYASI HIC YAZILMIYOR. GUI eski V ciktisini
        // diskte birakip kullanici onu "mutation" saniyor (uc dosyadan ikisi
        // bayt-bayt ayni). Olcum gecisiyle AYNI parametre: allow_call=true
        // (0.4.1 x86 rel32 dis-cagri fixup'i destekliyor).
        MutFn m2 = mutate_function(&pe.buf[raw2], c.f->rva, c.f->size, pe.is64,
                                   pe.imagebase, pe.sizeofimage, true,
                                   opt.mut_strength, c.f->rva ^ 0x9E3779B9u,
                                   c.mut_rva /* GERCEK base */,
                                   sdk_rva.count(c.f->rva) != 0 /* 0.5.1: yalniz SDK bolgesi */,
                                   prolog_of.count(c.f->rva) ? prolog_of[c.f->rva] : 0);
        if (!m2.ok || m2.code.size() != c.mut.code.size()) {
            { FILE* f1 = fopen("/tmp/mutpass1.bin","wb"); if(f1){fwrite(c.mut.code.data(),1,c.mut.code.size(),f1);fclose(f1);} FILE* f2 = fopen("/tmp/mutpass2.bin","wb"); if(f2){fwrite(m2.code.data(),1,m2.code.size(),f2);fclose(f2);} L("[HATA] mutasyon tutarsiz: " + c.f->name + " neden=" + m2.why + " " + std::to_string(m2.code.size()) + " vs " + std::to_string(c.mut.code.size())); return 1; }
        }
        u32 o = c.mut_rva - newva_guess;
        memcpy(&secimg[o], m2.code.data(), m2.code.size());
        // 0.5.0: runtime kapisini govde onune yaz (pushad/pushaq korumali)
        if (rt_any) {
            std::vector<u8> g = pe.is64
                ? build_mgate_x64(c.mut_gate_rva, xrt_entry_rva, cfg_rva, c.mut_rva)
                : build_mgate_x86(c.mut_gate_rva, xrt_entry_rva, cfg_rva, c.mut_rva);
            u32 go = c.mut_gate_rva - newva_guess;
            memcpy(&secimg[go], g.data(), g.size());
        }
    }
    // state baytlari 0 (VM ilk calismada 1 yapar)

    int sehm = 2;
    if (getenv("XPROTECT_NOSEH")) sehm = 0;
    u32 seh_unw_rva = 0, seh_unw_cnt = 0;
    // ============================================================
    // 0.8.0 SEH — DİNAMİK UNWIND KAYDI (wine-güvenli tasarım)
    // Ölçüldü (3-modlu bisection): dd[3]'ü bayt-özdeş kopyaya repoint
    // etmek wine'da C++ istisna dağıtımını BOZUYOR (0xC0000005);
    // .vmpx bölümü eklemek zararsız ama gereksiz. Bu yüzden dd[3]'e ve
    // .pdata/.xdata'ya DOKUNULMAZ. Bunun yerine .vmp0 sonuna
    // [tablo][info blokları] yazılır; xrt_entry İLK kapıda
    // ntdll!RtlAddFunctionTable ile dinamik kaydeder (JIT/VMProtect
    // runtime modeli). Kayıtlar:
    //   - M gövdesi: SADIK info (mutator yığın-ayar haritasından:
    //     push reg -> UWOP_PUSH_NONVOL, sub rsp -> UWOP_ALLOC_*)
    //   - M kapısı: MININFO (yaprak-varsayım; kapı dengeli push/pop)
    //   - tramp stub: STUBINFO (15 push+sub 0x330 = tek ALLOC_LARGE
    //     0x3A8; tam RSP yürüyüşü, 4-bit slot sınırına takılmadan)
    // ============================================================
    if (pe.is64 && rt_blob && sehm >= 2) {
        struct URec { u32 beg, end; std::vector<u8> info; };
        std::vector<URec> urecs;
        static const u8 MININFO[4]  = { 0x01, 0x00, 0x00, 0x00 };
        static const u8 STUBINFO[8] = { 0x01, 0x21, 0x20, 0x00, 0x1A, 0x01, 0x75, 0x00 };
        for (auto& c : comps) {
            if (c.ty == 1) {
                std::vector<u8> ib;
                int slots = 0;
                bool enc = c.mut.uw_ok && !c.mut.uw.empty()
                           && c.mut.prolog_out > 0 && c.mut.prolog_out <= 255;
                if (enc) for (auto& u2 : c.mut.uw) {
                    if (u2.off > 255) { enc = false; break; }
                    if (u2.kind == 0) slots += 1;
                    else {
                        u32 v = u2.val;
                        if (v % 8) { enc = false; break; }
                        slots += (v / 8 <= 15) ? 1 : (v / 8 <= 255 ? 2 : 3);
                    }
                    if (slots > 15) { enc = false; break; }
                }
                if (enc) {
                    ib.assign(4, 0);
                    ib[0] = 0x01;
                    ib[1] = (u8)c.mut.prolog_out;
                    ib[2] = (u8)(slots << 4);
                    for (auto& u2 : c.mut.uw) {
                        ib.push_back((u8)u2.off);
                        if (u2.kind == 0) ib.push_back((u8)(u2.reg << 4));  // PUSH_NONVOL
                        else {
                            u32 v = u2.val, q = v / 8;
                            if (q <= 15) ib.push_back((u8)((q << 4) | 2));  // ALLOC_SMALL
                            else if (q <= 255) { ib.push_back(0x01);         // ALLOC_LARGE i0
                                                 ib.push_back((u8)q); ib.push_back((u8)(q >> 8)); }
                            else { ib.push_back(0x11);                       // ALLOC_LARGE i1
                                   ib.push_back((u8)v); ib.push_back((u8)(v >> 8));
                                   ib.push_back((u8)(v >> 16)); ib.push_back((u8)(v >> 24)); }
                        }
                    }
                    while (ib.size() % 4) ib.push_back(0);
                }
                if (ib.empty()) ib.assign(MININFO, MININFO + 4);
                URec r; r.beg = c.mut_rva; r.end = c.mut_rva + (u32)c.mut.code.size();
                r.info = ib; urecs.push_back(r);
                if (rt_any && c.mut_gate_rva) {
                    std::vector<u8> g = build_mgate_x64(c.mut_gate_rva, xrt_entry_rva, cfg_rva, c.mut_rva);
                    URec g2; g2.beg = c.mut_gate_rva; g2.end = c.mut_gate_rva + (u32)g.size();
                    g2.info.assign(MININFO, MININFO + 4); urecs.push_back(g2);
                }
            } else if (c.tramp) {
                URec r; r.beg = c.stub_rva; r.end = c.stub_rva + c.stub_len;
                r.info.assign(STUBINFO, STUBINFO + 8); urecs.push_back(r);
            }
        }
        std::sort(urecs.begin(), urecs.end(),
                  [](const URec& a, const URec& b2) { return a.beg < b2.beg; });
        for (size_t i = 0; i + 1 < urecs.size(); i++)
            if (urecs[i].end > urecs[i + 1].beg) urecs[i].end = urecs[i + 1].beg;
        u32 tbl_off = ((u32)secimg.size() + 15) & ~15u;
        u32 info_off = tbl_off + (u32)urecs.size() * 12;
        u32 need = info_off;
        for (auto& r : urecs) need += (u32)r.info.size();
        if ((u32)secimg.size() < need) secimg.resize(need, 0);
        u32 tbl_rva = newva_guess + tbl_off;
        for (size_t i = 0; i < urecs.size(); i++) {
            wrv32(secimg, tbl_off + (u32)i * 12 + 0, urecs[i].beg);
            wrv32(secimg, tbl_off + (u32)i * 12 + 4, urecs[i].end);
            wrv32(secimg, tbl_off + (u32)i * 12 + 8, newva_guess + info_off);
            memcpy(&secimg[info_off], urecs[i].info.data(), urecs[i].info.size());
            info_off += (u32)urecs[i].info.size();
        }
        wrv32(secimg, cfg_off + 0x44, tbl_rva);        // XCFG_OFF_UNWRVA
        wrv32(secimg, cfg_off + 0x48, (u32)urecs.size()); // XCFG_OFF_UNWCNT
        seh_unw_rva = tbl_rva; seh_unw_cnt = (u32)urecs.size();
        snprintf(b, sizeof b, "[SEH] dinamik unwind: kayit=%u tabloRVA=0x%06X (xrt ilk kapida RtlAddFunctionTable)",
                 (u32)urecs.size(), tbl_rva);
        L(b);
    }

    u32 vmp_rva = 0;
    u32 chars = 0xE0000060u;   // CNT_CODE|MEM_EXEC|MEM_READ|MEM_WRITE
    /* 1.2.2-A11-v3 KANITLI TASARIM: memprot YALIN kipte (CRC yok — cfg
       state yazisi olmayacak) .vmp0 LOADER seviyesinde EXECUTE_READ map
       edilir (0x60000020) — kullanici raporundaki "jmp'in gotturdugu yer"
       (.vmp0 stub) korumasi DISK-seviyesinden baslar. Kanit: loader-RX
       .vmp0 + memprot = VM dogru hesap (sdk_v=5142, rc=42); .vmp0 RWX +
       memprot = VM bozuk (rc=1, t42+memp birebir reprodüksiyon).
       CRC kipinde .vmp0 yazilabilir kalir (cfg state yazisi calisir). */
    if (opt.memprot && !opt.rt_selfcrc && !opt.rt_textcrc && !opt.rt_filecrc)
        chars = 0x60000020u;   // CNT_CODE|MEM_EXEC|MEM_READ (yazma YOK)
    /* 1.2.0-B5 cpDebugMode: INT3 dolumu BOLGE-KALANINDA zaten uygulanir
       (yerinde-stub yolu: govde kalan = 0xCC; tramp yolu: bolge junk = 0xCC)
       — debugger korumali bolgeye duserse trap. .vmp0 ic-dolumu YAPILMAZ:
       cfg'nin sifir-alanlari canlidir; tam-dolum onlari ezer (rc=1 kaniti,
       ilk-denemede state byte 0xCC olmustu). debugmode bayragi log'a islenir. */
    if (opt.debugmode)
        log.push_back("[DEBUGMODE] INT3 dolumu aktif: bolge-kalanlari 0xCC (govde + tramp junk)");

    // ============================================================
    // 1.2.2-A13: WATERMARK GOMME — UO processors.cc BaseFunction::AddWatermark 1:1
    // Her derleme IC surum watermark'i gomulur (UO version_watermark davranisi);
    // cpIncludeWatermark isaretliyse kullanici watermarklari (wm_values) da.
    // Kopya sayisi: UO il.cc:4667 — runtime katmanli: 8, yalin: 10.
    // Yerlesim: .vmp0 sonunda slotlu alan (slot = dump+16, slot ici rastgele
    // kayma) — her kopya WM.Compile() ile YENIDEN uretilir (jokerler
    // kopya-basina farkli). FileCRC .vmp0'i zaten atlar (tasma derdi yok).
    // ============================================================
    {
        std::vector<std::string> wms;
        wms.push_back(WM_VERSION_VALUE);
        if (!opt.wm_values.empty())
            for (auto& v : opt.wm_values) if (!v.empty()) wms.push_back(v);
        const u32 wm_copies = rt_blob ? 8u : 10u;   // UO: ctx.runtime ? 8 : 10
        u32 wm_base = ((u32)secimg.size() + 15) & ~15u;
        u32 wm_area = 0;
        struct WmPlan { std::vector<u8> dump; u32 off; size_t wi; };
        std::vector<WmPlan> wm_plan;
        for (size_t wi = 0; wi < wms.size(); wi++) {
            std::vector<u8> dump, mask;
            wm_compile(wms[wi], dump, mask);
            if (dump.empty()) continue;
            for (u32 i = 0; i < wm_copies; i++) {
                std::vector<u8> d2, m2;             // her kopya taze derleme (jokerler yeniden)
                wm_compile(wms[wi], d2, m2);
                wm_plan.push_back({ d2, wm_base + wm_area, wi });
                wm_area += (u32)d2.size() + 16;     // slot: dump + 16B aylik
            }
        }
        if (!wm_plan.empty()) {
            u32 need = wm_base + wm_area;
            if ((u32)secimg.size() < need) secimg.resize(need, 0);
            for (auto& pr : wm_plan) {
                u32 jit = (u32)(rand() & 15);       // slot ici rastgele kayma (ayri kopya gorunumu)
                memcpy(&secimg[pr.off + jit], pr.dump.data(), pr.dump.size());
            }
            u32 n_us = 0;
            for (auto& pr : wm_plan) if (pr.wi > 0) n_us++;
            snprintf(b, sizeof b, "[WM] watermark alanı: .vmp0+0x%X (%uB) | sürüm imzası: %u kopya | kullanıcı: %u kopya (%zu watermark)",
                     wm_base, wm_area, wm_copies, n_us, wms.size() - 1);
            L(b);
            for (size_t wi = 1; wi < wms.size(); wi++) {
                snprintf(b, sizeof b, "[WM] kullanıcı watermark[%zu]: value=%s (%u kopya)", wi, wms[wi].c_str(), wm_copies);
                L(b);
            }
        }
    }

    if (!pe.add_section(".vmp0", secimg, chars, vmp_rva)) { L("[HATA] section eklenemedi"); return 1; }
    snprintf(b, sizeof b, "[SECTION] .vmp0 RVA=0x%06X boyut=0x%06X | VM blob %dB | vm_entry RVA=0x%06X",
             vmp_rva, (u32)secimg.size(), blob_len, vmp_rva + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF));
    L(b);
    if (vmp_rva != newva_guess) L("[UYARI] section RVA beklentiyle farkli!");

    // --- .text yamalama ---
    for (auto& c : comps) {
        FnInfo& f = *c.f;
        bool okraw; u32 raw = pe.rva2raw(f.rva, &okraw);
        if (!okraw) { f.note += " | yama raw yok"; continue; }
        if (c.ty == 1) {
            // MUTASYON: giris kapisi E9 -> .vmp0'taki (runtime kapisi +)
            // mutasyonlu govde. Govde native x86/x64 kodu olarak calisir
            // (VM YOK, tam hiz); rt aciksa once bir-kez butunluk kontrolu.
            i32 rel = (i32)((rt_any ? c.mut_gate_rva : c.mut_rva) - (f.rva + 5));
            u8 j[5] = { 0xE9, (u8)(u32)rel, (u8)((u32)rel >> 8), (u8)((u32)rel >> 16), (u8)((u32)rel >> 24) };
            memcpy(&pe.buf[raw], j, 5);
            for (u32 i = 5; i < f.size; i++) pe.buf[raw + i] = 0xCC;
            f.virtualized = true;
            snprintf(b, sizeof b, "[MUT] %s @RVA=0x%06X boyut=0x%X | ikame=%u junk=%u kapi=%u (blok=%u) | %uB->%uB (x%.2f) | govde=0x%06X",
                     f.name.c_str(), f.rva, f.size,
                     c.mut.st.subst, c.mut.st.junk, c.mut.st.gates, c.mut.st.nblocks,
                     c.mut.st.orig_bytes, c.mut.st.new_bytes,
                     c.mut.st.orig_bytes ? (double)c.mut.st.new_bytes / (double)c.mut.st.orig_bytes : 0.0,
                     c.mut_rva);
            L(b);
            for (auto& n : c.mut.notes) L(n);
            continue;
        }
        if (c.tramp) {
            i32 rel = (i32)(c.stub_rva - (f.rva + 5));
            u8 j[5] = { 0xE9, (u8)(u32)rel, (u8)((u32)rel >> 8), (u8)((u32)rel >> 16), (u8)((u32)rel >> 24) };
            memcpy(&pe.buf[raw], j, 5);
            for (u32 i = 5; i < f.size; i++) pe.buf[raw + i] = 0xCC;
        } else {
            // YERINDE stub: stub_rva = fonksiyonun kendi RVA'si olacak sekilde uret
            u32 vent = vmp_rva + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF);
            std::vector<u8> st;
            bool isreg3 = sdk_rva.count(f.rva) != 0;
            u32 cont3 = isreg3 ? (f.rva + f.size) : 0;
            if (pe.is64) st = build_stub_x64(f.rva, vent, c.key, c.bc_rva, (u32)c.plain.size(),
                                             (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont3,
                                             c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
            else         st = build_stub_x86(f.rva, vent, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm,
                                             (rt_any || vf_area) ? xrt_entry_rva : 0, (rt_any || vf_area) ? cfg_rva : 0, cont3,
                                             c.perm_seed, c.vm_id, opt.vm_adv ? 1 : 0, opt.vmregs ? 1 : 0);
            memcpy(&pe.buf[raw], st.data(), st.size());
            for (u32 i = (u32)st.size(); i < f.size; i++) pe.buf[raw + i] = 0xCC;
        }
        f.virtualized = true;
        snprintf(b, sizeof b, "[YAMA] %s @RVA=0x%06X boyut=0x%X | bc=%uB key=0x%llX | stubRVA=0x%06X retimm=%u %s",
                 f.name.c_str(), f.rva, f.size, (u32)c.enc.size(),
                 (unsigned long long)c.key, c.stub_rva, c.v.retimm,
                 c.tramp ? "(trampoline)" : "(yerinde)");
        L(b);
        if (c.ty == 2 && c.mut.ok) {
            snprintf(b, sizeof b, "  [ULTRA] on-mutasyon: ikame=%u junk=%u kapi=%u | %uB->%uB (x%.2f)",
                     c.mut.st.subst, c.mut.st.junk, c.mut.st.gates,
                     c.mut.st.orig_bytes, c.mut.st.new_bytes,
                     c.mut.st.orig_bytes ? (double)c.mut.st.new_bytes / (double)c.mut.st.orig_bytes : 0.0);
            L(b);
        }
        for (auto& n : c.v.notes) L(n);
    }

    // --- BUGFIX #13: ezilen bolgelerin eski reloc girdilerini temizle ---
    // Yerinde stub + trampoline .text yamasi fonksiyonun TUM govdesini
    // eziyor (stub + int3). Orijinal koda ait HIGHLOW girdileri bu
    // baytlarin uzerinde kalirsa gercek Windows ASLR (DYNAMICBASE) loader
    // tarafindan +delta ile yamalanir -> stub immediateleri (VM anahtari!)
    // ve E9 rel32 bozulur -> ilk VM cagrisinda cokme. Wine preferred-base
    // yukledigi icin (delta=0) bu hata wine'da gorunmezdi.
    {
        std::vector<std::pair<u32,u32>> ranges;
        for (auto& c : comps)
            if (c.f->virtualized) ranges.push_back({ c.f->rva, c.f->size });
        u32 removed = 0; std::string rnote;
        if (pe.filter_relocs(ranges, removed, rnote)) L("[RELOC] " + rnote);
        else L("[HATA] reloc filtreleme: " + rnote);
    }

    // --- secenek bayraklari ---
    // 0.8.1 NOT: .rdata artik YAZILABILIR yapilmaz — strenc kopyalari .vmp0
    // icinde cozulur, orijinal .rdata'ya runtime yazma YOKTU. Read-only
    // kalmasi korumayi guclendirir (eski in-place cozum flag'i kaldirildi).
    if (opt.memprot && text) {
        u32 fh = pe.e_lfanew + 4;
        u16 optsize = 0; memcpy(&optsize, &pe.buf[fh + 16], 2);
        u32 sh = fh + 20 + optsize;
        for (u32 i = 0; i < pe.secs.size(); i++) {
            u32 o = sh + i * 40;
            char nm[9]; memcpy(nm, &pe.buf[o], 8); nm[8] = 0;
            if (opt.memprot && strcmp(nm, ".text") == 0) {
                u32 ch = text->chars & ~0x80000000u;   // WRITE kaldir -> EXECUTE_READ
                memcpy(&pe.buf[o + 36], &ch, 4);
                snprintf(b, sizeof b, "[MEMPROT] .text Chars=0x%08X (yazilamaz)", ch);
                L(b);
            }
            if (opt.memprot && strcmp(nm, ".vmp0") == 0) {
                /* 1.2.2-A11: dosyada yazilabilir; runtime ilk VM cagrisinda
                   EXECUTE_READ'e kucler (VEH yazma-guvesi ile birlikte) */
                u32 ch = 0; memcpy(&ch, &pe.buf[o + 36], 4);
                snprintf(b, sizeof b, "[MEMPROT] .vmp0 Chars=0x%08X %s",
                         ch, (ch & 0x80000000u) ? "(CRC kipi: yazilabilir, VEH kurulu)"
                                                : "(yazilamaz — jmp hedefi korumali; VEH kurulu)");
                L(b);
            }
        }
    }

    // ============================================================
    // 0.5.0/0.6.0 — XRT butunlik degerleri + paketleme (SIRA KRITIK):
    //   1) reloc dizini + self CRC + text CRC  -> PRE-PACK .text baytlari
    //      (runtime acilmis bellek uzerinden hesaplar; sikistirilmis
    //       dosya uzerinden hesaplansaydi hicbir zaman eslesmezdi)
    //   2) 0.6.0 cpPack + cpStripFixups + cpStripDebugInfo
    //      (dosya compaction: file CRC'nin final dosya uzerinden
    //       hesaplanmasi icin cfg yazimindan once olmali)
    //   3) file CRC (final dosya) + cfg yazimi (0x48: pack_rva dahil)
    // NOT: add_section push_back secs vector'unu realloc eder -> pack
    // sonrasi text/rdata isaretcileri secbyname ile TAZELENIR.
    // ============================================================
    u32 xr_reloc_rva = 0, xr_reloc_sz = 0;
    u32 xr_self_len = 0, xr_sc = 0, xr_tc = 0;
    if (rt_any) {
        u32 ddoff = pe.is64 ? 112 : 96;
        memcpy(&xr_reloc_rva, &pe.buf[pe.e_lfanew + 24 + ddoff + 40], 4);
        memcpy(&xr_reloc_sz,  &pe.buf[pe.e_lfanew + 24 + ddoff + 44], 4);
        // --- 0.7.0 FIX ("butunluk kontrolu kod = #2") ----------------------
        // cpStripFixups .reloc'u SILIYOR (veri memset-0 + dizin 0/0 + ASLR
        // bayraklari temiz). Strip sonrasi yukleyici delta UYGULAMAZ; fakat
        // cfg'ye strip-ONCESI rva/sz yaziliyordu: runtime silinmis (sifir)
        // tabloyu okuyup bsz<8 ile HICBIR bayti atlamaz, derleme-tarzi ise
        // ESKI tablo ile yamali baytlari atliyordu -> iki CRC farkli ->
        // xrt_entry err=2 (metin2 D7610 U+loadercrc+stripfixups kaniti:
        // saklanan 0x01ED0622 != runtime 0x42E27385). Cozum: strip varsa
        // iki taraf da ATLAMASIZ duz bayt CRC'si kullanir (cfg'ye 0/0).
        if (opt.strip_fixups) { xr_reloc_rva = 0; xr_reloc_sz = 0; }
        // --- self CRC: vm blob + xrt kodu (cfg haric) ---
        xr_self_len = xrt_code_off + xrt_len;
        u32 c = 0xFFFFFFFFu;
        for (u32 i = 0; i < xr_self_len && i < secimg.size(); i++) c = xcrc_up(c, secimg[i]);
        xr_sc = ~c;
        // --- text CRC: sayfa sayfa, reloc yamalarini atlayarak (PRE-PACK) ---
        if (text && text->vsz) {
            bool okt; u32 traw = pe.rva2raw(text->va, &okt);
            const u8* rraw = 0;
            if (xr_reloc_rva && xr_reloc_sz) {
                bool okr; u32 rr = pe.rva2raw(xr_reloc_rva, &okr);
                if (okr && rr + xr_reloc_sz <= pe.buf.size()) rraw = &pe.buf[rr];
            }
            u32 c2 = 0xFFFFFFFFu;
            u8 flag[4096 + 16];
            for (u32 pg = 0; pg < text->vsz; pg += 0x1000) {
                u32 pgrva = text->va + pg;
                u32 plen = (text->vsz - pg < 0x1000) ? (text->vsz - pg) : 0x1000;
                for (u32 i = 0; i < plen + 8 && i < sizeof flag; i++) flag[i] = 0;
                if (rraw) {
                    u32 ro = 0;
                    while (ro + 8 <= xr_reloc_sz) {
                        u32 page_rva; memcpy(&page_rva, rraw + ro, 4);
                        u32 bsz;     memcpy(&bsz, rraw + ro + 4, 4);
                        if (bsz < 8 || ro + bsz > xr_reloc_sz) break;
                        if (page_rva == pgrva) {
                            for (u32 eo = 8; eo + 2 <= bsz; eo += 2) {
                                u16 e; memcpy(&e, rraw + ro + eo, 2);
                                u32 typ = (u32)(e >> 12);
                                u32 off = (u32)(e & 0xFFF);
                                u32 len = (typ == 3) ? 4 : (typ == 10 ? 8 : 0);
                                if (len && off < plen + 8)
                                    for (u32 i = 0; i < len && off + i < sizeof flag; i++)
                                        flag[off + i] = 1;
                            }
                        }
                        ro += bsz;
                    }
                }
                for (u32 i = 0; i < plen; i++) {
                    if (flag[i]) continue;
                    // 0.5.0 DUZELTME: ham-boyut kelepcesi — vsz > rawsz
                    // oldugunda yuklenen goruntude sonrasi SIFIRDIR.
                    u8 by = 0;
                    u32 off = pg + i;
                    if (okt && off < text->rawsz && traw + off < pe.buf.size())
                        by = pe.buf[traw + off];
                    c2 = xcrc_up(c2, by);
                }
            }
            xr_tc = ~c2;
        }
    }

    // ---------------- 0.6.0: cpPack + strip ----------------
    // 0.8.0 SectionCryptor anahtarlari (oturum-gecici xorshift64*;
    // cfg'de XRC_KEYMASK ile maskeli yasilir — diskte acik anahtar yok)
    u64 sc_k0 = 0, sc_k1 = 0;
    u32 pack_rva = 0;
    if (opt.pack) {
        if (opt.sectcrypt) {
            u64 seed = (u64)time(nullptr) ^ (u64)(uintptr_t)&pe ^ ((u64)clock() << 24)
                     ^ 0x5854505354415254ULL;
            for (int i = 0; i < 8; i++) {
                seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
                u64 v = seed * 0x2545F4914F6CDD1DULL;
                if (i == 6) sc_k0 = v;
                if (i == 7) sc_k1 = v;
            }
            if (!sc_k0) sc_k0 = 0xD1B5A4A9ULL;   // tam-sifir anahtari engelle
        }
        std::string perr;
        int prc = do_pack(pe, cfg_rva, xrt_unpack_rva, log, pack_rva,
                          opt.sectcrypt ? 1u : 0u, sc_k0, sc_k1, perr,
                          opt.rsrcprot);
        if (prc != 0) {
            L(std::string("[HATA] PACK: ") + perr);
            L("[HATA] Paketleme tamamlanamadi — cikti dosyasi YAZILMADI.");
            return 4;
        }
    }
    if (opt.strip_fixups) strip_fixups(pe, log);
    if (opt.strip_debug)  strip_debug(pe, log);
    text = pe.secbyname(".text");   // add_section realloc -> tazele
    rdata = pe.secbyname(".rdata");

    if (rt_any || opt.pack || vf_area) {   /* 1.2.2-A16: VF da cfg yazar */
        // 0.6.0: pack-only derlemede bile cfg YAZILMALI (xrt_unpack cfg
        // okur; magic yoksa unpack hic calismaz -> .text sikisik kalir).
        // --- file CRC: FINAL dosya (CheckSum alani + .vmp0 ham araligi atla) ---
        u32 cksum_off = pe.e_lfanew + 24 + 64;   // OptionalHeader.CheckSum
        u32 vraw0 = 0, vraw1 = 0;
        {
            const Section* vs = pe.secbyname_c(".vmp0");
            if (vs) { vraw0 = vs->rawoff; vraw1 = vs->rawoff + vs->rawsz; }
        }
        u32 fc = 0xFFFFFFFFu;
        for (u32 i = 0; i < pe.buf.size(); i++) {
            if (i >= cksum_off && i < cksum_off + 4) continue;
            if (i >= vraw0 && i < vraw1) continue;
            fc = xcrc_up(fc, pe.buf[i]);
        }
        fc = ~fc;
        // --- cfg'yi pe.buf icine yaz (0.8.0: 0x60 — sectcrypt anahtarlari dahil) ---
        bool okc2; u32 cfg_raw = pe.rva2raw(cfg_rva, &okc2);
        if (!okc2 || cfg_raw + XCFG_SIZE_E > pe.buf.size()) {
            L("[HATA] XRT cfg yerlesimi raw yok"); return 1;
        }
        u8 cfg[XCFG_SIZE_E]; memset(cfg, 0, sizeof cfg);
        u32 fl = 0;
        if (opt.rt_selfcrc) fl |= 0x01;
        if (opt.rt_textcrc) fl |= 0x02;
        if (opt.rt_filecrc) fl |= 0x04;
        if (opt.rt_msg)     fl |= 0x08;
        if (opt.rt_exit)    fl |= 0x10;
        if (opt.memprot)    fl |= 0x20;   /* 1.2.2-A11: IC memory protection */
        if (vf_area)         fl |= 0x40;   /* 1.2.2-A16: Virtual Files tek-kurulum */
        auto cwr = [&](u32 off, u32 v) { memcpy(cfg + off, &v, 4); };
        cwr(0x00, 0x31545258u);                 // 'XRT1'
        cwr(0x04, fl);
        cwr(0x08, 0);                           // state: 0 (ilk cagrida kontrol)
        /* 1.2.2-A11: cfg[0x09] = memprot-VEH gate (0=wine-guvenli varsayilan;
           --mpveh ile 1 — gercek-Windows test anahtari; wine'da VEH kaydi
           VM akisini bozuyor — noop-handler bisect kaniti v5) */
        cwr(0x09, (opt.memprot && opt.mpveh) ? 0x01000000u : 0);   /* byte@0x09 */
        cwr(0x0C, vmp_rva);                     // self_rva (vm blob basi)
        cwr(0x10, xr_self_len);
        cwr(0x14, xr_sc);
        cwr(0x18, text ? text->va : 0);
        cwr(0x1C, text ? text->vsz : 0);
        cwr(0x20, xr_tc);
        cwr(0x24, xr_reloc_rva);
        cwr(0x28, xr_reloc_sz);
        cwr(0x2C, fc);
        cwr(0x30, vraw0);
        cwr(0x34, vraw1);
        cwr(0x38, cksum_off);
        cwr(0x3C, cfg_rva);
        cwr(0x40, pack_rva);                    // 0.6.0: XPK1 blok RVA (.vmp1)
        cwr(0x44, seh_unw_rva);                 // 0.8.0: dinamik unwind tablo RVA
        cwr(0x48, seh_unw_cnt);                 // 0.8.0: dinamik unwind kayit sayisi
        // 0.8.0 SectionCryptor: flag + maskeli anahtarlar (xr_cipher.h sozlesmesi)
        u8 scf = (opt.sectcrypt && pack_rva) ? 1 : 0;
        u64 kmask = XRC_KEYMASK(cfg_rva);
        u64 m0 = sc_k0 ^ kmask, m1 = sc_k1 ^ kmask;
        cwr(XRC_CFG_FLAG, scf);
        cwr(XRC_CFG_KEY0, (u32)m0); cwr(XRC_CFG_KEY0 + 4, (u32)(m0 >> 32));
        cwr(XRC_CFG_KEY1, (u32)m1); cwr(XRC_CFG_KEY1 + 4, (u32)(m1 >> 32));
        memcpy(&pe.buf[cfg_raw], cfg, XCFG_SIZE_E);
        // ---- 0.6.1 SAHTE-BASARI KORUMASI ----
        // cfg yazımı (0x48B) bytecode/stub uzerine tasmamali. 0.6.0'da
        // rezerv 0x40 kaldi: son 8B (pack_rva=0 + reserved=0) ilk bc'nin
        // ilk 8 baytını eziyordu (metin2 ULTRA+loaderCRC = sessiz no-op).
        // Yazım SONRASI enc baytlarını diskten doğrula — tasma varsa
        // cikti YAZILMAZ (0.5.1 sahte-başarı koruması geleneği).
        for (auto& c2 : comps) {
            if (c2.ty == 1) continue;
            if ((u32)c2.enc.size() < 16) continue;
            bool okv; u32 braw2 = pe.rva2raw(c2.bc_rva, &okv);
            if (!okv || braw2 + 16 > pe.buf.size()) continue;
            if (memcmp(&pe.buf[braw2], c2.enc.data(), 16) != 0) {
                L("[HATA] XRT cfg yazımı bytecode üzerine taştı (0.6.0 rezerv bug) — ÇIKTI YAZILMADI");
                L("[HATA] bc RVA=0x" + hex32(c2.bc_rva) + " ilk 16B ezildi. Rezerv XCFG_SIZE_E=0x48 olmalı.");
                return 5;
            }
        }
        snprintf(b, sizeof b,
                 "[XRT] runtime katmani: flags=0x%X | self=0x%08X (%uB) | text=0x%08X (0x%X, reloc-atla %uB) | file=0x%08X (atla: cksum+%u, .vmp0 %u..%u) | pack=0x%X",
                 fl, xr_sc, xr_self_len, xr_tc, text ? text->vsz : 0, xr_reloc_sz, fc,
                 cksum_off, vraw0, vraw1, pack_rva);
        L(b);
        L(std::string("[XRT] xrt_entry=0x") + hex32(xrt_entry_rva) + " cfg=0x" + hex32(cfg_rva) +
          " | her korumali giris BIR KEZ kontrol eder (state kilidi); hata: " +
          (opt.rt_msg ? "MessageBoxA + " : "") + (opt.rt_exit ? "ExitProcess" : "ud2 zehir"));
    } else if (opt.iat_prot) {
        L("[XRT] yalniz IAT korumasi: xrt_resolve gecikmeli cozumleyici yerlesti (cfg kullanilmaz)");
    }

    /* 0.5.1 SAHTE-BASARI KORUMASI: secili fonksiyonlarin HICBIRI
    uygulanamadiysa cikti dosyasi HIC YAZILMAZ (0.5.0 sessiz "korunmus"
    kopya yaziyordu). rc=3 -> GUI uyari kutusu + CLI net hata. */
    if (comps.empty() && !opt.pack && !opt.strip_fixups && !opt.strip_debug && !lic_any) {
        L("[HATA] HICBIR FONKSIYON UYGULANAMADI - cikti dosyasi YAZILMADI.");
        L("[HATA] Nedenler yukarida [RED] satirlarinda.");
        return 3;
    }
    pe.fix_checksum();
    if (!pe.save(out)) { L("[HATA] kaydedilemedi: " + out); return 1; }
    snprintf(b, sizeof b, "[KAYIT] %s (%zu bayt)", out.c_str(), pe.buf.size());
    L(b);
    L("[OZET] tipler: V=" + std::to_string(nV) + " M=" + std::to_string(nM) + " U=" + std::to_string(nU)
      + (nUf ? " (U->V dusus=" + std::to_string(nUf) + ")" : "")
      + " | vmn=" + std::to_string(opt.vmn) + (opt.vm_adv ? " ADV" : "")
      + " | antidebug=" + (opt.antidebug ? "ACIK" : "kapali")
      + " | resprot=" + (opt.rsrcprot ? "ACIK" : "kapali")
      + " | checkvm=" + (opt.checkvm ? "ACIK" : "kapali")
      + " | strenc=" + (opt.strenc ? "ACIK" : "kapali")
      + " | memprot=" + (opt.memprot ? "ACIK" : "kapali")
      + " | vmenc=" + (opt.vmenc ? "ACIK" : "KAPALI")
      + " | vmregs=" + (opt.vmregs ? "ACIK" : "KAPALI")
      + " | chkret=" + (opt.antidebug ? "ACIK" : "kapali")   /* 1.2.0-A8: donus-adresi int3 kontrolu */
      + " | mutasyon-gucu=" + std::to_string(opt.mut_strength)
      + " | runtime=" + (rt_any ? std::string("ACIK(self=") + (opt.rt_selfcrc ? "1" : "0")
          + ",text=" + (opt.rt_textcrc ? "1" : "0") + ",file=" + (opt.rt_filecrc ? "1" : "0") + ")" : "kapali")
      + " | iat=" + (opt.iat_prot ? "ACIK(" + std::to_string(thunk_slots.size()) + " thunk)" : "kapali")
      + " | sdk=" + (opt.sdk_scan ? "ACIK" : "kapali")
      + " | pack=" + (opt.pack ? (std::string("ACIK(LZMA, XPK1=0x") + hex32(pack_rva) + ")") : std::string("kapali"))
      + " | sectcrypt=" + (opt.pack ? (opt.sectcrypt ? "ACIK(CFB-64)" : "kapali") : "-")
      + " | stripfix=" + (opt.strip_fixups ? "ACIK" : "kapali")
      + " | stripdbg=" + (opt.strip_debug ? "ACIK" : "kapali"));
    return 0;
}
