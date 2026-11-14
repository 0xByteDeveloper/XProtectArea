// ============================================================
// xprotect_dotnet.cpp — .NET PE desteği (dotnetfile.cc portu)
// ============================================================
// UniversalObfuscator (VMProtect 3.5.1) core/dotnetfile.cc (12425 satır)
// zincirinin XProtect mimarisiyle portu. UO'nun 1:1 kopyası DEĞİLDİR;
// kavram-paritesi: CLR header + metadata (#~ tabloları) çözümü,
// TypeDef/MethodDef keşfi, IL gövde okuma, P/Invoke tanıma.
//
// Kapsam (v1, dürüst):
//  - CLR header (PE data-dizini 14) + IMAGE_COR20_HEADER
//  - Metadata root ("BSJB") + akış dizini (#~, #Strings, #US, #GUID, #Blob)
//  - Tablolar: Module(0x00) TypeRef(0x01) TypeDef(0x02) Field(0x04)
//    MethodDef(0x06) — HeapSizes ile string idx genişliği
//  - MethodDef satırı: RVA, ImplFlags, Flags, Name, ParamList
//    + SATIR DOSYA-OFSETLERİ (engine RVA/miNative yaması için — 1.2.3)
//  - MethodDef gövde okuma: tiny/fat header, locals-token, EH clauses
//  - P/Invoke tanıma (ImplFlags mdPinvokeImpl biti)
// UO'da bulunan ama v1'de olmayanlar (sonraki tur): ImplMap/MemberRef
// çözümleme (P/Invoke hedef adları), GenericParam, Property/Event,
// AssemblyRef, #US çözümleme, ILData token sistemi.
//
// MOTOR ENTEGRASYONU: fonksiyon keşfi (UI "Kaynak: DOTNET" sütunu) +
// engine_main'de seçili yöntemler xprotect_il.cpp IL->x86 derleyicisinden
// geçirilir; yerleşim sonrası MethodDef RVA'sı stub'a yamanır, ImplFlags
// miNative (1) yapılır (VMProtect .NET native-giriş semantiği).
// ============================================================
#include "xprotect_dotnet.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace xpdotnet {

static u32 rd16(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8); }
static u32 rd32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

// PE 'ş' çözümleme: satırlar/akışlar dosya-görünümü üzerinden okunur.
// UO'daki PESegmentList yaklaşımının yerine rva->fileoff tablosu.
struct Sec { u32 va, rawptr, rawsz, vsz; };

static bool pe_sections(const u8* d, size_t n, std::vector<Sec>* out, u32* data_dirs,
                        u32* num_dirs, bool* is64, u32* imagebase) {
    if (n < 0x40 || memcmp(d, "MZ", 2) != 0) return false;
    u32 e_lfanew = rd32(d + 0x3C);
    if (e_lfanew + 0x18 > n || memcmp(d + e_lfanew, "PE\0\0", 4) != 0) return false;
    u16 nsec = rd16(d + e_lfanew + 6);
    u16 opt_sz = rd16(d + e_lfanew + 20);  // SizeOfOptionalHeader (COFF alanı)
    u16 opt_h = rd16(d + e_lfanew + 24);   // OptionalHeader.Magic
    if (opt_h != 0x10B && opt_h != 0x20B) return false;
    *is64 = (opt_h == 0x20B);
    const u8* oh = d + e_lfanew + 24;
    /* 1.2.5 FIX (x/.NET kök-nedeni): PE spec (IMAGE_OPTIONAL_HEADER32/64):
       NumberOfRvaAndSizes — PE32: 0x5C, PE64: 0x6C; DataDirectory — PE32:
       0x60, PE64: 0x70. Eski kod ikisinde de 0x48/0x4C kullanıyordu (PE32'de
       0x48 = SizeOfStackReserve!) — GERÇEK csc/roslyn çıktılarında CLR
       dizini hiç bulunamıyor ("CLR veri-dizini yok") ve .NET dosyaları
       native sanılıyordu. minidn sentezleyicisi aynı yanlış layout'u yazdığı
       için testler geçiyordu; sentezleyiciler de spec'e alındı. */
    u32 dd_base = *is64 ? 0x70 : 0x60;
    u32 nras_off = dd_base - 4;               /* NumberOfRvaAndSizes */
    *num_dirs = rd32(oh + nras_off);
    if (*num_dirs > 16) *num_dirs = 16;
    memset(data_dirs, 0, 16 * 8);
    for (u32 i = 0; i < *num_dirs; i++) {
        const u8* de = oh + dd_base + i * 8;
        data_dirs[i * 2] = rd32(de);
        data_dirs[i * 2 + 1] = rd32(de + 4);
    }
    *imagebase = rd32(oh + 0x1C);
    if (*is64) { u64 ib = 0; memcpy(&ib, oh + 0x18, 8); *imagebase = (u32)ib; }
    size_t so = e_lfanew + 24 + opt_sz;
    for (u16 i = 0; i < nsec; i++) {
        size_t s = so + (size_t)i * 40;
        if (s + 40 > n) break;
        Sec sec;
        sec.vsz = rd32(d + s + 8);
        sec.va = rd32(d + s + 12);
        sec.rawsz = rd32(d + s + 16);
        sec.rawptr = rd32(d + s + 20);
        out->push_back(sec);
    }
    return true;
}

static u32 rva2off(const std::vector<Sec>& secs, u32 rva, bool* ok) {
    *ok = false;
    for (size_t i = 0; i < secs.size(); i++) {
        u32 va = secs[i].va, vs = secs[i].vsz ? secs[i].vsz : secs[i].rawsz;
        if (rva >= va && rva < va + vs) {
            u32 delta = rva - va;
            if (delta >= secs[i].rawsz) return 0;   // dosyada yok (BSS)
            *ok = true;
            return secs[i].rawptr + delta;
        }
    }
    return 0;
}

// #~ tablo satır genişlikleri (ECMA-335 II.24.2.6) — v1 kümesi
struct Schema {
    u8 heapsizes;
    u32 rows[8];          // idx: 0=Module 1=TypeRef 2=TypeDef 3=FieldPtr(0x03)
                          //      4=Field 5=MethodPtr 6=MethodDef 7=Param
    bool present[8];
};

static bool has_flag(u64 valid, u32 idx) { return (valid >> idx) & 1ULL; }

bool parse(const u8* d, size_t n, Image* out) {
    out->ok = false;
    out->is_dotnet = false;
    std::vector<Sec> secs;
    u32 dirs[32], ndirs = 0;
    bool is64 = false;
    u32 imagebase = 0;
    if (!pe_sections(d, n, &secs, dirs, &ndirs, &is64, &imagebase)) { out->err = "PE basligi okunamadi"; return false; }
    out->is64 = is64;
    u32 com_rva = dirs[14 * 2], com_sz = dirs[14 * 2 + 1];
    if (!com_rva || com_sz < 72) { out->err = "CLR veri-dizini yok (native PE)"; return false; }

    bool okf = false;
    u32 com_off = rva2off(secs, com_rva, &okf);
    if (!okf || com_off + 72 > n) { out->err = "CLR header dosyada degil"; return false; }
    const u8* cor = d + com_off;
    if (rd32(cor) != 72) { out->err = "IMAGE_COR20_HEADER.cb != 72"; return false; }
    u32 flags = rd32(cor + 16);
    out->is_dll = (flags & 0x1) ? false : true;    // COMIMAGE_FLAGS_ILONLY kontrolu asagida
    if (!(flags & 0x1)) { out->err = "ILONLY bayragi yok (mixed/native)"; return false; }
    u32 meta_rva = rd32(cor + 8), meta_sz = rd32(cor + 12);
    out->entry_token = rd32(cor + 20);
    u32 meta_off = rva2off(secs, meta_rva, &okf);
    if (!okf || meta_off + 20 > n || memcmp(d + meta_off, "BSJB", 4) != 0) {
        out->err = "metadata BSJB imzasi yok"; return false;
    }
    out->is_dotnet = true;
    u16 md_ver = rd16(d + meta_off + 4);
    // veri ofsetleri: imza(4)+maj(2)+min(2)+reserved(4)+len(4) -> version string
    u32 vlen = rd32(d + meta_off + 12);
    u64 p = meta_off + 16 + vlen;
    if (p + 6 > n) { out->err = "metadata basligi kirik"; return false; }
    /* 1.2.5 FIX (x/.NET kök-nedeni-2): ECMA II.24.2.2 — version'dan SONRA
       Flags(2) gelir, Streams(2) ondan sonra gelir. Eski kod Flags'i
       NumberOfStreams sanıp stream-header'ları 2 bayt kaydırıyordu;
       GERÇEK csc çıktısında "#~ akisi yok" üretiyordu. (minidn
       sentezleyicisi Flags'i hiç yazmıyordu — o da spec'e alındı.) */
    u16 md_flags = rd16(d + p);            // Flags (II.24.2.2)
    u16 nstreams = rd16(d + p + 2);        // NumberOfStreams
    p += 4;
    u64 tab_off = 0, tab_sz = 0, str_off = 0, str_sz = 0, us_off = 0, us_sz = 0, blob_off = 0, blob_sz = 0;
    for (int i = 0; i < nstreams; i++) {
        if (p + 8 > n) break;
        u32 o = rd32(d + p), sz = rd32(d + p + 4);
        p += 8;
        std::string name;
        while (p < n && d[p]) name += (char)d[p++];
        p++;                                    // NUL atla
        p += (4 - ((p - meta_off) & 3)) & 3;   // 4-bayt hizalı isim + padding
        if (name == "#~" || name == "#-") { tab_off = meta_off + o; tab_sz = sz; }
        else if (name == "#Strings") { str_off = meta_off + o; str_sz = sz; }
        else if (name == "#US") { us_off = meta_off + o; us_sz = sz; }
        else if (name == "#Blob") { blob_off = meta_off + o; blob_sz = sz; }
    }
    if (!tab_off || tab_off + 24 > n) { out->err = "#~ akisi yok"; return false; }
    if (md_flags & 0x1) {
        /* ExtraData biti: stream-header'lardan sonra 4 bayt ek veri (II.24.2.2) */
        p += 4;
    }
    Schema sc;
    memset(&sc, 0, sizeof sc);
    // #~: Reserved(2) Major(1) Minor(1) HeapSizes(1) Reserved(1) Valid(8) Sorted(8)
    sc.heapsizes = d[tab_off + 4];
    /* 1.2.5 FIX (x/.NET kök-nedeni-3): başlıkta Valid maskesi spec'te +6'da
       (22 baytlık başlık), ama gerçek üreticilerin bir kısmında +8'de (24
       bayt — RunPEForm.exe kanıt). Bit2 (TypeDef) + bit6 (MethodDef) her
       .NET derlemesinde zorunludur — maskede ikisi görünene kadar +2
       kaydır; bulunamazsa net hata. */
    u64 valid = 0;
    u32 valid_off = 0;
    for (u32 vo = 6; vo <= 8; vo += 2) {
        u64 v = (u64)rd32(d + tab_off + vo) | ((u64)rd32(d + tab_off + vo + 4) << 32);
        if ((v & 0x44ULL) == 0x44ULL) { valid = v; valid_off = vo; break; }
    }
    if (!valid_off) {
        out->err = "#~ Valid maskesi cozumlenemedi (TypeDef/MethodDef yok)";
        return false;
    }
    u64 sorted = (u64)rd32(d + tab_off + valid_off + 8) | ((u64)rd32(d + tab_off + valid_off + 12) << 32);
    (void)sorted;
    sc.present[0] = has_flag(valid, 0);
    sc.present[1] = has_flag(valid, 1);
    sc.present[2] = has_flag(valid, 2);
    sc.present[3] = has_flag(valid, 3);
    sc.present[4] = has_flag(valid, 4);
    sc.present[5] = has_flag(valid, 5);
    sc.present[6] = has_flag(valid, 6);
    sc.present[7] = has_flag(valid, 8);   // Param = bit 8
    /* 1.2.5 FIX (x/.NET kök-nedeni-3): satir-sayisi listesi VALID maskesindeki
       TUM tablolar icin vardir (RunPEForm'da 23 tablo!) — desteklenen ilk 8'in
       okunmasi yetmez; satir-verisi baslangici = baslik + 4*popcount(valid).
       Desteklenen tablonun sayisi = maskedeki sirasi (rank). */
    u32 npres = 0;
    for (u64 v = valid; v; v >>= 1) npres += (u32)(v & 1);
    u64 rows_start = tab_off + valid_off + 16 + (u64)npres * 4;
    if (rows_start + 8 > n) { out->err = "satir-verisi tasiyor"; return false; }
    auto count_of = [&](u32 tid) -> u32 {
        if (!((valid >> tid) & 1ULL)) return 0;
        u32 rank = 0;
        for (u32 b = 0; b < tid; b++) if ((valid >> b) & 1ULL) rank++;
        u64 co = tab_off + valid_off + 16 + (u64)rank * 4;
        if (co + 4 > n) return 0;
        return rd32(d + co);
    };
    for (int i = 0; i < 8; i++) {
        static const u32 tid[8] = {0, 1, 2, 3, 4, 5, 6, 8};
        sc.rows[i] = count_of(tid[i]);
    }
    bool s4 = (sc.heapsizes & 1) != 0;      // #Strings 4 bayt idx
    bool g4 = (sc.heapsizes & 2) != 0;      // #GUID 4 bayt idx
    bool b4 = (sc.heapsizes & 4) != 0;      // #Blob 4 bayt idx
    u32 sidx = s4 ? 4 : 2;
    u32 wTypeRef = 2 + 2 * sidx;                             // Scope, Name, Namespace
    u32 wTypeDef = 4 + 2 * sidx + 2 + 2 + 2;                 // Flags, Name, NS, Extends, FieldList, MethodList
    u32 wMethodDef = 4 + 2 + 2 + sidx + (b4 ? 4 : 2) + 2;    // RVA, ImplFlags, Flags, Name, Signature, ParamList
    u32 wParam = 2 + 2 + sidx;                               // Sequence, Flags, Name
    (void)wParam;
    auto str_at0 = [&](u32 idx) -> std::string {
        if (!s4) idx &= 0xFFFF;
        if (idx >= str_sz || str_off + idx >= n) return "";
        u64 sp = str_off + idx;
        std::string r;
        while (sp < n && d[sp] && sp - str_off < str_sz) r += (char)d[sp++];
        return r;
    };
    /* 1.2.5 FIX (x/.NET kök-nedeni-4): Module satir genisligi ureticiye gore
       degisiyor (standart 4/6; bazi ureticilerde 8/10 — RunPEForm kaniti 10).
       Sabit genislik yerine TD1(flags=0)+MD1-3 desen dogrulamasiyla
       KALIBRASYON yapilir; dogrulanan genisliklerle tabanlar hesaplanir. */
    u32 wModule = sidx + (g4 ? 4 : 2);
    u32 wField = 2 + sidx + (b4 ? 4 : 2);
    u64 td_base = 0, md_base = 0;
    bool kalibre = false;
    auto md_pat = [&](u64 x) -> bool {
        if (x + 14 > n) return false;
        u32 rva = rd32(d + x);
        u16 impl = rd16(d + x + 4), flg = rd16(d + x + 6);
        u32 namei = s4 ? rd32(d + x + 8) : rd16(d + x + 8);
        u32 sigi = (b4 ? rd32(d + x + 8 + sidx) : rd16(d + x + 8 + sidx)) & (b4 ? 0xFFFFFFFFu : 0xFFFFu);
        u32 pli = (b4 ? rd32(d + x + 8 + sidx + (b4 ? 4 : 2)) : rd16(d + x + 8 + sidx + (b4 ? 4 : 2))) & 0xFFFFu;
        if (rva != 0 && (rva < 0x1000 || rva >= 0x40000000u)) return false;
        if (impl > 7) return false;
        if (namei >= str_sz) return false;
        if (blob_sz && sigi >= blob_sz) return false;
        if (pli > sc.rows[7] + 1) return false;
        return true;
    };
    static const u32 wM_cand[5] = {4, 6, 8, 10, 12};
    for (int im = 0; im < 5 && !kalibre; im++) {
        u32 wm = wM_cand[im];
        u64 td = rows_start + (u64)wm + (sc.present[1] ? (u64)sc.rows[1] * wTypeRef : 0);
        if (sc.rows[2] == 0) {                       // TypeDef yok: sadece MD dene
            u64 md = td;
            if (sc.rows[6] >= 3 && md_pat(md) && md_pat(md + wMethodDef) && md_pat(md + 2 * wMethodDef)) {
                td_base = td; md_base = md; wModule = wm; kalibre = true;
            } else if (sc.rows[6] == 0) {
                td_base = td; md_base = md; wModule = wm; kalibre = true;
            }
            continue;
        }
        if (td + 14 > n) continue;
        u32 fl1 = rd32(d + td);
        u32 name1 = s4 ? rd32(d + td + 4) : rd16(d + td + 4);
        if (fl1 != 0 || name1 >= str_sz) continue;
        std::string n1 = str_at0(name1);
        if (n1.empty() || (unsigned char)n1[0] < 0x20) continue;
        u64 md = td + (u64)sc.rows[2] * wTypeDef
               + (sc.present[3] ? (u64)sc.rows[3] * 2 : 0)
               + (sc.present[4] ? (u64)sc.rows[4] * wField : 0);
        if (sc.rows[6] >= 3) {
            if (!(md_pat(md) && md_pat(md + wMethodDef) && md_pat(md + 2 * wMethodDef))) continue;
        }
        td_base = td; md_base = md; wModule = wm; kalibre = true;
    }
    if (!kalibre) {
        /* kaliibrasyon tutmadi: hesaplanan degerlerle devam (eski davranis),
           minidn gibi sentetik dosyalar icin guvenli yol */
        u64 off = rows_start;
        td_base = off + (sc.present[0] ? (u64)sc.rows[0] * wModule : 0)
                + (sc.present[1] ? (u64)sc.rows[1] * wTypeRef : 0);
        md_base = td_base + (u64)sc.rows[2] * wTypeDef
                + (sc.present[3] ? (u64)sc.rows[3] * 2 : 0)
                + (sc.present[4] ? (u64)sc.rows[4] * wField : 0);
        wModule = sidx + (g4 ? 4 : 2);
    }
#ifdef XPDN_DEBUG
    fprintf(stderr, "[XPDN] tab_off=0x%llX valid_off=%u heapsizes=%u valid=%llX npres=%u rows_start=0x%llX\n",
            (unsigned long long)tab_off, valid_off, sc.heapsizes, (unsigned long long)valid, npres,
            (unsigned long long)rows_start);
    fprintf(stderr, "[XPDN] rows M=%u TR=%u TD=%u F=%u MD=%u P=%u | wM=%u wTR=%u wTD=%u wF=%u wMD=%u | td=%llX md=%llX kali=%d\n",
            sc.rows[0], sc.rows[1], sc.rows[2], sc.rows[4], sc.rows[6], sc.rows[7],
            wModule, wTypeRef, wTypeDef, wField, wMethodDef,
            (unsigned long long)td_base, (unsigned long long)md_base, (int)kalibre);
#endif
    u32 td_w = wTypeDef, md_w = wMethodDef;
    auto str_at = [&](u32 idx) -> std::string {
        if (!s4) idx &= 0xFFFF;
        if (idx >= str_sz || str_off + idx >= n) return "";
        u64 sp = str_off + idx;
        std::string r;
        while (sp < n && d[sp] && sp - str_off < str_sz) r += (char)d[sp++];
        return r;
    };
    for (u32 r = 0; r < sc.rows[2]; r++) {
        u64 ro = td_base + (u64)r * td_w;
        if (ro + td_w > n) break;
        const u8* row = d + ro;
        u32 namei = s4 ? rd32(row + 4) : rd16(row + 4);
        u32 nsi = s4 ? rd32(row + 4 + sidx) : rd16(row + 4 + sidx);
        // TypeDef satırı: Flags(0..3) Name(4..5) NS(6..7) Extends(8..9)
        //                 FieldList(10..11) MethodList(12..13)
        u32 fieldlist = s4 ? rd32(row + 10) : rd16(row + 10);
        u32 methodlist = s4 ? rd32(row + 12) : rd16(row + 12);
        (void)fieldlist;
        TypeDef td;
        td.name = str_at(namei);
        td.ns = str_at(nsi);
        td.type_full = td.ns.empty() ? td.name : (td.ns + "." + td.name);
        td.method_first = methodlist;
        td.method_last = (r + 1 < sc.rows[2])
            ? (s4 ? rd32(d + ro + td_w + 12) : rd16(d + ro + td_w + 12))
            : sc.rows[6] + 1;
        out->typedefs.push_back(td);
    }
    for (u32 r = 0; r < sc.rows[6]; r++) {
        u64 ro = md_base + (u64)r * md_w;
        if (ro + md_w > n) break;
        const u8* row = d + ro;
        Method m;
        m.rva = rd32(row);
        m.impl_flags = rd16(row + 4);
        m.flags = rd16(row + 6);
        u32 namei = s4 ? rd32(row + 8) : rd16(row + 8);
        m.name = str_at(namei);
        m.row_rva_off = (u32)ro;                 // 1.2.3: RVA alanının dosya ofseti
        m.row_impl_off = (u32)ro + 4;            // ImplFlags alanının dosya ofseti
        m.token = 0x06000000u | (r + 1);
        m.is_pinvoke = (m.impl_flags & 0x1000) != 0;
        m.is_native = (m.impl_flags & 0x3) == 1;
        m.is_abstract = (m.flags & 0x0400) != 0;
        m.is_static = (m.flags & 0x0010) != 0;
        out->methods.push_back(m);
    }
    // TypeDef adlarını yöntemlere eşle
    for (size_t ti = 0; ti < out->typedefs.size(); ti++) {
        TypeDef& td = out->typedefs[ti];
        for (u32 mi = td.method_first; mi >= 1 && mi < td.method_last && mi <= out->methods.size(); mi++) {
            Method& m = out->methods[mi - 1];
            m.type_name = td.type_full;
        }
    }
    // --- param sayısı: imza blobundan (v1 basit ayrıştırıcı) ---
    for (size_t mi = 0; mi < out->methods.size(); mi++) {
        Method& m = out->methods[mi];
        u64 ro = md_base + (u64)mi * md_w;
        u32 sigi = s4 ? rd32(d + ro + 8 + sidx) : rd16(d + ro + 8 + sidx);
        if (!b4) sigi &= 0xFFFF;
        if (blob_off && sigi && blob_off + sigi < n) {
            const u8* sb = d + blob_off + sigi;
            // compressed length
            u64 sp = 0; u32 len = 0;
            if (sb[0] & 0x80) { if (sb[0] & 0x40) len = ((u32)(sb[0] & 0x1F) << 24) | ((u32)sb[1] << 16) | ((u32)sb[2] << 8) | sb[3], sp = 4; else len = ((u32)(sb[0] & 0x3F) << 8) | sb[1], sp = 2; }
            else len = sb[0], sp = 1;
            if (sp + len <= blob_sz) {
                const u8* s2 = sb + sp;
                // call conv + param count
                u32 cc = s2[0];
                u64 ip = 1;
                if ((cc & 0x10) != 0) ip++;                 // HASTHIS -> ek bayt
                u32 pcnt = 0, shift = 0;
                while (ip < len) {                          // compressed uint
                    u8 c0 = s2[ip];
                    if (c0 & 0x80) { if (c0 & 0x40) { pcnt |= ((u32)(c0 & 0x1F)) << shift; shift += 5; ip += 1; if (shift >= 29) break; }
                                     else { pcnt |= ((u32)(c0 & 0x3F)) << shift; ip += 2; break; } }
                    else { pcnt |= ((u32)c0) << shift; ip += 1; break; }
                }
                m.param_count = pcnt;
                // ret tipinin ELEMENT_TYPE'ı: ilk tip baytı (basit tipler için)
                if (ip < len) {
                    u8 t = s2[ip];
                    while (t == 0x1D || t == 0x1F || t == 0x20 || t == 0x1E) { ip++; if (ip >= len) break; t = s2[ip]; }   // SZARRAY/CMOD skip
                    if (t == 0x11 || t == 0x12) {           // VALUETYPE/CLASS -> token idx (compressed)
                        ip++; u32 tk = 0, sh2 = 0;
                        while (ip < len && sh2 < 29) { u8 c0 = s2[ip]; tk |= ((u32)(c0 & 0x7F)) << sh2; sh2 += 7; if (!(c0 & 0x80)) { ip++; break; } ip++; }
                    } else if (t == 0x0F || t == 0x10 || t == 0x45 || t == 0x46) {
                        ip++;                                // PTR/BYREF/CMOD
                    }
                    if (ip < len) m.ret_type = s2[ip];
                }
            }
        }
        m.has_ret = (m.ret_type != 0x01);                   // ELEMENT_TYPE_VOID
        // --- gövde okuma (RVA != 0: gövdeli yöntem) ---
        if (m.rva) {
            bool okb = false;
            u32 bo = rva2off(secs, m.rva, &okb);
            if (okb && bo < n) {
                const u8* bh = d + bo;
                if ((bh[0] & 0x3) == 0x2) {                 // tiny
                    m.body_len = (bh[0] >> 2) & 0x3F;
                    m.body_off = bo + 1;
                    m.fat_header = false;
                    m.max_stack = 8;
                } else if ((bh[0] & 0x3) == 0x3) {          // fat
                    u32 hs = (u32)((bh[1] >> 4) & 0xF) * 4;
                    m.fat_header = true;
                    m.max_stack = rd16(bh + 2);
                    u32 codesz = rd32(bh + 4) & 0x00FFFFFF;
                    m.local_sig = rd32(bh + 8);
                    m.body_off = bo + hs;
                    m.body_len = codesz;
                    /* 1.2.4 (x2 fix): MoreSects biti FLAGS kelimesinde
                       (ECMA II.25.4.4: bit3 = 0x0008) — eski kod bh[2]'ye
                       bakiyordu, o byte maxstack'in alcak byte'i (8) ve her
                       fat govde EH saniliyordu (Method2 yanlis RED). */
                    if ((rd16(bh) & 0x0008) != 0) {               // EHTable
                        // EH clause'ları 4-bayt hizalı; flags=0x40 -> FAT (24B) yoksa küçük (12B)
                        u64 ehp = (u64)m.body_off + codesz;
                        ehp = (ehp + 3) & ~(u64)3;
                        if (ehp + 4 <= n) {
                            u32 dsz = rd32(d + ehp);
                            u32 csize = (dsz >> 24) == 0x40 ? 24 : 12;
                            u32 cnt = (dsz & 0x00FFFFFF) / csize;
                            for (u32 e = 0; e < cnt; e++) m.eh_count++;
                        }
                    }
                }
            }
        }
    }
#ifdef XPDN_DEBUG
    fprintf(stderr, "[XPDN] str_off=%u str_sz=%u blob_off=%u\n", (unsigned)str_off, (unsigned)str_sz, (unsigned)blob_off);
    fprintf(stderr, "[XPDN] td_base=%u md_base=%u rows[0]=%u rows[2]=%u rows[6]=%u\n",
            td_base, md_base, sc.rows[0], sc.rows[2], sc.rows[6]);
    for (size_t _i = 0; _i < out->methods.size(); _i++)
        fprintf(stderr, "[XPDN] m[%zu] name='%s' rva=0x%X impl=0x%X flags=0x%X nameidx@off=\n",
                _i, out->methods[_i].name.c_str(), out->methods[_i].rva,
                out->methods[_i].impl_flags, out->methods[_i].flags);
#endif
    out->ok = true;
    out->err.clear();
    snprintf(out->ver_buf, sizeof out->ver_buf, "%u", md_ver);
    return true;
}

// Gövde baytlarını (header hariç IL) kopyala
bool read_body(const u8* d, size_t n, const Method& m, std::vector<u8>* il) {
    if (!m.body_off || !m.body_len) return false;
    if ((size_t)m.body_off + m.body_len > n) return false;
    il->assign(d + m.body_off, d + m.body_off + m.body_len);
    return true;
}

// StandAloneSig yerel-değişken imzasını çöz (slot boyutları + tipler)
bool parse_locals(const u8* d, size_t n, const Image& img, u32 local_sig_token,
                  std::vector<u8>* types, std::vector<u32>* sizes) {
    if (!local_sig_token || (local_sig_token >> 24) != 0x11) return false;
    // StandAloneSig satırı: Signature(blob idx) — tablo 0x11 bizim 8'lik kümede yok;
    // v1: blob'a token-index ile doğrudan gidemeyiz — StandAloneSig satır ofsetini
    // hesaplamak için tablo 0x11'i de ayrıştırmamız gerekir. Kısayol: engine
    // tarafında yerel imzası çözülemeyen fat-gövde = RED (net mesaj).
    (void)d; (void)n; (void)img;
    types->clear(); sizes->clear();
    return false;
}

} // namespace xpdotnet
