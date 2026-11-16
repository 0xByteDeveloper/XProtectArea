// ============================================================
// xprotect_dwarf.cpp — DWARF v2..v4 .debug_info subprogram keşfi (v1)
// ============================================================
// x3 portu: UO/VMProtect dwarf.cc'nin XProtect karşılığı (kavram-parite;
// kod özgün, PE + fonksiyon-keşfi odağı). Okunan bölümler:
//   .debug_info    : DIE ağacı
//   .debug_abbrev  : DIE şemaları (code -> tag + form listesi)
//   .debug_str     : DW_FORM_strp adları
// Yöntem: her CU başlığından abbrev dekoderi kurulur → DIE ağacı
// yürütülür → DW_TAG_subprogram(0x2E) low_pc/high_pc/name çiftleri
// fonksiyon listesine yazılır. high_pc adres-form ise (low<=high) fark,
// sabit-form ise (high<low, offset) boyut doğrudandır (DWARF kuralı).
// v1'de YOK: DWARF v5, .debug_ranges/rnglists, DWARF64, split-DWARF.
// ============================================================
#include "xprotect_dwarf.h"
#include <cstring>

namespace xpdwarf {

static u32 rd16(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8); }
static u32 rd32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static u64 rd64(const u8* p) { return (u64)rd32(p) | ((u64)rd32(p + 4) << 32); }

struct Cursor {
    const u8* p;
    const u8* end;
    bool ok = true;
    u8 u8_()  { if (p + 1 > end) { ok = false; return 0; } return *p++; }
    u16 u16_(){ if (p + 2 > end) { ok = false; return 0; } u16 v = (u16)(p[0] | (p[1] << 8)); p += 2; return v; }
    u32 u32_(){ if (p + 4 > end) { ok = false; return 0; } u32 v = rd32(p); p += 4; return v; }
    u64 u64_(){ if (p + 8 > end) { ok = false; return 0; } u64 v = rd64(p); p += 8; return v; }
    u64 uleb() {
        u64 r = 0; int sh = 0;
        for (;;) {
            if (p >= end) { ok = false; return r; }
            u8 b = *p++; r |= (u64)(b & 0x7F) << sh;
            if (!(b & 0x80)) break;
            sh += 7;
        }
        return r;
    }
    i64 sleb() {
        i64 r = 0; u32 sh = 0; u8 b2 = 0;
        for (;;) {
            if (p >= end) { ok = false; return r; }
            b2 = *p++; r |= (i64)(b2 & 0x7F) << sh; sh += 7;
            if (!(b2 & 0x80)) break;
        }
        if (sh < 63 && (b2 & 0x40)) r |= ((i64)-1) << sh;
        return r;
    }
    const u8* raw(size_t k) {
        if (p + k > end) { ok = false; return end; }
        const u8* q = p; p += k; return q;
    }
};

struct AbbRow { u64 at, form; };
struct AbbDecl { u64 code, tag; bool kids; std::vector<AbbRow> attrs; };

static bool read_abbrev(const u8* ab, size_t abn, u64 off,
                        std::vector<AbbDecl>* out) {
    if (off >= abn) return false;
    Cursor c{ ab + off, ab + abn };
    for (;;) {
        u64 code = c.uleb();
        if (!c.ok) return false;
        if (code == 0) return true;                       // liste sonu
        AbbDecl dcl;
        dcl.code = code;
        dcl.tag = c.uleb();
        u8 kids = c.u8_();
        dcl.kids = kids != 0;
        for (;;) {
            u64 at = c.uleb(), form = c.uleb();
            if (!c.ok) return false;
            if (at == 0 && form == 0) break;
            /* cp273 DWARF5 FIX: DW_FORM_implicit_const (0x21) — degeri
               abbrev tablosunda SLEB128 olarak YAZILIDIR; DIE akisina
               bayt konmaz. Burada okunup atilir (desync engeli). */
            if (form == 0x21) (void)c.sleb();
            dcl.attrs.push_back({ at, form });
        }
        out->push_back(dcl);
    }
}

// okunan degerin cinsi
enum Vk { VK_NONE = 0, VK_UINT, VK_STRP, VK_ISTR };
static const u8* lst = 0; static size_t lstn = 0;   /* v5: .debug_line_str (parse doldurur) */
struct Val { Vk k = VK_NONE; u64 v = 0; const u8* s = 0; };

static Val read_val(Cursor& c, u64 form, u8 addr_size) {
    Val v;
    /* cp273: DWARF form kodlari — 6 bagimsiz kanitla kilitlendi
       (objdump isimleri + ham baytlar: string=0x08 data2=0x05 data1=0x0B
        strp=0x0E ref4=0x13 implicit_const=0x21) */
    switch (form) {
    case 0x01: v.k = VK_UINT; v.v = addr_size == 8 ? c.u64_() : (addr_size == 4 ? c.u32_() : c.u16_()); break;  // addr
    case 0x02: c.raw(2); break;                                            // block2
    case 0x03: c.raw(4); break;                                            // block4
    case 0x05: v.k = VK_UINT; v.v = c.u16_(); break;                       // data2
    case 0x06: v.k = VK_UINT; v.v = c.u32_(); break;                       // data4
    case 0x07: v.k = VK_UINT; v.v = c.u64_(); break;                       // data8
    case 0x08: v.k = VK_ISTR; v.s = c.p; while (c.p < c.end && *c.p) c.p++; if (c.p < c.end) c.p++; break;  // string (inline)
    case 0x09: { u64 k = c.uleb(); c.raw(k); break; }                      // block
    case 0x0A: c.raw(1); break;                                            // block1
    case 0x0B: v.k = VK_UINT; v.v = c.u8_(); break;                        // data1
    case 0x0C: v.k = VK_UINT; v.v = c.u8_(); break;                        // flag
    case 0x0D: v.k = VK_UINT; v.v = (u64)c.uleb(); break;                  // sdata
    case 0x0E: v.k = VK_STRP; v.v = c.u32_(); break;                       // strp
    case 0x0F: c.uleb(); break;                                            // udata
    case 0x10: v.k = VK_UINT; v.v = addr_size == 8 ? c.u64_() : c.u32_(); break;  // ref_addr
    case 0x11: c.u8_(); break;                                             // ref1
    case 0x12: c.u16_(); break;                                            // ref2
    case 0x13: c.u32_(); break;                                            // ref4
    case 0x14: c.u64_(); break;                                            // ref8
    case 0x15: c.uleb(); break;                                            // ref_udata
    case 0x16: { u64 f2 = c.uleb(); if (c.ok) v = read_val(c, f2, addr_size); break; }  // indirect
    case 0x17: c.u32_(); break;                                            // sec_offset
    case 0x18: { u64 k = c.uleb(); c.raw(k); break; }                      // exprloc
    case 0x19: v.k = VK_UINT; v.v = 1; break;                              // flag_present
    case 0x1A: c.uleb(); break;                                            // strx
    case 0x1B: c.uleb(); break;                                            // addrx
    case 0x1C: c.u32_(); break;                                            // ref_sup4
    case 0x1D: c.u32_(); break;                                            // strp_sup
    case 0x1E: c.raw(16); break;                                           // data16
    case 0x1F: { u32 o = c.u32_(); v.k = VK_ISTR; v.s = (lst && o < lstn) ? (lst + o) : 0; } break;  // line_strp
    case 0x20: c.u64_(); break;                                            // ref_sig8
    case 0x21: break;                                                      // implicit_const — DIE'da 0 bayt
    case 0x22: c.uleb(); break;                                            // loclistx
    case 0x23: c.uleb(); break;                                            // rnglistx
    case 0x24: c.u64_(); break;                                            // ref_sup8
    case 0x25: c.u8_(); break;                                             // strx1
    case 0x26: c.u16_(); break;                                            // strx2
    case 0x27: c.raw(3); break;                                            // strx3
    case 0x28: c.u32_(); break;                                            // strx4
    case 0x29: c.u8_(); break;                                             // addrx1
    case 0x2A: c.u16_(); break;                                            // addrx2
    case 0x2B: c.raw(3); break;                                            // addrx3
    case 0x2C: c.u32_(); break;                                            // addrx4
    case 0x2D: c.uleb(); break;                                            // udata
    default: c.ok = false; break;
    }
    return v;
}

bool parse(const unsigned char* d, size_t n, unsigned long long imagebase,
           std::vector<DwarfFn>* out, std::string* err) {
    if (n < 0x40 || d[0] != 'M' || d[1] != 'Z') { if (err) *err = "PE imzasi yok"; return false; }
    u32 e_lfa = rd32(d + 0x3C);
    if (e_lfa + 24 + 224 > n || memcmp(d + e_lfa, "PE\0\0", 4) != 0) { if (err) *err = "PE cozulemedi"; return false; }
    u16 nsec = rd16(d + e_lfa + 6);
    u16 optsz = rd16(d + e_lfa + 20);
    size_t so = e_lfa + 24 + optsz;
    /* cp273: uzun bolum isimleri (".debug_info" 11k) mingw'de COFF string
       tablosuna "/NN" seklinde yazilir — UO dwarf.cc paritesi: cozer */
    const char* strtab = 0; u32 strtab_sz = 0;
    {
        u32 symoff = rd32(d + e_lfa + 12);
        u32 nsym = rd32(d + e_lfa + 16);
        u32 stroff = symoff + nsym * 18u;
        if (stroff + 4 <= n) {
            strtab_sz = rd32(d + stroff);
            if (strtab_sz && stroff + strtab_sz <= n) strtab = (const char*)(d + stroff);
        }
    }
    const u8* di = 0; size_t din = 0;
    const u8* ab = 0; size_t abn = 0;
    const u8* st = 0; size_t stn = 0;
    u64 ibase = imagebase;
    for (u16 i = 0; i < nsec; i++) {
        size_t s = so + (size_t)i * 40;
        if (s + 40 > n) break;
        char nm[9]; memset(nm, 0, 9); memcpy(nm, d + s, 8);
        const char* ln = 0;
        if (nm[0] == '/' && strtab) {
            unsigned long idx2 = strtoul(nm + 1, 0, 10);
            if (idx2 < strtab_sz) ln = strtab + idx2;
        }
        const char* eff = ln ? ln : nm;
        u32 vsz = rd32(d + s + 8), va = rd32(d + s + 12), rawsz = rd32(d + s + 16), raw = rd32(d + s + 20);
        if (!strncmp(eff, ".debug_info", 11) && rawsz) { di = d + raw; din = rawsz < vsz ? rawsz : vsz; }
        else if (!strncmp(eff, ".debug_abbrev", 13) && rawsz) { ab = d + raw; abn = rawsz < vsz ? rawsz : vsz; }
        else if (!strncmp(eff, ".debug_str", 10) && rawsz) { st = d + raw; stn = rawsz < vsz ? rawsz : vsz; }
        else if (!strncmp(eff, ".debug_line_str", 15) && rawsz) { lst = d + raw; lstn = rawsz < vsz ? rawsz : vsz; }
        (void)va;
    }
    if (!di || !ab) { if (err) *err = ".debug_info/.debug_abbrev yok"; return false; }

    size_t pos = 0;
    int cus = 0, fns = 0;
    while (pos + 4 <= din) {
        u32 len = rd32(di + pos);
        if (len == 0xFFFFFFFFu || len < 4) break;                          // DWARF64/dotuk — v1 disi
        if (pos + 4 + len > din) break;
        Cursor c{ di + pos + 4, di + pos + 4 + len - 4 };
        u16 ver = c.u16_();
        u64 aboff = 0;
        u8 addr_size = 8;
        if (ver >= 2 && ver <= 3) {
            /* cp273: DWARF2/3 header: ver(2) aboff(4) addr(1) — segment YOK */
            aboff = c.u32_();
            addr_size = c.u8_();
        } else if (ver == 4) {
            /* cp273: DWARF4 header: ver(2) aboff(4) addr(1) seg(1) */
            aboff = c.u32_();
            addr_size = c.u8_();
            (void)c.u8_();
        } else if (ver == 5) {
            /* cp273: DWARF5 CU header — unit_type'a gore EKSTRA alanlar:
               DW_UT_type(2)/split_type(6): +64-bit type_signature +32-bit
               type_offset; DW_UT_skeleton(4)/split_compile(5): +64-bit dwo_id.
               Okunmazsa DIE akisi 8-12 bayt desync olur (kok-neden!). */
            u8 ut = c.u8_();
            addr_size = c.u8_();
            aboff = c.u32_();
            if (ut == 2 || ut == 6) { (void)c.u64_(); (void)c.u32_(); }
            else if (ut == 4 || ut == 5) { (void)c.u64_(); }
        } else break;                                                       // v5 sonraki tur
        if (!c.ok) break;
        std::vector<AbbDecl> abd;
        if (!read_abbrev(ab, abn, aboff, &abd)) break;

        // DIE agaci: kids yigini ile derinlik
        int depth = 0;
        while (c.ok && c.p < c.end) {
            u64 code = c.uleb();
            if (!c.ok) break;
            if (code == 0) { if (depth > 0) depth--; continue; }            // null: seviye kapat
            const AbbDecl* dec = 0;
            for (auto& a : abd) if (a.code == code) { dec = &a; break; }
            if (!dec) break;                                                // bilinmeyen kod → CU birak
            bool hl = false, hh = false, hn = false;
            u64 low = 0, high = 0;
            std::string nm;
            for (auto& ar : dec->attrs) {
                Val v = read_val(c, ar.form, addr_size);
                if (!c.ok) break;
                if (dec->tag != 0x2Eu) continue;                            // yalniz DW_TAG_subprogram
                if (ar.at == 0x11 && v.k == VK_UINT) { low = v.v; hl = true; }      // DW_AT_low_pc
                else if (ar.at == 0x12 && v.k == VK_UINT && !hh) { high = v.v; hh = true; } // DW_AT_high_pc
                else if (ar.at == 0x03 && v.k == VK_STRP && st && !hn) {     // DW_AT_name (strp)
                    u64 o = v.v;
                    if (o < stn) {
                        const u8* q = st + o;
                        while ((size_t)(q - st) < stn && *q) q++;
                        nm.assign((const char*)st + o, (size_t)(q - (st + o)));
                        hn = true;
                    }
                } else if (ar.at == 0x03 && v.k == VK_ISTR && v.s && !hn) {  // DW_AT_name (inline)
                    const u8* q = v.s;
                    while (*q) q++;
                    nm.assign((const char*)v.s, (size_t)(q - v.s));
                    hn = true;
                }
            }
            if (!c.ok) break;
            if (dec->tag == 0x2Eu && hl && hh && low) {                      // subprogram + adres cifti
                DwarfFn f;
                u64 rva = (low >= ibase) ? low - ibase : low;
                u64 sz;
                if (high > low) sz = high - low;
                else sz = high;                                              // offset-form (sabit sinif)
                if (sz && sz < 0x1000000u) {
                    f.rva = rva;
                    f.size = sz;
                    f.name = nm;
                    out->push_back(f);
                    fns++;
                }
            }
            if (dec->kids) depth++;                                          // cocuklara gir
            if (depth > 64) break;                                           // koruma
        }
        cus++;
        pos += 4 + len;
    }
    if (!fns) { if (err) *err = "subprogram bulunamadi"; return false; }
    return true;
}

} // namespace xpdwarf
