// ============================================================
// engine_pe.cpp — PE32/PE32+ okuma-yazma, section ekleme,
// export + COFF sembol tablosu okuma
// ============================================================
#include "engine.hpp"

static u32 rd32(const std::vector<u8>& b, size_t o) {
    return (u32)b[o] | ((u32)b[o+1] << 8) | ((u32)b[o+2] << 16) | ((u32)b[o+3] << 24);
}
static u16 rd16(const std::vector<u8>& b, size_t o) {
    return (u16)(b[o] | (b[o+1] << 8));
}
static void wr32(std::vector<u8>& b, size_t o, u32 v) {
    b[o] = (u8)v; b[o+1] = (u8)(v >> 8); b[o+2] = (u8)(v >> 16); b[o+3] = (u8)(v >> 24);
}
static void wr16(std::vector<u8>& b, size_t o, u16 v) {
    b[o] = (u8)v; b[o+1] = (u8)(v >> 8);
}

bool PEFile::load(const std::string& path, std::string& err) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { err = "dosya acilamadi: " + path; return false; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    buf.resize((size_t)sz);
    if (fread(buf.data(), 1, (size_t)sz, f) != (size_t)sz) { fclose(f); err = "okuma kisa"; return false; }
    fclose(f);

    if (sz < 0x40 || rd16(buf, 0) != 0x5A4D) { err = "MZ imzasi yok"; return false; }
    e_lfanew = rd32(buf, 0x3C);
    if (e_lfanew + 0x100 > buf.size() || rd32(buf, e_lfanew) != 0x00004550) { err = "PE imzasi yok"; return false; }
    u32 fh = e_lfanew + 4;
    machine = rd16(buf, fh);
    u16 nsec = rd16(buf, fh + 2);
    symtab_off = rd32(buf, fh + 8);
    symtab_n = rd32(buf, fh + 12);
    u16 optsize = rd16(buf, fh + 16);
    u32 opt = fh + 20;
    if (optsize == 0) { err = "optional header yok"; return false; }
    u16 magic = rd16(buf, opt);
    if (magic == 0x20B) is64 = true;
    else if (magic == 0x10B) is64 = false;
    else { err = "PE32+/PE32 magic yok"; return false; }

    entry_rva      = rd32(buf, opt + 16);
    if (is64) {
        // PE32+: ImageBase ULONGLONG (8 bayt) @ opt+24
        ib64 = (u64)rd32(buf, opt + 24) | ((u64)rd32(buf, opt + 28) << 32);
        imagebase = (u32)ib64;   // alt 32 bit: RVA matematigi mod 2^32 tutarlidir
    } else {
        ib64      = rd32(buf, opt + 28);
        imagebase = rd32(buf, opt + 28);
    }
    secalign       = rd32(buf, opt + 32);
    filealign      = rd32(buf, opt + 36);
    sizeofimage    = rd32(buf, opt + 56);
    sizeofheaders  = rd32(buf, opt + 60);
    strtab_off = symtab_off + symtab_n * 18;

    u32 sh = opt + optsize;
    for (u16 i = 0; i < nsec; i++) {
        u32 o = sh + i * 40;
        Section s;
        memcpy(s.name, &buf[o], 8); s.name[8] = 0;
        s.vsz    = rd32(buf, o + 8);
        s.va     = rd32(buf, o + 12);
        s.rawsz  = rd32(buf, o + 16);
        s.rawoff = rd32(buf, o + 20);
        s.chars  = rd32(buf, o + 36);
        secs.push_back(s);
    }
    return true;
}

bool PEFile::save(const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    bool ok = fwrite(buf.data(), 1, buf.size(), f) == buf.size();
    fclose(f);
    return ok;
}

const Section* PEFile::secbyname_c(const char* n) const {
    for (auto& s : secs)
        if (strncmp(s.name, n, 8) == 0) return &s;
    return nullptr;
}

u32 PEFile::rva2raw(u32 rva, bool* ok) const {
    if (ok) *ok = false;
    for (auto& s : secs) {
        u32 al = (s.vsz + secalign - 1) & ~(secalign - 1);
        if (rva >= s.va && rva < s.va + (al ? al : secalign)) {
            u32 off = rva - s.va;
            if (off < s.rawsz) { if (ok) *ok = true; return s.rawoff + off; }
            if (ok) *ok = true;   // sanal bolge (bss)
            return s.rawoff + (off < s.rawsz ? off : s.rawsz);
        }
    }
    return 0;
}

Section* PEFile::secbyrva(u32 rva) {
    for (auto& s : secs)
        if (rva >= s.va && rva < s.va + s.vsz) return &s;
    return nullptr;
}

Section* PEFile::secbyname(const char* n) {
    for (auto& s : secs)
        if (strncmp(s.name, n, 8) == 0) return &s;
    return nullptr;
}

bool PEFile::add_section(const char* name, const std::vector<u8>& data, u32 chars, u32& out_rva) {
    if (secs.size() >= 96) return false;
    u32 vsize = (u32)((data.size() + secalign - 1) & ~(secalign - 1));
    u32 lastva = 0, lastvsz = 0;
    for (auto& s : secs) { if (s.va + s.vsz > lastva + lastvsz) { lastva = s.va; lastvsz = s.vsz; } }
    u32 newva = (lastva + lastvsz + secalign - 1) & ~(secalign - 1);
    u32 rawoff = (u32)((buf.size() + filealign - 1) & ~(filealign - 1));
    u32 rawsz = (u32)((data.size() + filealign - 1) & ~(filealign - 1));

    buf.resize(rawoff + rawsz, 0);
    memcpy(&buf[rawoff], data.data(), data.size());

    u16 nsec = rd16(buf, e_lfanew + 6);
    wr16(buf, e_lfanew + 6, nsec + 1);

    u32 fh = e_lfanew + 4;
    u16 optsize = rd16(buf, fh + 16);
    u32 sh = fh + 20 + optsize + (u32)(nsec * 40);
    memset(&buf[sh], 0, 40);
    memcpy(&buf[sh], name, strlen(name) > 8 ? 8 : strlen(name));
    wr32(buf, sh + 8, (u32)data.size());   // VirtualSize
    wr32(buf, sh + 12, newva);
    wr32(buf, sh + 16, rawsz);
    wr32(buf, sh + 20, rawoff);
    wr16(buf, sh + 34, 0);
    wr32(buf, sh + 36, chars);

    wr32(buf, e_lfanew + 4 + 20 + 56, sizeofimage + vsize);  // SizeOfImage artimi
    sizeofimage += vsize;

    Section ns; memset(ns.name, 0, 9); strncpy(ns.name, name, 8);
    ns.vsz = (u32)data.size(); ns.va = newva; ns.rawsz = rawsz; ns.rawoff = rawoff; ns.chars = chars;
    secs.push_back(ns);
    out_rva = newva;
    return true;
}

bool PEFile::filter_relocs(const std::vector<std::pair<u32,u32>>& ranges,
                           u32& removed, std::string& note) {
    removed = 0; note.clear();
    // data directory 5 = BaseRelocationTable
    u32 fh = e_lfanew + 4;
    u16 optsize = rd16(buf, fh + 16);
    u32 opt = fh + 20;
    u32 dd = opt + (is64 ? 112 : 96) + 5 * 8;
    u32 rel_rva = rd32(buf, dd), rel_sz = rd32(buf, dd + 4);
    if (!rel_rva || !rel_sz) { note = "reloc tablosu yok"; return true; }
    bool ok; u32 raw = rva2raw(rel_rva, &ok);
    if (!ok || (u64)raw + rel_sz > buf.size()) { note = "reloc raw erisilemiyor"; return false; }

    std::vector<u8> out(rel_sz, 0);
    u32 src = raw, dst = 0;
    u32 end = raw + rel_sz;
    while (src + 8 <= end) {
        u32 page = rd32(buf, src);
        u32 bsz  = rd32(buf, src + 4);
        if (bsz < 8 || src + bsz > end) break;   // bozuk block -> dur
        u32 nent = (bsz - 8) / 2;
        std::vector<u16> keep;
        for (u32 i = 0; i < nent; i++) {
            u16 e = rd16(buf, src + 8 + i * 2);
            u32 type = (u32)e >> 12;
            u32 off  = (u32)e & 0x0FFF;
            if (type == 0) continue;              // padding — yeniden hizalanir
            u32 rva = page + off;
            bool inrepl = false;
            for (auto& r : ranges)
                if (rva >= r.first && rva < r.first + r.second) { inrepl = true; break; }
            if (inrepl) { removed++; continue; }  // motorun ezdigi bayt -> girdi gebersin
            keep.push_back(e);
        }
        if (!keep.empty()) {
            u32 newsz = 8 + (u32)keep.size() * 2;
            if (newsz & 3) { keep.push_back(0); newsz += 2; }   // 4-bayt hizalama pad'i
            wr32(out, dst, page);
            wr32(out, dst + 4, newsz);
            for (u32 i = 0; i < keep.size(); i++) wr16(out, dst + 8 + i * 2, keep[i]);
            dst += newsz;
        }
        src += bsz;
    }
    memcpy(&buf[raw], out.data(), rel_sz);
    wr32(buf, dd + 4, dst);   // yeni tablo boyutu (RVA ayni; kuyruk sifir)
    note = "reloc girdisi silindi: " + std::to_string(removed) + ", yeni boyut=" + std::to_string(dst);
    return true;
}

void PEFile::fix_checksum() {
    u32 fh = e_lfanew + 4;
    u16 optsize = rd16(buf, fh + 16);
    u32 opt = fh + 20;
    u32 cs_off = opt + 64;
    wr32(buf, cs_off, 0);
    u64 sum = 0;
    size_t n = buf.size();
    for (size_t i = 0; i + 1 < n; i += 2) {
        u32 w = rd16(buf, i);
        sum += w;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (n & 1) { sum += buf[n - 1]; sum = (sum & 0xFFFF) + (sum >> 16); }
    wr32(buf, cs_off, (u32)(sum + n));
}

void PEFile::exports(std::vector<std::pair<std::string, u32>>& out) {
    u32 fh = e_lfanew + 4;
    u16 optsize = rd16(buf, fh + 16);
    u32 opt = fh + 20;
    u32 dd = opt + (is64 ? 112 : 96);   // data directory 0
    u32 exp_rva = rd32(buf, dd), exp_sz = rd32(buf, dd + 4);
    if (!exp_rva || !exp_sz) return;
    bool ok; u32 raw = rva2raw(exp_rva, &ok);
    if (!ok) return;
    u32 nnames = rd32(buf, raw + 24);
    u32 names_rva = rd32(buf, raw + 32);
    u32 funcs_rva = rd32(buf, raw + 28);
    u32 ords_rva  = rd32(buf, raw + 36);
    u32 nrva = rva2raw(names_rva, &ok); if (!ok) return;
    u32 frva = rva2raw(funcs_rva, &ok); if (!ok) return;
    u32 orva = rva2raw(ords_rva, &ok);  if (!ok) return;
    for (u32 i = 0; i < nnames && i < 4096; i++) {
        u32 strva = rd32(buf, nrva + i * 4);
        u32 sraw = rva2raw(strva, &ok); if (!ok) continue;
        std::string name((char*)&buf[sraw]);
        u16 ord = rd16(buf, orva + i * 2);
        u32 faddr = rd32(buf, frva + ord * 4);   // bu RVA'dir (export adresi)
        out.push_back({ name, faddr });
    }
}

void PEFile::coff_symbols(std::vector<std::pair<std::string, u32>>& out) {
    if (!symtab_n || symtab_off == 0 || symtab_off >= buf.size()) return;
    u32 n = symtab_n;
    u32 o = symtab_off;
    for (u32 i = 0; i < n; ) {
        u8 rec[18];
        if (o + 18 > buf.size()) break;
        memcpy(rec, &buf[o], 18);
        int naux = rec[17];
        i32 secnum = (i16)rd16(buf, o + 6);
        u32 val = rd32(buf, o + 4);
        u8 storage = rec[16];
        std::string name;
        if (rec[0] == 0 && rec[1] == 0 && rec[2] == 0 && rec[3] == 0) {
            u32 stro = rd32(buf, o + 4);
            u32 so = strtab_off + stro;
            if (so < buf.size()) name = (char*)&buf[so];
        } else {
            name.assign((char*)rec, 8);
            size_t z = name.find('\0');
            if (z != std::string::npos) name.resize(z);
        }
        // fonksiyon: storage 2 (external) / 3 (static), section > 0, type hi byte 0x20
        u16 type = rd16(buf, o + 8);
        if ((storage == 2 || storage == 3) && secnum > 0 && (type >> 8) == 0x20
            && (size_t)secnum <= secs.size()) {
            u32 rva = secs[secnum - 1].va + val;
            if (!name.empty() && name[0] != '.') out.push_back({ name, rva });
        }
        i += 1 + naux;
        o += 18 * (1 + naux);
    }
}
