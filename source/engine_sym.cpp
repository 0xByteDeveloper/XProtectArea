// ============================================================
// engine_sym.cpp — PDB / MAP / stub fonksiyon kesfi (port)
// Kaynak referans: universalObfusPublicSrc core/pdb.h (wine
// kodundan tureyen PDB_DS_HEADER / pdb_ds_reader / S_* sabitleri)
// ve VMProtect GUI'nin sembol listeleme davranisi.
//
// Dogrulama (gercek dosyalarla, bu sandbox):
//   Test64.pdb       -> WrapPos 0x1000/0x28, MovePlayer 0x1030/0xA4,
//                       GhostStep 0x10E0/0xD0, CheckCollision 0x11B0/0x4C,
//                       GameTick 0x1200/0x35  (export tablosuyla BIREBIR)
//   pepeek_cozum.pdb -> 1305 GPROC (seg=1)
//   XProtectUI.pdb   -> 1604 GPROC (seg=1)
// ============================================================
#include "engine_sym.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>

// ---------------- yardimcilar ----------------
static su16 rd16(const su8* p) { su16 v; memcpy(&v, p, 2); return v; }
static su32 rd32(const su8* p) { su32 v; memcpy(&v, p, 4); return v; }

// CodeView sembol tipleri (pdb.h birebir)
#define S_PUB_V3      0x110E
#define S_LPROC_V3    0x110F
#define S_GPROC_V3    0x1110
#define S_LPROC32_ID  0x1146
#define S_GPROC32_ID  0x1147

// ============================================================
// PDB (MSF 7.00 "DS" bicimi)
// ============================================================
struct PdbStreams {
    const su8* d = NULL;
    size_t dlen = 0;
    su32 block_size = 0;
    su32 num_blocks = 0;
    struct SInfo { su32 size = 0xFFFFFFFFu; std::vector<su32> blocks; };
    std::vector<SInfo> streams;
    bool ok = false;

    bool init(const su8* data, size_t n, std::string& err) {
        d = data; dlen = n;
        if (n < 64) { err = "PDB cok kucuk"; return false; }
        static const char SIG[] = "Microsoft C/C++ MSF 7.00";
        if (memcmp(data, SIG, 24) != 0) {
            // JG (PDB2) bicimi — NB10
            if (memcmp(data, "Microsoft C/C++ program database 2.00", 37) == 0)
                err = "PDB2 (JG) bicimi desteklenmiyor";
            else
                err = "PDB imzasi gecersiz";
            return false;
        }
        block_size = rd32(data + 32);
        su32 free_block = rd32(data + 36);
        num_blocks = rd32(data + 40);
        su32 dir_size = rd32(data + 44);
        su32 block_map_block = rd32(data + 52);
        (void)free_block;
        if (block_size < 64 || block_size > 0x100000 || !num_blocks ||
            (size_t)num_blocks * block_size > dlen + block_size) {
            err = "PDB superblog bozuk"; return false;
        }
        // akis dizini: block_map_block'in gosterdigi bloglarda blok listesi
        su32 ndir_blocks = (dir_size + block_size - 1) / block_size;
        if ((size_t)block_map_block * block_size + (size_t)ndir_blocks * 4 > dlen) {
            err = "PDB blok haritasi tasma"; return false;
        }
        std::vector<su32> dir_blocks(ndir_blocks);
        memcpy(dir_blocks.data(), data + (size_t)block_map_block * block_size, (size_t)ndir_blocks * 4);
        for (su32 b : dir_blocks)
            if ((size_t)b * block_size + block_size > dlen) { err = "PDB dir blogu tasma"; return false; }
        std::vector<su8> dir((size_t)dir_size);
        size_t got = 0;
        for (su32 b : dir_blocks) {
            size_t take = std::min((size_t)block_size, dir.size() - got);
            memcpy(dir.data() + got, data + (size_t)b * block_size, take);
            got += take;
        }
        // akis dizini cozumle
        if (dir.size() < 4) { err = "PDB akis dizini bos"; return false; }
        su32 nstreams = rd32(dir.data());
        if (nstreams > 0x10000) { err = "PDB akis sayisi sacma"; return false; }
        streams.resize(nstreams);
        size_t off = 4 + (size_t)nstreams * 4;
        if (off > dir.size()) { err = "PDB akis dizini kirik"; return false; }
        for (su32 i = 0; i < nstreams; i++) {
            su32 sz = rd32(dir.data() + 4 + (size_t)i * 4);
            streams[i].size = sz;
            if (sz == 0xFFFFFFFFu || sz == 0) continue;
            su32 nb = (sz + block_size - 1) / block_size;
            if (off + (size_t)nb * 4 > dir.size()) { streams[i].size = 0xFFFFFFFFu; continue; }
            streams[i].blocks.resize(nb);
            memcpy(streams[i].blocks.data(), dir.data() + off, (size_t)nb * 4);
            off += (size_t)nb * 4;
        }
        ok = true;
        return true;
    }

    // akisi tampona oku
    bool read_stream(su32 idx, std::vector<su8>& out) const {
        if (idx >= streams.size()) return false;
        const SInfo& s = streams[idx];
        if (s.size == 0xFFFFFFFFu || s.size == 0 || s.blocks.empty()) return false;
        out.resize(s.size);
        size_t got = 0;
        for (su32 b : s.blocks) {
            size_t take = std::min((size_t)block_size, out.size() - got);
            if ((size_t)b * block_size + take > dlen) return false;
            memcpy(out.data() + got, d + (size_t)b * block_size, take);
            got += take;
        }
        return true;
    }
};

// CV kayit yuruyusu: [u16 reclen][u16 tip][payload]; ilerleme reclen+2.
// geri donus: toplanan kod sembolleri (seg,off,size,name).
struct CvFunc { su16 seg; su32 off; su32 size; std::string name; };

static size_t cv_walk(const su8* ms, size_t len, size_t skip,
                      const SymSections& secs, std::vector<CvFunc>& out) {
    size_t p = skip;
    while (p + 4 <= len) {
        su16 reclen = rd16(ms + p);
        su16 rectype = rd16(ms + p + 2);
        if (reclen < 2 || p + (size_t)reclen + 2 > len) break;
        if (rectype == S_GPROC_V3 || rectype == S_LPROC_V3 ||
            rectype == S_GPROC32_ID || rectype == S_LPROC32_ID) {
            if (reclen >= 0x28) {
                CvFunc f;
                f.size = rd32(ms + p + 0x10);
                f.off = rd32(ms + p + 0x20);
                f.seg = rd16(ms + p + 0x24);
                const su8* nb = ms + p + 0x27;
                const su8* ne = ms + p + reclen + 2;
                const su8* q = nb;
                while (q < ne && *q) q++;
                f.name.assign((const char*)nb, (size_t)(q - nb));
                out.push_back(f);
            }
        } else if (rectype == S_PUB_V3) {
            if (reclen >= 0x0e) {
                su32 fl = rd32(ms + p + 0x04);
                su32 off = rd32(ms + p + 0x08);
                su16 seg = rd16(ms + p + 0x0C);
                if (fl != 0) {          // lld: 2=kod; MSVC: 1=kod — ikisi de alinir, exec filtresi asagida
                    CvFunc f;
                    f.seg = seg; f.off = off; f.size = 0;
                    const su8* nb = ms + p + 0x0E;
                    const su8* ne = ms + p + reclen + 2;
                    const su8* q = nb;
                    while (q < ne && *q) q++;
                    f.name.assign((const char*)nb, (size_t)(q - nb));
                    out.push_back(f);
                }
            }
        }
        p += (size_t)reclen + 2;
    }
    return out.size();
}

bool pdb_parse(const su8* data, size_t n, const SymSections& secs,
               std::vector<SymEntry>& out, std::string& err) {
    PdbStreams ps;
    if (!ps.init(data, n, err)) return false;
    // DBI akisi = 3
    std::vector<su8> dbi;
    if (!ps.read_stream(3, dbi) || dbi.size() < 64) { err = "DBI akisi okunamadi"; return false; }
    su16 symrec_stream = rd16(dbi.data() + 0x14);
    su32 modi_sz = rd32(dbi.data() + 0x18);
    if (modi_sz == 0 || 64 + (size_t)modi_sz > dbi.size()) { err = "DBI modul listesi yok"; return false; }
    size_t end = 64 + (size_t)modi_sz;

    // --- modul listesi: 64 bayt sabit + zstring + zstring + pad4 ---
    // (lld/LLVM bicimi; MSVC 28B+pstring bicimi de denenir, temiz yuruyen kazanir)
    struct Mod { su16 stream; std::string name; };
    std::vector<Mod> mods;
    {
        size_t o = 64;
        while (o + 64 <= end) {
            Mod m;
            m.stream = rd16(dbi.data() + o + 0x22);
            size_t p = o + 64;
            for (int k = 0; k < 2; k++) {
                size_t q = p;
                while (q < end && dbi[q]) q++;
                if (q >= end) break;
                std::string nm((const char*)dbi.data() + p, q - p);
                if (k == 0) m.name = nm;
                p = q + 1;
            }
            p = (p + 3) & ~(size_t)3;
            if (p <= o) break;
            mods.push_back(m);
            o = p;
        }
        if (mods.empty() || 64 + modi_sz < o - 8) {
            // MSVC bicimi dene: 28 bayt + pstring mod + pstring obj + pad4
            mods.clear();
            size_t o = 64;
            while (o + 28 <= end) {
                Mod m;
                m.stream = (su16)rd32(dbi.data() + o);  // MSVC: ilk u32 = akis indeksi
                size_t p = o + 28;
                for (int k = 0; k < 2 && p < end; k++) {
                    su8 l = dbi[p]; p++;
                    if (p + l > end) break;
                    std::string nm((const char*)dbi.data() + p, l);
                    if (k == 0) m.name = nm;
                    p += l;
                }
                p = (p + 3) & ~(size_t)3;
                if (p <= o) break;
                mods.push_back(m);
                o = p;
            }
        }
    }

    std::vector<CvFunc> all;
    // modul akislari
    for (auto& m : mods) {
        if (m.stream == 0xFFFF || m.stream >= ps.streams.size()) continue;
        std::vector<su8> ms;
        if (!ps.read_stream(m.stream, ms) || ms.size() < 8) continue;
        std::vector<CvFunc> a, b;
        cv_walk(ms.data(), ms.size(), 4, secs, a);
        cv_walk(ms.data(), ms.size(), 0, secs, b);
        for (auto& f : (a.size() >= b.size() ? a : b)) all.push_back(f);
    }
    // global publics (symrecord akisi) — GPROC kapsamayan RVA'lar icin
    std::vector<CvFunc> pubs;
    if (symrec_stream != 0xFFFF && symrec_stream < ps.streams.size()) {
        std::vector<su8> ms;
        if (ps.read_stream(symrec_stream, ms))
            cv_walk(ms.data(), ms.size(), 0, secs, pubs);
    }

    // birlestir: GPROC oncelikli (boyut bilir), PUB32 bosluklari doldurur
    std::vector<SymEntry> res;
    std::vector<bool> taken;
    for (auto& f : all) {
        su32 rva;
        if (!secs.seg_rva(f.seg, f.off, &rva)) continue;
        if (!secs.rva_exec(rva)) continue;
        if (f.name.empty() || f.name[0] == '.') continue;
        SymEntry e;
        e.rva = rva; e.size = f.size; e.name = f.name; e.source = SYM_PDB;
        res.push_back(e);
    }
    std::sort(res.begin(), res.end(), [](const SymEntry& a, const SymEntry& b) { return a.rva < b.rva; });
    res.erase(std::unique(res.begin(), res.end(), [](const SymEntry& a, const SymEntry& b) { return a.rva == b.rva; }), res.end());
    for (auto& f : pubs) {
        su32 rva;
        if (!secs.seg_rva(f.seg, f.off, &rva)) continue;
        if (!secs.rva_exec(rva)) continue;
        if (f.name.empty() || f.name[0] == '.') continue;
        // zaten var mi (ikili arama)?
        auto it = std::lower_bound(res.begin(), res.end(), rva,
            [](const SymEntry& e, su32 v) { return e.rva < v; });
        if (it != res.end() && it->rva == rva) continue;
        SymEntry e;
        e.rva = rva; e.size = 0; e.name = f.name; e.source = SYM_PDB;
        res.insert(it, e);
    }
    if (res.empty()) { err = "PDB icinde kod sembulu yok"; return false; }
    out.insert(out.end(), res.begin(), res.end());
    err = "";
    return true;
}

// ============================================================
// MAP (MS linker / lld)
//  "0001:00000030  _main  00401030 f  main.obj"
// ============================================================
static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool map_parse(const char* text, size_t n, const SymSections& secs,
               su32 imagebase, std::vector<SymEntry>& out, std::string& err) {
    if (!text || n < 16) { err = "map bos"; return false; }
    size_t i = 0, nlstart = 0;
    int found = 0;
    std::vector<SymEntry> res;
    while (i <= n) {
        bool eol = (i == n) || (text[i] == '\n');
        if (!eol) { i++; continue; }
        size_t len = i - nlstart;
        const char* L = text + nlstart;
        if (len > 8) {
            const char* p = L;
            while (*p == ' ' || *p == '\t') p++;
            // "SSSS:OOOOOOOO" ayraci
            const char* colon = NULL;
            for (const char* q = p; q < p + 12 && *q; q++)
                if (*q == ':') { colon = q; break; }
            if (colon && colon - p == 4) {
                bool hexok = true;
                for (const char* q = p; q < colon; q++) if (hexv(*q) < 0) hexok = false;
                if (hexok) {
                    su32 seg = 0, off = 0;
                    for (int k = 0; k < 4; k++) seg = seg * 16 + (su32)hexv(p[k]);
                    size_t olen = 0;
                    const char* q = colon + 1;
                    while (q < L + len && hexv(*q) >= 0 && olen < 8) { off = off * 16 + (su32)hexv(*q); q++; olen++; }
                    // isim: ilk bosluk sonrasi token
                    const char* nstart = q;
                    while (nstart < L + len && (*nstart == ' ' || *nstart == '\t')) nstart++;
                    const char* nend = nstart;
                    while (nend < L + len && *nend != ' ' && *nend != '\t' && *nend != '\r') nend++;
                    if (nend > nstart) {
                        std::string nm(nstart, (size_t)(nend - nstart));
                        // kolon sirasi: seg:off  isim  VA(hex)  flag(f)  obj
                        // VA kolonunu atla
                        const char* vstart = nend;
                        while (vstart < L + len && (*vstart == ' ' || *vstart == '\t')) vstart++;
                        const char* vend = vstart;
                        while (vend < L + len && *vend != ' ' && *vend != '\t' && *vend != '\r') vend++;
                        // flag kolonu: tek harf 'f'/'F' (fonksiyon)
                        const char* fstart = vend;
                        while (fstart < L + len && (*fstart == ' ' || *fstart == '\t')) fstart++;
                        const char* fend = fstart;
                        while (fend < L + len && *fend != ' ' && *fend != '\t' && *fend != '\r') fend++;
                        bool isfunc = (fend - fstart == 1) && (*fstart == 'f' || *fstart == 'F');
                        if (isfunc && nm[0] != 0 && seg > 0 && seg <= secs.secs.size()) {
                            su32 rva = secs.secs[seg - 1].va + off;
                            if (secs.rva_exec(rva)) {
                                SymEntry e;
                                e.rva = rva; e.size = 0;
                                e.name = nm;
                                e.source = SYM_MAP;
                                res.push_back(e);
                                found++;
                            }
                        }
                    }
                }
            }
        }
        nlstart = i + 1;
        i++;
    }
    if (res.empty()) { err = "map icinde fonksiyon yok"; return false; }
    std::sort(res.begin(), res.end(), [](const SymEntry& a, const SymEntry& b) { return a.rva < b.rva; });
    res.erase(std::unique(res.begin(), res.end(), [](const SymEntry& a, const SymEntry& b) { return a.rva == b.rva; }), res.end());
    out.insert(out.end(), res.begin(), res.end());
    (void)imagebase;
    err = "";
    return true;
}

// ============================================================
// debug dizini: RSDS/NB10 kayitlarindan PDB adlari + GUID/age
// ============================================================
void pe_debug_pdb_names(const su8* pe, size_t n, const SymSections& secs,
                        std::vector<DbgPdbRef>& out) {
    if (n < 0x200) return;
    su32 e_lfanew = rd32(pe + 0x3C);
    if (e_lfanew + 0x100 > n || memcmp(pe + e_lfanew, "PE\0\0", 4) != 0) return;
    const su8* coff = pe + e_lfanew + 4;
    const su8* opt = coff + 20;
    su16 magic = rd16(opt);
    const su8* dd = opt + (magic == 0x20B ? 112 : 96);
    su32 dbg_rva = rd32(dd + 6 * 8);
    su32 dbg_sz = rd32(dd + 6 * 8 + 4);
    if (!dbg_rva || !dbg_sz) return;
    // rva -> dosya ofseti
    auto r2f = [&](su32 rva) -> size_t {
        for (auto& s : secs.secs)
            if (rva >= s.va && rva < s.va + (s.rawsz ? s.rawsz : s.vsz)) return s.rawptr + (rva - s.va);
        return 0;
    };
    size_t off = r2f(dbg_rva);
    if (!off || off + dbg_sz > n) return;
    for (su32 i = 0; i + 28 <= dbg_sz; i += 28) {
        const su8* e = pe + off + i;
        su32 typ = rd32(e + 12);
        su32 sz = rd32(e + 16);
        size_t raw = rd32(e + 24);   // PointerToRawData (+24)
        if (typ != 2 || !sz || !raw || raw + sz > n) continue;   // IMAGE_DEBUG_TYPE_CODEVIEW
        const su8* cv = pe + raw;
        if (sz < 24) continue;
        DbgPdbRef ref;
        if (memcmp(cv, "RSDS", 4) == 0) {
            memcpy(ref.guid, cv + 4, 16);
            ref.age = rd32(cv + 20);
            ref.has_guid = true;
            const char* nm = (const char*)cv + 24;
            if (*nm) { ref.name = nm; out.push_back(ref); }
        } else if (memcmp(cv, "NB10", 4) == 0 && sz >= 16) {
            const char* nm = (const char*)cv + 16;
            if (*nm) { ref.name = nm; out.push_back(ref); }   // NB10: sig+offset yerine timestamp; guid yok
        }
    }
}

// PDB info akisi (stream 1): Version, TimeDateStamp, Age, GUID, cbNames...
// VC70+ ve LLVM bicimleri ayni duzen — dogrulama gercek dosyalarla yapildi:
//   Test64.pdb age=1 guid=0ad37762... == exe RSDS (ESLESME=True)
//   pepeek_cozum.pdb age=1 guid=265a2b1a... == exe RSDS (ESLESME=True)
bool pdb_matches(const su8* data, size_t n, const su8 guid[16], su32 age) {
    if (!data || n < 64) return false;
    PdbStreams ps;
    std::string err;
    if (!ps.init(data, n, err)) return false;
    if (ps.streams.size() < 2) return false;
    std::vector<su8> info;
    if (!ps.read_stream(1, info) || info.size() < 28) return false;
    su32 a = rd32(info.data() + 8);
    if (a != age) return false;
    return memcmp(info.data() + 12, guid, 16) == 0;
}

// ============================================================
// stub taramasi: pdb/map yoksa — VMProtect davranisi
// giris noktasi + prologue desenleri (16 bayt hizali)
// ============================================================
static bool match_patt(const su8* p, size_t rem, const su8* patt, size_t plen) {
    if (rem < plen) return false;
    return memcmp(p, patt, plen) == 0;
}

void stub_scan(const su8* pe, size_t n, const SymSections& secs,
               bool is64, su32 ep_rva, std::vector<SymEntry>& out) {
    // giris noktasi
    if (ep_rva && secs.rva_exec(ep_rva)) {
        SymEntry e;
        char b[32];
        snprintf(b, sizeof b, "entry_%08X", ep_rva);
        e.rva = ep_rva; e.name = b; e.source = SYM_STUB;
        out.push_back(e);
    }
    auto r2f = [&](su32 rva) -> size_t {
        for (auto& s : secs.secs)
            if (rva >= s.va && rva < s.va + (s.rawsz ? s.rawsz : s.vsz)) return s.rawptr + (rva - s.va);
        return 0;
    };
    static const su8 p64[][8] = {
        { 0x55, 0x48, 0x89, 0xE5 },        // push rbp; mov rbp,rsp (clang kodlamasi)
        { 0x55, 0x48, 0x8B, 0xEC },        // push rbp; mov rbp,rsp (alternatif)
        { 0x55, 0x56, 0x57 },              // push rbp,rsi,rdi
        { 0x55, 0x57, 0x56 },
        { 0x55, 0x53 },                    // push rbp,rbx
        { 0x55, 0x41, 0x54 },              // push rbp,r12..
        { 0x55, 0x41, 0x55 },
        { 0x55, 0x41, 0x56 },
        { 0x55, 0x41, 0x57 },
        { 0x48, 0x83, 0xEC },              // sub rsp, imm8
        { 0x48, 0x81, 0xEC },              // sub rsp, imm32
        { 0xF3, 0x0F, 0x1E, 0xFA },        // endbr64 (CET)
        { 0x53, 0x48, 0x89, 0x5C, 0x24 },  // push rbx; mov [rsp+8],rbx
        { 0x57, 0x48, 0x89, 0x5C, 0x24 },
        { 0x56, 0x57 },                    // push rsi,rdi
        { 0x53, 0x56 },
        { 0x53, 0x57 },
        { 0x41, 0x54 },                    // push r12..r15
        { 0x41, 0x55 },
        { 0x41, 0x56 },
        { 0x41, 0x57 },
        { 0x40, 0x53 },                    // push rbx (REX)
        { 0x40, 0x55 },
        { 0x40, 0x56 },
        { 0x40, 0x57 },
        { 0x48, 0x89, 0x5C, 0x24 },        // mov [rsp+8],rbx
    };
    static const size_t p64l[] = { 4, 4, 3, 3, 2, 3, 3, 3, 3, 3, 3, 4, 5, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4 };
    static const su8 p32[][8] = {
        { 0x55, 0x8B, 0xEC },              // push ebp; mov ebp,esp
        { 0x55, 0x89, 0xE5 },              // (alternatif kodlama)
        { 0x53, 0x56, 0x57 },              // push rbx,rsi,rdi
        { 0x56, 0x57 },
        { 0x53, 0x56 },
        { 0x51, 0x52 },
        { 0x83, 0xEC },                    // sub esp, imm8
        { 0x81, 0xEC },                    // sub esp, imm32
        { 0xA1 },                          // mov eax, [abs]
    };
    static const size_t p32l[] = { 3, 3, 3, 2, 2, 2, 2, 2, 1 };

    for (auto& s : secs.secs) {
        if (!s.is_exec() || !s.rawsz) continue;
        for (su32 rva = (s.va + 15) & ~(su32)15; rva + 16 < s.va + s.vsz; rva += 16) {
            size_t off = r2f(rva);
            if (!off || off + 16 > n) continue;
            const su8* p = pe + off;
            size_t rem = n - off;
            bool hit = false;
            if (is64) {
                for (size_t k = 0; k < sizeof(p64l) / sizeof(p64l[0]) && !hit; k++)
                    hit = match_patt(p, rem, p64[k], p64l[k]);
            } else {
                for (size_t k = 0; k < sizeof(p32l) / sizeof(p32l[0]) && !hit; k++)
                    hit = match_patt(p, rem, p32[k], p32l[k]);
            }
            if (!hit) continue;
            // zaten listelenmis RVA mi? (cagiran dedupe yapar; burada sadece out)
            SymEntry e;
            char b[32];
            snprintf(b, sizeof b, "stub_%08X", rva);
            e.rva = rva; e.name = b; e.source = SYM_STUB;
            out.push_back(e);
        }
    }
}
