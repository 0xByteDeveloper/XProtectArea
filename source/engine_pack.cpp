// ============================================================
// engine_pack.cpp — 0.6.0 cpPack: LZMA paketleme + strip fixups/debug
// Referans: VMProtect core/pefile.cc Save(cpPack) + runtime/loader.cc
// PACKER_INFO akisi (third-party/lzma LZMA SDK portu ile birebir).
//
// Duzen:
//   .vmp1 = [XPK1 baslik][kayitlar][props 5B][sikistirilmis akislar][stub]
//   Kayit: {src_rva, dst_rva, dst_size} — src: .vmp1 icinde akis RVA'si,
//   dst: sikistirilan bolum RVA'si, dst_size: orijinal rawsz.
//   Runtime: EP -> stub -> xrt_unpack (xrt_core.c) -> OEP.
//   Paketlenen: dizin tasimayan bolumler (import/TLS/export/reloc/debug/
//   loadcfg/IAT/CLR tasiyanlar + .vmp* muaf). ASLR temizlenir, dosya
//   compaction ile yigilir (gercek boyut kazanci).
// ============================================================
#include "engine.hpp"
#include <cstdlib>
#include <cstring>
#include "xr_cipher.h"   // 0.8.0 SectionCryptor (runtime ile ORTAK sozlesme)

extern "C" {
#include "lzma/LzmaEnc.h"
#include "lzma/LzmaDecode.h"   // LZMA_PROPERTIES_SIZE
}

// ---- LZMA SDK bellek saglayicilari (motor tarafi — malloc serbest) ----
static void* SzAllocP(void*, size_t n) { return malloc(n); }
static void  SzFreeP(void*, void* p) { free(p); }
static ISzAlloc g_EngineAlloc = { SzAllocP, SzFreeP };

static u32 pow2ceil(u32 v) {
    u32 p = 1u << 16;                       // en az 64K sozluk
    while (p < v && p < (1u << 26)) p <<= 1;
    return p;
}

// LZMA ile sikistir (birebir VMProtect altyapisi: LZMA1 + end-mark).
// dict: cagiran taraf belirler (tum akislar AYNI props ile sikistirilir —
// referanstaki tek-LzmaDecodeProperties davranisi).
bool lzma_compress(const u8* in, u32 inlen, u32 dict,
                   std::vector<u8>& out, u8 props[5]) {
    out.clear();
    if (!in || !inlen) return false;
    CLzmaEncProps p; LzmaEncProps_Init(&p);
    p.level = 9;
    p.dictSize = dict;
    p.writeEndMark = 1;                     // runtime dst_size tamamlama kontrolu
    LzmaEncProps_Normalize(&p);
    size_t cap = (size_t)inlen + inlen / 8 + 4096;
    std::vector<u8> dest(cap);
    SizeT destLen = (SizeT)dest.size();
    SizeT propsSize = LZMA_PROPERTIES_SIZE;
    SRes r = LzmaEncode(dest.data(), &destLen, in, (SizeT)inlen, &p,
                        props, &propsSize, 1, 0, &g_EngineAlloc, &g_EngineAlloc);
    if (r != 0 || propsSize != LZMA_PROPERTIES_SIZE) return false;
    out.assign(dest.data(), dest.data() + destLen);
    return true;
}

// ---------------- EP redirect stub uretecleri ----------------
// x64 (RIP-goreli cfg — ASLR-guvenli), 23 bayt:
//   NOT: xrt blob'u Linux gcc ile derlenir -> SysV ABI; ilk argiman RDI.
//   48 8D 3D rel32   lea rdi,[rip+cfg]
//   E8 rel32         call xrt_unpack
//   85 C0            test eax,eax
//   75 05            jne poison
//   E9 rel32         jmp oep
//   0F 0B            ud2 (poison)
std::vector<u8> build_packstub_x64(u32 stub_rva, u32 unpack_rva, u32 cfg_rva, u32 oep_rva,
                                   u32 tls_arr_rva = 0) {
    std::vector<u8> c;
    auto w32 = [&](u32 v) { c.push_back((u8)v); c.push_back((u8)(v >> 8)); c.push_back((u8)(v >> 16)); c.push_back((u8)(v >> 24)); };
    c.push_back(0x48); c.push_back(0x8D); c.push_back(0x3D);
    w32(cfg_rva - (stub_rva + 7));
    c.push_back(0xE8); w32(unpack_rva - (stub_rva + 12));
    c.push_back(0x85); c.push_back(0xC0);
    c.push_back(0x75); c.push_back(0x05);
    if (tls_arr_rva) {
        // 1.2.0-B2: state=1 (xrt_unpack set etmez — tramp'lar defer kalmasin)
        // lea rdi,[rip+rel] (cfg); mov byte [rdi+8],1
        u32 shere = stub_rva + 16;
        c.push_back(0x48); c.push_back(0x8D); c.push_back(0x3D); w32(cfg_rva - (shere + 7));
        c.push_back(0xC6); c.push_back(0x47); c.push_back(0x08); c.push_back(0x01);
        // 1.2.0-B2: unpack sonrasi TLS trampolin dongusu (OEP oncesi)
        // layout: lea rdi(7) call(5) test(2) jne(2) = 16; lea rbx(7) -> .loop=23
        // .loop: mov rax,[rbx](3) test(3) jz(2,rel=11) call(2) add(4) jmp(5)
        // .done = 42: jmp oep(5) ud2(2)
        u32 loop_at = stub_rva + 34;   // 16+11( state ) + 7( lea rbx )
        c.push_back(0x48); c.push_back(0x8D); c.push_back(0x1D); w32(tls_arr_rva - (stub_rva + 27 + 7));
        c.push_back(0x48); c.push_back(0x8B); c.push_back(0x03);          // mov rax,[rbx]
        c.push_back(0x48); c.push_back(0x85); c.push_back(0xC0);          // test rax,rax
        c.push_back(0x74); c.push_back(0x15);                             // jz .done (+21: call+args+add+jmp)
        c.push_back(0x31); c.push_back(0xC9);                             // xor ecx,ecx (hModule)
        c.push_back(0xBA); c.push_back(0x01); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); // mov edx,1 (DLL_PROCESS_ATTACH)
        c.push_back(0x45); c.push_back(0x31); c.push_back(0xC0);          // xor r8d,r8d (Reserved)
        c.push_back(0xFF); c.push_back(0xD0);                             // call rax
        c.push_back(0x48); c.push_back(0x83); c.push_back(0xC3); c.push_back(0x08); // add rbx,8
        c.push_back(0xE9); w32(loop_at - (stub_rva + (u32)c.size() + 4)); // jmp .loop
        // .done:
    }
    c.push_back(0xE9); w32(oep_rva - (stub_rva + (u32)c.size() + 4));
    c.push_back(0x0F); c.push_back(0x0B);
    return c;
}

// x86 (call $+5 / pop eax hilesi — ASLR-guvenli), 36 bayt:
//   E8 00000000      call $+5
//   58               pop eax            ; eax = stub+5
//   2D 05000000      sub eax,5          ; eax = stub
//   05 imm32         add eax, cfg-stub  ; eax = cfg VA
//   50               push eax
//   E8 rel32         call xrt_unpack
//   83 C4 04         add esp,4
//   85 C0            test eax,eax
//   75 05            jne poison
//   E9 rel32         jmp oep
//   0F 0B            ud2
std::vector<u8> build_packstub_x86(u32 stub_rva, u32 unpack_rva, u32 cfg_rva, u32 oep_rva,
                                   u32 tls_arr_rva = 0) {
    std::vector<u8> c;
    auto w32 = [&](u32 v) { c.push_back((u8)v); c.push_back((u8)(v >> 8)); c.push_back((u8)(v >> 16)); c.push_back((u8)(v >> 24)); };
    c.push_back(0xE8); w32(0);
    c.push_back(0x58);
    c.push_back(0x2D); w32(5);
    c.push_back(0x05); w32(cfg_rva - stub_rva);
    c.push_back(0x50);
    c.push_back(0xE8); w32(unpack_rva - (stub_rva + 22));
    c.push_back(0x83); c.push_back(0xC4); c.push_back(0x04);
    c.push_back(0x85); c.push_back(0xC0);
    c.push_back(0x75); c.push_back(0x05);
    if (tls_arr_rva) {
        // 1.2.0-B2: unpack sonrasi TLS dongusu — eax = cfg VA
        // state=1 once: mov byte [eax+8],1 (C6 40 08 01)
        c.push_back(0xC6); c.push_back(0x40); c.push_back(0x08); c.push_back(0x01);
        // dizi VA: eax = cfg + (tls_arr_rva - cfg_rva)
        c.push_back(0x05); w32(tls_arr_rva - cfg_rva);
        c.push_back(0x89); c.push_back(0xC3);                 // mov ebx,eax
        // .loop=41: mov eax,[ebx](2) test(2) jz(2,rel=6) call(2) add(3) jmp(5) — .done=53
        c.push_back(0x8B); c.push_back(0x03);                 // mov eax,[ebx]
        c.push_back(0x85); c.push_back(0xC0);                 // test
        c.push_back(0x74); c.push_back(0x10);                 // jz .done (+16: call+pushlar+add+jmp)
        c.push_back(0x6A); c.push_back(0x00);                 // push 0 (Reserved)
        c.push_back(0x6A); c.push_back(0x01);                 // push 1 (DLL_PROCESS_ATTACH)
        c.push_back(0x6A); c.push_back(0x00);                 // push 0 (hModule)
        c.push_back(0xFF); c.push_back(0xD0);                 // call eax (stdcall: args callee-temiz)
        c.push_back(0x83); c.push_back(0xC3); c.push_back(0x04); // add ebx,4
        c.push_back(0xE9); w32((stub_rva + 41) - (stub_rva + (u32)c.size() + 4)); // jmp .loop
        // .done:
    }
    c.push_back(0xE9); w32(oep_rva - (stub_rva + (u32)c.size() + 4));
    c.push_back(0x0F); c.push_back(0x0B);
    return c;
}

// ---------------- yardimci PE yazicilari ----------------
static u32 grd32(const std::vector<u8>& b, size_t o) { return (u32)b[o] | ((u32)b[o+1] << 8) | ((u32)b[o+2] << 16) | ((u32)b[o+3] << 24); }
static u16 grd16(const std::vector<u8>& b, size_t o) { return (u16)(b[o] | (b[o+1] << 8)); }
static void gwr32(std::vector<u8>& b, size_t o, u32 v) { b[o] = (u8)v; b[o+1] = (u8)(v >> 8); b[o+2] = (u8)(v >> 16); b[o+3] = (u8)(v >> 24); }
static void gwr16(std::vector<u8>& b, size_t o, u16 v) { b[o] = (u8)v; b[o+1] = (u8)(v >> 8); }

static u32 pk_opt(PEFile& pe) { return pe.e_lfanew + 4 + 20; }
static u32 pk_dd(PEFile& pe, int idx) { return pk_opt(pe) + (pe.is64 ? 112 : 96) + 8 * (u32)idx; }
static u32 pk_align(u32 v, u32 a) { return (v + a - 1) & ~(a - 1); }

// ---------------- cpStripFixups ----------------
// .reloc dizinini kaldirir + ASLR bayraklarini temizler (VMProtect:
// fixups derleme-zamaninda kesinlesir; yukleyici delta uygulamaz).
bool strip_fixups(PEFile& pe, std::vector<std::string>& log) {
    char b[256];
    u32 dd = pk_dd(pe, 5);   // directory 5 = BASERELOC
    u32 rva = grd32(pe.buf, dd), sz = grd32(pe.buf, dd + 4);
    if (rva && sz) {
        for (auto& s : pe.secs) {
            if (rva >= s.va && rva < s.va + s.vsz) {
                bool ok; u32 raw = pe.rva2raw(rva, &ok);
                if (ok && raw + sz <= pe.buf.size()) memset(&pe.buf[raw], 0, sz);
                snprintf(b, sizeof b, "[STRIPFIX] .reloc dizini silindi (%u bayt)", sz);
                log.push_back(b);
                break;
            }
        }
        gwr32(pe.buf, dd, 0); gwr32(pe.buf, dd + 4, 0);
    }
    u16 dc = grd16(pe.buf, pk_opt(pe) + 70);
    if (dc & 0x0060) {
        dc &= (u16)~0x0060;
        gwr16(pe.buf, pk_opt(pe) + 70, dc);
        log.push_back("[STRIPFIX] DYNAMIC_BASE/HIGH_ENTROPY_VA temizlendi (ASLR kapali)");
    }
    return true;
}

// ---------------- cpStripDebugInfo ----------------
bool strip_debug(PEFile& pe, std::vector<std::string>& log) {
    char b[256];
    u32 dd = pk_dd(pe, 6);   // directory 6 = DEBUG
    u32 rva = grd32(pe.buf, dd), sz = grd32(pe.buf, dd + 4);
    if (rva && sz) {
        bool ok; u32 raw = pe.rva2raw(rva, &ok);
        if (ok && raw + sz <= pe.buf.size()) memset(&pe.buf[raw], 0, sz);
        snprintf(b, sizeof b, "[STRIPDBG] debug dizini silindi (%u bayt)", sz);
        log.push_back(b);
        gwr32(pe.buf, dd, 0); gwr32(pe.buf, dd + 4, 0);
    }
    u32 fh = pe.e_lfanew + 4;
    if (pe.symtab_n && pe.symtab_off) {
        snprintf(b, sizeof b, "[STRIPDBG] COFF sembol tablosu cikarildi (%u kayit)", pe.symtab_n);
        log.push_back(b);
        gwr32(pe.buf, fh + 8, 0);
        gwr32(pe.buf, fh + 12, 0);
        pe.symtab_off = 0; pe.symtab_n = 0; pe.strtab_off = 0;
    }
    return true;
}

// ---------------- cpPack: bolum paketleme + dosya sikistirma ----------------
// 0.8.0 SectionCryptor: sectcrypt=1 iken LZMA akislari CFB-64 ile sifrelenir
// (anahtar cfg'de maskeli; runtime xrt_unpack yerinde cozer). Kayit 16B:
// {src_rva, dst_rva, dst_size, src_size} — srcsz CFB icin zorunlu.
// donus: 0 = tamam (pack_rva cfg'ye yazilir), >0 = red (err'de neden)
int do_pack(PEFile& pe, u32 cfg_rva, u32 unpack_rva,
            std::vector<std::string>& log, u32& pack_rva_out,
            u32 sectcrypt, u64 ck0, u64 ck1, std::string& err,
            bool resprot) {
    char b[320];
    pack_rva_out = 0;
    u32 opto = pk_opt(pe);
    const u32 size_before = (u32)pe.buf.size();

    // --- on-kosullar (durusluk: red edilirse NET neden) ---
    u16 fchars = grd16(pe.buf, pe.e_lfanew + 4 + 18);   // FileHeader.Characteristics
    if (fchars & 0x2000) { err = "DLL dosyalari 0.6.0'da paketlenmez (reloc/tam-loader 0.9.0'da)"; return 1; }
    // TLS: 1.2.0-B2 TAM-LOADER — callback'ler artik RED edilmez. Her
    // callback icin .vmp1 icinde trampoline uretilir: EP'den ONCE calisir,
    // once xrt_unpack ile paketli bolumleri acar, SONRA orijinal callback'e
    // atlar. Callback DIZISI de .vmp1'e tasınır (dizinin eski bolumu
    // paketlenmis olsa bile yukleyici dogru listeyi okur). NOT: dizi
    // mutlak VA tasir — ASLR'li ciktilarda --stripfixups ile birlikte
    // kullanin (yukleyici yeni dizi icin reloc yazmaz).
    u32 tls_cb_count = 0;
    std::vector<u32> tls_orig_rvas;
    {
        u32 tlrva = grd32(pe.buf, pk_dd(pe, 9));
        u32 tlsz  = grd32(pe.buf, pk_dd(pe, 9) + 4);
        if (tlrva && tlsz) {
            bool ok; u32 traw = pe.rva2raw(tlrva, &ok);
            if (ok && traw + tlsz <= pe.buf.size()) {
                u32 cboff = pe.is64 ? 24 : 12;   // AddressOfCallBacks alani
                u64 cbva = pe.is64
                    ? ((u64)grd32(pe.buf, traw + cboff) | ((u64)grd32(pe.buf, traw + cboff + 4) << 32))
                    : (u64)grd32(pe.buf, traw + cboff);
                u64 ib = pe.ib64 ? pe.ib64 : (u64)pe.imagebase;
                if (cbva > ib && cbva - ib < 0x10000000u) {
                    u32 cbrva = (u32)(cbva - ib);
                    bool okc; u32 cbraw = pe.rva2raw(cbrva, &okc);
                    if (okc) {
                        u32 entsz = pe.is64 ? 8 : 4;
                        for (u32 k = 0; k < 64; k++) {
                            u32 o = cbraw + k * entsz;
                            if (o + entsz > pe.buf.size()) break;
                            u64 v = pe.is64 ? (u64)grd32(pe.buf, o) | ((u64)grd32(pe.buf, o + 4) << 32)
                                            : (u64)grd32(pe.buf, o);
                            if (!v) break;
                            if (v > ib && v - ib < 0x10000000u)
                                tls_orig_rvas.push_back((u32)(v - ib));
                            if (tls_orig_rvas.size() >= 16) break;
                        }
                    }
                }
            }
        }
        tls_cb_count = (u32)tls_orig_rvas.size();
    }
    if (grd32(pe.buf, pk_dd(pe, 14) + 4)) { err = ".NET (CLR) dosyalari paketlenmez"; return 1; }
    if (grd32(pe.buf, pk_dd(pe, 4) + 4)) { err = "imzali (Authenticode) dosya paketlenmez"; return 1; }
    u32 oep = grd32(pe.buf, opto + 16);
    if (!oep) { err = "giris noktasi (EP) 0 — paketlenemez"; return 1; }

    // --- dizin sahibi bolumleri koru ---
    // 0 EXPORT,1 IMPORT,2 RESOURCE,3 EXCEPTION,5 RELOC,6 DEBUG,7 ARCH,
    // 9 TLS,10 LOADCFG,13 IAT,14 CLR,15 DELAY
    const int dirs[] = { 0,1,2,3,5,6,7,9,10,13,14,15 };
    std::vector<int> skip(pe.secs.size(), 0);
    u32 res_rva = 0, res_sz = 0;   // 1.2.0-B3 RESPROT kanit alani
    for (int di : dirs) {
        // 1.2.0-B3 cpResourceProtection: RESOURCE dizin sahibi bolum
        // skip-EDILMEZ — .rsrc icerigi LZMA+CFB'ye girer, unpack geri
        // yazar (VMP Resources semantigi: statikte sifreli, RAM'de acik;
        // RDT+DataEntry RVA'lari bolum yerinde kaldigi icin degismez).
        if (resprot && di == 2) continue;
        u32 rva = grd32(pe.buf, pk_dd(pe, di));
        u32 sz  = grd32(pe.buf, pk_dd(pe, di) + 4);
        if (!rva || !sz) continue;
        if (di == 2) { res_rva = rva; res_sz = sz; }
        for (size_t i = 0; i < pe.secs.size(); i++)
            if (rva >= pe.secs[i].va && rva < pe.secs[i].va + pe.secs[i].vsz) skip[i] = 1;
    }
    if (resprot && res_rva && res_sz)
        log.push_back("[RESPROT] .rsrc paket-akisina katildi (statikte sifreli; unpack geri yazar)");

    // --- ORTAK props: en buyuk bolume gore sozluk (referanstaki tek-
    //     LzmaDecodeProperties davranisi) ---
    u32 maxsec = 0;
    for (size_t i = 0; i < pe.secs.size(); i++) {
        Section& s = pe.secs[i];
        if (skip[i]) continue;
        if (strncmp(s.name, ".vmp", 4) == 0) continue;
        if (strncmp(s.name, ".tls", 4) == 0) continue;   // TLS sablonu hic paketlenmez
        if (!s.rawsz || !s.vsz) continue;
        if (s.rawsz > maxsec) maxsec = s.rawsz;
    }
    if (!maxsec) { err = "paketlenecek bolum yok (tum bolumler dizin tasiyor/muaf)"; return 1; }
    u32 dict = pow2ceil(maxsec);

    // --- adaylari sikistir ---
    struct Reg { u32 dst_rva, dst_size, src_off; u32 src_len; std::vector<u8> stream; };
    std::vector<Reg> regs;
    u8 props[5]; bool props_ok = false;
    for (size_t i = 0; i < pe.secs.size(); i++) {
        Section& s = pe.secs[i];
        if (skip[i]) continue;
        if (strncmp(s.name, ".vmp", 4) == 0) continue;
        if (strncmp(s.name, ".tls", 4) == 0) continue;   // TLS sablonu hic paketlenmez
        if (!s.rawsz || !s.vsz) continue;
        bool ok; u32 raw = pe.rva2raw(s.va, &ok);
        if (!ok || (u64)raw + s.rawsz > pe.buf.size()) continue;
        Reg r; r.dst_rva = s.va; r.dst_size = s.rawsz; r.src_off = 0;
        r.src_len = (u32)r.stream.size();   // lzma_compress sonrasi asagida guncellenir
        if (!lzma_compress(&pe.buf[raw], s.rawsz, dict, r.stream, props)) {
            snprintf(b, sizeof b, "[PACK] %s sikistirilamadi — muaf tutuldu", s.name);
            log.push_back(b);
            continue;
        }
        props_ok = true;
        r.src_len = (u32)r.stream.size();
        regs.push_back(std::move(r));
        snprintf(b, sizeof b, "[PACK] %s RVA=0x%08X %u B -> LZMA %zu B (%%%.1f)%s", s.name, s.va, s.rawsz, regs.back().stream.size(), 100.0 * regs.back().stream.size() / s.rawsz, sectcrypt ? " [CFB]" : "");
        log.push_back(b);
    }
    if (regs.empty() || !props_ok) { err = "hicbir bolum sikistirilamadi"; return 1; }

    // --- .vmp1 verisini kur ---
    u32 cur = pk_align(16 + (u32)regs.size() * 16 + 5, 16);
    std::vector<u8> data;
    auto put32 = [&](u32 v) { data.push_back((u8)v); data.push_back((u8)(v>>8)); data.push_back((u8)(v>>16)); data.push_back((u8)(v>>24)); };
    put32(0x31504B58u);           // 'XPK1'
    put32((u32)regs.size());
    put32(0);                     // props_rva (RVA'lari bolum RVA'si bilinince yazariz)
    put32(sectcrypt ? 1u : 0u);   // 0.8.0: hdr+12 rezerv = SectionCryptor flag
    for (auto& r : regs) { put32(0); put32(r.dst_rva); put32(r.dst_size); put32(0); }  // src + srcsz placeholder
    data.resize(pk_align((u32)data.size(), 16), 0);
    u32 props_off = (u32)data.size();
    data.insert(data.end(), props, props + 5);
    data.resize(pk_align((u32)data.size(), 16), 0);
    for (auto& r : regs) {
        data.resize(pk_align((u32)data.size(), 16), 0);
        r.src_off = (u32)data.size();
        if (sectcrypt) {
            // 0.8.0 SectionCryptor: AKISIN KENDISINI sifrele (kayit-bagi nonce).
            // KRITIK: compaction asamasi r.stream.data() yazar — o yuzden
            // sifreleme r.stream uzerinde yapilmali (data'da yerali sifreleme
            // compaction'in yazacagi plain ile EZILIRDI — 0.8.0 bulgusu).
            xr_cfb(ck0, ck1, XRC_NONCE(ck0, r.dst_rva),
                   r.stream.data(), r.src_len, 0 /*sifrele*/);
        }
        data.insert(data.end(), r.stream.begin(), r.stream.end());
    }
    data.resize(pk_align((u32)data.size(), 16), 0);
    u32 stub_off = (u32)data.size();
    // stub alani: 48B temel + TLS dongusu icin ek (callback varsa ~72B)
    data.resize(stub_off + 48 + (tls_cb_count ? 72 : 0), 0);
    u32 tls_tramp_off = 0, tls_arr_off = 0;
    if (tls_cb_count) {
        // TLS alani: n x tramp (128B/a) + hizalama + (n+1) x dizi-girdisi
        data.resize(pk_align((u32)data.size(), 16), 0);
        tls_tramp_off = (u32)data.size();
        data.resize(tls_tramp_off + tls_cb_count * 128, 0);
        data.resize(pk_align((u32)data.size(), 16), 0);
        tls_arr_off = (u32)data.size();
        data.resize(tls_arr_off + (tls_cb_count + 1) * (pe.is64 ? 8 : 4), 0);
    }

    u32 vmp1_rva = 0;
    if (!pe.add_section(".vmp1", data, 0xE00000E0u /*RWX*/, vmp1_rva)) {
        err = ".vmp1 bolumu eklenemedi"; return 1;
    }
    // RVA'lari cfg/records icine yaz
    {
        bool ok; u32 praw = pe.rva2raw(vmp1_rva, &ok);
        if (!ok) { err = ".vmp1 raw erisilemiyor"; return 1; }
        gwr32(pe.buf, praw + 8, vmp1_rva + props_off);
        for (size_t i = 0; i < regs.size(); i++) {
            gwr32(pe.buf, praw + 16 + (u32)i * 16, vmp1_rva + regs[i].src_off);
            gwr32(pe.buf, praw + 16 + (u32)i * 16 + 12, regs[i].src_len);   // 0.8.0: srcsz
        }
    }
    if (sectcrypt)
        log.push_back("[SECTCRYPT] akislar CFB-64 sifrelendi (anahtar cfg'de maskeli, kayit-bagi nonce)");
    // stub'i gercek RVA'lerle uret ve yerlestir
    u32 stub_rva = vmp1_rva + stub_off;
    {
        u32 tls_arr_rva = tls_cb_count ? (vmp1_rva + tls_arr_off) : 0;
        std::vector<u8> st = pe.is64 ? build_packstub_x64(stub_rva, unpack_rva, cfg_rva, oep, tls_arr_rva)
                                     : build_packstub_x86(stub_rva, unpack_rva, cfg_rva, oep, tls_arr_rva);
        st.resize(48 + (tls_cb_count ? 72 : 0), 0xCC);
        bool ok; u32 sraw = pe.rva2raw(stub_rva, &ok);
        if (!ok) { err = "stub raw erisilemiyor"; return 1; }
        memcpy(&pe.buf[sraw], st.data(), st.size());
    }
    // EP -> stub
    gwr32(pe.buf, opto + 16, stub_rva);
    snprintf(b, sizeof b, "[PACK] EP 0x%X -> unpack stub 0x%X (.vmp1) | OEP 0x%X stub'e gomuldu", oep, stub_rva, oep);
    log.push_back(b);



    // --- ASLR temizle (fixups artik yukleyicide uygulanmaz) ---
    {
        u16 dc = grd16(pe.buf, opto + 70);
        dc &= (u16)~0x0060;
        gwr16(pe.buf, opto + 70, dc);
        log.push_back("[PACK] DYNAMIC_BASE/HIGH_ENTROPY_VA temizlendi (sabit taban)");
    }

        // --- 1.2.0-B2: TLS trampoline'leri + callback dizisi tasinmasi ---
    if (tls_cb_count) {
        bool okv; u32 vraw = pe.rva2raw(vmp1_rva, &okv);
        if (!okv) { err = ".vmp1 raw erisilemiyor (TLS)"; return 1; }
        u64 ib = pe.ib64 ? pe.ib64 : (u64)pe.imagebase;
        u32 entsz = pe.is64 ? 8 : 4;
        for (u32 k = 0; k < tls_cb_count; k++) {
            u32 tramp_rva = vmp1_rva + tls_tramp_off + k * 128;
            u32 orig_rva = tls_orig_rvas[k];
            std::vector<u8> t;
            auto w32 = [&](u32 v) { t.push_back((u8)v); t.push_back((u8)(v >> 8)); t.push_back((u8)(v >> 16)); t.push_back((u8)(v >> 24)); };
            if (pe.is64) {
                /* DEFER tasarimi: TLS-zamaninda (cfg state=0) NO-OP ret;
                   EP-stub unpack'ten sonra dongude cagirir (state=1) ->
                   callback paket-acilmis bellekte calisir, yazimlari
                   unpack tarafindan EZILMEZ (tls_ran=0 kaniti).
                   SIRA DERSI (0x80000004 kaniti): push regs SONRA pushfq;
                   popfq SONRA pop regs — aksi halde popfq rax-slot'unu
                   bayrak diye yukler (TF=1 -> single-step krizi). */
                for (int r = 15; r >= 8; r--) { t.push_back(0x41); t.push_back((u8)(0x50 + (r - 8))); }
                t.push_back(0x57); t.push_back(0x56); t.push_back(0x55); t.push_back(0x53);
                t.push_back(0x52); t.push_back(0x51); t.push_back(0x50);
                t.push_back(0x9C);
                // lea r11,[rip+rel32] -> cfg VA (r11 volatile)
                u32 here = tramp_rva + 24;
                t.push_back(0x4C); t.push_back(0x8D); t.push_back(0x1D); w32(cfg_rva - (here + 7));
                // cmp byte [r11+8],0 ; je .defer (state=0: TLS zamanı -> no-op)
                // (ModRM 7B = rm=r11; 79 olursa r9 okunur — junk-state -> erken
                //  callback calisir, unpack yazimlarini ezilirdi: 0xC0000005)
                t.push_back(0x41); t.push_back(0x80); t.push_back(0x7B); t.push_back(0x08); t.push_back(0x00);
                t.push_back(0x74); t.push_back(0x1D);   // je +29 (defer'daki popfq'ya)
                // popfq + 15 pop + jmp orig (hedef = gercel callback)
                t.push_back(0x9D);
                t.push_back(0x58); t.push_back(0x59); t.push_back(0x5A); t.push_back(0x5B);
                t.push_back(0x5D); t.push_back(0x5E); t.push_back(0x5F);
                for (int r = 8; r <= 15; r++) { t.push_back(0x41); t.push_back((u8)(0x58 + (r - 8))); }
                u32 jafter = tramp_rva + (u32)t.size() + 5;
                t.push_back(0xE9); w32(orig_rva - jafter);
                // .defer: popfq + 15 pop + ret
                t.push_back(0x9D);
                t.push_back(0x58); t.push_back(0x59); t.push_back(0x5A); t.push_back(0x5B);
                t.push_back(0x5D); t.push_back(0x5E); t.push_back(0x5F);
                for (int r = 8; r <= 15; r++) { t.push_back(0x41); t.push_back((u8)(0x58 + (r - 8))); }
                t.push_back(0xC3);
                t.resize(128, 0xCC);
            } else {
                // pushad + pushfd
                t.push_back(0x60); t.push_back(0x9C);
                // call $+5; pop eax; sub eax,7 -> eax = tramp rva
                // (pushad+pushfd = 2 bayt once: pop edilen deger tramp+7)
                t.push_back(0xE8); w32(0);
                t.push_back(0x58);
                t.push_back(0x2D); w32(7);
                // add eax, (cfg_rva - tramp_rva) -> eax = cfg VA
                t.push_back(0x05); w32(cfg_rva - tramp_rva);
                // cmp byte [eax+8],0 ; je .defer (state=0: TLS zamanı -> no-op)
                t.push_back(0x80); t.push_back(0x78); t.push_back(0x08); t.push_back(0x00);
                t.push_back(0x74); t.push_back(0x07);   // je +7 (defer'daki popfd'ye)
                // popfd + popad + jmp orig
                t.push_back(0x9D); t.push_back(0x61);
                u32 jafter = tramp_rva + (u32)t.size() + 5;
                t.push_back(0xE9); w32(orig_rva - jafter);
                // .defer: popfd + popad + ret
                t.push_back(0x9D); t.push_back(0x61); t.push_back(0xC3);
                t.resize(128, 0xCC);
            }
            bool okt; u32 traw2 = pe.rva2raw(tramp_rva, &okt);
            if (!okt) { err = "trampolin raw erisilemiyor"; return 1; }
            memcpy(&pe.buf[traw2], t.data(), t.size());
        }
        // yeni callback dizisi (mutlak VA'lar) + TLS-dir guncelleme
        for (u32 k = 0; k < tls_cb_count; k++) {
            u32 ao = tls_arr_off + k * entsz;
            u64 va = (u64)(vmp1_rva + tls_tramp_off + k * 128) + ib;
            if (pe.is64) {
                gwr32(pe.buf, vraw + ao, (u32)va);
                gwr32(pe.buf, vraw + ao + 4, (u32)(va >> 32));
            } else gwr32(pe.buf, vraw + ao, (u32)va);
        }
        // sonlandirici 0
        if (pe.is64) {
            gwr32(pe.buf, vraw + tls_arr_off + tls_cb_count * 8, 0);
            gwr32(pe.buf, vraw + tls_arr_off + tls_cb_count * 8 + 4, 0);
        } else gwr32(pe.buf, vraw + tls_arr_off + tls_cb_count * 4, 0);
        // TLS-dir AddressOfCallBacks -> yeni dizi VA
        bool okd; u32 draw = pe.rva2raw(grd32(pe.buf, pk_dd(pe, 9)), &okd);
        if (okd) {
            u32 cboff = pe.is64 ? 24 : 12;
            u64 newarr = (u64)(vmp1_rva + tls_arr_off) + ib;
            if (pe.is64) {
                gwr32(pe.buf, draw + cboff, (u32)newarr);
                gwr32(pe.buf, draw + cboff + 4, (u32)(newarr >> 32));
            } else gwr32(pe.buf, draw + cboff, (u32)newarr);
        }
        snprintf(b, sizeof b, "[TLS-LOADER] %u callback -> .vmp1 trampolin + EP-sonrasi cagri dongusu (defer-tasarim: callback paket-acilmis bellekte calisir)", tls_cb_count);
        log.push_back(b);
    }

    // --- COFF sembolleri (compaction sonrasi ofset gecersiz kalir) ---
    if (pe.symtab_n && pe.symtab_off) {
        u32 fh2 = pe.e_lfanew + 4;
        gwr32(pe.buf, fh2 + 8, 0); gwr32(pe.buf, fh2 + 12, 0);
        pe.symtab_off = 0; pe.symtab_n = 0; pe.strtab_off = 0;
        log.push_back("[PACK] COFF sembol tablosu cikarildi");
    }

    // --- bolum rawsz'lerini sikismis boyuta cek + DOSYA COMPACTION ---
    {
        u32 fh = pe.e_lfanew + 4;
        u16 optsize = grd16(pe.buf, fh + 16);
        u32 sh = fh + 20 + optsize;
        for (auto& r : regs) {
            for (size_t i = 0; i < pe.secs.size(); i++) {
                if (pe.secs[i].va == r.dst_rva) {
                    u32 newraw = pk_align((u32)r.stream.size(), pe.filealign);
                    gwr32(pe.buf, sh + (u32)i * 40 + 16, newraw);
                    pe.secs[i].rawsz = newraw;
                }
            }
        }
        u32 ns = (u32)pe.secs.size();
        u32 headers_end = sh + ns * 40;
        u32 cursor = pk_align(headers_end, pe.filealign);
        std::vector<u32> newoff(ns, 0);
        for (u32 i = 0; i < ns; i++) {
            if (!pe.secs[i].rawsz) continue;
            cursor = pk_align(cursor, pe.filealign);
            newoff[i] = cursor;
            cursor += pe.secs[i].rawsz;
        }
        std::vector<u8> nb((size_t)cursor, 0);
        memcpy(&nb[0], &pe.buf[0], headers_end);
        for (u32 i = 0; i < ns; i++) {
            if (!newoff[i]) continue;
            Section& s = pe.secs[i];
            // 0.6.0 KRITIK: paketlenen bolumlere ORIJINAL baytlar degil,
            // SIKISTIRILMIS akis yazilir (rawsz zaten sikismis boyuta cekildi).
            bool is_packed = false;
            for (auto& r : regs) {
                if (r.dst_rva == s.va) {
                    memcpy(&nb[newoff[i]], r.stream.data(), r.stream.size());
                    is_packed = true;
                    break;
                }
            }
            if (!is_packed && (u64)s.rawoff + s.rawsz <= pe.buf.size())
                memcpy(&nb[newoff[i]], &pe.buf[s.rawoff], s.rawsz);
            gwr32(nb, sh + i * 40 + 20, newoff[i]);
            s.rawoff = newoff[i];
        }
        pe.buf.swap(nb);
        u32 newsoh = pk_align(headers_end, pe.filealign);
        gwr32(pe.buf, opto + 60, newsoh);
        pe.sizeofheaders = newsoh;
        snprintf(b, sizeof b, "[PACK] dosya compaction: %u -> %u bayt", size_before, (u32)pe.buf.size());
        log.push_back(b);
    }
    pack_rva_out = vmp1_rva;
    err.clear();
    return 0;
}
