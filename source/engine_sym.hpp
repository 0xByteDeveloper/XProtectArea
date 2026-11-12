// ============================================================
// engine_sym.hpp — PDB / MAP / stub fonksiyon kesfi
// universalObfusPublicSrc core/pdb.h + function_dialog.cc
// davranisinin XProtect portu (kaynagi: VMProtect 3.5.1).
//
// Hedef PE'ye ait .pdb veya .map varsa fonksiyon RVA listesi
// bunlardan okunur; hicbiri yoksa stub fonksiyonlar listelenir
// (giris noktasi + prologue taramasi) — VMProtect davranisi.
// ============================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

typedef uint8_t  su8;
typedef uint16_t su16;
typedef uint32_t su32;
typedef uint64_t su64;

// sembol kaynagi
enum SymSource {
    SYM_EXPORT = 0,   // PE export tablosu
    SYM_COFF = 1,     // COFF sembol tablosu
    SYM_PDB = 2,      // CodeView PDB (MSF 7.00)
    SYM_MAP = 3,      // linker .map dosyasi
    SYM_STUB = 4      // prologue taramasi (pdb/map yoksa)
};

struct SymEntry {
    su32 rva = 0;
    su32 size = 0;          // 0 = bilinmiyor (sonraki sembole gore hesaplanir)
    std::string name;
    int source = SYM_EXPORT;
    bool is_export = false;
};

// bolum tablosu (cagiranin doldurdugu basit gorunum)
struct SymSections {
    struct Sec {
        su32 va = 0, vsz = 0, rawsz = 0, rawptr = 0, chars = 0;
        std::string name;
        bool is_exec() const { return (chars & 0x20000000u) != 0; }
    };
    std::vector<Sec> secs;
    // segment numarasi (1-tabanli) -> RVA; 0 ise gecersiz
    bool seg_rva(su16 seg, su32 off, su32* rva) const {
        if (seg == 0 || (size_t)seg > secs.size()) return false;
        *rva = secs[seg - 1].va + off;
        return true;
    }
    bool rva_exec(su32 rva) const {
        for (auto& s : secs)
            if (s.is_exec() && rva >= s.va && rva < s.va + s.vsz) return true;
        return false;
    }
};

// --- PDB (CodeView MSF 7.00 "DS") ---
// data: pdb dosyasinin tam icerigi.
// Donus: out'a S_GPROC32/S_LPROC32/S_PUB32 kod sembolleri eklenir.
// notlar: modul akislari (+4 onek) ve symrecord akisi taranir.
bool pdb_parse(const su8* data, size_t n, const SymSections& secs,
               std::vector<SymEntry>& out, std::string& err);

// --- MAP (MS linker / lld -Map ciktisi) ---
// text: map dosyasinin tam icerigi (text modda).
bool map_parse(const char* text, size_t n, const SymSections& secs,
               su32 imagebase, std::vector<SymEntry>& out, std::string& err);

// --- debug dizini: aday PDB kayitlari (RSDS/NB10) ---
// PE tamponundan debug directory taranir; pdb yol/adi + GUID/age doner.
struct DbgPdbRef {
    std::string name;
    su8 guid[16];
    su32 age = 0;
    bool has_guid = false;
};
void pe_debug_pdb_names(const su8* pe, size_t n, const SymSections& secs,
                        std::vector<DbgPdbRef>& out);

// --- PDB info akisi (stream 1) GUID/age karsilastirmasi ---
// bayat/eslesmeyen PDB'yi elemez (VMP davranisi).
bool pdb_matches(const su8* data, size_t n, const su8 guid[16], su32 age);

// --- stub taramasi (pdb/map yoksa) ---
// giris noktasi + calistirilabilir bolumlerde prologue desenleri.
// pe: dosya tamponu; ep_rva: giris RVA'si.
void stub_scan(const su8* pe, size_t n, const SymSections& secs,
               bool is64, su32 ep_rva, std::vector<SymEntry>& out);
