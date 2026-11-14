// ============================================================
// xprotect_dwarf.h — DWARF .debug_info fonksiyon keşfi (x3 portu)
// ============================================================
// UniversalObfuscator (VMProtect 3.5.1) core/dwarf.cc zincirinin
// XProtect portu — v1 kapsam (dürüst):
//   - PE'de .debug_info/.debug_abbrev/.debug_str bölümleri
//   - DWARF v2..v4 Compilation Unit header'ı
//   - abbrev tablosu (skeleton: kod+form okuma)
//   - DW_TAG_subprogram (0x2E) + DW_AT_low_pc (0x11) +
//     DW_AT_high_pc (0x12: adres YA DA offset-form) → fonksiyon adı/RVA/boyut
//   - DW_AT_name imzası #debug_str (DW_FORM_strp) veya inline
// v1'de YOK (sonraki turlar): DWARF v5 (str_offsets, line_str),
//   .debug_ranges/.debug_rnglists (çok-parçalı adresler), DWARF64,
//   split-DWARF, inline-expansion kapsam hesabı.
// Kullanım: MinGW/clang -g ile derlenen PE'lerde PDB olmadan fonksiyon
// adları+boyutları çıkar (pdbscope pdbless'in kör kaldığı yer).
// ============================================================
#ifndef XPROTECT_DWARF_H
#define XPROTECT_DWARF_H
#include <string>
#include <vector>
#include <cstdint>

namespace xpdwarf {

struct DwarfFn {
    unsigned long long rva = 0;     // low_pc (image-offset: PE'de VA == RVA + imagebase; burada RVA doner)
    unsigned long long size = 0;    // high_pc - low_pc (high_pc offset-form ise low_pc+high)
    std::string name;
};

// .debug_info'yu ayrıştır; imagebase ile RVA'ya cevirir. Hata durumunda err dolu.
bool parse(const unsigned char* d, size_t n, unsigned long long imagebase,
           std::vector<DwarfFn>* out, std::string* err);

} // namespace xpdwarf
#endif
