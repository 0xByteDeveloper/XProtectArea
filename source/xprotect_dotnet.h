// ============================================================
// xprotect_dotnet.h — .NET PE desteği arayüzü (1.2.3)
// ============================================================
// UO (VMProtect 3.5.1) core/dotnetfile.cc + dotnet.h kavram-paritesi.
// UI fonksiyon keşfi + engine MethodDef yaması için satır-ofsetleri
// döndürür (1.2.3'te eklendi: RVA alanının dosya ofseti).
// ============================================================
#ifndef XPROTECT_DOTNET_H
#define XPROTECT_DOTNET_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef uint16_t u16;

namespace xpdotnet {

// ELEMENT_TYPE basit kodları (ECMA-335 II.23.1.16)
enum : u8 {
    ET_VOID = 0x01, ET_BOOL = 0x02, ET_CHAR = 0x03, ET_I1 = 0x04,
    ET_U1 = 0x05, ET_I2 = 0x06, ET_U2 = 0x07, ET_I4 = 0x08,
    ET_U4 = 0x09, ET_I8 = 0x0A, ET_U8 = 0x0B, ET_R4 = 0x0C,
    ET_R8 = 0x0D, ET_STRING = 0x0E, ET_PTR = 0x0F, ET_BYREF = 0x10,
    ET_VALUETYPE = 0x11, ET_CLASS = 0x12, ET_OBJECT = 0x1C,
    ET_SZARRAY = 0x1D, ET_I = 0x18, ET_U = 0x19
};

struct Method {
    std::string name;        // #Strings'ten
    std::string type_name;   // "Namespace.Type"
    u32 rva = 0;             // MethodDef RVA (IL gövde veya native)
    u32 token = 0;           // 0x06xxxxxx
    u32 flags = 0;           // MethodAttributes
    u32 impl_flags = 0;      // MethodImplAttributes
    u32 param_count = 0;     // imza blobundan
    u8  ret_type = ET_VOID;
    bool has_ret = false;
    bool is_static = false;
    bool is_pinvoke = false;
    bool is_native = false;
    bool is_abstract = false;
    // gövde
    u32 body_off = 0;        // dosya ofseti (IL başlangıcı, header sonrası)
    u32 body_len = 0;
    bool fat_header = false;
    u32 max_stack = 0;
    u32 local_sig = 0;       // StandAloneSig token
    u32 eh_count = 0;
    // 1.2.3 motor yaması için satır alanı dosya-ofsetleri
    u32 row_rva_off = 0;
    u32 row_impl_off = 0;
    // 1.2.5-A14 (x2 devam): P/Invoke — ImplMap (0x1C) çözümü
    std::string pinv_dll;    // ModuleRef (0x1A) ismi ("kernel32.dll")
    std::string pinv_name;   // ImportName (#Strings)
    bool pinv_cdecl = false; // PM_CALLCONV_CDECL (0x0001); değilse stdcall
};

struct TypeDef {
    std::string name, ns, type_full;
    u32 flags = 0;                           // A14: ExplicitLayout tespiti
    u32 method_first = 0, method_last = 0;   // MethodDef 1-tabanlı aralık
    u32 field_first = 0, field_last = 0;     // A14: Field 1-tabanlı aralık
};

struct Image {
    bool ok = false;
    bool is_dotnet = false;
    bool is64 = false;
    bool is_dll = false;
    std::string err;
    u32 metadata_rva = 0, metadata_sz = 0;
    u32 entry_token = 0;
    char ver_buf[16] = {0};
    std::vector<TypeDef> typedefs;
    std::vector<Method> methods;
    // 1.2.5-A13 (x2/x7a): StandAloneSig (0x11) tablosu — satir basina blob
    // indeksi; ldloc/stloc icin yerel imzalari buradan cozulur.
    std::vector<u32> sas_blob;   // satir r -> blob idx (1-tabanli token r-1)
    u64 blob_off = 0;            // #Blob stream dosya ofseti (parse_locals)
    u32 blob_sz = 0;
    bool blob4 = false;          // #Blob indeks genisligi 4 mu
    // 1.2.5-A14 (x2 devam): P/Invoke + statik/explicit alanlar
    std::map<u32, u32> field_rva;   // Field token (0x04xxxxxx) -> FieldRVA
    std::map<u32, i32> field_off;   // Field token -> explicit-layout offset
};

bool parse(const u8* d, size_t n, Image* out);
bool read_body(const u8* d, size_t n, const Method& m, std::vector<u8>* il);
bool parse_locals(const u8* d, size_t n, const Image& img, u32 local_sig_token,
                  std::vector<u8>* types, std::vector<u32>* sizes);

} // namespace xpdotnet

#endif
