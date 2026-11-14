// ============================================================
// xprotect_il.h — CIL/IL desteği arayüzü (1.2.3)
// ============================================================
// UO (VMProtect 3.5.1) core/il.h + il.cc kavram-paritesi:
//  - tam CIL opcode tablosu (ECMA-335 Part III; 1-bayt + 0xFE ön-ekli)
//  - gövde çözücü (ReadCommand eş-değeri)
//  - IL -> x86-32 derleyici (tamsayı alt-kümesi; UO CompileToVM'in
//    XProtect mimarisindeki karşılığı: IL->x86->mevcut VM lifter hattı)
// Kapsam (v1, dürüst): ldarg/ldloc/starg/stloc/ldc/dup/pop/add/sub/mul/
// div/rem(±un)/and/or/xor/shl/shr/shr.un/neg/not/conv(ailesi)/br ailesi/
// beq..blt(±un)/brfalse/brtrue/ceq/cgt/clt/ldloca/ldarga/ldnull/ret.
// RED (v1): call/callvirt(newobj dahil)/ldstr/alan&statik alan erişimi/
// box/unbox/castclass/newarr/ldlen/ldelem/stelem/throw/leave/switch/
// ldftn/ckfinite/r4-r8 aritmetiği/conv.ovf/localloc/locals-imzalı fat
// gövde (StandAloneSig v2'de). x64 IL derleyici v2'de.
// ============================================================
#ifndef XPROTECT_IL_H
#define XPROTECT_IL_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef int8_t i8;
typedef int16_t i16;
typedef int64_t i64;
typedef int32_t i32;

namespace xpil {

// ILOperandType eş-değeri
enum XPILOperand : u8 {
    XOP_NONE, XOP_I8, XOP_I32, XOP_I64, XOP_R, XOP_BR8, XOP_BR32,
    XOP_VAR8, XOP_VAR16, XOP_STR, XOP_TOK, XOP_SWITCH, XOP_R4, XOP_R8
};
enum XPILFlow : u8 {
    XF_NEXT, XF_BRANCH, XF_COND, XF_CALL, XF_RET, XF_THROW, XF_BREAK, XF_META
};

struct Info {
    const char* name;
    XPILOperand op;
    XPILFlow flow;
    bool prefix;
};

extern const Info TAB1[256];     // 1-bayt
extern const Info TAB2[256];     // 0xFE ön-ekli

struct Cmd {
    u32 off = 0;                 // IL gövde içinde bayt ofseti
    u32 len = 0;                 // toplam komut boyutu
    u16 code = 0;                // tablo indeksi (0x100 + TAB2 için)
    u32 target = 0;              // dal hedefi (IL ofseti)
    u32 token = 0;               // InlineMethod/Type/Field/String/Tok
    u64 imm_u = 0;
    i64 imm_i = 0;
    std::vector<u32> sw;         // switch hedefleri
};

// IL gövdesini çöz; hata varsa err'e yaz ve false döner.
bool decode(const u8* il, size_t n, std::vector<Cmd>* out, std::string* err);

// Komut listesinden okunabilir döküm (UI/kanıt için)
std::string disasm(const std::vector<Cmd>& cmds, size_t n,
                   const std::map<u32, std::string>* tok_names);

// IL -> x86-32 derleyici (tamsayı alt-kümesi).
// girdi: decode çıktısı + gövde meta. çıktı: konum-bağımsız x86-32 kod.
// çağrı dizisi (CLR x86 native-callable varsayımı): args yığında
// [ebp+8+i*4], callee temizler (ret args*4), dönüş EAX.
//   this'i ayrı yazma: instance yöntemlerde arg0=this.
struct X86Fn {
    bool ok = false;
    std::string why_red;
    std::vector<u8> code;
    u32 args_bytes = 0;          // ret imm için
    bool has_ret = false;
    u32 il_len = 0;
};
bool to_x86(const std::vector<Cmd>& cmds, u32 locals_count, bool has_ret,
            bool is_static, u32 param_count, X86Fn* out);

// desteklenen opcode sayısı (parite ölçümü için)
u32 supported_count();

} // namespace xpil

#endif
