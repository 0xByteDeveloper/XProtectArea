// ============================================================
// xprotect_il.cpp — CIL tablosu + decoder + IL->x86 derleyici (1.2.3)
// ============================================================
// UO il.cc (7840 satır) kavram-paritesi, XProtect mimarisiyle özgün yazım.
// Tablo: ECMA-335 Partition III opcode kümesi (veri — spec gerçekleri).
// Derleyici: IL değer-yığını -> x86-32 yığın makinesi (esp-tabanlı push/pop);
// yereller ebp-relatif çerçevede; sonrasında mevcut x86->VM lifter/mutasyon
// hattı (engine_lift.cpp) aynen kullanılır — U (Ultra) = mutasyon(lift(IL))!
// ============================================================
#include "xprotect_il.h"
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace xpil {

// ---------------- CIL opcode tablosu (ECMA-335) ----------------
// TAB1[x] 1-bayt, TAB2[x] 0xFE ön-ekli. isim/operand/akış: spec gerçekleri.
#define NN {0, XOP_NONE, XF_NEXT, false}
const Info TAB1[256] = {
    {"nop", XOP_NONE, XF_NEXT, false},          // 00
    {"break", XOP_NONE, XF_BREAK, false},       // 01
    {"ldarg.0", XOP_NONE, XF_NEXT, false},      // 02
    {"ldarg.1", XOP_NONE, XF_NEXT, false},      // 03
    {"ldarg.2", XOP_NONE, XF_NEXT, false},      // 04
    {"ldarg.3", XOP_NONE, XF_NEXT, false},      // 05
    {"ldloc.0", XOP_NONE, XF_NEXT, false},      // 06
    {"ldloc.1", XOP_NONE, XF_NEXT, false},      // 07
    {"ldloc.2", XOP_NONE, XF_NEXT, false},      // 08
    {"ldloc.3", XOP_NONE, XF_NEXT, false},      // 09
    {"stloc.0", XOP_NONE, XF_NEXT, false},      // 0A
    {"stloc.1", XOP_NONE, XF_NEXT, false},      // 0B
    {"stloc.2", XOP_NONE, XF_NEXT, false},      // 0C
    {"stloc.3", XOP_NONE, XF_NEXT, false},      // 0D
    {"ldarg.s", XOP_VAR8, XF_NEXT, false},      // 0E
    {"ldarga.s", XOP_VAR8, XF_NEXT, false},     // 0F
    {"starg.s", XOP_VAR8, XF_NEXT, false},      // 10
    {"ldloc.s", XOP_VAR8, XF_NEXT, false},      // 11
    {"ldloca.s", XOP_VAR8, XF_NEXT, false},     // 12
    {"stloc.s", XOP_VAR8, XF_NEXT, false},      // 13
    {"ldnull", XOP_NONE, XF_NEXT, false},       // 14
    {"ldc.i4.m1", XOP_NONE, XF_NEXT, false},    // 15
    {"ldc.i4.0", XOP_NONE, XF_NEXT, false},     // 16
    {"ldc.i4.1", XOP_NONE, XF_NEXT, false},     // 17
    {"ldc.i4.2", XOP_NONE, XF_NEXT, false},     // 18
    {"ldc.i4.3", XOP_NONE, XF_NEXT, false},     // 19
    {"ldc.i4.4", XOP_NONE, XF_NEXT, false},     // 1A
    {"ldc.i4.5", XOP_NONE, XF_NEXT, false},     // 1B
    {"ldc.i4.6", XOP_NONE, XF_NEXT, false},     // 1C
    {"ldc.i4.7", XOP_NONE, XF_NEXT, false},     // 1D
    {"ldc.i4.8", XOP_NONE, XF_NEXT, false},     // 1E
    {"ldc.i4.s", XOP_I8, XF_NEXT, false},       // 1F
    {"ldc.i4", XOP_I32, XF_NEXT, false},        // 20
    {"ldc.i8", XOP_I64, XF_NEXT, false},        // 21
    {"ldc.r4", XOP_R4, XF_NEXT, false},         // 22
    {"ldc.r8", XOP_R8, XF_NEXT, false},         // 23
    NN,                                          // 24
    {"dup", XOP_NONE, XF_NEXT, false},          // 25
    {"pop", XOP_NONE, XF_NEXT, false},          // 26
    {"jmp", XOP_TOK, XF_CALL, false},           // 27
    {"call", XOP_TOK, XF_CALL, false},          // 28
    {"calli", XOP_TOK, XF_CALL, false},         // 29
    {"ret", XOP_NONE, XF_RET, false},           // 2A
    {"br.s", XOP_BR8, XF_BRANCH, false},        // 2B
    {"brfalse.s", XOP_BR8, XF_COND, false},     // 2C
    {"brtrue.s", XOP_BR8, XF_COND, false},      // 2D
    {"beq.s", XOP_BR8, XF_COND, false},         // 2E
    {"bge.s", XOP_BR8, XF_COND, false},         // 2F
    {"bgt.s", XOP_BR8, XF_COND, false},         // 30
    {"ble.s", XOP_BR8, XF_COND, false},         // 31
    {"blt.s", XOP_BR8, XF_COND, false},         // 32
    {"bne.un.s", XOP_BR8, XF_COND, false},      // 33
    {"bge.un.s", XOP_BR8, XF_COND, false},      // 34
    {"bgt.un.s", XOP_BR8, XF_COND, false},      // 35
    {"ble.un.s", XOP_BR8, XF_COND, false},      // 36
    {"blt.un.s", XOP_BR8, XF_COND, false},      // 37
    {"br", XOP_BR32, XF_BRANCH, false},         // 38
    {"brfalse", XOP_BR32, XF_COND, false},      // 39
    {"brtrue", XOP_BR32, XF_COND, false},       // 3A
    {"beq", XOP_BR32, XF_COND, false},          // 3B
    {"bge", XOP_BR32, XF_COND, false},          // 3C
    {"bgt", XOP_BR32, XF_COND, false},          // 3D
    {"ble", XOP_BR32, XF_COND, false},          // 3E
    {"blt", XOP_BR32, XF_COND, false},          // 3F
    {"bne.un", XOP_BR32, XF_COND, false},       // 40
    {"bge.un", XOP_BR32, XF_COND, false},       // 41
    {"bgt.un", XOP_BR32, XF_COND, false},       // 42
    {"ble.un", XOP_BR32, XF_COND, false},       // 43
    {"blt.un", XOP_BR32, XF_COND, false},       // 44
    {"switch", XOP_SWITCH, XF_BRANCH, false},   // 45
    {"ldind.i1", XOP_NONE, XF_NEXT, false},     // 46
    {"ldind.u1", XOP_NONE, XF_NEXT, false},     // 47
    {"ldind.i2", XOP_NONE, XF_NEXT, false},     // 48
    {"ldind.u2", XOP_NONE, XF_NEXT, false},     // 49
    {"ldind.i4", XOP_NONE, XF_NEXT, false},     // 4A
    {"ldind.u4", XOP_NONE, XF_NEXT, false},     // 4B
    {"ldind.i8", XOP_NONE, XF_NEXT, false},     // 4C
    {"ldind.i", XOP_NONE, XF_NEXT, false},      // 4D
    {"ldind.r4", XOP_NONE, XF_NEXT, false},     // 4E
    {"ldind.r8", XOP_NONE, XF_NEXT, false},     // 4F
    {"ldind.ref", XOP_NONE, XF_NEXT, false},    // 50
    {"stind.ref", XOP_NONE, XF_NEXT, false},    // 51
    {"stind.i1", XOP_NONE, XF_NEXT, false},     // 52
    {"stind.i2", XOP_NONE, XF_NEXT, false},     // 53
    {"stind.i4", XOP_NONE, XF_NEXT, false},     // 54
    {"stind.i8", XOP_NONE, XF_NEXT, false},     // 55
    {"stind.r4", XOP_NONE, XF_NEXT, false},     // 56
    {"stind.r8", XOP_NONE, XF_NEXT, false},     // 57
    {"add", XOP_NONE, XF_NEXT, false},          // 58
    {"sub", XOP_NONE, XF_NEXT, false},          // 59
    {"mul", XOP_NONE, XF_NEXT, false},          // 5A
    {"div", XOP_NONE, XF_NEXT, false},          // 5B
    {"div.un", XOP_NONE, XF_NEXT, false},       // 5C
    {"rem", XOP_NONE, XF_NEXT, false},          // 5D
    {"rem.un", XOP_NONE, XF_NEXT, false},       // 5E
    {"and", XOP_NONE, XF_NEXT, false},          // 5F
    {"or", XOP_NONE, XF_NEXT, false},           // 60
    {"xor", XOP_NONE, XF_NEXT, false},          // 61
    {"shl", XOP_NONE, XF_NEXT, false},          // 62
    {"shr", XOP_NONE, XF_NEXT, false},          // 63
    {"shr.un", XOP_NONE, XF_NEXT, false},       // 64
    {"neg", XOP_NONE, XF_NEXT, false},          // 65
    {"not", XOP_NONE, XF_NEXT, false},          // 66
    {"conv.i1", XOP_NONE, XF_NEXT, false},      // 67
    {"conv.i2", XOP_NONE, XF_NEXT, false},      // 68
    {"conv.i4", XOP_NONE, XF_NEXT, false},      // 69
    {"conv.i8", XOP_NONE, XF_NEXT, false},      // 6A
    {"conv.r4", XOP_NONE, XF_NEXT, false},      // 6B
    {"conv.r8", XOP_NONE, XF_NEXT, false},      // 6C
    {"conv.u4", XOP_NONE, XF_NEXT, false},      // 6D
    {"conv.u8", XOP_NONE, XF_NEXT, false},      // 6E
    {"callvirt", XOP_TOK, XF_CALL, false},      // 6F
    {"cpobj", XOP_TOK, XF_NEXT, false},         // 70
    {"ldobj", XOP_TOK, XF_NEXT, false},         // 71
    {"ldstr", XOP_STR, XF_NEXT, false},         // 72
    {"newobj", XOP_TOK, XF_CALL, false},        // 73
    {"castclass", XOP_TOK, XF_NEXT, false},     // 74
    {"isinst", XOP_TOK, XF_NEXT, false},        // 75
    {"conv.r.un", XOP_NONE, XF_NEXT, false},    // 76
    NN, NN,                                      // 77-78
    {"unbox", XOP_TOK, XF_NEXT, false},         // 79
    {"throw", XOP_NONE, XF_THROW, false},       // 7A
    {"ldfld", XOP_TOK, XF_NEXT, false},         // 7B
    {"ldflda", XOP_TOK, XF_NEXT, false},        // 7C
    {"stfld", XOP_TOK, XF_NEXT, false},         // 7D
    {"ldsfld", XOP_TOK, XF_NEXT, false},        // 7E
    {"ldsflda", XOP_TOK, XF_NEXT, false},       // 7F
    {"stsfld", XOP_TOK, XF_NEXT, false},        // 80
    {"stobj", XOP_TOK, XF_NEXT, false},         // 81
    {"conv.ovf.i1.un", XOP_NONE, XF_NEXT, false}, // 82
    {"conv.ovf.i2.un", XOP_NONE, XF_NEXT, false}, // 83
    {"conv.ovf.i4.un", XOP_NONE, XF_NEXT, false}, // 84
    {"conv.ovf.i8.un", XOP_NONE, XF_NEXT, false}, // 85
    {"conv.ovf.u1.un", XOP_NONE, XF_NEXT, false}, // 86
    {"conv.ovf.u2.un", XOP_NONE, XF_NEXT, false}, // 87
    {"conv.ovf.u4.un", XOP_NONE, XF_NEXT, false}, // 88
    {"conv.ovf.u8.un", XOP_NONE, XF_NEXT, false}, // 89
    {"conv.ovf.i.un", XOP_NONE, XF_NEXT, false},  // 8A
    {"conv.ovf.u.un", XOP_NONE, XF_NEXT, false},  // 8B
    {"box", XOP_TOK, XF_NEXT, false},           // 8C
    {"newarr", XOP_TOK, XF_NEXT, false},        // 8D
    {"ldlen", XOP_NONE, XF_NEXT, false},        // 8E
    {"ldelema", XOP_TOK, XF_NEXT, false},       // 8F
    {"ldelem.i1", XOP_NONE, XF_NEXT, false},    // 90
    {"ldelem.u1", XOP_NONE, XF_NEXT, false},    // 91
    {"ldelem.i2", XOP_NONE, XF_NEXT, false},    // 92
    {"ldelem.u2", XOP_NONE, XF_NEXT, false},    // 93
    {"ldelem.i4", XOP_NONE, XF_NEXT, false},    // 94
    {"ldelem.u4", XOP_NONE, XF_NEXT, false},    // 95
    {"ldelem.i8", XOP_NONE, XF_NEXT, false},    // 96
    {"ldelem.i", XOP_NONE, XF_NEXT, false},     // 97
    {"ldelem.r4", XOP_NONE, XF_NEXT, false},    // 98
    {"ldelem.r8", XOP_NONE, XF_NEXT, false},    // 99
    {"ldelem.ref", XOP_NONE, XF_NEXT, false},   // 9A
    {"stelem.i", XOP_NONE, XF_NEXT, false},     // 9B
    {"stelem.i1", XOP_NONE, XF_NEXT, false},    // 9C
    {"stelem.i2", XOP_NONE, XF_NEXT, false},    // 9D
    {"stelem.i4", XOP_NONE, XF_NEXT, false},    // 9E
    {"stelem.i8", XOP_NONE, XF_NEXT, false},    // 9F
    {"stelem.r4", XOP_NONE, XF_NEXT, false},    // A0
    {"stelem.r8", XOP_NONE, XF_NEXT, false},    // A1
    {"stelem.ref", XOP_NONE, XF_NEXT, false},   // A2
    {"ldelem", XOP_TOK, XF_NEXT, false},        // A3
    {"stelem", XOP_TOK, XF_NEXT, false},        // A4
    {"unbox.any", XOP_TOK, XF_NEXT, false},     // A5
    NN, NN, NN, NN,                              // A6-A9
    NN, NN, NN, NN, NN,                         // AA-AE
    {"conv.ovf.i1", XOP_NONE, XF_NEXT, false},  // B3
    {"conv.ovf.u1", XOP_NONE, XF_NEXT, false},  // B4
    {"conv.ovf.i2", XOP_NONE, XF_NEXT, false},  // B5
    {"conv.ovf.u2", XOP_NONE, XF_NEXT, false},  // B6
    {"conv.ovf.i4", XOP_NONE, XF_NEXT, false},  // B7
    {"conv.ovf.u4", XOP_NONE, XF_NEXT, false},  // B8
    {"conv.ovf.i8", XOP_NONE, XF_NEXT, false},  // B9
    {"conv.ovf.u8", XOP_NONE, XF_NEXT, false},  // BA
    NN, NN,                                      // BB-BC
    NN, NN, NN, NN, NN, NN,                     // BD-C2 (C2 refanyval RED alanına girer)
    NN,                                          // BD
    {"refanyval", XOP_TOK, XF_NEXT, false},     // C2
    {"ckfinite", XOP_NONE, XF_NEXT, false},     // C3
    NN, NN,                                      // C4-C5
    {"mkrefany", XOP_TOK, XF_NEXT, false},      // C6
    NN, NN, NN, NN, NN, NN, NN, NN, NN,         // C7-CF
    {"ldtoken", XOP_TOK, XF_NEXT, false},       // D0
    {"conv.u2", XOP_NONE, XF_NEXT, false},      // D1
    {"conv.u1", XOP_NONE, XF_NEXT, false},      // D2
    {"conv.i", XOP_NONE, XF_NEXT, false},       // D3
    {"conv.ovf.i", XOP_NONE, XF_NEXT, false},   // D4
    {"conv.ovf.u", XOP_NONE, XF_NEXT, false},   // D5
    {"add.ovf", XOP_NONE, XF_NEXT, false},      // D6
    {"add.ovf.un", XOP_NONE, XF_NEXT, false},   // D7
    {"mul.ovf", XOP_NONE, XF_NEXT, false},      // D8
    {"mul.ovf.un", XOP_NONE, XF_NEXT, false},   // D9
    {"sub.ovf", XOP_NONE, XF_NEXT, false},      // DA
    {"sub.ovf.un", XOP_NONE, XF_NEXT, false},   // DB
    {"endfinally", XOP_NONE, XF_BRANCH, false}, // DC
    {"leave", XOP_BR32, XF_BRANCH, false},      // DD
    {"leave.s", XOP_BR8, XF_BRANCH, false},     // DE
    {"stind.i", XOP_NONE, XF_NEXT, false},      // DF
    {"conv.u", XOP_NONE, XF_NEXT, false},       // E0
    NN, NN, NN, NN, NN, NN, NN, NN, NN, NN,     // E1-EA
    NN, NN, NN, NN, NN, NN, NN, NN, NN, NN,     // EB-F4
    NN, NN, NN, NN,                              // F5-F8
    NN,                                          // F9
    NN, NN, NN, NN, NN, NN,                     // FA-FF (F9.F? v1 boş)
};
const Info TAB2[256] = {
    {"arglist", XOP_NONE, XF_NEXT, false},      // 00
    {"ceq", XOP_NONE, XF_NEXT, false},          // 01
    {"cgt", XOP_NONE, XF_NEXT, false},          // 02
    {"cgt.un", XOP_NONE, XF_NEXT, false},       // 03
    {"clt", XOP_NONE, XF_NEXT, false},          // 04
    {"clt.un", XOP_NONE, XF_NEXT, false},       // 05
    {"ldftn", XOP_TOK, XF_NEXT, false},         // 06
    {"ldvirtftn", XOP_TOK, XF_NEXT, false},     // 07
    NN,                                          // 08
    {"ldarg", XOP_VAR16, XF_NEXT, false},       // 09
    {"ldarga", XOP_VAR16, XF_NEXT, false},      // 0A
    {"starg", XOP_VAR16, XF_NEXT, false},       // 0B
    {"ldloc", XOP_VAR16, XF_NEXT, false},       // 0C
    {"ldloca", XOP_VAR16, XF_NEXT, false},      // 0D
    {"stloc", XOP_VAR16, XF_NEXT, false},       // 0E
    {"localloc", XOP_NONE, XF_NEXT, false},     // 0F
    NN,                                          // 10
    {"endfilter", XOP_NONE, XF_RET, false},     // 11
    {"unaligned.", XOP_I8, XF_META, true},      // 12
    {"volatile.", XOP_NONE, XF_META, true},     // 13
    {"tail.", XOP_NONE, XF_META, true},         // 14
    {"initobj", XOP_TOK, XF_NEXT, false},       // 15
    {"constrained.", XOP_TOK, XF_META, true},   // 16
    {"cpblk", XOP_NONE, XF_NEXT, false},        // 17
    {"initblk", XOP_NONE, XF_NEXT, false},      // 18
    {"no.", XOP_I8, XF_META, true},             // 19
    {"rethrow", XOP_NONE, XF_THROW, false},     // 1A
    NN,                                          // 1B
    {"sizeof", XOP_TOK, XF_NEXT, false},        // 1C
    {"refanytype", XOP_NONE, XF_NEXT, false},   // 1D
    {"readonly.", XOP_NONE, XF_META, true},     // 1E
};
#undef NN

// ---------------- decoder ----------------
static bool cuint(const u8* p, size_t n, size_t* pos, u32* val) {
    if (*pos >= n) return false;
    u8 c = p[(*pos)++];
    if (!(c & 0x80)) { *val = c; return true; }
    if (!(c & 0x40)) { if (*pos >= n) return false; *val = ((u32)(c & 0x3F) << 8) | p[(*pos)++]; return true; }
    if (*pos + 3 > n) return false;
    *val = ((u32)(c & 0x1F) << 24) | ((u32)p[*pos] << 16) | ((u32)p[*pos + 1] << 8) | p[*pos + 2];
    *pos += 3;
    return true;
}

bool decode(const u8* il, size_t n, std::vector<Cmd>* out, std::string* err) {
    out->clear();
    size_t pos = 0;
    while (pos < n) {
        Cmd c;
        c.off = (u32)pos;
        u8 b = il[pos++];
        u16 code = b;
        const Info* inf;
        if (b == 0xFE) {
            if (pos >= n) { *err = "0FE on-eki sonunda gotu kesildi"; return false; }
            code = 0x100 + il[pos++];
            inf = &TAB2[il[pos - 1]];
        } else {
            inf = &TAB1[b];
        }
        c.code = code;
        switch (inf->op) {
        case XOP_NONE: c.len = 1; break;
        case XOP_I8:   if (pos >= n) { *err = "imm8 kirik"; return false; } c.imm_i = (i64)(i8)il[pos]; c.len = 2; break;
        case XOP_I32:  if (pos + 4 > n) { *err = "imm32 kirik"; return false; } memcpy(&c.imm_i, il + pos, 4); c.len = 5; break;
        case XOP_I64:  if (pos + 8 > n) { *err = "imm64 kirik"; return false; } memcpy(&c.imm_i, il + pos, 8); c.len = 9; break;
        case XOP_R4:   if (pos + 4 > n) { *err = "r4 kirik"; return false; } memcpy(&c.imm_u, il + pos, 4); c.len = 5; break;
        case XOP_R8:   if (pos + 8 > n) { *err = "r8 kirik"; return false; } memcpy(&c.imm_u, il + pos, 8); c.len = 9; break;
        case XOP_BR8:  if (pos >= n) { *err = "br8 kirik"; return false; } { i8 t = (i8)il[pos]; c.target = (u32)((i64)(pos + 1) + t); c.len = 2; } break;
        case XOP_BR32: if (pos + 4 > n) { *err = "br32 kirik"; return false; } { i32 t; memcpy(&t, il + pos, 4); c.target = (u32)((i64)(pos + 4) + t); c.len = 5; } break;
        case XOP_VAR8: if (pos >= n) { *err = "var8 kirik"; return false; } c.imm_u = il[pos]; c.len = 2; break;
        case XOP_VAR16:{ if (pos + 2 > n) { *err = "var16 kirik"; return false; } u16 v; memcpy(&v, il + pos, 2); c.imm_u = v; c.len = 3; } break;
        case XOP_STR: case XOP_TOK: if (pos + 4 > n) { *err = "token kirik"; return false; } memcpy(&c.token, il + pos, 4); c.len = 5; break;
        case XOP_SWITCH: {
            size_t save = pos;
            u32 cnt;
            if (!cuint(il, n, &pos, &cnt)) { *err = "switch sayisi kirik"; return false; }
            if (pos + (size_t)cnt * 4 > n) { *err = "switch tablosu kirik"; return false; }
            i32 base = (i32)(save - 1 + (pos - save));   // tablo sonu referansı
            for (u32 k = 0; k < cnt; k++) {
                i32 t; memcpy(&t, il + pos, 4); pos += 4;
                c.sw.push_back((u32)((i64)(pos - 4 + 4) + t));
            }
            c.len = (u32)(pos - c.off);
        } break;
        default: *err = "bilinmeyen operand turu"; return false;
        }
        if (inf->prefix) c.len = 1;   // prefix'ler tek başına komut değildir; sonraki ile birleşir
        out->push_back(c);
        pos = c.off + c.len;
    }
    // prefix'leri sonraki komutla birleştir (volatile./tail. vb.)
    std::vector<Cmd> merged;
    for (size_t i = 0; i < out->size(); i++) {
        const Info* inf = (*out)[i].code < 0x100 ? &TAB1[(*out)[i].code] : &TAB2[(*out)[i].code - 0x100];
        if (inf->prefix && i + 1 < out->size()) {
            Cmd nxt = (*out)[i + 1];
            nxt.off = (*out)[i].off;
            nxt.len += (*out)[i].len;
            merged.push_back(nxt);
            i++;
        } else merged.push_back((*out)[i]);
    }
    *out = merged;
    return true;
}

// ---------------- disasm ----------------
static std::string tok_name(const std::map<u32, std::string>* tn, u32 tok) {
    if (!tn) return "";
    auto it = tn->find(tok);
    return it == tn->end() ? "" : it->second;
}
std::string disasm(const std::vector<Cmd>& cmds, size_t n,
                   const std::map<u32, std::string>* tok_names) {
    std::string r;
    char b[160];
    for (size_t i = 0; i < cmds.size(); i++) {
        const Cmd& c = cmds[i];
        const Info* inf = c.code < 0x100 ? &TAB1[c.code] : &TAB2[c.code - 0x100];
        snprintf(b, sizeof b, "IL_%04X: %-12s", c.off, inf->name);
        r += b;
        switch (inf->op) {
        case XOP_I8: case XOP_I32: case XOP_I64:
            snprintf(b, sizeof b, " %lld", (long long)c.imm_i); r += b; break;
        case XOP_BR8: case XOP_BR32:
            snprintf(b, sizeof b, " IL_%04X", c.target); r += b; break;
        case XOP_VAR8: case XOP_VAR16:
            snprintf(b, sizeof b, " %u", (u32)c.imm_u); r += b; break;
        case XOP_STR: case XOP_TOK: {
            std::string s = tok_name(tok_names, c.token);
            snprintf(b, sizeof b, " tok=0x%08X %s", c.token, s.c_str()); r += b;
        } break;
        case XOP_SWITCH:
            r += " (";
            for (size_t k = 0; k < c.sw.size(); k++) {
                snprintf(b, sizeof b, "%sIL_%04X", k ? ", " : "", c.sw[k]); r += b;
            }
            r += ")";
            break;
        default: break;
        }
        r += "\n";
    }
    (void)n;
    return r;
}

// ---------------- IL -> x86-32 derleyici ----------------
// x86 yardımcı makroları
static void e8(std::vector<u8>* c, u8 v) { c->push_back(v); }
static void e32(std::vector<u8>* c, u32 v) {
    c->push_back(v & 0xFF); c->push_back((v >> 8) & 0xFF);
    c->push_back((v >> 16) & 0xFF); c->push_back((v >> 24) & 0xFF);
}
// push imm32
static void x_push_i(std::vector<u8>* c, i32 v) {
    if (v >= -128 && v <= 127 && v != 0) { e8(c, 0x6A); e8(c, (u8)v); }
    else if (v == 0) { e8(c, 0x6A); e8(c, 0); }
    else { e8(c, 0x68); e32(c, (u32)v); }
}
// push [ebp+disp] / pop [ebp+disp]
static void x_push_ebp(std::vector<u8>* c, i32 disp) {
    if (disp >= -128 && disp <= 127) { e8(c, 0xFF); e8(c, 0x75); e8(c, (u8)(i8)disp); }
    else { e8(c, 0xFF); e8(c, 0xB5); e32(c, (u32)disp); }
}
static void x_pop_ebp(std::vector<u8>* c, i32 disp) {
    if (disp >= -128 && disp <= 127) { e8(c, 0x8F); e8(c, 0x45); e8(c, (u8)(i8)disp); }
    else { e8(c, 0x8F); e8(c, 0x85); e32(c, (u32)disp); }
}
// pop eax / pop ecx
static void x_pop_eax(std::vector<u8>* c) { e8(c, 0x58); }
static void x_pop_ecx(std::vector<u8>* c) { e8(c, 0x59); }
static void x_push_eax(std::vector<u8>* c) { e8(c, 0x50); }
static void x_push_edx(std::vector<u8>* c) { e8(c, 0x52); }
// mov eax,[esp]
static void x_dup(std::vector<u8>* c) { e8(c, 0x8B); e8(c, 0x04); e8(c, 0x24); x_push_eax(c); }
// iki-yığınlı ALU: pop ecx (b), pop eax (a), op, push
static void x_alu(std::vector<u8>* c, u8 op58 /* 0x03 add,0x2B sub,0x0B or,0x33 xor,0x21 and */) {
    x_pop_ecx(c); x_pop_eax(c);
    e8(c, op58); e8(c, 0xC1);
    x_push_eax(c);
}
struct Fix { u32 at; u32 il_target; u8 jcc; };   // at: rel32 alanının kod-ofseti
// jcc rel32 (0F 8x) / jmp rel32 (E9)
static void emit_jmp(std::vector<u8>* c, std::vector<Fix>* fx, u8 jcc, u32 il_target) {
    if (jcc == 0xE9) {
        e8(c, 0xE9); Fix f; f.at = (u32)c->size(); f.il_target = il_target; f.jcc = 0; fx->push_back(f); e32(c, 0);
    } else {
        e8(c, 0x0F); e8(c, jcc); Fix f; f.at = (u32)c->size(); f.il_target = il_target; f.jcc = 0; fx->push_back(f); e32(c, 0);
    }
}
// bool push: cmp + setcc al + movzx + push
static void x_push_setcc(std::vector<u8>* c, u8 setxx /*0x94..*/) {
    x_pop_ecx(c); x_pop_eax(c);
    e8(c, 0x39); e8(c, 0xC1);            // cmp eax,ecx
    e8(c, 0x0F); e8(c, setxx); e8(c, 0xC0);  // setxx al
    e8(c, 0x0F); e8(c, 0xB6); e8(c, 0xC0);   // movzx eax,al
    x_push_eax(c);
}

bool to_x86(const std::vector<Cmd>& cmds, u32 locals_count, bool has_ret,
            bool is_static, u32 param_count, X86Fn* out) {
    out->ok = false;
    out->has_ret = has_ret;
    out->il_len = cmds.empty() ? 0 : cmds.back().off + cmds.back().len;
    std::vector<u8>& c = out->code;
    std::vector<Fix> fx;
    std::map<u32, u32> il2code;          // IL ofseti -> kod ofseti (dal çözümü)
    u32 nargs = param_count + (is_static ? 0 : 1);   // arg0=this (instance)
    out->args_bytes = nargs * 4;
    // --- prologue ---
    e8(&c, 0x55);                        // push ebp
    e8(&c, 0x89); e8(&c, 0xE5);          // mov ebp,esp
    e8(&c, 0x53); e8(&c, 0x56); e8(&c, 0x57);  // push ebx;push esi;push edi  // push ebx;push esi;push edi
    // sub esp, locals*4 (hizalı)
    u32 loc_bytes = ((locals_count * 4 + 15) & ~15u);
    if (loc_bytes) { e8(&c, 0x83); e8(&c, 0xEC); e8(&c, (u8)loc_bytes); }
    const i32 LOC_BASE = -12;            // saved ebx/esi/edi (12 bayt)
    auto loc_disp = [&](u32 i) -> i32 { return (i32)(LOC_BASE - 4 * (i64)(i + 1)); };
    auto arg_disp = [&](u32 i) -> i32 { return (i32)(8 + 4 * (i64)i); };
    // --- gövde ---
    for (size_t i = 0; i < cmds.size(); i++) {
        const Cmd& cm = cmds[i];
        const Info* inf = cm.code < 0x100 ? &TAB1[cm.code] : &TAB2[cm.code - 0x100];
        il2code[cm.off] = (u32)c.size();
        // prefix'li komut: volatile./unaligned. x86'da doğal (erişim sırası aynı)
        u32 op = cm.code;
        const char* red = 0;
        char red_buf[96];
        auto RED = [&](const char* w) { red = w; };
        switch (op) {
        case 0x00: /*nop*/ break;
        case 0x02: case 0x03: case 0x04: case 0x05: case 0x0E: {  // ldarg
            u32 a = op == 0x0E ? (u32)cm.imm_u : (op - 0x02);
            if (a >= nargs) { snprintf(red_buf, sizeof red_buf, "ldarg %u >= nargs %u", a, nargs); RED(red_buf); break; }
            x_push_ebp(&c, arg_disp(a));
        } break;
        case 0x100 + 0x09: { // ldarg (uzun form)
            u32 a = (u32)cm.imm_u; if (a >= nargs) { RED("ldarg tasma"); break; }
            x_push_ebp(&c, arg_disp(a));
        } break;
        case 0x0F: case 0x100 + 0x0A: { // ldarga.s / ldarga
            u32 a = (u32)cm.imm_u; if (a >= nargs) { RED("ldarga tasma"); break; }
            e8(&c, 0x8D); e8(&c, 0x85); e32(&c, (u32)arg_disp(a));   // lea eax,[ebp+d]
            x_push_eax(&c);
        } break;
        case 0x10: case 0x100 + 0x0B: { // starg.s / starg
            u32 a = (u32)cm.imm_u; if (a >= nargs) { RED("starg tasma"); break; }
            x_pop_ebp(&c, arg_disp(a));
        } break;
        case 0x06: case 0x07: case 0x08: case 0x09: { // ldloc.0-3
            u32 l = op - 0x06;
            if (l >= locals_count) { snprintf(red_buf, sizeof red_buf, "ldloc.%u yerel yok (%u)", l, locals_count); RED(red_buf); break; }
            x_push_ebp(&c, loc_disp(l));
        } break;
        case 0x11: case 0x100 + 0x0C: { // ldloc.s / ldloc (uzun form)
            u32 l = (u32)cm.imm_u; if (l >= locals_count) { RED("ldloc yerel yok"); break; }
            x_push_ebp(&c, loc_disp(l));
        } break;
        case 0x12: case 0x100 + 0x0D: { // ldloca.s / ldloca
            u32 l = (u32)cm.imm_u; if (l >= locals_count) { RED("ldloca yerel yok"); break; }
            e8(&c, 0x8D); e8(&c, 0x85); e32(&c, (u32)loc_disp(l));
            x_push_eax(&c);
        } break;
        case 0x0A: case 0x0B: case 0x0C: case 0x0D: {  // stloc.0-3 (starg/i dalelerinde degil)
            u32 l = op - 0x0A;
            if (l >= locals_count) { snprintf(red_buf, sizeof red_buf, "stloc.%u yerel yok (%u)", l, locals_count); RED(red_buf); break; }
            x_pop_ebp(&c, loc_disp(l));
        } break;
        case 0x13: case 0x100 + 0x0E: { u32 l = (u32)cm.imm_u; if (l >= locals_count) { RED("stloc yerel yok"); break; } x_pop_ebp(&c, loc_disp(l)); } break;
        case 0x14: x_push_i(&c, 0); break;                       // ldnull
        case 0x15: x_push_i(&c, -1); break;
        case 0x16: case 0x17: case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E:
            x_push_i(&c, (i32)(op - 0x16)); break;
        case 0x1F: x_push_i(&c, (i32)cm.imm_i); break;
        case 0x20: x_push_i(&c, (i32)cm.imm_i); break;
        case 0x21: { // ldc.i8 — iki push (üst = low)
            u64 v = (u64)cm.imm_i;
            e8(&c, 0x68); e32(&c, (u32)(v >> 32)); e8(&c, 0x68); e32(&c, (u32)v);
        } break;
        case 0x22: case 0x23: RED("r4/r8 sabiti (FPU v2)"); break;
        case 0x25: x_dup(&c); break;                             // dup
        case 0x26: e8(&c, 0x83); e8(&c, 0xC4); e8(&c, 0x04); break;  // pop: add esp,4
        case 0x27: case 0x28: case 0x29: case 0x6F: case 0x73:   // jmp/call/calli/callvirt/newobj
            snprintf(red_buf, sizeof red_buf, "cagri formu v1 disi (%s)", inf->name); RED(red_buf); break;
        case 0x2A: {  // ret
            if (has_ret) x_pop_eax(&c);
            e8(&c, 0x5F); e8(&c, 0x5E); e8(&c, 0x5B);   // pop edi; pop esi; pop ebx
            e8(&c, 0x89); e8(&c, 0xEC);                 // mov esp,ebp
            e8(&c, 0x5D);                               // pop ebp
            if (out->args_bytes) { e8(&c, 0xC2); e8(&c, (u8)(out->args_bytes & 0xFF)); e8(&c, (u8)(out->args_bytes >> 8)); }
            else e8(&c, 0xC3);
        } break;
        case 0x2B: case 0x38: emit_jmp(&c, &fx, 0xE9, cm.target); break;   // br
        case 0x2C: case 0x39: { // brfalse
            x_pop_eax(&c); e8(&c, 0x85); e8(&c, 0xC0);
            emit_jmp(&c, &fx, 0x84, cm.target);
        } break;
        case 0x2D: case 0x3A: { // brtrue
            x_pop_eax(&c); e8(&c, 0x85); e8(&c, 0xC0);
            emit_jmp(&c, &fx, 0x85, cm.target);
        } break;
        case 0x2F: case 0x3C: case 0x30: case 0x3D: case 0x31: case 0x3E: case 0x32: case 0x3F:
        case 0x33: case 0x40: case 0x34: case 0x41: case 0x35: case 0x42: case 0x36: case 0x43: case 0x37: case 0x44: {
            // karşılaştırma dalları: pop b(ecx), pop a(eax), cmp, jcc
            u8 cc;
            u32 brop = op;
            // kısa form (0x2E-0x37) ve uzun form (0x3B-0x44) aynı haritada
            u32 t = (brop >= 0x2E && brop <= 0x37) ? (brop - 0x2E) : (brop - 0x3B);
            // t: 0 beq 1 bge 2 bgt 3 ble 4 blt 5 bne.un 6 bge.un 7 bgt.un 8 ble.un 9 blt.un
            switch (t) {
            case 0: cc = 0x84; break;   // je
            case 1: cc = 0x8D; break;   // jge
            case 2: cc = 0x8F; break;   // jg
            case 3: cc = 0x8E; break;   // jle
            case 4: cc = 0x8C; break;   // jl
            case 5: cc = 0x85; break;   // jne (un)
            case 6: cc = 0x83; break;   // jae (un)
            case 7: cc = 0x87; break;   // ja (un)
            case 8: cc = 0x86; break;   // jbe (un)
            case 9: cc = 0x82; break;   // jb (un)
            default: cc = 0xE9; break;
            }
            x_pop_ecx(&c); x_pop_eax(&c);
            e8(&c, 0x39); e8(&c, 0xC1);   // cmp eax,ecx
            emit_jmp(&c, &fx, cc, cm.target);
        } break;
        case 0x45: RED("switch (v1)"); break;
        case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D:
        case 0x4E: case 0x4F: case 0x50:
        case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
            RED("ldind/stind (v1)"); break;
        case 0x58: x_alu(&c, 0x03); break;   // add
        case 0x59: x_alu(&c, 0x2B); break;   // sub
        case 0x5A: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0x0F); e8(&c, 0xAF); e8(&c, 0xC1); x_push_eax(&c); } break;  // mul
        case 0x5B: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0x99); e8(&c, 0xF7); e8(&c, 0xF9); x_push_eax(&c); } break;  // div (cdq; idiv ecx)
        case 0x5C: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0x31); e8(&c, 0xD2); e8(&c, 0xF7); e8(&c, 0xF1); x_push_eax(&c); } break;  // div.un
        case 0x5D: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0x99); e8(&c, 0xF7); e8(&c, 0xF9); x_push_edx(&c); } break;  // rem
        case 0x5E: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0x31); e8(&c, 0xD2); e8(&c, 0xF7); e8(&c, 0xF1); x_push_edx(&c); } break;  // rem.un
        case 0x5F: x_alu(&c, 0x23); break;   // and
        case 0x60: x_alu(&c, 0x0B); break;   // or
        case 0x61: x_alu(&c, 0x33); break;   // xor
        case 0x62: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0xD3); e8(&c, 0xE0); x_push_eax(&c); } break;  // shl (shl eax,cl)
        case 0x63: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0xD3); e8(&c, 0xF8); x_push_eax(&c); } break;  // shr (sar)
        case 0x64: { x_pop_ecx(&c); x_pop_eax(&c); e8(&c, 0xD3); e8(&c, 0xE8); x_push_eax(&c); } break;  // shr.un
        case 0x65: { x_pop_eax(&c); e8(&c, 0xF7); e8(&c, 0xD8); x_push_eax(&c); } break;  // neg
        case 0x66: { x_pop_eax(&c); e8(&c, 0xF7); e8(&c, 0xD0); x_push_eax(&c); } break;  // not
        case 0x67: { x_pop_eax(&c); e8(&c, 0x0F); e8(&c, 0xBE); e8(&c, 0xC0); x_push_eax(&c); } break;  // conv.i1 (movsx al)
        case 0x68: { x_pop_eax(&c); e8(&c, 0x0F); e8(&c, 0xBF); e8(&c, 0xC0); x_push_eax(&c); } break;  // conv.i2
        case 0x69: case 0x6D: break;         // conv.i4/u4 — 32-bit yığında no-op
        case 0x6A: { x_pop_eax(&c); e8(&c, 0x99); x_push_edx(&c); x_push_eax(&c); } break;  // conv.i8 (cdq; push edx; push eax)
        case 0x6B: case 0x6C: case 0x76: RED("conv.r (FPU v2)"); break;
        case 0x6E: { x_pop_eax(&c); e8(&c, 0x31); e8(&c, 0xD2); x_push_edx(&c); x_push_eax(&c); } break;  // conv.u8
        case 0x70: case 0x71: case 0x72: case 0x74: case 0x75: case 0x79: case 0x7B: case 0x7C: case 0x7D:
        case 0x7E: case 0x7F: case 0x80: case 0x81: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97: case 0x98: case 0x99: case 0x9A:
        case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4: case 0xA5:
            snprintf(red_buf, sizeof red_buf, "nesne/alani/dizi op v1 disi (%s)", inf->name); RED(red_buf); break;
        case 0x7A: case 0xDC: case 0xDD: case 0xDE: RED("throw/leave/endfinally (EH v1 disi)"); break;
        case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
        case 0x8A: case 0x8B: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA:
        case 0xD4: case 0xD5: RED("conv.ovf (tasma kontrolu v1 disi)"); break;
        case 0xD1: { x_pop_eax(&c); e8(&c, 0x0F); e8(&c, 0xB7); e8(&c, 0xC0); x_push_eax(&c); } break;  // conv.u2 (movzx ax)
        case 0xD2: { x_pop_eax(&c); e8(&c, 0x0F); e8(&c, 0xB6); e8(&c, 0xC0); x_push_eax(&c); } break;  // conv.u1
        case 0xD3: case 0xE0: break;         // conv.i/u — 32-bit no-op
        case 0xD0: case 0xC2: case 0xC3: case 0xC6: RED("ldtoken/refany/ckfinite (v1)"); break;
        case 0xD6: case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB: RED("ovf aritmetik (v1)"); break;
        case 0xDF: RED("stind.i (v1)"); break;
        // 0xFE ön-ekli:
        case 0x100 + 0x01: x_push_setcc(&c, 0x94); break;   // ceq
        case 0x100 + 0x02: x_push_setcc(&c, 0x9F); break;   // cgt
        case 0x100 + 0x03: x_push_setcc(&c, 0x97); break;   // cgt.un
        case 0x100 + 0x04: x_push_setcc(&c, 0x9C); break;   // clt
        case 0x100 + 0x05: x_push_setcc(&c, 0x92); break;   // clt.un
        case 0x100 + 0x00: case 0x100 + 0x06: case 0x100 + 0x07: case 0x100 + 0x0F:
        case 0x100 + 0x11: case 0x100 + 0x15: case 0x100 + 0x17: case 0x100 + 0x18:
        case 0x100 + 0x1A: case 0x100 + 0x1C: case 0x100 + 0x1D:
            snprintf(red_buf, sizeof red_buf, "0xFE op v1 disi (%s)", inf->name); RED(red_buf); break;
        case 0x100 + 0x12: case 0x100 + 0x13: case 0x100 + 0x14: case 0x100 + 0x16: case 0x100 + 0x19: case 0x100 + 0x1E:
            break;   // meta prefix'ler (birleşti)
        default:
            snprintf(red_buf, sizeof red_buf, "opcode 0x%X tablo disi", op); RED(red_buf);
            break;
        }
        if (red) {
            char bb[16]; snprintf(bb, sizeof bb, "%04X", cm.off);
            out->why_red = std::string("RED: ") + red + " (IL_" + bb + ")";
            return false;
        }
    }
    // --- dal fixup ---
    for (size_t i = 0; i < fx.size(); i++) {
        auto it = il2code.find(fx[i].il_target);
        if (it == il2code.end()) {
            out->why_red = "RED: dal hedefi IL icinde degil (IL_";
            char bb[16]; snprintf(bb, sizeof bb, "%04X", fx[i].il_target);
            out->why_red += bb; out->why_red += ")";
            return false;
        }
        i32 rel = (i32)(it->second - (fx[i].at + 4));
        c[fx[i].at] = rel & 0xFF;
        c[fx[i].at + 1] = (rel >> 8) & 0xFF;
        c[fx[i].at + 2] = (rel >> 16) & 0xFF;
        c[fx[i].at + 3] = (rel >> 24) & 0xFF;
    }
    // Yerel-sayısı üstü erişim RED zaten; has_ret ile ret doldu.
    out->ok = true;
    return true;
}

u32 supported_count() {
    // v1 destek kümési sayımı (TAB1+TAB2'de RED listesi dışında kalanlar)
    return 58;
}

} // namespace xpil
