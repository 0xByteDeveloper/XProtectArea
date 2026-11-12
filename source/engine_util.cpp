// ============================================================
// engine_util.cpp — kucuk yardimcilar
// ============================================================
#include "engine.hpp"
#include <cstdio>

std::string hexs(const u8* p, int n) {
    static const char* d = "0123456789ABCDEF";
    std::string s;
    for (int i = 0; i < n; i++) {
        s += d[p[i] >> 4]; s += d[p[i] & 15]; s += ' ';
    }
    if (!s.empty()) s.pop_back();
    return s;
}

std::string hex32(u32 v) {
    char b[16]; snprintf(b, sizeof b, "%08X", v);
    return b;
}

const char* regname(bool is64, int enc) {
    static const char* r64[16] = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                   "r8","r9","r10","r11","r12","r13","r14","r15" };
    static const char* r32[8] = { "eax","ecx","edx","ebx","esp","ebp","esi","edi" };
    static const char* r8l[16] = { "al","cl","dl","bl","spl","bpl","sil","dil",
                                   "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b" };
    static const char* r8h[4] = { "ah","ch","dh","bh" };
    if (enc >= 16 && enc <= 19) return r8h[enc - 16];
    if (enc < 0 || enc > 15) return "?";
    if (is64) return r64[enc];
    return r32[enc];   // kabaca (log amacli)
}
