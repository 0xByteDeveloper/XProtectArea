// ============================================================
// engine_disasm.cpp — x86/x64 kucuk-alt-kume cozucu (lifter icin)
// Yalnizca derleyici uretimine uygun talimatlar desteklenir;
// bilinmeyen olkus -> XP_UNKNOWN (lifter fonksiyonu red eder).
// ============================================================
#include "engine.hpp"

static int reg8enc(bool is64, bool rex, int r) {
    if (is64 && rex) return r;              // spl..dil / r8b..r15b
    if (r >= 4 && !rex && !is64) return 16 + (r - 4); // ah,ch,dh,bh (x86)
    if (r >= 4 && !rex && is64)  return 16 + (r - 4); // ah,ch,dh,bh (rex yok)
    return r;
}

Insn disasm(const u8* p, int maxlen, bool is64, u32 pc, u64 imagebase, u32 imagesize) {
    Insn I; I.pc = pc;
    int i = 0;
    bool rex = false, rexw = false, rexr = false, rexx = false, rexb = false;
    bool op66 = false;

    // --- on ekler ---
    /* 0.9.0-DeepVM: segment ve rep onekleri ARTIK YUTULMAZ — yakalanir:
       - 0x64/0x65 (FS/GS): bellek isleminde gercek taban gerekir (metin2
         fs:[0x18] TEB erisimi). Insn.seg'e yazilir; belleksiz talimatta
         onek dekorektir -> yutulmus gibi davranilir.
       - 0xF2/0xF3 (repne/rep): string islemlerinde Insn.rep'e yazilir;
         diger talimatlarda anlamsiz (F3 90 = pause -> NOP zaten).
       - 0x2E/0x36/0x3E/0x26 (CS/SS/DS/ES) ve 0x67: duzlem segmentlerde
         taban 0 oldugu icin anlamsiz -> yut (eski davranis). */
    while (i < maxlen) {
        u8 b = p[i];
        if (b == 0x66) { op66 = true; i++; continue; }
        if (b == 0x67 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26) { i++; continue; }
        if (b == 0x64 || b == 0x65) { I.seg = b - 0x60; i++; continue; }  /* 4=FS 5=GS */
        if (b == 0xF2) { I.rep = 3; i++; continue; }   /* repne */
        if (b == 0xF3) { I.rep = I.rep ? I.rep : 2; i++; continue; }  /* rep(e); pause F3 90 */
        /* 1.1.0-A4: 0x9B (FWAIT) — FPU op'u oncesinde bekleme-oneki
           (9B DF E0 fstsw ax, 9B D9 /7 fstcw); tek basina FWAIT talimati. */
        if (b == 0x9B) {
            if (i + 1 < maxlen && p[i + 1] >= 0xD8 && p[i + 1] <= 0xDF) { i++; continue; }
            I.op = XP_FWAIT; I.len = (u32)(i + 1); I.text = "fwait"; return I;
        }
        if (is64 && b >= 0x40 && b <= 0x4F) {
            rex = true; rexw = (b >> 3) & 1; rexr = (b >> 2) & 1;
            rexx = (b >> 1) & 1; rexb = b & 1; i++; continue;
        }
        break;
    }
    if (i >= maxlen) return I;
    u8 op = p[i++];

    int sz = op66 ? 2 : (is64 && rexw ? 8 : 4);

    // --- ModRM okuyucu ---
    auto read_modrm = [&](int opsz, int& regf, MemOp& m, bool memok, bool is8=false)->bool {
        if (i >= maxlen) return false;
        u8 mrm = p[i++];
        int mod = mrm >> 6, rg = (mrm >> 3) & 7, rm = mrm & 7;
        /* NOT: reg alanı GRP3/GRP4/GRP5/C0-C1'de alt-opcode'dur — remap YOK.
           Byte-op reg alanı yüksek-bayt kayıt çözümü yalniz 0x88-0x8B'de yapılır. */
        regf = rg + (rexr ? 8 : 0);
        if (mod == 3) {
            m.present = false;
            int rr = rm + (rexb ? 8 : 0);
            m.base = is8 ? reg8enc(is64, rexb, rr) : rr;
            return true;
        }
        if (!memok) return false;
        m.present = true;
        if (rm == 4 && !(is64 && mod == 0 && false)) {
            // SIB (x86 rm=4; x64 rm=4)
            if (i >= maxlen) return false;
            u8 sib = p[i++];
            int sc = sib >> 6, ix = (sib >> 3) & 7, bs = sib & 7;
            m.scale = sc;
            m.idx = (ix == 4) ? -1 : ix + (rexx ? 8 : 0);
            if (bs == 5 && mod == 0) {
                m.base = -1;
                if (i + 4 > maxlen) return false;
                long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                i += 4;
                /* 1.1.0-DUZELTME: x64'te SIB base=5 mod=0 index=var ->
                   [idx*8 + disp32] (disp HAM; mutlak DEGIL). Yalniz index de
                   yoksa (ix==4) [disp32] mutlak adreslemedir. x86: mod=0
                   base=5 her zaman mutlak (eski davranis). */
                if (is64 && ix != 4) { m.riprel = false; m.absimage = false; m.disp = d; }
                else      { m.absimage = true; m.absval = (u64)d; m.disp = 0; }
            } else {
                m.base = bs + (rexb ? 8 : 0);
                if (mod == 1) { if (i >= maxlen) return false;
                    m.disp = (signed char)p[i++]; }
                else if (mod == 2) { if (i + 4 > maxlen) return false;
                    long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                    i += 4; m.disp = d; }
            }
        } else if (rm == 5 && mod == 0) {
            m.base = -1;
            if (i + 4 > maxlen) return false;
            long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
            i += 4;
            if (is64) { m.riprel = true; m.disp = d; }   // rip-rel: hedef = pc+len+disp
            else      { m.absimage = true; m.absval = (u64)d; }
        } else {
            m.base = rm + (rexb ? 8 : 0);
            if (mod == 1) { if (i >= maxlen) return false;
                m.disp = (signed char)p[i++]; }
            else if (mod == 2) { if (i + 4 > maxlen) return false;
                long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                i += 4; m.disp = d; }
        }
        (void)opsz;
        return true;
    };

    auto read_imm = [&](int n)->u64 {
        u64 v = 0;
        for (int k = 0; k < n && i < maxlen; k++) v |= ((u64)p[i + k]) << (8 * k);
        i += n;
        return v;
    };

    auto sxt = [](u64 v, int n)->u64 {
        if (n == 1) return (u64)(long long)(signed char)(u8)v;
        if (n == 4) return (u64)(long long)(int)(u32)v;
        return v;
    };

    I.len = 0; // sonunda set edilecek
    int regf = -1;

    switch (op) {
    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97: {
        /* xchg rax, r (90+r); 90 = xchg rax,rax = NOP */
        if (op == 0x90) { I.op = XP_NOP; break; }
        I.op = XP_XCHG;
        I.sz = (is64 && rexw) ? 8 : 4;
        I.r1 = reg8enc(is64, 0, 0);                       /* rax */
        I.r2 = reg8enc(is64, rexb, (op & 7) + (rexb ? 8 : 0));
        break;
    }
    case 0x86: case 0x87: {   /* xchg r/m8,r8 / xchg r/m,r */
        I.op = XP_XCHG;
        I.sz = (op == 0x86) ? 1 : ((is64 && rexw) ? 8 : 4);
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0x86)) return I;
        if (m.present) { I.text = "xchg mem destegi yok"; I.op = XP_UNKNOWN; return I; }
        I.r1 = m.base; I.r2 = rg;
        break;
    }
    case 0x9B: I.op = XP_NOP; break;
    case 0xCC: I.op = XP_INT3; break;
    /* 0.9.0-DeepVM: bayrak/segme/dongu talimatlari */
    case 0x9C: if (op66) { I.text = "pushfw desteklenmiyor"; return I; }
               I.op = XP_PUSHF; break;
    case 0x9D: if (op66) { I.text = "popfw desteklenmiyor"; return I; }
               I.op = XP_POPF; break;
    case 0x9E: I.op = XP_SAHF; break;
    case 0x9F: I.op = XP_LAHF; break;
    case 0xF5: I.op = XP_SETFLAG; I.ud = 2; break;  /* CMC */
    case 0xF8: I.op = XP_SETFLAG; I.ud = 0; break;  /* CLC */
    case 0xF9: I.op = XP_SETFLAG; I.ud = 1; break;  /* STC */
    case 0xFC: I.op = XP_SETFLAG; I.ud = 3; break;  /* CLD */
    case 0xFD: I.op = XP_SETFLAG; I.ud = 4; break;  /* STD */
    case 0xE0: I.op = XP_LOOP; I.cc = 2;  /* loopne */
               I.imm = read_imm(1); I.immsz = 1;
               I.target = pc + i + (u64)(long long)(signed char)(u8)I.imm; break;
    case 0xE1: I.op = XP_LOOP; I.cc = 1;  /* loope */
               I.imm = read_imm(1); I.immsz = 1;
               I.target = pc + i + (u64)(long long)(signed char)(u8)I.imm; break;
    case 0xE2: I.op = XP_LOOP; I.cc = 0;  /* loop */
               I.imm = read_imm(1); I.immsz = 1;
               /* 67 onekli bicimde i=2 (hedef pc+3), icsiz i=1 (pc+2) */
               I.target = pc + i + (u64)(long long)(signed char)(u8)I.imm; break;
    case 0xE3: I.op = XP_JECXZ;
               I.imm = read_imm(1); I.immsz = 1;
               I.target = pc + i + (u64)(long long)(signed char)(u8)I.imm; break;
    /* 0.9.0-DeepVM: string islemleri (A4-A7/AA-AF) + rep onekleri */
    case 0xA4: case 0xA5: I.op = XP_STR; I.ud = 0;   /* movs */
        I.sz = (op == 0xA4) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4)); break;
    case 0xAA: case 0xAB: I.op = XP_STR; I.ud = 1;   /* stos */
        I.sz = (op == 0xAA) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4)); break;
    case 0xAC: case 0xAD: I.op = XP_STR; I.ud = 2;   /* lods */
        I.sz = (op == 0xAC) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4)); break;
    case 0xAE: case 0xAF: I.op = XP_STR; I.ud = 3;   /* scas */
        I.sz = (op == 0xAE) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4)); break;
    case 0xA6: case 0xA7: I.op = XP_STR; I.ud = 4;   /* cmps */
        I.sz = (op == 0xA6) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4)); break;
    case 0x0F: {
        if (i >= maxlen) return I;
        u8 op2 = p[i++];
        if (op2 == 0x1F) { I.op = XP_NOP; regf = 0; MemOp m; if (!read_modrm(4, regf, m, true)) return I; }
        else if (op2 >= 0x80 && op2 <= 0x8F) {
            I.op = XP_JCC; I.cc = op2 - 0x80; I.sz = 4;
            I.imm = read_imm(4); I.immsz = 4;
            I.target = pc + 6 + (u32)(int)I.imm;
        }
        else if (op2 >= 0x90 && op2 <= 0x9F) {
            I.op = XP_SETCC; I.cc = op2 - 0x90;
            if (i >= maxlen) return I;
            u8 mrm = p[i++]; int mod = mrm >> 6, rm = mrm & 7;
            if (mod != 3) { return I; }
            I.r1 = reg8enc(is64, rexb, rm + (rexb ? 8 : 0));
        }
        else if (op2 >= 0x40 && op2 <= 0x4F) { // CMOVcc r, r/m
            I.op = XP_CMOV; I.cc = op2 - 0x40; I.sz = sz;
            int rg; MemOp m;
            if (!read_modrm(sz, rg, m, true, sz == 1)) return I;
            I.r1 = rg; I.mem = m;
            if (!m.present) I.r2 = m.base;
        }
        else if (op2 >= 0xC8 && op2 <= 0xCF) {  /* 0.8.0: bswap r32/r64 */
            I.op = XP_BSWAP;
            I.sz = (is64 && rexw) ? 8 : 4;
            I.r1 = reg8enc(is64, rexb, (op2 & 7) + (rexb ? 8 : 0));
        }
        else if (op2 == 0xAF) { // IMUL r, r/m
            I.op = XP_IMUL_RR;
            MemOp m;
            if (!read_modrm(sz, regf, m, true)) return I;
            I.r1 = regf;
            /* 0.9.0: bellek formu artk destekli (OP_IMUL_RM) */
            if (m.present) { I.mem = m; }
            else I.r2 = m.base;
        }
        else if (op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
            /* 0.9.0: BT/BTS/BTR/BTC r/m(hedef), r(bit-kaynagi).
               KURAL: I.r1 = hedef reg | -1(mem) ; I.r2 = kaynak reg | -1 */
            I.op = XP_BT; I.ud = (op2 == 0xA3) ? 0 : (op2 == 0xAB) ? 1 : (op2 == 0xB3) ? 2 : 3;
            I.sz = sz;
            MemOp m;
            if (!read_modrm(sz, regf, m, true)) return I;
            if (m.present) { I.mem = m; I.r1 = -1; }
            else           { I.r1 = m.base; }
            I.r2 = regf;
            I.immsz = 0;
        }
        else if (op2 == 0xBA) {
            /* 0.9.0: BT ailesi r/m, imm8 (grp8). I.r1 = hedef reg | -1(mem). */
            if (i >= maxlen) return I;
            u8 mrm = p[i++];
            int sub = (mrm >> 3) & 7;
            if (sub < 4) { I.text = "grp8 bt degil"; return I; }
            I.op = XP_BT; I.ud = sub - 4;   /* 4=BT 5=BTS 6=BTR 7=BTC */
            I.sz = sz;
            int mod = mrm >> 6, rm = mrm & 7;
            if (mod == 3) {
                I.r1 = rm + (rexb ? 8 : 0); I.r2 = -1;
            } else {
                i -= 1;                 /* modrm'i read_modrm'e birak */
                MemOp m; int rg2;
                if (!read_modrm(sz, rg2, m, true)) return I;
                I.mem = m; I.r1 = -1; I.r2 = -1;
            }
            I.imm = read_imm(1); I.immsz = 1;
        }
        else if (op2 == 0xA4 || op2 == 0xA5 || op2 == 0xAC || op2 == 0xAD) {
            /* 0.9.0: SHLD/SHRD r/m, r, imm8|CL */
            I.op = (op2 == 0xA4 || op2 == 0xA5) ? XP_SHLD : XP_SHRD;
            I.sz = (is64 && rexw) ? 8 : sz;
            MemOp m;
            if (!read_modrm(I.sz, regf, m, true)) return I;
            if (m.present) { I.text = "shld/shrd bellek hedef"; return I; }
            I.r1 = m.base;      /* hedef reg */
            I.r2 = regf;        /* kaynak reg */
            if (op2 == 0xA4 || op2 == 0xAC) { I.imm = read_imm(1); I.immsz = 1; }
            else I.immsz = -1;  /* CL */
        }
        else if (op2 == 0xC0 || op2 == 0xC1) {
            /* 0.9.0: XADD r/m, r */
            I.op = XP_XADD;
            I.sz = (op2 == 0xC0) ? 1 : sz;
            MemOp m;
            if (!read_modrm(I.sz, regf, m, true, I.sz == 1)) return I;
            if (!m.present) { I.r1 = m.base; I.r2 = regf; }  /* hedef reg, kaynak reg */
            else { I.mem = m; I.r1 = -1; I.r2 = regf; }
        }
        else if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            I.op = (op2 == 0xB6 || op2 == 0xB7) ? XP_MOVZX : XP_MOVSX;
            I.sz = is64 && rexw ? 8 : 4;
            I.mem.present = false;
            int rg; MemOp m;
            if (!read_modrm(sz, rg, m, true, (op2 == 0xB6 || op2 == 0xBE))) return I;
            I.r1 = rg;
            I.mem = m;
            if (m.present) { /* kaynak bellek */ }
            else I.r2 = m.base;
            if (op2 == 0xB6 || op2 == 0xBE) I.immsz = 1; else I.immsz = 2; // kaynak boyut
        }
        else { I.text = "0F ikinci opcode desteklenmiyor"; return I; }
        break;
    }
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: {
        I.op = XP_PUSH_R; I.sz = is64 ? 8 : 4;
        I.r1 = op - 0x50 + (rexb ? 8 : 0);
        break;
    }
    case 0x68: { I.op = XP_PUSH_I; I.imm = read_imm(4); I.immsz = 4; break; }
    case 0x6A: { I.op = XP_PUSH_I; I.imm = read_imm(1);
                 I.imm = (u64)(long long)(signed char)(u8)I.imm; I.immsz = 4; break; }
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        I.op = XP_POP_R; I.sz = is64 ? 8 : 4;
        I.r1 = op - 0x58 + (rexb ? 8 : 0);
        break;
    }
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
        if (is64) { I.text = "rex tek basina"; return I; }
        I.op = XP_INCDEC_R; I.ud = 0; I.sz = 4; I.r1 = op - 0x40; break;
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        if (is64) { I.text = "rex tek basina"; return I; }
        I.op = XP_INCDEC_R; I.ud = 1; I.sz = 4; I.r1 = op - 0x48; break;
    case 0x88: case 0x89: case 0x8A: case 0x8B: {
        // 88/89: MOV r/m, r  |  8A/8B: MOV r, r/m
        I.op = (op == 0x88 || op == 0x89) ? XP_MOV_MR : XP_MOV_RM;
        I.sz = (op == 0x88 || op == 0x8A) ? 1 : sz;
        int rg; MemOp m;
        /* 0.9.0 KOK-FIX: 88/8A byte formu is8=true ALMALI — yoksa AH/BH/CH/DH
           (rm kod 4-7) RSP/RBP/RSI/RDI diye cozulur (mov %sil,%%ah AH yerine
           RSP'nin dusuk baytina yazar -> sahf/pushf zinciri corba). */
        if (!read_modrm(I.sz, rg, m, true, I.sz == 1)) return I;
        if (I.sz == 1) rg = reg8enc(is64, rexr, rg);   /* reg alani: AH..BH */
        if (m.present) {
            if (op == 0x88 || op == 0x89) { I.mem = m; I.r1 = rg; }
            else { I.mem = m; I.r1 = rg; }
        } else {
            I.r1 = (op == 0x88 || op == 0x89) ? m.base : rg;
            I.r2 = (op == 0x88 || op == 0x89) ? rg : m.base;
        }
        // 8-bit yuksek bayt kaynak/hedef kontrolu
        if (I.sz == 1) {
            int src = (op == 0x88 || op == 0x89) ? I.r1 : I.r2;
            if (src >= 16 && !is64) { /* ah..bh ok (VM destekler) */ }
        }
        break;
    }
    case 0x8D: { // LEA r, m
        I.op = XP_LEA; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        if (!m.present) { I.text = "lea reg,reg"; return I; }
        I.r1 = rg; I.mem = m;
        break;
    }
    case 0xC6: { // MOV r/m8, imm8
        I.op = XP_MOV_MI; I.sz = 1;
        int rg; MemOp m;
        if (!read_modrm(1, rg, m, true, true)) return I;
        if (!m.present) { I.r1 = m.base; I.text = "mov r8,imm"; return I; }
        I.mem = m; I.imm = read_imm(1); I.immsz = 1;
        break;
    }
    case 0xC7: { // MOV r/m, imm32 (op66: r/m16, imm16 — 0.9.0 KOK-FIX)
        I.op = XP_MOV_MI; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        if (!m.present) {
            // mov r32, imm32 (op66: mov r16, imm16)
            I.op = XP_MOV_RI; I.r1 = m.base; I.r2 = -1;
            if (op66) { I.imm = read_imm(2); I.immsz = 2; }
            else { I.imm = read_imm(4); I.immsz = 4; }
            break;
        }
        I.mem = m;
        if (op66) { I.imm = read_imm(2); I.immsz = 2; }
        else { I.imm = read_imm(4); I.immsz = 4; }
        break;
    }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        I.op = XP_MOV_RI; I.sz = 1;
        I.r1 = reg8enc(is64, rexb, (op - 0xB0) + (rexb ? 8 : 0));
        I.imm = read_imm(1); I.immsz = 1;
        break;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        I.r1 = op - 0xB8 + (rexb ? 8 : 0);
        if (is64 && rexw) { I.op = XP_MOV_RI64; I.imm = read_imm(8); I.immsz = 8; }
        else if (op66) {
            /* 0.9.0 KOK-FIX: 66 B8 = mov r16, imm16 — imm 2 BAYT (eski kod
               hep 4 okuyordu -> akis desync, sonraki talimatlar cop). */
            I.op = XP_MOV_RI; I.sz = 2; I.imm = read_imm(2); I.immsz = 2;
        }
        else { I.op = XP_MOV_RI; I.sz = 4; I.imm = read_imm(4); I.immsz = 4; }
        break;
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13:   /* 0.9.0: ADC */
    case 0x18: case 0x19: case 0x1A: case 0x1B:   /* 0.9.0: SBB */
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B: {
        int lo = op & 7;
        int alu = op >> 3; // 0=ADD 1=OR 2=ADC 3=SBB 4=AND 5=SUB 6=XOR 7=CMP
        static const int amap[8] = { ALU_ADD, -1, ALU_ADC, ALU_SBB, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        I.alu = (alu == 1) ? ALU_OR : amap[alu];
        if (I.alu < 0) { I.text = "alu destegi yok"; return I; }
        I.op = XP_ALU;
        I.sz = (lo < 4) ? ((lo & 1) ? sz : 1) : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, I.sz == 1)) return I;
        if (lo == 0 || lo == 1) { // op r/m, r  (mem = hedef)
            if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -2; }
            else { I.r1 = m.base; I.r2 = rg; }
        } else {                  // op r, r/m  (mem = kaynak)
            if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -3; }
            else { I.r1 = rg; I.r2 = m.base; }
        }
        break;
    }
    case 0x80: case 0x81: case 0x83: {
        static const int amap[8] = { ALU_ADD, ALU_OR, ALU_ADC, ALU_SBB, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        int alu2 = -1;
        I.op = XP_ALU; I.sz = (op == 0x80) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0x80)) return I;
        alu2 = amap[rg & 7];
        if (alu2 < 0) { I.text = "grp1 alu"; return I; }
        I.alu = alu2;
        if (m.present) { I.mem = m; I.r1 = -1; }
        else { I.r1 = m.base; }
        // 0x83: imm8 ISIMLI genisletilir (add eax,-1 gibi). Sext YOKTU ->
        // -1 yerine +255 kodlaniyor, if-zincirleri (cmp+ja) yalnis dala giriyordu.
        I.imm = (op == 0x81) ? read_imm(4) : sxt(read_imm(1), 1);
        I.immsz = op == 0x81 ? 4 : 1;
        break;
    }
    case 0x04: case 0x05: case 0x0C: case 0x0D:
    case 0x14: case 0x15: case 0x1C: case 0x1D:   /* 0.9.0: ADC/SBB acc */
    case 0x24: case 0x25: case 0x2C: case 0x2D:
    case 0x34: case 0x35: case 0x3C: case 0x3D: {
        // ALU acc-form: op AL,imm8 | op eAX,imm32
        int hi = op >> 3;
        static const int amap2[8] = { ALU_ADD, ALU_OR, ALU_ADC, ALU_SBB, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        int alu2 = amap2[hi & 7];
        if (alu2 < 0) { I.text = "acc alu"; return I; }
        I.op = XP_ALU; I.alu = alu2;
        // x86 acc-form: AL-form op&7==4 (imm8), eAX-form op&7==5 (imm32).
        // ESKI TEST "op & 4" YANLISTI: 0x05 (add eax,imm32) de op&4=4 oldugu
        // icin AL,imm8 saniliyor, 1 bayt okuyup tum akis kayiyordu!
        if ((op & 7) == 4) { // x04/x0C/x24/x2C/x34/x3C: AL, imm8
            I.sz = 1; I.r1 = 0;
            I.imm = read_imm(1); I.immsz = 1;
        } else {      // x05/x0D/x25/x2D/x35/x3D: eAX, imm32 (REX.W -> 64)
            I.sz = op66 ? 2 : (is64 && rexw ? 8 : 4); I.r1 = 0;
            I.imm = read_imm(4); I.immsz = 4;
        }
        break;
    }
    case 0x84: case 0x85: { // TEST r/m, r
        I.op = XP_ALU; I.alu = ALU_TEST; I.sz = (op == 0x84) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, I.sz == 1)) return I;
        if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -2; }
        else { I.r1 = m.base; I.r2 = rg; }
        break;
    }
    case 0xA8: case 0xA9: { // TEST r, imm
        I.op = XP_ALU; I.alu = ALU_TEST; I.sz = (op == 0xA8) ? 1 : sz;
        I.r1 = 0; I.imm = read_imm(op == 0xA8 ? 1 : 4); I.immsz = op == 0xA8 ? 1 : 4;
        break;
    }
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        I.op = XP_SHIFT; I.sz = (op == 0xC0) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0xC0)) return I;
        int sh = rg & 7;
        /* 0.8.0: ROL(0)/ROR(1) artik kaldirilir; RCL(2)/RCR(3) el-arkasi
           SHL'ye dusme TEHLIKESI kapatildi -> duru RED */
        if (sh == 2 || sh == 3) { I.text = "rcl/rcr desteklenmiyor"; I.op = XP_UNKNOWN; return I; }
        if (sh < 4)  { I.shi = (sh == 0) ? SHI_ROL : SHI_ROR; }
        else I.shi = (sh == 5) ? SHI_SHR : (sh == 7 ? SHI_SAR : SHI_SHL);
        if (m.present) { I.mem = m; I.r1 = -1; }
        else I.r1 = m.base;
        if (op == 0xC0 || op == 0xC1) { I.imm = read_imm(1); I.immsz = 1; }
        else if (op == 0xD2 || op == 0xD3) I.immsz = -1; // CL
        else { I.imm = 1; I.immsz = 1; }
        break;
    }
    case 0x69: case 0x6B: { // IMUL r, r/m, imm
        I.op = XP_IMUL_RRI; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        I.r1 = rg; I.mem = m;
        if (!m.present) I.r2 = m.base;
        // 0x6B: imm8 ISIMLI genisletilir (imul r,r/m,-N yaygin)
        I.imm = (op == 0x69) ? read_imm(4) : sxt(read_imm(1), 1);
        I.immsz = op == 0x69 ? 4 : 1;
        break;
    }
    case 0xF6: case 0xF7: { // GRP3
        I.sz = (op == 0xF6) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0xF6)) return I;
        int sub = rg & 7;
        if (sub == 0) { // TEST r/m, imm
            I.op = XP_ALU; I.alu = ALU_TEST;
            if (m.present) { I.mem = m; I.r1 = -1; }
            else I.r1 = m.base;
            I.imm = read_imm(I.sz == 1 ? 1 : 4); I.immsz = I.sz == 1 ? 1 : 4;
        } else if (sub == 7) { // IDIV r/m
            I.op = XP_IDIV;
            if (m.present) { I.text = "idiv bellek"; return I; }
            I.r1 = m.base;
        } else if (sub == 2) { // NOT r/m (bayrak etkisi YOK)
            I.op = XP_NOT; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else if (sub == 3) { // NEG r/m (CF=x!=0, ZF/SF/OF)
            I.op = XP_NEG; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else if (sub == 4) { // 0.9.0: MUL r/m (RDX:RAX = RAX * r/m)
            I.op = XP_MUL; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else if (sub == 6) { // 0.9.0: DIV r/m (RDX:RAX / r/m)
            I.op = XP_DIV; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else { I.text = "grp3 imul kalmadi"; return I; }
        break;
    }
    case 0xFE: { // GRP4: INC/DEC r/m8
        int rg; MemOp m;
        if (!read_modrm(1, rg, m, true, true)) return I;
        int sub = rg & 7;
        I.sz = 1;
        if (m.present) { I.op = XP_INCDEC_M; I.ud = (sub == 0) ? 0 : 1; I.mem = m; }
        else { I.op = XP_INCDEC_R; I.ud = (sub == 0) ? 0 : 1; I.r1 = reg8enc(is64, rexb, m.base); }
        break;
    }
    case 0xFF: { // GRP5
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        int sub = rg & 7;
        if (sub == 0 || sub == 1) {
            I.sz = sz;
            if (m.present) { I.op = XP_INCDEC_M; I.ud = (sub == 0) ? 0 : 1; I.mem = m; }
            else { I.op = XP_INCDEC_R; I.ud = (sub == 0) ? 0 : 1; I.r1 = m.base; }
        } else if (sub == 2) {
            // 0.5.0: call [mem] (FF15/FF10) — dolayli. 1.2.2-A10: reg-form
            // (FF D0 call eax) da XP_CALLI uretir (mem yok, r1=reg) —
            // VM OP_NCALLI form=2 kayit-formuyla natcall yapar.
            I.op = XP_CALLI; I.sz = sz;
            if (m.present) { I.mem = m; I.text = "call [mem]"; }
            else { I.r1 = m.base; I.text = "call reg"; }
        } else if (sub == 4 && m.present) {
            I.op = XP_JMPI; I.sz = sz; I.mem = m;
            I.text = "jmp [mem]";
        } else { I.text = "grp5 push/far"; return I; }
        break;
    }
    case 0xE8: { I.op = XP_CALL; I.imm = read_imm(4); I.immsz = 4;
                 I.target = pc + 5 + (u32)(int)I.imm; break; }
    case 0xE9: { I.op = XP_JMP; I.imm = read_imm(4); I.immsz = 4;
                 I.target = pc + 5 + (u32)(int)I.imm; break; }
    case 0xEB: { I.op = XP_JMP; I.imm = read_imm(1); I.immsz = 1;
                 I.target = pc + 2 + (u32)(long long)(signed char)(u8)I.imm; break; }
    case 0xC2: { I.op = XP_RETI16; I.imm = read_imm(2); I.immsz = 2; break; }
    case 0xC3: { I.op = XP_RET; break; }
    case 0xC9: { I.op = XP_LEAVE; break; }
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
        I.op = XP_JCC; I.cc = op - 0x70; I.sz = 4;
        I.imm = read_imm(1); I.immsz = 1;
        I.target = pc + 2 + (u64)(long long)(signed char)(u8)I.imm;
        break;
    }
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
        // mov AL/eAX <-> moffs32 (x86 mutlak statik erisim)
        I.op = (op == 0xA0 || op == 0xA1) ? XP_MOV_RM : XP_MOV_MR;
        I.sz = (op == 0xA0 || op == 0xA2) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4));
        I.r1 = 0;  // AL/AX/EAX/RAX
        MemOp m; m.present = true; m.absimage = true;
        u64 v = read_imm(4);
        m.absval = v;
        I.mem = m;
        if (is64 && !rexw && (op == 0xA1 || op == 0xA3)) { /* 32-bit moffs isaret genisletme: nadir, kabul */ }
        break;
    }
    case 0x98: { I.op = XP_CWDE; break; }
    case 0x99: { I.op = XP_CDQ; break; }
    case 0x63: { if (!is64) { I.text = "arpl"; return I; }
                 I.op = XP_MOVSX; I.sz = sz; I.immsz = 4;
                 int rg; MemOp m;
                 if (!read_modrm(sz, rg, m, true)) return I;
                 if (m.present) { I.mem = m; I.r1 = rg; } else { I.r1 = rg; I.r2 = m.base; }
                 break; }
    /* ---- 1.1.0-A4-FPU: x87 uzayi (D8-DF) — UniversalObfuscator paritesi.
       FPU bellek-form boyutlari aileden gelir (0x66 oneki etkisiz);
       mod=3 formlarda r1 = st(i) (0..7). RED'ler (FLDENV/FSTENV/FSAVE/
       FRSTOR/ftu yok-formlari) XP_UNKNOWN doner -> lifter duru RED. */
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
        int rg; MemOp m;
        if (!read_modrm(4, rg, m, true)) return I;
        bool rform = !m.present;
        int si = rform ? (m.base & 7) : 0;    /* st(i) indeksi (REX.B FPU'da yok) */
#ifdef A4DBG
        fprintf(stderr, "[A4DBG] op=%02x modrm-in rg=%d rform=%d si=%d\n", (int)op, (int)rg, (int)rform, (int)si);
#endif
        switch (op) {
        case 0xD8:
            if (rform) {
                switch (rg) {
                case 0: I.op = XP_FADD;  I.ud = 0; I.r1 = si; break;   /* D8 C0+i ST0+=STi */
                case 1: I.op = XP_FMUL;  I.ud = 0; I.r1 = si; break;   /* D8 C8+i ST0*=STi */
                case 2: I.op = XP_FCOM;  I.ud = 0; I.r1 = si; break;   /* D8 D0+i */
                case 3: I.op = XP_FCOMP; I.ud = 0; I.r1 = si; break;   /* D8 D8+i */
                case 4: I.op = XP_FSUB;  I.ud = 0; I.r1 = si; break;   /* D8 E0+i ST0-=STi */
                case 5: I.op = XP_FSUBR; I.ud = 0; I.r1 = si; break;   /* D8 E8+i ST0=STi-ST0 */
                case 6: I.op = XP_FDIV;  I.ud = 0; I.r1 = si; break;   /* D8 F0+i */
                case 7: I.op = XP_FDIVR; I.ud = 0; I.r1 = si; break;   /* D8 F8+i */
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FADD;  I.sz = 4; I.mem = m; break;
                case 1: I.op = XP_FMUL;  I.sz = 4; I.mem = m; break;
                case 2: I.op = XP_FCOM;  I.sz = 4; I.mem = m; break;
                case 3: I.op = XP_FCOMP; I.sz = 4; I.mem = m; break;
                case 4: I.op = XP_FSUB;  I.sz = 4; I.mem = m; break;
                case 5: I.op = XP_FSUBR; I.sz = 4; I.mem = m; break;
                case 6: I.op = XP_FDIV;  I.sz = 4; I.mem = m; break;
                case 7: I.op = XP_FDIVR; I.sz = 4; I.mem = m; break;
                }
            }
            break;
        case 0xD9:
            if (rform) {
                if (rg == 0)      { I.op = XP_FLD;    I.r1 = si; break; }
                if (rg == 1)      { I.op = XP_FXCH;   I.r1 = si; break; }
                if (rg == 2 && si == 0) { I.op = XP_FNOP; break; }         /* D9 D0 */
                if (rg == 3)      { I.op = XP_FSTP;   I.r1 = si; break; }  /* D9 D8+i */
                if (rg == 4) {
                    if (si == 0) I.op = XP_FCHS;
                    else if (si == 1) I.op = XP_FABS;
                    else if (si == 4) I.op = XP_FTST;
                    else if (si == 5) I.op = XP_FXAM;
                    break;
                }
                if (rg == 5) {
                    if (si == 0) I.op = XP_FLD1;
                    else if (si == 1) I.op = XP_FLDL2T;
                    else if (si == 2) I.op = XP_FLDL2E;
                    else if (si == 3) I.op = XP_FLDPI;
                    else if (si == 4) I.op = XP_FLDLG2;
                    else if (si == 5) I.op = XP_FLDLN2;
                    else if (si == 6) I.op = XP_FLDZ;
                    break;
                }
                if (rg == 6) {
                    if (si == 0) I.op = XP_F2XM1;
                    else if (si == 1) I.op = XP_FYL2X;
                    else if (si == 2) I.op = XP_FPTAN;
                    else if (si == 3) I.op = XP_FPATAN;
                    else if (si == 4) I.op = XP_FXTRACT;
                    else if (si == 5) I.op = XP_FPREM1;
                    else if (si == 6) I.op = XP_FDECSTP;
                    else if (si == 7) I.op = XP_FINCSTP;
                    break;
                }
                if (rg == 7) {
                    if (si == 0) I.op = XP_FPREM;
                    else if (si == 1) I.op = XP_FYL2XP1;
                    else if (si == 2) I.op = XP_FSQRT;
                    else if (si == 3) I.op = XP_FSINCOS;
                    else if (si == 4) I.op = XP_FRNDINT;
                    else if (si == 5) I.op = XP_FSCALE;
                    else if (si == 6) I.op = XP_FSIN;
                    else if (si == 7) I.op = XP_FCOS;
                    break;
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FLD;   I.sz = 4; I.mem = m; break;
                case 2: I.op = XP_FST;   I.sz = 4; I.mem = m; break;
                case 3: I.op = XP_FSTP;  I.sz = 4; I.mem = m; break;
                case 5: I.op = XP_FLDCW; I.sz = 2; I.mem = m; break;
                case 7: I.op = XP_FSTCW; I.sz = 2; I.mem = m; break;
                default: return I;   /* FLDENV/FSTENV/yer. -> RED */
                }
            }
            break;
        case 0xDA:
            if (rform) {
                if (rg == 5 && si == 1) { I.op = XP_FUCOMPP; break; }  /* DA E9 */
                switch (rg) {
                case 0: I.op = XP_FCMOV; I.cc = 2; I.r1 = si; break;  /* FCMOVB */
                case 1: I.op = XP_FCMOV; I.cc = 4; I.r1 = si; break;  /* FCMOVE */
                case 2: I.op = XP_FCMOV; I.cc = 6; I.r1 = si; break;  /* FCMOVBE */
                case 3: I.op = XP_FCMOV; I.cc = 10; I.r1 = si; break; /* FCMOVU (PF) */
                case 4: I.op = XP_FCMOV; I.cc = 3; I.r1 = si; break;  /* FCMOVNB */
                case 5: I.op = XP_FCMOV; I.cc = 5; I.r1 = si; break;  /* FCMOVNE */
                case 6: I.op = XP_FCMOV; I.cc = 7; I.r1 = si; break;  /* FCMOVNBE */
                case 7: I.op = XP_FCMOV; I.cc = 11; I.r1 = si; break; /* FCMOVNU (NP) */
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FIADD;  I.sz = 4; I.mem = m; break;
                case 1: I.op = XP_FIMUL;  I.sz = 4; I.mem = m; break;
                case 2: I.op = XP_FICOM;  I.sz = 4; I.mem = m; break;
                case 3: I.op = XP_FICOMP; I.sz = 4; I.mem = m; break;
                case 4: I.op = XP_FISUBR; I.sz = 4; I.mem = m; break;
                case 5: I.op = XP_FISUB;  I.sz = 4; I.mem = m; break;
                case 6: I.op = XP_FIDIVR; I.sz = 4; I.mem = m; break;
                case 7: I.op = XP_FIDIV;  I.sz = 4; I.mem = m; break;
                }
            }
            break;
        case 0xDB:
            if (rform) {
                if (rg == 4) {
                    if (si == 2) I.op = XP_FCLEX;      /* DB E2 (9B DB E2) */
                    else if (si == 3) I.op = XP_FINIT; /* DB E3 (9B DB E3) */
                    break;
                }
                if (rg == 5) { I.op = XP_FUCOMI; I.r1 = si; break; }
                if (rg == 6) { I.op = XP_FCOMI;  I.r1 = si; break; }
            } else {
                switch (rg) {
                case 0: I.op = XP_FILD;   I.sz = 4; I.mem = m; break;
                case 1: I.op = XP_FISTTP; I.sz = 4; I.mem = m; break;
                case 2: I.op = XP_FIST;   I.sz = 4; I.mem = m; break;
                case 3: I.op = XP_FISTP;  I.sz = 4; I.mem = m; break;
                case 5: I.op = XP_FLD;    I.sz = 10; I.mem = m; break;
                case 7: I.op = XP_FSTP;   I.sz = 10; I.mem = m; break;
                default: return I;
                }
            }
            break;
        case 0xDC:
            if (rform) {
                switch (rg) {
                case 0: I.op = XP_FADD;  I.ud = 1; I.r1 = si; break;   /* DC C0+i STi+=ST0 */
                case 1: I.op = XP_FMUL;  I.ud = 1; I.r1 = si; break;   /* DC C8+i STi*=ST0 */
                case 2: I.op = XP_FCOM;  I.ud = 1; I.r1 = si; break;
                case 3: I.op = XP_FCOMP; I.ud = 1; I.r1 = si; break;
                case 4: I.op = XP_FSUBR; I.ud = 1; I.r1 = si; break;   /* DC E0+i STi=ST0-STi */
                case 5: I.op = XP_FSUB;  I.ud = 1; I.r1 = si; break;   /* DC E8+i STi-=ST0 */
                case 6: I.op = XP_FDIVR; I.ud = 1; I.r1 = si; break;   /* DC F0+i */
                case 7: I.op = XP_FDIV;  I.ud = 1; I.r1 = si; break;   /* DC F8+i */
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FADD;  I.sz = 8; I.mem = m; break;
                case 1: I.op = XP_FMUL;  I.sz = 8; I.mem = m; break;
                case 2: I.op = XP_FCOM;  I.sz = 8; I.mem = m; break;
                case 3: I.op = XP_FCOMP; I.sz = 8; I.mem = m; break;
                case 4: I.op = XP_FSUB;  I.sz = 8; I.mem = m; break; /* DC 20 = fsub m64 (empirik: mem tablo TERS DEGIL) */
                case 5: I.op = XP_FSUBR; I.sz = 8; I.mem = m; break; /* DC 28 = fsubr m64 */
                case 6: I.op = XP_FDIV;  I.sz = 8; I.mem = m; break; /* DC 30 = fdiv m64 */
                case 7: I.op = XP_FDIVR; I.sz = 8; I.mem = m; break; /* DC 38 = fdivr m64 */
                }
            }
            break;
        case 0xDD:
            if (rform) {
                switch (rg) {
                case 0: I.op = XP_FFREE;   I.r1 = si; break;
                case 2: I.op = XP_FST;     I.r1 = si; break;   /* DD D0+i = FST ST(i) (reg=2) */
                case 3: I.op = XP_FSTP;    I.r1 = si; break;   /* DD D8+i = FSTP ST(i) (reg=3) */
                case 4: I.op = XP_FUCOM;   I.r1 = si; break;   /* DD E0+i */
                case 5: I.op = XP_FUCOMP;  I.r1 = si; break;   /* DD E8+i */
                default: return I;
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FLD;    I.sz = 8; I.mem = m; break;
                case 2: I.op = XP_FST;    I.sz = 8; I.mem = m; break;
                case 3: I.op = XP_FSTP;   I.sz = 8; I.mem = m; break;
                case 7: I.op = XP_FSTSW;  I.sz = 2; I.mem = m; break; /* DD /7 (fnstsw m16) */
                default: return I;   /* FRSTOR/FNSAVE -> RED */
                }
            }
            break;
        case 0xDE:
            if (rform) {
                if (rg == 2 && si == 1) { I.op = XP_FCOMPP; break; }  /* DE D9 */
                switch (rg) {
                case 0: I.op = XP_FADDP;  I.r1 = si; break;
                case 1: I.op = XP_FMULP;  I.r1 = si; break;
                case 3: I.op = XP_FSUBRP; I.r1 = si; break;   /* DE E0+i */
                case 4: I.op = XP_FSUBP;  I.r1 = si; break;   /* DE E8+i */
                case 5: I.op = XP_FDIVRP; I.r1 = si; break;   /* DE F0+i */
                case 6: I.op = XP_FDIVP;  I.r1 = si; break;   /* DE F8+i */
                default: return I;
                }
            } else {
                switch (rg) {
                case 0: I.op = XP_FIADD;  I.sz = 2; I.mem = m; break;
                case 1: I.op = XP_FIMUL;  I.sz = 2; I.mem = m; break;
                case 2: I.op = XP_FICOM;  I.sz = 2; I.mem = m; break;
                case 3: I.op = XP_FICOMP; I.sz = 2; I.mem = m; break;
                case 4: I.op = XP_FISUBR; I.sz = 2; I.mem = m; break;
                case 5: I.op = XP_FISUB;  I.sz = 2; I.mem = m; break;
                case 6: I.op = XP_FIDIVR; I.sz = 2; I.mem = m; break;
                case 7: I.op = XP_FIDIV;  I.sz = 2; I.mem = m; break;
                }
            }
            break;
        case 0xDF:
            if (rform) {
                /* DF E0 = fstsw ax: mod=3, reg=4, rm=0 (empirik: nasm/gcc)
                   DF E8+i = fucomip (reg=5), DF F0+i = fcomip (reg=6) */
                if (rg == 4 && si == 0) { I.op = XP_FSTSW; break; }  /* DF E0 = fstsw ax */
                if (rg == 5) { I.op = XP_FUCOMIP; I.r1 = si; break; } /* DF E8+i */
                if (rg == 6) { I.op = XP_FCOMIP;  I.r1 = si; break; } /* DF F0+i */
                return I;
            } else {
                switch (rg) {
                case 0: I.op = XP_FILD;   I.sz = 2; I.mem = m; break;
                case 1: I.op = XP_FISTTP; I.sz = 2; I.mem = m; break;
                case 2: I.op = XP_FIST;   I.sz = 2; I.mem = m; break;
                case 3: I.op = XP_FISTP;  I.sz = 2; I.mem = m; break;
                case 4: I.op = XP_FBLD;   I.sz = 10; I.mem = m; break;
                case 5: I.op = XP_FILD;   I.sz = 8; I.mem = m; break;
                case 6: I.op = XP_FBSTP;  I.sz = 10; I.mem = m; break;
                case 7: I.op = XP_FISTP;  I.sz = 8; I.mem = m; break;
                }
            }
            break;
        }
        I.text = "fpu";
        break;
    }
    default:
        I.text = "opcode desteklenmiyor";
        return I;
    }

    I.len = (u32)i;
    if (I.op == XP_UNKNOWN) return I;
    return I;
}
