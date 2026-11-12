// ============================================================
// engine_mut.cpp — 0.3.0 MUTASYON CEKIRDEGI
// VMProtect "Mutation" katmaninin yerli uygulamasi:
//   1) talimat ikamesi (add<->sub, mov<->push/pop, xor<->sub,
//      test<->or, inc/dec<->lea, not<->xor ...)
//   2) canli-register analizi (16 GPR + FLAGS sozu-register,
//      temel-blok CFG uzerinde geriye dogru veri-akisi)
//   3) JMP kapilari (EB rel8 + atlanan junk; zincirli varyant)
//   4) kod yeniden uretimi (dahili jmp/jcc rel32 fixup, dis
//      cagri rel32 yeniden hesabi, x64 rip-goreceli disp yamasi)
//
// DOGRULUK KURALLARI (kiran her kural reddi getirir):
//   - ikameler bayrak semantigini BOZMAMALI: bayrak yazan
//     talimat baska bicime cevrilirse yanlis bayrak kalir.
//     "flags dead after" kosulu liveness ile kanitlanir.
//   - junk yalnizca OLU register'lara dokunur (rsp/rbp hep
//     yasak) ve bayrak yazan junk sadece bayraklar oluyken.
//   - kapi junk'i HIC CALISMAZ (kosulsuz jmp atlar) ama yine
//     gecerli x86 kodu uretilir (anti-disasm tuzak honeypot).
//   - butun uretilen formlar lifter-guvenlidir: Ultra (M+V)
//     ayni akistan sanallastirilir.
// ============================================================
#include "engine.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

typedef int8_t i8;               // engine.hpp'de yok (yalniz i16/i32/i64)

namespace {

const int RF = 16;               // FLAGS sozu-register indeksi
const u32 FFLAG = (1u << RF);
const u32 REGALL = 0xFFFF;       // 16 GPR maskesi

// ---------------- talimat kaydi ----------------
struct MInsn {
    Insn I;
    u32 pc = 0;                  // orijinal RVA
    const u8* raw = nullptr;     // kaynak baytlar
    u32 uses = 0, defs = 0;      // liveness maskeleri
    u32 live_after = 0;          // talimattan SONRA canli set
    int bb = 0;
};

// ---------------- kucuk kodlayici ----------------
// Yalnizca mutasyonun urettigi formlar: her cikti lifter
// tarafindan cozulebilir olacak sekilde sinirlandirilmistir.
struct Enc {
    std::vector<u8>& o;
    bool is64;
    void b(u8 x) { o.push_back(x); }
    void w32(u32 v) { for (int k = 0; k < 4; k++) o.push_back((u8)(v >> (8 * k))); }
    void w64(u64 v) { for (int k = 0; k < 8; k++) o.push_back((u8)(v >> (8 * k))); }

    // mov r32, imm32 (B8+r id) — sifir genisletmeli
    void mov_r_imm32(int r, u32 imm) {
        if (r >= 8) b(0x41);
        b((u8)(0xB8 + (r & 7))); w32(imm);
    }
    // movabs r64, imm64 (48/49 B8+r iq)
    void mov_r_imm64(int r, u64 imm) {
        b(r >= 8 ? 0x49 : 0x48);
        b((u8)(0xB8 + (r & 7))); w64(imm);
    }
    // lea r, [r + disp] — operand boyutu korunur; rm=4 (rsp/r12) SIB ister,
    // rm=5 mod!=0 (rbp/r13) disp zorunlu (zaten var)
    void lea_self(int r, i64 d, int sz) {
        if (sz == 2) b(0x66);
        bool hi = r >= 8;
        if (is64) {
            u8 rex = (u8)((sz == 8 ? 8 : 0) | (hi ? 5 : 0));
            if (rex) b((u8)(0x40 | rex));
        }
        b(0x8D);
        u8 rm = (u8)(r & 7);
        bool d8 = (d >= -128 && d <= 127);
        u8 mod = d8 ? 0x40 : 0x80;
        if (rm == 4) { b((u8)(mod | (rm << 3) | 4)); b(0x24); }
        else b((u8)(mod | (rm << 3) | rm));
        if (d8) b((u8)(i8)d); else w32((u32)(i32)d);
    }
    // GRP1: ALU kodu -> /ext (ADD /0 OR /1 AND /4 SUB /5 XOR /6 CMP /7)
    static int grp1_of(int alu) {
        switch (alu) {
        case ALU_ADD: return 0; case ALU_OR: return 1; case ALU_AND: return 4;
        case ALU_SUB: return 5; case ALU_XOR: return 6; case ALU_CMP: return 7;
        }
        return -1;
    }
    // add/sub/xor/or/and r, imm  (80/81/83 /ext)
    void alu_r_imm(int alu, int r, i64 imm, int sz) {
        int ext = grp1_of(alu);
        if (ext < 0) return;
        if (sz == 2) b(0x66);
        bool hi = r >= 8;
        if (is64) {
            u8 rex = (u8)((sz == 8 ? 8 : 0) | (hi ? 5 : 0));
            if (rex) b((u8)(0x40 | rex));
        }
        bool imm8 = (imm >= -128 && imm <= 127);
        if (sz == 1) {                 // 8-bit: yalnizca 80 + imm8
            b(0x80); b((u8)(0xC0 | (ext << 3) | (r & 7))); b((u8)(i8)imm);
        } else if (imm8) {
            b(0x83); b((u8)(0xC0 | (ext << 3) | (r & 7))); b((u8)(i8)imm);
        } else {
            b(0x81); b((u8)(0xC0 | (ext << 3) | (r & 7))); w32((u32)(i32)imm);
        }
    }
    // ALU r, r (reg,reg; "r <- r/m" yonunde opcode'lar)
    void alu_rr(int alu, int rd, int rs, int sz) {
        // bizim ALU sirasi: ADD SUB AND OR XOR CMP TEST
        static const u8 t[7] = { 0x03, 0x2B, 0x23, 0x0B, 0x33, 0x3B, 0x85 };
        u8 opc = (sz == 1) ? (u8)(t[alu] - 1) : t[alu];
        if (sz == 2) b(0x66);
        bool hid = rd >= 8, his = rs >= 8;
        if (is64) {
            u8 rex = (u8)((sz == 8 ? 8 : 0) | (hid ? 4 : 0) | (his ? 1 : 0));
            if (rex) b((u8)(0x40 | rex));
        }
        b(opc);
        b((u8)(0xC0 | ((rd & 7) << 3) | (rs & 7)));
    }
    void push_r(int r)  { if (r >= 8) b(0x41); b((u8)(0x50 + (r & 7))); }
    void pop_r(int r)   { if (r >= 8) b(0x41); b((u8)(0x58 + (r & 7))); }
    void push_imm32(u32 v) { b(0x68); w32(v); }
    void nop1() { b(0x90); }
    void nop5() { b(0x0F); b(0x1F); b(0x44); b(0x00); b(0x00); }
    // rel32 alani: alarin bayt ofsetini dondurur (fixup icin)
    u32 jmp_rel32()  { b(0xE9); u32 at = (u32)o.size(); w32(0); return at; }
    u32 jcc_rel32(int cc) { b(0x0F); b((u8)(0x80 + cc)); u32 at = (u32)o.size(); w32(0); return at; }
    u32 call_rel32() { b(0xE8); u32 at = (u32)o.size(); w32(0); return at; }
    // JMP kapi: EB rel8 + (cagiranin ekleyecegi junk) — rel8 geri yamalanir
    u32 gate_rel8() { b(0xEB); u32 at = (u32)o.size(); b(0x00); return at; }
};

// ---------------- fixup kaydi ----------------
struct MFix { u32 at; u32 anchor; u32 val; int kind; };
// kind 0: dahili rel32 (val=orijinal pc) — rel = pc2new[val] - anchor
// kind 1: RVA-goreceli (val=hedef RVA) — rel = val - (base_rva + anchor)
// anchor = yapa alaninin bitecegi talimat ici ofset (rel32 formlarinda
// alan sonu == talimat sonu; rip-gorecelide talimat SONU — imm dahil).
// HATA DERSI #4: capa, disp alani sonu sanildi -> imm'li formlarda hedef kayiyordu.

// ---------------- uses/defs cikarimi ----------------
// KISMEN yazan (8/16-bit, setcc, cmov) talimatlar READ+WRITE sayilir
// (muhafazakar: olumluluk sinyalini bastirir, asla yanlis olum vermez).
// RET donus degerleri (RAX/RDX) kullanilir sayilir. CALL/ disari JMP
// tum register + bayraklari OKUR varsayilir (argumanlar bilinemez).
static void ud_of(MInsn& m) {
    const Insn& I = m.I;
    u32 u = 0, d = 0;
    auto R = [&](int r) { if (r >= 0 && r < 16) u |= (1u << r); };
    auto W = [&](int r) { if (r >= 0 && r < 16) d |= (1u << r); };
    auto RW = [&](int r) { R(r); W(r); };
    auto MEM = [&]() { if (I.mem.present) { R(I.mem.base); R(I.mem.idx); } };
    bool full_w = (I.sz >= 4);              // 32/64-bit yazim tam genisler
    switch (I.op) {
    case XP_PUSH_R: R(I.r1); break;
    case XP_POP_R:  W(I.r1); break;
    case XP_PUSH_I: break;
    case XP_MOV_MR: case XP_MOV_RM:
        if (!I.mem.present) {
            // reg <- reg (r1=hedef, r2=kaynak; 32/64-bit yazim tam genisler)
            if (I.sz >= 4) { W(I.r1); R(I.r2); } else RW(I.r1);
            if (I.sz < 4) R(I.r2);
        } else if (I.op == XP_MOV_MR) {
            MEM(); R(I.r1);                     // [mem] <- r
        } else {
            MEM(); if (I.sz >= 4) W(I.r1); else RW(I.r1);   // r <- [mem]
        }
        break;
    case XP_MOV_MI: MEM(); break;
    case XP_MOV_RI: case XP_MOV_RI64:
        if (full_w || I.op == XP_MOV_RI64) W(I.r1); else RW(I.r1);
        break;
    case XP_LEA: MEM(); if (I.sz >= 4) W(I.r1); else RW(I.r1); break;
    case XP_ALU: {
        d |= FFLAG;                          // tum ALU bayrak yazar (TEST dahil)
        bool ro = (I.alu == ALU_CMP || I.alu == ALU_TEST);  // CMP/TEST YALNIZCA OKUR
        // HATA DERSI #3: ALU hedefi ayni zamanda KAYNAKTIR (a = a op b).
        // ud_of eskiden yalniz W(r1) yaziyordu -> hedef register "olu" sayiliyor
        // -> junk canli degeri eziyordu (add ecx,[g_px] ornegi).
        if (I.immsz > 0) {                   // op r/m, imm
            MEM();
            if (I.mem.present) { /* mem rw (cmp/test: sadece oku) */ }
            else if (I.r1 >= 0) {
                R(I.r1);
                if (!ro) { if (I.sz >= 4) W(I.r1); else RW(I.r1); }
            }
        } else if (I.mem.present) {
            MEM();
            if (I.r1 >= 0 && I.r2 == -2) R(I.r1);          // [mem] <- r (r kaynak)
            else if (I.r1 >= 0) {
                R(I.r1);
                if (!ro) { if (I.sz >= 4) W(I.r1); else RW(I.r1); }
            }
        } else {
            R(I.r1); R(I.r2);
            if (!ro) { if (I.sz >= 4) W(I.r1); else RW(I.r1); }
        }
        break;
    }
    case XP_SHIFT: {
        d |= FFLAG;
        MEM();
        // HATA DERSI #6: shift kaynagi da OKUR (r = r << n). Eksik R(r1)
        // "shl ecx,4" oncesi ecx'i olu sanip junk eziyordu (x86 MovePlayer).
        if (I.mem.present) {}
        else { R(I.r1); if (I.sz >= 4) W(I.r1); else RW(I.r1); }
        if (I.immsz == -1) R(1);             // %cl
        break;
    }
    case XP_IMUL_RRI: case XP_IMUL_RR:
        d |= FFLAG; MEM();
        if (I.sz >= 4) W(I.r1); else RW(I.r1);
        if (I.op == XP_IMUL_RR) R(I.r1);     // imul r1, r1*r2: kaynak r1 de OKUNUR
        R(I.r2);                             // (RRI uclu-formunda r1 salt hedeftir)
        break;
    case XP_INCDEC_R: case XP_INCDEC_M:
        // inc/dec CF KORUR: bayraklari yazmaz say (muhafazakar),
        // r/m uzerinde oku+yaz
        MEM();
        if (!I.mem.present) { if (I.sz >= 4) W(I.r1); else RW(I.r1); }
        break;
    case XP_MOVZX: case XP_MOVSX:
        MEM(); if (I.sz >= 4) W(I.r1); else RW(I.r1);
        if (!I.mem.present) R(I.r2);
        break;
    case XP_JMP: break;                       // hedef analizi CFG'de
    case XP_JCC: u |= FFLAG; break;
    case XP_CALL:                             // argumanlar bilinemez: hepsi canli
        u |= REGALL | FFLAG;
        break;
    case XP_RET: case XP_RETI16:
        u |= (1u << 0) | (1u << 2) | (1u << 4);  // RAX/RDX donus + RSP
        break;
    case XP_SETCC: u |= FFLAG; RW(I.r1); break;
    case XP_CMOV: u |= FFLAG; MEM(); RW(I.r1); if (!I.mem.present) R(I.r2); break;
    case XP_CWDE: RW(0); break;
    case XP_CDQ: R(0); W(2); break;
    case XP_IDIV: d |= FFLAG; R(0); R(2); RW(0); RW(2); R(I.r1); break;
    /* ---- 0.9.0-DeepVM: yeni komutlarin uses/defs (muhafazakar) ---- */
    case XP_MUL:   /* RDX:RAX = RAX * r/m (sz1: AX = AL*r8) */
        d |= FFLAG; MEM(); R(0); R(I.r1); RW(0); RW(2); break;
    case XP_DIV:   /* RDX:RAX / r/m — bayraklar tanimsiz */
        d |= FFLAG; MEM(); R(0); R(2); R(I.r1); RW(0); RW(2); break;
    case XP_BT:    /* CF <- test bit; BTS/BTR/BTC r/m yazar */
        d |= FFLAG; MEM(); if (!I.mem.present) R(I.r1);
        if (I.immsz > 0) { /* imm bit */ }
        else R(I.r2);
        if (I.ud != 0) { if (!I.mem.present) RW(I.r1); }
        break;
    case XP_SHLD: case XP_SHRD:
        d |= FFLAG; RW(I.r1); R(I.r2); if (I.immsz == -1) R(1); break;
    case XP_XADD:  /* dst += src; src <- eski dst — ikisi de RW */
        d |= FFLAG; MEM(); if (!I.mem.present) RW(I.r1); RW(I.r2); break;
    case XP_IMUL_RM:
        d |= FFLAG; MEM(); RW(I.r1); break;
    case XP_STR:   /* ESI/EDI (+ECX rep, +EAX lods/stos/scas) + DF yonu */
        d |= FFLAG; R(6); R(7);
        if (I.rep) R(1);
        if (I.ud == 1 || I.ud == 2 || I.ud == 3) R(0);   /* stos/lods/scas: rax */
        if (I.ud == 2) RW(0);                            /* lods: rax <- [rsi] */
        RW(6); if (I.ud == 0 || I.ud == 4) RW(7);
        if (I.rep) RW(1);
        break;
    case XP_LOOP:  /* --rcx; loope/loopne ZF okur */
        R(1); RW(1); if (I.cc != 0) u |= FFLAG; break;
    case XP_JECXZ: R(1); break;
    case XP_SETFLAG: d |= FFLAG; break;
    case XP_PUSHF: u |= FFLAG; W(4); break;
    case XP_POPF:  d |= FFLAG; R(4); break;
    case XP_SAHF:  d |= FFLAG; R(0); break;   /* AH kaynak */
    case XP_LAHF:  RW(0); break;              /* AH <- flags */
    case XP_NEG: d |= FFLAG; MEM(); if (!I.mem.present) RW(I.r1); break;
    case XP_NOT: MEM(); if (!I.mem.present) RW(I.r1); break;
    case XP_LEAVE: R(5); W(4); W(5); break;
    /* ---- 1.1.0-A4-FPU: x87 islemleri ----
       x87 yigini VM-reg degildir (gercek birim) — GPR maskesine dokunmaz.
       Bellek-formlari adresleme registerlarini OKUR (MEM()); FSTSW AX
       EAX yazar; FCOMI ailesi bayrak yazar; FCMOV bayrak okur. */
    case XP_FLD: case XP_FST: case XP_FSTP:
    case XP_FILD: case XP_FIST: case XP_FISTP: case XP_FISTTP:
    case XP_FADD: case XP_FMUL: case XP_FSUB: case XP_FSUBR:
    case XP_FDIV: case XP_FDIVR:
    case XP_FIADD: case XP_FIMUL: case XP_FICOM: case XP_FICOMP:
    case XP_FISUB: case XP_FISUBR: case XP_FIDIV: case XP_FIDIVR:
    case XP_FCOM: case XP_FCOMP:
    case XP_FBLD: case XP_FBSTP: case XP_FSTCW: case XP_FLDCW:
        MEM(); break;
    case XP_FSTSW:
        MEM(); if (!I.mem.present) W(0);   /* fstsw ax -> EAX */
        break;
    case XP_FCOMI: case XP_FCOMIP: case XP_FUCOMI: case XP_FUCOMIP:
        d |= FFLAG; break;                 /* CF/PF/ZF yazar */
    case XP_FCMOV:
        u |= FFLAG; break;                 /* kosul bayraklari okur */
    case XP_FNOP: case XP_FWAIT: case XP_FCLEX: case XP_FINIT:
    case XP_FDECSTP: case XP_FINCSTP:
    case XP_FCHS: case XP_FABS: case XP_FSQRT: case XP_FTST: case XP_FXAM:
    case XP_FSIN: case XP_FCOS: case XP_FSINCOS: case XP_FPTAN: case XP_FPATAN:
    case XP_FYL2X: case XP_FYL2XP1: case XP_F2XM1: case XP_FPREM: case XP_FPREM1:
    case XP_FRNDINT: case XP_FSCALE: case XP_FXTRACT:
    case XP_FLD1: case XP_FLDZ: case XP_FLDPI:
    case XP_FLDL2T: case XP_FLDL2E: case XP_FLDLG2: case XP_FLDLN2:
    case XP_FXCH: case XP_FFREE: case XP_FFREEP:
    case XP_FADDP: case XP_FMULP: case XP_FSUBP: case XP_FSUBRP:
    case XP_FDIVP: case XP_FDIVRP: case XP_FCOMPP: case XP_FUCOMPP:
        break;                             /* x87-dahili; GPR/bayrak etkisi yok */
    case XP_NOP: case XP_INT3: break;
    default: break;
    }
    m.uses = u; m.defs = d;
}

} // namespace

// ============================================================
// mutate_function
// ============================================================
MutFn mutate_function(const u8* code, u32 rva, u32 size, bool is64,
                      u64 imagebase, u32 imagesize, bool allow_call,
                      int strength, u32 seed, u32 base_rva, bool region_mode,
                      u32 prolog_size) {
    MutFn F; F.st.orig_bytes = size;
    if (strength < 1) strength = 1;
    if (strength > 3) strength = 3;

    // olasiliklar (binde)
    int p_junk  = strength == 1 ? 150 : (strength == 2 ? 300 : 480);
    int p_gate  = strength == 1 ?  60 : (strength == 2 ? 160 : 280);
    int p_subst = strength == 1 ? 450 : (strength == 2 ? 750 : 950);
    if (getenv("CPL_NOSUBST")) p_subst = 0;
    if (getenv("CPL_NOJUNK"))  p_junk = 0;
    if (getenv("CPL_NOGATE"))  p_gate = 0;

    u32 rng = seed ? seed : 0x12345678u;
    auto rnd = [&]() { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; return rng; };

    // ---------------- 1) tarama (lifter ile AYNI politika) ----------------
    std::vector<MInsn> ins;
    std::set<u32> leaders;
    bool saw_ret = false, body_ended = false;
    u32 end = rva + size;
    u32 pc = rva;
    while (pc < end) {
        Insn I = disasm(code + (pc - rva), (int)(end - pc), is64, pc, imagebase, imagesize);
        if (I.op == XP_UNKNOWN || I.len == 0) {
            if (!saw_ret) { F.why = "pc=0x" + hex32(pc) + ": " + (I.text.empty() ? "cozulemedi" : I.text); return F; }
            break;
        }
        if (I.op == XP_INT3) { if (saw_ret) break; F.why = "ret oncesi int3"; return F; }
        if (saw_ret) {
            if (I.op == XP_NOP) { body_ended = true; pc += I.len; continue; }
            if (I.op == XP_INT3) break;
            if (body_ended) break;
        }
        MInsn m; m.I = I; m.pc = pc; m.raw = code + (pc - rva);
        ud_of(m);
        ins.push_back(m);
        // liderler: dal hedefleri + kontrol akisi talimatlarindan sonrasi
        if (I.op == XP_JMP || I.op == XP_JCC || I.op == XP_RET || I.op == XP_RETI16)
            leaders.insert(pc + I.len);
        if ((I.op == XP_JMP || I.op == XP_JCC) && I.target >= rva && I.target < end)
            leaders.insert((u32)I.target);
        if (I.op == XP_JMP && !(I.target >= rva && I.target < end)) {
            if (!allow_call) { F.why = "disari jmp (call yok)"; return F; }
            saw_ret = true;                  // kuyruk cagri = fonksiyon sonu (lifter politikasi)
        }
        if (I.op == XP_JCC && !(I.target >= rva && I.target < end)) {
            F.why = "disari jcc"; return F;
        }
        if (I.op == XP_CALL && !allow_call) { F.why = "call desteklenmiyor"; return F; }
        // 0.5.0: dolayli cagri/atlamasi — mutator icin guvenli degil (hedef
        // bilinemez + x64 riprel konum-bagimli). IAT korumasi aciksa bu
        // noktalar derleme ONCESI E8/E9'a cevrildiginden buraya ulasmaz.
        if (I.op == XP_CALLI || I.op == XP_JMPI) {
            F.why = "dolayli cagri/atlamasi (IAT korumasi ile E8'e cevrilir)";
            return F;
        }
        if (I.op == XP_RET || I.op == XP_RETI16) saw_ret = true;
        pc += I.len;
    }
    if (!saw_ret) {
        // 0.5.0: SDK/manual BOLGE — govde ret icermeyebilir. Mutant govdenin
        // sonuna region_end'e (rva+size) E9 ilave edilir; yigin degmez.
        if (!region_mode) { F.why = "ret bulunamadi"; return F; }
        F.region_tail = true;
    }
    if (ins.empty()) { F.why = "bos govde"; return F; }
    F.st.ninsn = (u32)ins.size();

    // ---------------- 2) temel bloklar + CFG ----------------
    leaders.insert(rva);                       // giris
    leaders.erase(end);                        // son talimattan sonrasi blok degil
    std::vector<u32> ldr(leaders.begin(), leaders.end());
    std::sort(ldr.begin(), ldr.end());
    std::map<u32, int> blk_of;
    std::vector<std::pair<int, int>> blocks;   // [baslangix, son] insn indeksi
    {
        int cur = 0;
        for (size_t i = 0; i < ins.size(); i++) {
            bool isldr = (i == 0) || std::binary_search(ldr.begin(), ldr.end(), ins[i].pc);
            if (i == 0 || isldr) {
                if (i > 0) blocks.push_back({ cur, (int)i - 1 });
                cur = (int)i;
            }
        }
        blocks.push_back({ cur, (int)ins.size() - 1 });
        // blok no atamasi
        for (size_t b = 0; b < blocks.size(); b++)
            for (int i = blocks[b].first; i <= blocks[b].second; i++)
                ins[i].bb = (int)b;
        // pc -> blok
        for (size_t b = 0; b < blocks.size(); b++)
            blk_of[ins[blocks[b].first].pc] = (int)b;
    }
    int nblk = (int)blocks.size();
    F.st.nblocks = (u32)nblk;

    std::vector<std::vector<int>> succ(nblk);
    for (int b = 0; b < nblk; b++) {
        MInsn& last = ins[blocks[b].second];
        bool internal = (last.I.op == XP_JMP || last.I.op == XP_JCC) &&
                        last.I.target >= rva && last.I.target < end;
        if (internal && !blk_of.count((u32)last.I.target)) {
            F.why = "gecersiz dal hedefi 0x" + hex32((u32)last.I.target); return F;
        }
        if (last.I.op == XP_JMP) {
            if (internal) succ[b].push_back(blk_of[(u32)last.I.target]);
            // disari jmp: terminal (kuyruk cagri)
        } else if (last.I.op == XP_JCC) {
            succ[b].push_back(blk_of[(u32)last.I.target]);
            if (blocks[b].second + 1 < (int)ins.size())
                succ[b].push_back(ins[blocks[b].second + 1].bb);   // dusme kenari: BLOK indeksi
        } else if (last.I.op == XP_RET || last.I.op == XP_RETI16) {
            // terminal
        } else {
            if (blocks[b].second + 1 < (int)ins.size())
                succ[b].push_back(ins[blocks[b].second + 1].bb);   // dusme kenari: BLOK indeksi
        }
    }

    // ---------------- 3) liveness (geriye dogru sabit nokta) ----------------
    std::vector<u32> live_in(nblk, 0), live_out(nblk, 0);
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b = nblk - 1; b >= 0; b--) {
            u32 out = 0;
            for (int s : succ[b]) out |= live_in[s];
            if (out != live_out[b]) { live_out[b] = out; changed = true; }
            u32 live = out;
            for (int i = blocks[b].second; i >= blocks[b].first; i--) {
                ins[i].live_after = live;
                live = ins[i].uses | (live & ~ins[i].defs);
            }
            if (live != live_in[b]) { live_in[b] = live; changed = true; }
        }
    }

    // ---------------- 4) kod uretimi ----------------
    std::vector<u8> out;
    Enc E{ out, is64 };
    std::vector<MFix> fixes;
    std::map<u32, u32> pc2new;

    // olumlu register secimi — YALNIZCA VOLATILE (ABI kurali):
    // x64: rax,rcx,rdx,r8-r11 | x86: eax,ecx,edx.
    // HATA DERSI #5: junk, callee-saved (rbx/rbp/r12-r15) yazabilirdi ->
    // mutasyonlu govde ABI'yi ihlal edip cagiranin (VM'in!) canli
    // callee-saved degerlerini eziyordu. rsp(4)/rbp(5) zaten hep yasakti.
    auto pick_dead = [&](u32 live) -> int {
        u32 dead = (~live) & REGALL;
        static const int pref64[7] = { 10, 11, 9, 8, 1, 2, 0 };    // volatile sirasi
        static const int pref86[3] = { 1, 2, 0 };
        if (is64) {
            for (int k = 0; k < 7; k++) if (dead & (1u << pref64[k])) return pref64[k];
        } else {
            for (int k = 0; k < 3; k++) if (dead & (1u << pref86[k])) return pref86[k];
        }
        return -1;
    };

    // calisan junk (bayrak-noruz zorunlu degil: bayraklar oluyorsa ALU serbest)
    // 0.4.1: NOP JUNK YOK — lifter "ret sonrasi dolgu = govde bitti" sezgisine
    // guvenir; mutantin ortasina serpilten 0x90/0F1F govdeyi yarida keser.
    // Olü register yoksa junk uretilmez (bos gec).
    auto junk_item = [&](u32 live, bool gate) {
        // kapi junk'i HIC CALISMAZ -> liveness kosulu yok (yine gecerli kod);
        // calisan junk ise OLU register ister
        int r = gate ? pick_dead(0) : pick_dead(live);
        bool fdead = gate || !(live & FFLAG);
        u32 roll = rnd() & 15;
        if (r < 0) return;
        if (roll < 4)       E.mov_r_imm32(r, rnd());
        else if (roll < 6)  { E.push_imm32(rnd()); E.pop_r(r); }
        else if (roll < 9 && fdead) E.alu_r_imm(ALU_ADD, r, (i32)rnd(), 4);
        else if (roll < 11 && fdead) E.alu_rr(ALU_TEST, r, r, 4);
        else if (roll < 13) E.lea_self(r, (i32)(rnd() % 64) - 32, 4);
        else if (roll < 14 && is64) E.mov_r_imm64(r, ((u64)rnd() << 32) | rnd());
        else if (fdead)     E.alu_rr(ALU_TEST, r, r, 4);
    };

    // JMP kapi: EB rel8 + atlanan junk (rel8 = junk uzunlugu)
    auto emit_gate = [&](u32 live) {
        u32 goff = (u32)out.size();
        u32 at = E.gate_rel8();
        (void)at;
        u32 jstart = (u32)out.size();
        int n = 1 + (int)(rnd() & 3);
        for (int k = 0; k < n; k++) junk_item(live, true);
        u32 jlen = (u32)out.size() - jstart;
        if (jlen > 120) jlen = 120;    // olmaz (4 oge x <=10B) — savunma satiri
        out[goff + 1] = (u8)jlen;
    };

    // ikame denemesi: true = uretildi (orijinal atlandi)
    auto try_subst = [&](MInsn& m, u32 live_after_i) -> bool {
        const Insn& I = m.I;
        bool fdead = !(live_after_i & FFLAG);
        bool sz48 = (I.sz == 4) || (I.sz == 8 && is64);
        // hata avı: tek tek ikame sınıflarını kapatma
        static const bool noS1 = getenv("CPL_NOS1") != nullptr;   // add/sub->lea
        static const bool noS3 = getenv("CPL_NOS3") != nullptr;   // add<->sub
        static const bool noS5 = getenv("CPL_NOS5") != nullptr;   // mov imm->push/pop
        static const bool noS6 = getenv("CPL_NOS6") != nullptr;   // xor/test rr
        static const bool noS8 = getenv("CPL_NOS8") != nullptr;   // mov rr->push/pop
        static const bool noS9 = getenv("CPL_NOS9") != nullptr;   // inc/dec
        static const bool noS13 = getenv("CPL_NOS13") != nullptr; // not->xor
        switch (I.op) {
        case XP_ALU: {
            if (I.mem.present) return false;
            // xor r,r -> sub r,r  (bayraklar birebir esit: ZF=1 SF=0 CF=0 OF=0 PF=1)
            if (I.immsz == 0 && I.alu == ALU_XOR && I.r1 >= 0 && I.r1 == I.r2 && !noS6) {
                E.alu_rr(ALU_SUB, I.r1, I.r2, I.sz); return true;
            }
            // test r,r -> or r,r  (bayraklar birebir esit)
            if (I.immsz == 0 && I.alu == ALU_TEST && I.r1 >= 0 && I.r1 == I.r2 && !noS6) {
                E.alu_rr(ALU_OR, I.r1, I.r2, I.sz); return true;
            }
            if (I.immsz > 0 && I.r1 >= 0) {
                i64 imm = (i64)(long long)(int)(u32)I.imm;   // s32 isaret genisletme
                // add/sub r,imm -> lea r,[r+imm] (lea bayrak YAZMAZ -> bayraklar olmali)
                // RSP HARIÇ: VM, c->regs[RSP] degerini VM_DELTA kaymasıyla tutar;
                // LEA rsp,[rsp+d] mem_addr üzerinden deltayı soyar -> yığın bozulur.
                // (M kipinde sorun yoktu çünkü native LEA doğru; U kipinde VM kuralı)
                if ((I.alu == ALU_ADD || I.alu == ALU_SUB) && fdead && sz48 && !noS1 && I.r1 != 4) {
                    i64 d = (I.alu == ALU_ADD) ? imm : -imm;
                    E.lea_self(I.r1, d, I.sz); return true;
                }
                // add <-> sub (aritmetik esdeger, CF TERS -> bayraklar olmali)
                if ((I.alu == ALU_ADD || I.alu == ALU_SUB) && fdead && sz48 && imm != 0 && !noS3) {
                    i64 nimm = -imm;
                    if (nimm >= -2147483648LL && nimm <= 2147483647LL) {
                        E.alu_r_imm(I.alu == ALU_ADD ? ALU_SUB : ALU_ADD, I.r1, nimm, I.sz);
                        return true;
                    }
                }
            }
            return false;
        }
        case XP_MOV_RI: {   // mov r32,imm32 -> push imm32; pop r (bayrak etkisiz)
            if (I.sz == 4 && I.r1 >= 0 && I.r1 != 4 && !noS5) {   // RSP: VM delta kurali
                u32 imm = (u32)I.imm;
                if (!is64 || (imm & 0x80000000u) == 0) {  // x64: isaret==sifir genisletme
                    E.push_imm32(imm); E.pop_r(I.r1); return true;
                }
            }
            return false;
        }
        case XP_MOV_MR: case XP_MOV_RM: {   // mod3: mov r1,r2 -> push r2; pop r1
            if (!I.mem.present && I.r1 >= 0 && I.r2 >= 0 && I.r1 != 4 && I.r2 != 4 && !noS8) {
                if ((!is64 && I.sz == 4) || (is64 && I.sz == 8)) {
                    E.push_r(I.r2); E.pop_r(I.r1); return true;
                }
            }
            return false;
        }
        case XP_INCDEC_R: {
            if (I.r1 < 0) return false;
            if (fdead && sz48 && !noS9 && I.r1 != 4) { E.lea_self(I.r1, I.ud ? -1 : 1, I.sz); return true; }
            if (fdead && !noS9)        { E.alu_r_imm(I.ud ? ALU_SUB : ALU_ADD, I.r1, 1, I.sz); return true; }
            return false;
        }
        case XP_NOT: {   // not r -> xor r,-1 (xor bayrak YAZAR; not yazmaz -> bayraklar olmali)
            if (!I.mem.present && I.r1 >= 0 && fdead && sz48 && !noS13) {
                E.alu_r_imm(ALU_XOR, I.r1, -1, I.sz); return true;
            }
            return false;
        }
        default: return false;
        }
    };

    // ham kopya + rip-goreceli disp kaydi
    auto emit_copy = [&](MInsn& m) {
        u32 noff = (u32)out.size();
        out.insert(out.end(), m.raw, m.raw + m.I.len);
        if (m.I.mem.riprel) {
            u32 tgt = m.pc + m.I.len + (u32)(long long)m.I.mem.disp;
            // DUSMAN HATASI #2 (0.3.0 gelistirme): disp32 her zaman talimatin
            // SON 4 bayti degildir! "add [rip+d],imm8/imm32" ve "mov [rip+d],imm"
            // formalarinda disp32'yi bir immedi takip eder. Konum:
            //   len - 4 - (takip eden immedi bayt sayisi)
            int isz = (m.I.immsz > 0) ? m.I.immsz : 0;   // CL shift'i (-1) = imm yok
            u32 dat = noff + m.I.len - 4 - (u32)isz;
            // CAPA: talimatin SONU (RIP bunu gosterir), disp alani sonu DEGIL
            u32 anch = noff + m.I.len;
            fixes.push_back({ dat, anch, tgt, 1 });
        }
    };

    // ---- talimat talimat uretim ----
    char nb[96];
    for (size_t i = 0; i < ins.size(); i++) {
        MInsn& m = ins[i];
        u32 live_before = (i > 0) ? ins[i - 1].live_after : (REGALL | FFLAG);

        if (i > 0) {
            // JMP kapi (olasilik; bazen zincirli iki kapi)
            if ((int)(rnd() % 1000) < p_gate) {
                emit_gate(live_before);
                if ((rnd() & 3) == 0) emit_gate(live_before);
                F.st.gates++;
            }
            // calisan junk
            if ((int)(rnd() % 1000) < p_junk) {
                int n = 1 + (int)(rnd() & 1);
                for (int k = 0; k < n; k++) junk_item(live_before, false);
                F.st.junk++;
                if (pick_dead(live_before) >= 0) F.st.dead_spots++;
            }
        }

        pc2new[m.pc] = (u32)out.size();
        if (getenv("CPL_MUTDBG"))
            fprintf(stderr, "[mut] i=%zu pc=%06x off=%04zu rng=%08x live=%08x la=%08x\n",
                    i, m.pc, out.size(), rng, live_before, m.live_after);

        // kontrol akisi talimatlari: her zaman yeniden kodlanir (rel32)
        if (m.I.op == XP_JMP) {
            bool internal = m.I.target >= rva && m.I.target < end;
            u32 at = E.jmp_rel32();
            fixes.push_back({ at, at + 4, (u32)m.I.target, internal ? 0 : 1 });
            if (F.notes.size() < 40) {
                snprintf(nb, sizeof nb, "jmp 0x%x%s", (u32)m.I.target, internal ? "" : " (dis)");
                F.notes.push_back(std::string("  ") + hex32(m.pc) + ": " + nb);
            }
        } else if (m.I.op == XP_JCC) {
            u32 at = E.jcc_rel32(m.I.cc);
            fixes.push_back({ at, at + 4, (u32)m.I.target, 0 });
            if (F.notes.size() < 40) {
                snprintf(nb, sizeof nb, "jcc%d 0x%x", m.I.cc, (u32)m.I.target);
                F.notes.push_back(std::string("  ") + hex32(m.pc) + ": " + nb);
            }
        } else if (m.I.op == XP_CALL) {
            u32 at = E.call_rel32();
            fixes.push_back({ at, at + 4, (u32)m.I.target, 1 });
        } else if ((int)(rnd() % 1000) < p_subst && try_subst(m, m.live_after)) {
            F.st.subst++;
            if (F.notes.size() < 40)
                F.notes.push_back(std::string("  [SUB] ") + hex32(m.pc) + ": " + m.I.text);
        } else {
            emit_copy(m);
        }
        // 0.8.0 SEH: prolog yigin-ayarlama haritasi (x64 .vmpx UNWIND_INFO)
        // Ikame kurallari yigin etkisini korur (push/pop ciftleri, add<->sub)
        // -> delta orijinal talimattan okunur, ofset cikis akisindan (pc2new).
        if (prolog_size && (m.pc - rva) < prolog_size) {
            const Insn& I2 = m.I;
            i64 dl = 0; int kind = -1; int reg = 0;
            if (I2.op == XP_PUSH_R && I2.r1 >= 0) { dl = is64 ? 8 : 4; kind = 0; reg = I2.r1; }
            else if (I2.op == XP_PUSH_I) { dl = is64 ? 8 : 4; kind = 1; }
            else if (I2.op == XP_ALU && !I2.mem.present && I2.r1 == 4 && I2.immsz > 0) {
                i64 v = (i64)(long long)(int)(u32)I2.imm;
                dl = (I2.alu == ALU_SUB) ? v : -v;
                kind = 1;
            } else if (I2.op == XP_POP_R || I2.op == XP_LEAVE ||
                       ((I2.op == XP_MOV_MR) && !I2.mem.present && I2.r1 == 4)) {
                F.uw_ok = false;   // prologda pop rsp/leave/mov rsp: emin olamayiz
            }
            if (kind == 0) F.uw.push_back({ pc2new[m.pc], 0, (u8)reg, 0 });
            else if (kind == 1 && dl > 0) F.uw.push_back({ pc2new[m.pc], 1, 0, (u32)dl });
            else if (kind == 1 && dl < 0) F.uw_ok = false;
            F.prolog_out = (u32)out.size();
        }
    }

    // ---------------- 5) fixup cozumu ----------------
    for (auto& fx : fixes) {
        i64 rel;
        if (fx.kind == 0) {
            auto it = pc2new.find(fx.val);
            if (it == pc2new.end()) { F.why = "fixup hedefi yok @0x" + hex32(fx.val); return F; }
            rel = (i64)it->second - (i64)fx.anchor;
        } else {
            rel = (i64)fx.val - (i64)((i64)base_rva + fx.anchor);
        }
        if (rel < -2147483648LL || rel > 2147483647LL) {
            F.why = "rel32 tasmasi @+" + std::to_string(fx.at); return F;
        }
        out[fx.at]     = (u8)(u32)(i32)rel;
        out[fx.at + 1] = (u8)(((u32)(i32)rel) >> 8);
        out[fx.at + 2] = (u8)(((u32)(i32)rel) >> 16);
        out[fx.at + 3] = (u8)(((u32)(i32)rel) >> 24);
    }

    if (getenv("CPL_MUTDUMP")) {
        char dp[64]; snprintf(dp, sizeof dp, "/tmp/mutdump_%X.bin", rva);
        FILE* df = fopen(dp, "wb");
        if (df) { fwrite(out.data(), 1, out.size(), df); fclose(df); }
    }
    // 0.5.0: BOLGE kipi — govde ret icermiyorsa sona region_end'e E9 ekle.
    // (yigin ayni kalir; region sonu kodu epilogu/ret'i kendisi yurutur)
    if (F.region_tail) {
        u32 cont = rva + size;
        u32 at = (u32)out.size();              // govde sonunda
        i64 rel = (i64)cont - (i64)((i64)base_rva + at + 5);
        if (rel < -2147483648LL || rel > 2147483647LL) {
            F.why = "region kuyrugu rel32 tasmasi"; return F;
        }
        out.push_back(0xE9);
        out.push_back((u8)(u32)(i32)rel);
        out.push_back((u8)(((u32)(i32)rel) >> 8));
        out.push_back((u8)(((u32)(i32)rel) >> 16));
        out.push_back((u8)(((u32)(i32)rel) >> 24));
        F.notes.push_back("  [BOLGE] sona E9 -> 0x" + hex32(cont) + " (region devami)");
    }
    F.code = std::move(out);
    F.st.new_bytes = (u32)F.code.size();
    F.ok = true;
    return F;
}
