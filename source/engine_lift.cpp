// ============================================================
// engine_lift.cpp — makine kodu -> VM bayt-kod lifter
// Akis: dogrusal cozum, temel akis haritasi, rel32 fixup'lari.
// ============================================================
#include "engine.hpp"

namespace {

struct Lift {
    std::vector<u8>& bc;
    std::vector<std::pair<u32, u32>>& fix;
    std::vector<u32>& str_refs;
    std::vector<std::pair<u32, u32>>& str_sites;   // 0.8.1: .rdata ref alan konumlari
    bool is64;
    u64 imagebase;
    u32 rdata_rva, rdata_size;
    bool antidebug = false;   // 1.2.0-A8: OP_CHKRET (dönüş-adresi int3 kontrolü) yayımı
    bool region_mode = false; // 1.2.0-A8: bölge kipinde dönüş adresi garanti DEĞİL — CHKRET yasak

    void e(u8 x) { bc.push_back(x); }
    // 0.8.0 polimorfik: komut opcode'u emit'i (gercel -> permüteli)
    const unsigned char* perm = 0;   // gercek->raw tablosu (VM_OPN)
    void eop(int op) { e(perm ? perm[op] : (u8)op); }
    void e32(u32 v) { for (int k = 0; k < 4; k++) bc.push_back((u8)(v >> (8 * k))); }
    void e64(u64 v) { for (int k = 0; k < 8; k++) bc.push_back((u8)(v >> (8 * k))); }
    void ereg(int r) { e((u8)r); }

    // MEM operandini akisa yazar; .rdata referanslarini toplar
    // 0.9.0: I.seg (FS/GS) varsa MEMF_SEG + seg + alt-form (vm mem_addr aynasi).
    // segmode'da disp HAM'dir: TEB-relative (gs:[0x30]) image-rva'ya cevrileMEZ.
    void emem(const MemOp& m, const Insn& I) {
        if (I.seg) {
            e(MEMF_SEG);
            e((u8)I.seg);
            if (m.riprel) {
                /* rip-rel + seg: TEB-relative degil — ham disp ile DISP_SEG */
                e(MEMF_DISP_SEG);
                e32((u32)(long long)m.disp);
                return;
            }
            if (m.absimage) {
                e(MEMF_DISP_SEG);
                e32((u32)m.absval);          /* HAM — rva cevrimi yok */
                return;
            }
            /* SIB: segmode'da VM img eklemez (mem_addr segmode) */
            e(MEMF_SIB);
            e((u8)(m.present && m.base >= 0 ? m.base : SIB_NOBASE));
            e((u8)(m.idx >= 0 ? m.idx : SIB_NOBASE));
            e((u8)m.scale);
            e32((u32)(long long)m.disp);
            return;
        }
        emem_noseg(m, I);
    }
    void emem_noseg(const MemOp& m, const Insn& I) {
        if (m.riprel) {
            u32 tgt = I.pc + I.len + (u32)(long long)m.disp;
            e(MEMF_DISP);
            if (tgt >= rdata_rva && tgt < rdata_rva + rdata_size)
                str_sites.push_back({(u32)bc.size(), tgt});  // 0.8.1: alan konumu kaydet
            e32(tgt);
            if (tgt >= rdata_rva && tgt < rdata_rva + rdata_size) str_refs.push_back(tgt);
            return;
        }
        if (m.absimage) {
            u64 rva = m.absval - imagebase;
            if (rva >= 0x10000000ull) { /* image disi mutlak adres */ }
            // INDEX VARSA SAKLA! (eski kod idx'i atiyor -> [idx*4+tab] tablo
            // okumalari hep ilk elemani veriyordu)
            if (m.idx >= 0) {
                e(MEMF_SIB_IMG);
                e((u8)SIB_NOBASE);
                e((u8)m.idx);
                e((u8)m.scale);
                if (rva >= rdata_rva && rva < rdata_rva + rdata_size)
                    str_sites.push_back({(u32)bc.size(), (u32)rva});  // 0.8.1
                e32((u32)rva);
            } else {
                e(MEMF_DISP);
                if (rva >= rdata_rva && rva < rdata_rva + rdata_size)
                    str_sites.push_back({(u32)bc.size(), (u32)rva});  // 0.8.1
                e32((u32)rva);
            }
            if (rva >= rdata_rva && rva < rdata_rva + rdata_size) str_refs.push_back((u32)rva);
            return;
        }
        if (m.present && m.base >= 0) {
            u32 disp = (u32)(long long)m.disp;
            u8 form = MEMF_SIB;
            // x86: [reg + VA] bicimli erisimlerde disp image-RVA'ya cevrilir;
            // VM MEMF_SIB_IMG ile c->base'i ekler. (x64: disp zaten yigin/gosterici)
            if (!is64 && disp >= imagebase && disp < imagebase + 0x10000000ull) {
                disp -= (u32)imagebase;
                form = MEMF_SIB_IMG;
            }
            e(form);
            e((u8)m.base);
            e((u8)(m.idx >= 0 ? m.idx : SIB_NOBASE));
            e((u8)m.scale);
            e32(disp);
        } else {
            // tabansiz SIB / disp32: mutlak gibi ele al (rva'ya cevrilemediyse hatali)
            e(MEMF_SIB);
            e((u8)SIB_NOBASE);
            e((u8)(m.idx >= 0 ? m.idx : SIB_NOBASE));
            e((u8)m.scale);
            u64 rva = (m.absimage ? (m.absval - imagebase) : (u64)(long long)m.disp);
            e32((u32)rva);
        }
    }

    bool alu_common(const Insn& I, bool has_imm) {
        if (has_imm) {
            if (I.mem.present) { e(OP_ALU_MI); e((u8)I.alu); e((u8)I.sz); emem(I.mem, I); e32((u32)(long long)I.imm); }
            else { e(OP_ALU_RI); e((u8)I.alu); e((u8)I.sz); ereg(I.r1); e32((u32)(long long)I.imm); }
            return true;
        }
        if (I.mem.present) {
            // kaynak ya da hedef bellek: iki yon
            // disasm: "op r/m,r" -> r1=reg kaynak; "op r,r/m" -> r1=reg hedef
            // ayirt etmek icin: XP_ALU üretiminde mem.present + r2 yoksa yon belirsiz.
            // Lifte girmeden once lifter_in belirtir.
            return false;
        }
        e(OP_ALU_RR); e((u8)I.alu); e((u8)I.sz); ereg(I.r1); ereg(I.r2);
        return true;
    }

    // ---- 1.0.0-UO: cmNor/cmNand yigin kapi yardimcilari (intel.cc birebir).
    // Kapilar VM yigininda (PUSHSZ slot) calisir: temp-reg YOK, host push/pop
    // YOK, zincir dugum-siniri icinde dengeli (JCC hedefleri op-sinirlaridir;
    // zincire atlansa tam yurutulur, atlanirsa hic baslamaz — iki durumda da
    // yigin/RSP dengesi bozulmaz). 0.9.5/0.10.0 cokme dersi: host-reg havuzu
    // ve IR-junk yerine SAF yigin kapilari.
    void g_push_r(int rn) { eop(OP_PUSH_R); e((u8)rn); }
    void g_push_i(u32 v) { eop(OP_PUSH_I); e32(v); }
    void g_gate(int g, int sz) { eop(g); e((u8)sz); }              // OP_NOR_ST | OP_NAND_ST
    void g_pop_rp(int sz, int rn) { eop(OP_POP_RP); e((u8)sz); e((u8)rn); }
    // operandin tersini yigina birakir: [PUSH r][PUSH r][NOR_ST] -> ~r (sz-maskeli)
    void g_inv_r(int rn, int sz) { g_push_r(rn); g_push_r(rn); g_gate(OP_NOR_ST, sz); }
    void g_inv_i(u32 v, int sz)  { g_push_i(v); g_push_i(v); g_gate(OP_NOR_ST, sz); }
};

} // namespace

// yon bilgisi: disasm XP_ALU'da mem.present ise r1=reg, r2=-1 ve 'mem_is_src'
// ayirt edilemiyor -> lifter'a ham modrm yonunu tasiyacak sekilde
// Insn.r2 == -2 (mem<-reg) / -3 (reg<-mem) kuralini kullanacagiz.
// (engine_disasm.cpp'de set edilir.)

VFn lift_function(const u8* code, u32 rva, u32 size, bool is64,
                  u64 imagebase, u32 imagesize, bool allow_call,
                  u32 rdata_rva, u32 rdata_size, int junk_level, u32 junk_seed,
                  bool pad_terminates, bool region_mode, u32 perm_seed,
                  bool antidebug) {
    VFn F; F.rva = rva; F.size = size;

    Lift L{ F.plain, F.fix, F.str_refs, F.str_sites, is64, imagebase, rdata_rva, rdata_size };
    L.antidebug = antidebug;          // 1.2.0-A8: UO AddCheckBreakpointSection karsiligi
    L.region_mode = region_mode;
    // 0.8.0 polimorfik isleyiciler: fonksiyon-bazina opcode permütasyonu
    unsigned char ptab[VM_OPN];
    if (perm_seed) { vm_perm_tab(perm_seed, ptab, 0); L.perm = ptab; }

    // mutation junk ureteci (deterministik LCG)
    u32 rng = junk_seed ? junk_seed : 0x12345678u;
    auto rnd = [&rng]() { rng = rng * 1103515245u + 12345u; return (rng >> 16) & 0x7FFF; };
    auto emit_junk = [&]() {
        if (junk_level < 2) return;
        u32 roll = rnd() & 7;
        if (roll < 3) {
            int n = 1 + (int)(rnd() & 3);
            for (int k = 0; k < n; k++) L.eop(OP_NOP);
        } else if (roll == 4) {
            // reg kaydet, junk it, ez, geri yukle (net sifir etki)
            // x64: R11(11) volatile; x86: ECX(1) volatile
            int r = is64 ? 11 : 1;
            L.eop(OP_PUSH_R); L.e((u8)r);
            L.eop(OP_PUSH_I); L.e32(rnd() | 1u);
            L.eop(OP_POP_R);  L.e((u8)r);
            L.eop(OP_POP_R);  L.e((u8)r);
        }
    };

    std::map<u32, u32> pc2ic;   // kaynak pc -> bc offset
    bool saw_ret = false;
    bool last_ret = false;      // 1.0.0: akisin son op'u RET mi (kok-fix)
    bool body_ended = false;    // ret sonrasi dolgu gorundu mu (govde bitti isareti)
    bool jcc_to_end = false;    // 1.1.0: jcc bolge-sonuna (end) atiyor
    u32 retimm = 0xFFFFFFFF;
    u32 end = rva + size;

    u32 pc = rva;
    while (pc < end) {
        Insn I = disasm(code + (pc - rva), (int)(end - pc), is64, pc, imagebase, imagesize);
        if (I.op == XP_UNKNOWN || I.len == 0) {
            // 0.4.1: MUTANT girdide bilinmeyen bayt = sessiz kisalma riski ->
            // sesli hata (yarim govde, VM'de erken cikis uretir).
            if (!pad_terminates) { F.why = "pc=0x" + hex32(pc) + ": mutant icinde cozulemeyen bayt"; return F; }
            if (!saw_ret) { F.why = "pc=0x" + hex32(pc) + ": " + (I.text.empty() ? "cozulemedi" : I.text); return F; }
            break; // ret sonrasi padding/CC -> dur
        }
        if (I.op == XP_INT3) { if (saw_ret) break; F.why = "ret oncesi int3"; return F; }
        if (saw_ret) {
            // ret sonrasi POLITIKA:
            //  - dolgu (nop/int3) gorurse govde bitti sayar; dolgudan SONRA
            //    gercek talimat gelirse baska fonksiyona tasindik -> dur.
            //  - dolgu YOKKEN ret sonrasi kod gelirse AYNI fonksiyonun coklu
            //    cikis/yaln sonrasi blogudur (zig bunu uretir) -> taramaya devam.
            if (I.op == XP_NOP) { if (pad_terminates) body_ended = true; pc += I.len; continue; }
            if (I.op == XP_INT3) break;
            if (body_ended && pad_terminates) break;
        }

        if (!F.plain.empty() && I.op != XP_RET) emit_junk();
        pc2ic[pc] = (u32)F.plain.size();
        last_ret = false;   // 1.0.0: her yeni talimat RET-degil varsayimiyla baslar
        if (getenv("CPL_LIFTDBG"))
            fprintf(stderr, "[lift] pc=%06x len=%d op=%d bytes=%02x %02x %02x %02x\n",
                    pc, (int)I.len, (int)I.op,
                    code[pc - rva], code[pc - rva + 1],
                    (I.len > 2 ? code[pc - rva + 2] : 0),
                    (I.len > 3 ? code[pc - rva + 3] : 0));
        char buf[96];

        /* 0.6.2 BOLGE GUVENLIGI (kullanici-kanitli sessiz yanlis-sonuc sinifi):
         * VM'nin rsp-uzayi OZELDIR: mem_addr[rsp] = regs[RSP] - VM_DELTA + disp
         * ve regs[RSP] giriste init_rsp (stub giris rsp'si) ile baslar — yani
         * tum rsp-goreli erisimler VM_DELTA (x64 0x600 / x86 0x420) kadar
         * gercek yiginin ALTINA gider.
         *  - FONKSIYON kipinde bu TUTARLI-SANALDIR: okuma/yazma ayni sanal
         *    tabani kullanir, govde kapalidir, sonuc dogru (kanit: f_stack=42).
         *  - BOLGE kipinde (SDK isareti / U->V dusus) ise korumasiz devam
         *    kodu GERCEK yigini okur -> VM yazmalari "kaybolur" (sessiz
         *    yanlis sonuc: sdk_u c=0, isol43 s=0; ebp-goreli D7610
         *    etkilenmez — kullanicinin kanitiyla uyumlu).
         * 0.6.2 karari: bolge icinde rsp-goreli erisim / rsp yeniden-esleme
         * = DURU RED (0.5.1 "sessiz yanlis sonuc yerine duru RED" gelenegi).
         * Gercek-yigin bolge kipi (ozel ctx + yigin degistirmeli stub) 0.8.0
         * kapsamindadir. */
        if (region_mode) {
            /* 1.2.2-A20 NOT: rbp-goreli BOLGE erisimi GERCEKTE calisiyor
               (vf_p74 kanit: volatile-yerelli region vf_loaded=1) — sdk_kanit
               -O0 crash'i printf-in-region + mutasyon-fixup'iydi (A20 fix).
               rbp-RED GERI ALINDI; yalniz rsp-RED kalir (0.6.2 duru). */
            bool rsp_mem   = I.mem.present && !I.mem.riprel && !I.mem.absimage
                             && I.mem.base == REG_RSP;
            bool rsp_remap = (I.op == XP_MOV_MR && !I.mem.present
                              && (I.r1 == REG_RSP || I.r2 == REG_RSP))
                             || (I.op == XP_LEAVE);
            if (rsp_mem || rsp_remap) {
                F.why = "bolge rsp-goreli erisim (0.6.2 duru RED — "
                        "fonksiyon-kipi koruma kullanin; gercek-yigin kipi 0.8.0)";
                return F;
            }
        }

        switch (I.op) {
        case XP_NOP: break;
        case XP_PUSH_R: L.eop(OP_PUSH_R); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "push %s", regname(is64, I.r1)); break;
        case XP_POP_R: L.eop(OP_POP_R); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "pop %s", regname(is64, I.r1)); break;
        case XP_PUSH_I: L.eop(OP_PUSH_I); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "push 0x%llx", (unsigned long long)I.imm); break;
        case XP_MOV_MR:
            if (!I.mem.present) {   // reg <- reg  (mov r/m,r mod3)
                L.eop(OP_MOV_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
                snprintf(buf, sizeof buf, "mov %s, %s (sz%d)", regname(is64, I.r1), regname(is64, I.r2), I.sz);
            } else {
                L.eop(OP_MOV_MR); L.e((u8)I.sz); L.emem(I.mem, I); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "mov [mem], %s (sz%d)", regname(is64, I.r1), I.sz);
            }
            break;
        case XP_MOV_RM:
            if (!I.mem.present) {   // reg <- reg  (mov r,r/m mod3)
                L.eop(OP_MOV_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
                snprintf(buf, sizeof buf, "mov %s, %s (sz%d)", regname(is64, I.r1), regname(is64, I.r2), I.sz);
            } else {
                L.eop(OP_MOV_RM); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "mov %s, [mem] (sz%d)", regname(is64, I.r1), I.sz);
            }
            break;
        case XP_MOV_MI: L.eop(OP_MOV_MI); L.e((u8)I.sz); L.emem(I.mem, I); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "mov [mem], imm%d=0x%llx", I.sz * 8, (unsigned long long)I.imm); break;
        case XP_MOV_RI: L.eop(OP_MOV_RI); L.e((u8)I.sz); L.ereg(I.r1); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "mov %s, imm=0x%llx", regname(is64, I.r1), (unsigned long long)I.imm); break;
        case XP_MOV_RI64: L.eop(OP_MOV_RI64); L.ereg(I.r1); L.e64(I.imm);
            snprintf(buf, sizeof buf, "movabs %s, 0x%llx", regname(is64, I.r1), (unsigned long long)I.imm); break;
        case XP_LEA: L.eop(OP_LEA_RM); L.ereg(I.r1); L.emem(I.mem, I);
            snprintf(buf, sizeof buf, "lea %s, [mem]", regname(is64, I.r1)); break;
        case XP_ALU: {
            // ---- 1.0.0-UO: cmAnd/cmOr/cmXor NOR/NAND yigin-kapi dekompozisyonu
            // (intel.cc CompileToVM case cmAnd/cmOr/cmXor birebir — VMProtect
            // VM'inde mantik komutu dogrudan YOKTUR, hepsi cmNor/cmNand
            // kapilarindan gecer). Reg-reg ve reg-imm formlari; mem formlari
            // yerel ALU ile (kapıya almak icin PUSH_M/POP_M gerekirdi —
            // konservatif kaplama, semantik ayni).
            // Zincirler (tum sz 1/2/4/8; sonuc POP_RP ile kismi-yazilir):
            //   AND: inv(b); inv(a); NOR           -> a&b   (cmAnd dal-1)
            //   OR : inv(a); inv(b); NAND          -> a|b   (cmOr dal-2)
            //   XOR: inv(b); inv(a); NOR; push b;
            //        push a; NOR; NOR              -> a^b   (cmXor dal-1)
            // Son kapi bayraklari yerel mantik op'u ile bayt-bayt ayni kurar.
            if (!I.mem.present && (I.alu == ALU_AND || I.alu == ALU_OR || I.alu == ALU_XOR)) {
                bool immf = I.immsz > 0;
                int rr = immf ? -1 : I.r2;   // operand-2 reg (imm formunda yiginda)
                if ((immf && I.r1 >= 0) || (!immf && I.r1 >= 0 && rr >= 0)) {
                    if (immf) L.g_inv_i((u32)(long long)I.imm, I.sz);
                    else      L.g_inv_r(rr, I.sz);
                    L.g_inv_r(I.r1, I.sz);
                    if (I.alu == ALU_AND) {
                        L.g_gate(OP_NOR_ST, I.sz);            // Nor(~a,~b)=a&b
                    } else if (I.alu == ALU_OR) {
                        L.g_gate(OP_NAND_ST, I.sz);           // Nand(~a,~b)=a|b
                    } else {
                        L.g_gate(OP_NOR_ST, I.sz);            // Nor(~a,~b)=a&b
                        if (immf) L.g_push_i((u32)(long long)I.imm); else L.g_push_r(rr);
                        L.g_push_r(I.r1);
                        L.g_gate(OP_NOR_ST, I.sz);            // Nor(a,b)=~(a|b)
                        L.g_gate(OP_NOR_ST, I.sz);            // Nor(a&b,~(a|b))=a^b
                    }
                    L.g_pop_rp(I.sz, I.r1);
                    snprintf(buf, sizeof buf, "%s%s KAPI-dekompoze (sz%d)",
                             I.alu == ALU_AND ? "and" : I.alu == ALU_OR ? "or" : "xor",
                             immf ? "-imm" : "-rr", I.sz);
                    break;
                }
            }
            // yon: engine_disasm XP_ALU üretiminde mem.present ise r2 == -2/-3 isareti
            if (I.immsz > 0) {
                if (I.mem.present) { L.eop(OP_ALU_MI); L.e((u8)I.alu); L.e((u8)I.sz); L.emem(I.mem, I); L.e32((u32)(long long)I.imm); }
                else { L.eop(OP_ALU_RI); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.e32((u32)(long long)I.imm); }
            } else if (I.mem.present) {
                if (I.r2 == -2) { L.eop(OP_ALU_MR); L.e((u8)I.alu); L.e((u8)I.sz); L.emem(I.mem, I); L.ereg(I.r1); }
                else { L.eop(OP_ALU_RM); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I); }
            } else {
                L.eop(OP_ALU_RR); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
            }
            snprintf(buf, sizeof buf, "alu%d (sz%d)", I.alu, I.sz); break;
        }
        case XP_XCHG:
            if (I.r1 < 0 || I.r2 < 0) { F.why = "xchg form"; return F; }
            L.eop(OP_XCHG_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
            snprintf(buf, sizeof buf, "xchg %s, %s", regname(is64, I.r1), regname(is64, I.r2));
            break;
        case XP_BSWAP:
            L.eop(OP_BSWAP_R); L.e((u8)I.sz); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "bswap %s", regname(is64, I.r1));
            break;
        case XP_SHIFT: {
            if (I.mem.present) {
                if (I.immsz == -1) { L.eop(OP_SHI_RM_CL); L.e((u8)I.shi); L.e((u8)I.sz); L.emem(I.mem, I); snprintf(buf, sizeof buf, "shift[mem]%%cl"); }
                else { L.eop(OP_SHI_RM_RI); L.e((u8)I.shi); L.e((u8)I.sz); L.emem(I.mem, I); L.e((u8)I.imm); snprintf(buf, sizeof buf, "shift[mem] %d", (int)I.imm); }
                break;
            }
            if (I.immsz == -1) { L.eop(OP_SHI_CL); L.e((u8)I.shi); L.e((u8)I.sz); L.ereg(I.r1); snprintf(buf, sizeof buf, "shift%%cl"); }
            else { L.eop(OP_SHI_RI); L.e((u8)I.shi); L.e((u8)I.sz); L.ereg(I.r1); L.e((u8)I.imm); snprintf(buf, sizeof buf, "shift %d", (int)I.imm); }
            break;
        }
        case XP_IMUL_RRI:
            if (I.mem.present) {
                L.eop(OP_IMUL_RMRI); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I); L.e32((u32)(long long)I.imm);
                snprintf(buf, sizeof buf, "imul %s, [mem], 0x%llx", regname(is64, I.r1), (unsigned long long)I.imm);
            } else {
                L.eop(OP_IMUL_RRI); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2); L.e32((u32)(long long)I.imm);
                snprintf(buf, sizeof buf, "imul %s, %s, 0x%llx", regname(is64, I.r1), regname(is64, I.r2), (unsigned long long)I.imm);
            }
            break;
        case XP_IMUL_RR: 
            if (I.mem.present) {
                /* 0.9.0: imul r, [mem] (0F AF bellek formu) */
                L.eop(OP_IMUL_RM); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "imul %s, [mem]", regname(is64, I.r1));
            } else {
                L.eop(OP_IMUL_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
                snprintf(buf, sizeof buf, "imul %s, %s", regname(is64, I.r1), regname(is64, I.r2));
            }
            break;
        case XP_INCDEC_R: L.eop(OP_INCDEC_R); L.e((u8)I.ud); L.e((u8)I.sz); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "%s %s", I.ud ? "dec" : "inc", regname(is64, I.r1)); break;
        case XP_INCDEC_M: L.eop(OP_INCDEC_M); L.e((u8)I.ud); L.e((u8)I.sz); L.emem(I.mem, I);
            snprintf(buf, sizeof buf, "%s [mem]", I.ud ? "dec" : "inc"); break;
        case XP_MOVZX: case XP_MOVSX: {
            /* 0.8.0 KRITIK FIX: e() DEGIL eop() — ham op bayti perm
               tablosunu atlardı; interpreter itab[0x13]=IDIV_R cozer,
               akis desync olur, itab OOB okuma -> wild write (sdk_ext
               kanit bug'i: movzx/movsx iceren her V bolgesi). */
            L.eop(I.op == XP_MOVZX ? OP_MOVZX : OP_MOVSX);
            L.e((u8)I.sz); L.e((u8)I.immsz); L.ereg(I.r1);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r2); }
            snprintf(buf, sizeof buf, "%s%d%s%d %s", I.op == XP_MOVZX ? "movzx" : "movsx",
                     I.sz * 8, "<-", I.immsz * 8, I.mem.present ? "[mem]" : regname(is64, I.r2)); break;
        }
        case XP_JMP: {
            if (I.target < rva || I.target >= end) {
                // 1.2.0-B1 rel32 dis-akis: OP_JMPEXT — kuyruk-jmp. VM done=3
                // ile cikar; stub push_area'dan kayitlari geri yukleyip
                // volatile-reg ile base+rva'ya atlar (donus adresi yiginda
                // kalir -> hedef kendi ret-imm'ini kendisi temizler).
                // (0.9.0'daki ncall+ret yerine: yigin temiz, x86 yaprak
                //  kipinde de calisir — eski RED "disari jmp (call yok)" kapandi.)
                L.eop(OP_JMPEXT); L.e32(I.target);
                saw_ret = true;
                snprintf(buf, sizeof buf, "jmp disari -> jmpext 0x%x (kuyruk)", I.target); break;
            }
            L.eop(OP_JMP); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "jmp 0x%x", I.target); break;
        }
        case XP_JCC: {
            /* 1.1.0: jcc -> bolge-SONU (SDK bolge siniri) artik GECERLI:
               son OP_RET'e yonlendirilir (asinan bozuk atama). */
            if (I.target == end) jcc_to_end = true;
            else if (I.target < rva || I.target >= end) {
                // 1.2.0-B1: disari jcc artik duru-RED DEGIL — OP_JCCEXT
                // (kosul dogruysa kuyruk-jmp; yanlissa akis VM icinde surer).
                L.eop(OP_JCCEXT); L.e((u8)I.cc); L.e32(I.target);
                snprintf(buf, sizeof buf, "jcc%d disari -> jccext 0x%x", I.cc, I.target); break;
            }
            L.eop(OP_JCC); L.e((u8)I.cc); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "jcc%d 0x%x", I.cc, I.target); break;
        }
        case XP_CALL: {
            if (!allow_call) { F.why = "call desteklenmiyor (x86 yaprak modu)"; return F; }
            L.eop(OP_NCALL); L.e32(I.target);
            snprintf(buf, sizeof buf, "call 0x%x (ncall)", I.target); break;
        }
        case XP_CALLI: {
            /* 1.2.2-A10: dolayli dogal cagri — FF /2 "call dword ptr [mem]"
               VE reg-form "call eax". metin2 E96D0 ("call dword ptr
               [eax+00000088]" — vtable-thiscall) kullanicinin coklu-fonksiyon
               RED raporunun kok-nedeniydi. Hedef derleme-zamaninda bilinemez:
               VM OP_NCALLI hedefi bellekten/kayittan MUTLAK VA okur (base
               eklenmez) ve OP_NCALL'le ayni natcall yolunu kullanir (x86:
               eax/ecx/edx + esp senkronu; x64: rcx,rdx,r8,r9; Encrypt
               Registers'la uyumlu). */
            if (!allow_call) { F.why = "calli desteklenmiyor (x86 yaprak modu)"; return F; }
            if (I.mem.present) {
                /* bellek-formu: form=0 (u32) / 1 (u64) — VM mem_addr ile
                   cozer, hedefi bellekten okur. */
                L.eop(OP_NCALLI); L.e((u8)(I.sz == 8 ? 1 : 0)); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "call [mem] (ncalli sz%d)", I.sz);
            } else if (I.r1 >= 0) {
                /* kayit-formu: FF D0 "call eax" — form=2 + reg-idx; VM
                   hedefi dogrudan VM kayit degerinden okur. */
                L.eop(OP_NCALLI); L.e((u8)2); L.e((u8)I.r1);
                snprintf(buf, sizeof buf, "call %s (ncalli reg)", regname(is64, I.r1));
            } else {
                F.why = "calli hedef-formu cozulemedi"; return F;
            }
            break;
        }
        case XP_JMPI: {
            /* 1.2.2-A10: "jmp dword ptr [mem]" — kuyruk-jmp hedefi calisma-
               zamaninda okunur. OP_JMPEXT hedefi base+rva'dir; dolayli hedef
               image-disi olabilir (IAT thunk) -> burada DURU RED: natgt
               base+rva matematigi image-disi hedefte yanlis atama uretir
               ("sessiz yanlis sonuc yerine duru RED" gelenegi). */
            F.why = "jmpi (jmp [mem]) desteklenmiyor — hedef calisma-zamaninda "
                    "bilinir, natgt base+rva image-disi hedefte kirilir";
            return F;
        }
        case XP_LEAVE: // mov rsp,rbp ; pop rbp
            L.eop(OP_MOV_RR); L.e((u8)8); L.ereg(REG_RSP); L.ereg(REG_RBP);
            L.eop(OP_POP_R);  L.ereg(REG_RBP);
            snprintf(buf, sizeof buf, "leave"); break;
        case XP_RET: 
            /* 1.2.0-A8: antidebug acikken her GERCEK ret onune donus-adresi
               kirici kontrolu (UO ret-section enjeksiyonu 1:1). BOLGE
               kipinde donus adresi garanti degil — atla. */
            if (L.antidebug && !L.region_mode) L.eop(OP_CHKRET);
            L.eop(OP_RET); saw_ret = true; last_ret = true;
            snprintf(buf, sizeof buf, "ret"); break;
        case XP_RETI16: {
            u32 im = (u32)I.imm;
            if (retimm != 0xFFFFFFFF && retimm != im) { F.why = "farkli ret imm"; return F; }
            if (L.antidebug && !L.region_mode) L.eop(OP_CHKRET);
            retimm = im; L.eop(OP_RET); saw_ret = true; last_ret = true;
            snprintf(buf, sizeof buf, "ret 0x%x", im); break;
        }
        case XP_SETCC: L.eop(OP_SETCC); L.e((u8)I.cc); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "setcc%d %s", I.cc, regname(is64, I.r1)); break;
        case XP_CMOV:
            L.eop(OP_CMOV); L.e((u8)I.cc); L.e((u8)I.sz); L.ereg(I.r1);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r2); }
            snprintf(buf, sizeof buf, "cmov%d %s", I.cc, I.mem.present ? "[mem]" : regname(is64, I.r2));
            break;
        case XP_CWDE: { // x64: CDQE rax<-eax ; x86: CWDE eax<-ax
            L.eop(OP_MOVSX); L.e((u8)(is64 ? 8 : 4)); L.e((u8)(is64 ? 4 : 2));
            L.ereg(REG_RAX); L.e((u8)0); L.ereg(REG_RAX);
            snprintf(buf, sizeof buf, "cwde/cdqe"); break; }
        case XP_CDQ: L.eop(OP_CQO);
            snprintf(buf, sizeof buf, "cdq/cqo"); break;
        case XP_IDIV: L.eop(OP_IDIV_R); L.e((u8)I.sz); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "idiv %s", regname(is64, I.r1)); break;
        case XP_NEG:
            if (I.mem.present) { L.eop(OP_NEG_M); L.e((u8)I.sz); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "neg [mem]"); }
            else { L.eop(OP_NEG_R); L.e((u8)I.sz); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "neg %s", regname(is64, I.r1)); }
            break;
        case XP_NOT:
            if (I.mem.present) { L.eop(OP_NOT_M); L.e((u8)I.sz); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "not [mem]"); }
            else { L.eop(OP_NOT_R); L.e((u8)I.sz); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "not %s", regname(is64, I.r1)); }
            break;

        /* ================= 0.9.0-DeepVM liftings =================
           vm_core.c handler akislariyla BIREBIR (vm_opcodes.h yorumlari). */
        case XP_PUSHF: L.eop(OP_PUSHF);
            snprintf(buf, sizeof buf, "pushf"); break;
        case XP_POPF: L.eop(OP_POPF);
            snprintf(buf, sizeof buf, "popf"); break;
        case XP_SAHF: L.eop(OP_SAHF);
            snprintf(buf, sizeof buf, "sahf"); break;
        case XP_LAHF: L.eop(OP_LAHF);
            snprintf(buf, sizeof buf, "lahf"); break;
        case XP_SETFLAG: L.eop(OP_SETFLAG); L.e((u8)I.ud);
            snprintf(buf, sizeof buf, "setflag%d", I.ud); break;
        case XP_MUL:
            if (I.mem.present) { L.eop(OP_MUL_R); L.e((u8)I.sz); L.e((u8)1); L.emem(I.mem, I); }
            else { L.eop(OP_MUL_R); L.e((u8)I.sz); L.e((u8)0); L.ereg(I.r1); }
            snprintf(buf, sizeof buf, "mul %s", I.mem.present ? "[mem]" : regname(is64, I.r1)); break;
        case XP_DIV:
            if (I.mem.present) { L.eop(OP_DIV_R); L.e((u8)I.sz); L.e((u8)1); L.emem(I.mem, I); }
            else { L.eop(OP_DIV_R); L.e((u8)I.sz); L.e((u8)0); L.ereg(I.r1); }
            snprintf(buf, sizeof buf, "div %s", I.mem.present ? "[mem]" : regname(is64, I.r1)); break;
        case XP_BT: {
            L.eop(OP_BT_X); L.e((u8)I.ud); L.e((u8)I.sz);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r1); }
            if (I.immsz > 0) { L.e((u8)1); L.e((u8)I.imm); }
            else { L.e((u8)0); L.ereg(I.r2); }
            snprintf(buf, sizeof buf, "bt%d %s", I.ud, I.mem.present ? "[mem]"
                     : regname(is64, I.r1)); break;
        }
        case XP_SHLD: case XP_SHRD: {
            L.eop(I.op == XP_SHLD ? OP_SHLD : OP_SHRD);
            L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
            if (I.immsz == -1) { L.e((u8)1); }         /* CL */
            else { L.e((u8)0); L.e((u8)I.imm); }
            snprintf(buf, sizeof buf, "%s %s, %s", I.op == XP_SHLD ? "shld" : "shrd",
                     regname(is64, I.r1), regname(is64, I.r2)); break;
        }
        case XP_LOOP: {
            if (I.target < rva || I.target >= end) { F.why = "disari loop"; return F; }
            L.eop(OP_LOOP); L.e((u8)I.cc); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "loop%d 0x%x", I.cc, I.target); break;
        }
        case XP_JECXZ: {
            if (I.target < rva || I.target >= end) { F.why = "disari jecxz"; return F; }
            L.eop(OP_JECXZ); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "jecxz 0x%x", I.target); break;
        }
        case XP_XADD: {
            L.eop(OP_XADD); L.e((u8)I.sz);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r1); }
            L.ereg(I.r2);
            snprintf(buf, sizeof buf, "xadd %s, %s", I.mem.present ? "[mem]" : regname(is64, I.r1),
                     regname(is64, I.r2)); break;
        }
        case XP_STR: {
            /* rep: I.rep 2=F3(repe) -> 1, 3=F2(repne) -> 2 */
            int rp = (I.rep == 2) ? 1 : (I.rep == 3) ? 2 : 0;
            L.eop(OP_STR); L.e((u8)I.ud); L.e((u8)I.sz); L.e((u8)rp);
            snprintf(buf, sizeof buf, "%s%s sz%d", rp == 1 ? "repe " : rp == 2 ? "repne " : "",
                     I.ud == 0 ? "movs" : I.ud == 1 ? "stos" : I.ud == 2 ? "lods"
                     : I.ud == 3 ? "scas" : "cmps", I.sz); break;
        }
        /* ---- 1.1.0-A4-FPU: UO FPU paritesi lifter tarafı ----
           Bellek-formlari OP_FPU_MEM (adres mem_addr ile); reg/implicit
           formlar OP_FPU_ST. ud: D8(ST0-form)=0 / DC(STi-form)=1. */
        case XP_FLD: case XP_FST: case XP_FSTP:
        case XP_FILD: case XP_FIST: case XP_FISTP: case XP_FISTTP:
        case XP_FADD: case XP_FMUL: case XP_FSUB: case XP_FSUBR:
        case XP_FDIV: case XP_FDIVR:
        case XP_FIADD: case XP_FIMUL: case XP_FICOM: case XP_FICOMP:
        case XP_FISUB: case XP_FISUBR: case XP_FIDIV: case XP_FIDIVR:
        case XP_FCOM: case XP_FCOMP:
        case XP_FBLD: case XP_FBSTP:
        case XP_FSTSW: case XP_FSTCW: case XP_FLDCW: {
            int sub = -1;
            bool memf = I.mem.present;
            if (I.op == XP_FLD)   sub = !memf ? FPU_FLD_ST   : (I.sz == 4 ? FPU_M_FLD32 : I.sz == 8 ? FPU_M_FLD64 : FPU_M_FLD80);
            else if (I.op == XP_FST)   sub = !memf ? FPU_FST_STI : (I.sz == 4 ? FPU_M_FST32 : FPU_M_FST64);
            else if (I.op == XP_FSTP)  sub = !memf ? FPU_FSTP_STI : (I.sz == 4 ? FPU_M_FSTP32 : I.sz == 8 ? FPU_M_FSTP64 : FPU_M_FSTP80);
            else if (I.op == XP_FILD)  sub = (I.sz == 2 ? FPU_M_FILD16 : I.sz == 4 ? FPU_M_FILD32 : FPU_M_FILD64);
            else if (I.op == XP_FIST)  sub = (I.sz == 2 ? FPU_M_FIST16 : FPU_M_FIST32);
            else if (I.op == XP_FISTP) sub = (I.sz == 2 ? FPU_M_FISTP16 : I.sz == 4 ? FPU_M_FISTP32 : FPU_M_FISTP64);
            else if (I.op == XP_FISTTP) sub = (I.sz == 2 ? FPU_M_FISTTP16 : I.sz == 4 ? FPU_M_FISTTP32 : FPU_M_FISTTP64);
            else if (I.op == XP_FADD)  sub = !memf ? (I.ud ? FPU_FADD_STI : FPU_FADD_ST0) : (I.sz == 4 ? FPU_M_FADD32 : FPU_M_FADD64);
            else if (I.op == XP_FMUL)  sub = !memf ? (I.ud ? FPU_FMUL_STI : FPU_FMUL_ST0) : (I.sz == 4 ? FPU_M_FMUL32 : FPU_M_FMUL64);
            else if (I.op == XP_FSUB)  sub = !memf ? (I.ud ? FPU_FSUB_STI : FPU_FSUB_ST0) : (I.sz == 4 ? FPU_M_FSUB32 : FPU_M_FSUB64);
            else if (I.op == XP_FSUBR) sub = !memf ? (I.ud ? FPU_FSUBR_STI : FPU_FSUBR_ST0) : (I.sz == 4 ? FPU_M_FSUBR32 : FPU_M_FSUBR64);
            else if (I.op == XP_FDIV)  sub = !memf ? (I.ud ? FPU_FDIV_STI : FPU_FDIV_ST0) : (I.sz == 4 ? FPU_M_FDIV32 : FPU_M_FDIV64);
            else if (I.op == XP_FDIVR) sub = !memf ? (I.ud ? FPU_FDIVR_STI : FPU_FDIVR_ST0) : (I.sz == 4 ? FPU_M_FDIVR32 : FPU_M_FDIVR64);
            else if (I.op == XP_FIADD) sub = (I.sz == 2 ? FPU_M_FIADD16 : FPU_M_FIADD32);
            else if (I.op == XP_FIMUL) sub = (I.sz == 2 ? FPU_M_FIMUL16 : FPU_M_FIMUL32);
            else if (I.op == XP_FICOM) sub = (I.sz == 2 ? FPU_M_FICOM16 : FPU_M_FICOM32);
            else if (I.op == XP_FICOMP) sub = (I.sz == 2 ? FPU_M_FICOMP16 : FPU_M_FICOMP32);
            else if (I.op == XP_FISUB) sub = (I.sz == 2 ? FPU_M_FISUB16 : FPU_M_FISUB32);
            else if (I.op == XP_FISUBR) sub = (I.sz == 2 ? FPU_M_FISUBR16 : FPU_M_FISUBR32);
            else if (I.op == XP_FIDIV) sub = (I.sz == 2 ? FPU_M_FIDIV16 : FPU_M_FIDIV32);
            else if (I.op == XP_FIDIVR) sub = (I.sz == 2 ? FPU_M_FIDIVR16 : FPU_M_FIDIVR32);
            else if (I.op == XP_FCOM)  sub = !memf ? FPU_FCOM_STI  : (I.sz == 4 ? FPU_M_FCOM32 : FPU_M_FCOM64);
            else if (I.op == XP_FCOMP) sub = !memf ? FPU_FCOMP_STI : (I.sz == 4 ? FPU_M_FCOMP32 : FPU_M_FCOMP64);
            else if (I.op == XP_FBLD)  sub = FPU_M_FBLD;
            else if (I.op == XP_FBSTP) sub = FPU_M_FBSTP;
            else if (I.op == XP_FSTSW) sub = memf ? FPU_M_FSTSW : FPU_FSTSW_AX;
            else if (I.op == XP_FSTCW) sub = FPU_M_FSTCW;
            else if (I.op == XP_FLDCW) sub = FPU_M_FLDCW;
            if (sub < 0) { F.why = "lifter: fpu sub cozulemedi"; return F; }
            if (memf) { L.eop(OP_FPU_MEM); L.e((u8)sub); L.emem(I.mem, I); }
            else      { L.eop(OP_FPU_ST);  L.e((u8)sub); L.e((u8)(I.r1 & 7)); }
            snprintf(buf, sizeof buf, "%s%s", "fpu-", I.text.c_str());
            break;
        }
        case XP_FXCH: case XP_FFREE: case XP_FFREEP:
        case XP_FADDP: case XP_FMULP: case XP_FSUBP: case XP_FSUBRP:
        case XP_FDIVP: case XP_FDIVRP:
        case XP_FCOMPP: case XP_FUCOMPP:
        case XP_FCOMI: case XP_FCOMIP: case XP_FUCOMI: case XP_FUCOMIP: {
            int sub;
            switch (I.op) {
            case XP_FXCH:   sub = FPU_FXCH; break;
            case XP_FFREE:  sub = FPU_FFREE; break;
            case XP_FFREEP: sub = FPU_FFREEP; break;
            case XP_FADDP:  sub = FPU_FADDP; break;
            case XP_FMULP:  sub = FPU_FMULP; break;
            case XP_FSUBP:  sub = FPU_FSUBP; break;
            case XP_FSUBRP: sub = FPU_FSUBRP; break;
            case XP_FDIVP:  sub = FPU_FDIVP; break;
            case XP_FDIVRP: sub = FPU_FDIVRP; break;
            case XP_FCOMPP: sub = FPU_FCOMPP; break;
            case XP_FUCOMPP: sub = FPU_FUCOMPP; break;
            case XP_FCOMI:  sub = FPU_FCOMI; break;
            case XP_FCOMIP: sub = FPU_FCOMIP; break;
            case XP_FUCOMI: sub = FPU_FUCOMI; break;
            default:        sub = FPU_FUCOMIP; break;
            }
            L.eop(OP_FPU_ST); L.e((u8)sub); L.e((u8)(I.r1 < 0 ? 0 : (I.r1 & 7)));
            snprintf(buf, sizeof buf, "fpu-st%d", sub);
            break;
        }
        case XP_FNOP: L.eop(OP_FPU_ST); L.e((u8)FPU_FNOP); L.e((u8)0); snprintf(buf, sizeof buf, "fnop"); break;
        case XP_FWAIT: L.eop(OP_FPU_ST); L.e((u8)FPU_FWAIT); L.e((u8)0); snprintf(buf, sizeof buf, "fwait"); break;
        case XP_FCLEX: L.eop(OP_FPU_ST); L.e((u8)FPU_FCLEX); L.e((u8)0); snprintf(buf, sizeof buf, "fclex"); break;
        case XP_FINIT: L.eop(OP_FPU_ST); L.e((u8)FPU_FINIT); L.e((u8)0); snprintf(buf, sizeof buf, "finit"); break;
        case XP_FDECSTP: L.eop(OP_FPU_ST); L.e((u8)FPU_FDECSTP); L.e((u8)0); snprintf(buf, sizeof buf, "fdecstp"); break;
        case XP_FINCSTP: L.eop(OP_FPU_ST); L.e((u8)FPU_FINCSTP); L.e((u8)0); snprintf(buf, sizeof buf, "fincstp"); break;
        case XP_FCHS: L.eop(OP_FPU_ST); L.e((u8)FPU_FCHS); L.e((u8)0); snprintf(buf, sizeof buf, "fchs"); break;
        case XP_FABS: L.eop(OP_FPU_ST); L.e((u8)FPU_FABS); L.e((u8)0); snprintf(buf, sizeof buf, "fabs"); break;
        case XP_FSQRT: L.eop(OP_FPU_ST); L.e((u8)FPU_FSQRT); L.e((u8)0); snprintf(buf, sizeof buf, "fsqrt"); break;
        case XP_FTST: L.eop(OP_FPU_ST); L.e((u8)FPU_FTST); L.e((u8)0); snprintf(buf, sizeof buf, "ftst"); break;
        case XP_FXAM: L.eop(OP_FPU_ST); L.e((u8)FPU_FXAM); L.e((u8)0); snprintf(buf, sizeof buf, "fxam"); break;
        case XP_FSIN: L.eop(OP_FPU_ST); L.e((u8)FPU_FSIN); L.e((u8)0); snprintf(buf, sizeof buf, "fsin"); break;
        case XP_FCOS: L.eop(OP_FPU_ST); L.e((u8)FPU_FCOS); L.e((u8)0); snprintf(buf, sizeof buf, "fcos"); break;
        case XP_FSINCOS: L.eop(OP_FPU_ST); L.e((u8)FPU_FSINCOS); L.e((u8)0); snprintf(buf, sizeof buf, "fsincos"); break;
        case XP_FPTAN: L.eop(OP_FPU_ST); L.e((u8)FPU_FPTAN); L.e((u8)0); snprintf(buf, sizeof buf, "fptan"); break;
        case XP_FPATAN: L.eop(OP_FPU_ST); L.e((u8)FPU_FPATAN); L.e((u8)0); snprintf(buf, sizeof buf, "fpatan"); break;
        case XP_FYL2X: L.eop(OP_FPU_ST); L.e((u8)FPU_FYL2X); L.e((u8)0); snprintf(buf, sizeof buf, "fyl2x"); break;
        case XP_FYL2XP1: L.eop(OP_FPU_ST); L.e((u8)FPU_FYL2XP1); L.e((u8)0); snprintf(buf, sizeof buf, "fyl2xp1"); break;
        case XP_F2XM1: L.eop(OP_FPU_ST); L.e((u8)FPU_F2XM1); L.e((u8)0); snprintf(buf, sizeof buf, "f2xm1"); break;
        case XP_FPREM: L.eop(OP_FPU_ST); L.e((u8)FPU_FPREM); L.e((u8)0); snprintf(buf, sizeof buf, "fprem"); break;
        case XP_FPREM1: L.eop(OP_FPU_ST); L.e((u8)FPU_FPREM1); L.e((u8)0); snprintf(buf, sizeof buf, "fprem1"); break;
        case XP_FRNDINT: L.eop(OP_FPU_ST); L.e((u8)FPU_FRNDINT); L.e((u8)0); snprintf(buf, sizeof buf, "frndint"); break;
        case XP_FSCALE: L.eop(OP_FPU_ST); L.e((u8)FPU_FSCALE); L.e((u8)0); snprintf(buf, sizeof buf, "fscale"); break;
        case XP_FXTRACT: L.eop(OP_FPU_ST); L.e((u8)FPU_FXTRACT); L.e((u8)0); snprintf(buf, sizeof buf, "fxtract"); break;
        case XP_FLD1: L.eop(OP_FPU_ST); L.e((u8)FPU_FLD1); L.e((u8)0); snprintf(buf, sizeof buf, "fld1"); break;
        case XP_FLDZ: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDZ); L.e((u8)0); snprintf(buf, sizeof buf, "fldz"); break;
        case XP_FLDPI: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDPI); L.e((u8)0); snprintf(buf, sizeof buf, "fldpi"); break;
        case XP_FLDL2T: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDL2T); L.e((u8)0); snprintf(buf, sizeof buf, "fldl2t"); break;
        case XP_FLDL2E: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDL2E); L.e((u8)0); snprintf(buf, sizeof buf, "fldl2e"); break;
        case XP_FLDLG2: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDLG2); L.e((u8)0); snprintf(buf, sizeof buf, "fldlg2"); break;
        case XP_FLDLN2: L.eop(OP_FPU_ST); L.e((u8)FPU_FLDLN2); L.e((u8)0); snprintf(buf, sizeof buf, "fldln2"); break;
        case XP_FCMOV: {
            /* cc (x86 JCC sirasi) -> FPU_FCMOV* subop */
            int sub;
            switch (I.cc) {
            case CC_B:  sub = FPU_FCMOVB; break;
            case CC_E:  sub = FPU_FCMOVE; break;
            case CC_BE: sub = FPU_FCMOVBE; break;
            case CC_P:  sub = FPU_FCMOVU; break;   /* unordered = PF=1 */
            case CC_AE: sub = FPU_FCMOVNB; break;
            case CC_NE: sub = FPU_FCMOVNE; break;
            case CC_A:  sub = FPU_FCMOVNBE; break;
            case CC_NP: sub = FPU_FCMOVNU; break;
            default: F.why = "lifter: fcmov cc yok"; return F;
            }
            L.eop(OP_FPU_ST); L.e((u8)sub); L.e((u8)(I.r1 & 7));
            snprintf(buf, sizeof buf, "fcmov st,st(%d) cc%d", I.r1 & 7, I.cc);
            break;
        }
        default:
            F.why = "lifter: bilinmeyen islem";
            return F;
        }
        F.notes.push_back(std::string("  ") + hex32(pc) + ": " + buf);
        pc += I.len;
    }

    if (!saw_ret) {
        // 0.5.0: SDK/manual BOLGE — govde ret icermeyebilir (orta-fonksiyon).
        // VM dongusu done bayragina ihtiyac duyar -> yapay OP_RET; stub ret
        // YERINE region_end'e atlar (cont_rva) -> yigin/donus adresi korunur.
        if (!region_mode) { F.why = "ret bulunamadi"; return F; }
        L.eop(OP_RET);
        last_ret = true;
        F.notes.push_back("  [BOLGE] govde ret yok — yapay OP_RET + stub region sonuna atlar");
    }
    // ---- 1.0.0 KOK-FIX (kullanici-kanitli oyun-cokmesi sinifi) ----
    // --add D7610:D766C gibi bolge-siniri son ret'i DIYARIDA birakir: lift
    // izi 'pop ebp'de biter, bytecode RET'siz kalir -> VM akis-tasmasi bc
    // sonrasi OOB bayti op diye okur (itab[garcop] stack-OOB) -> rastgele
    // VM op'u -> oyun cokmesi. 0.9.0 'sansliydi' (OOB bayti benign cozuldu);
    // 0.9.5/0.10.0'da bc boyutu degisince OOB bayt degisti -> cokme. Fix:
    // akis sonu RET ile GARANTILENIR (stub retimm ile temiz doner).
    if (!last_ret) {
        L.eop(OP_RET);
        F.notes.push_back("  [1.0.0-FIX] bolge-siniri kesigi: govde RET ile bitmiyordu — "
                          "yapay OP_RET eklendi (OOB akis-tasma kok-nedeni kapandi)");
    }
    /* 1.1.0: jcc->end hedefi — uc RET garantisini jcc hedefiyle birlestir.
       !last_ret: kok-fix RET az once Y=size-1'de emit edildi -> hedef Y.
       last_ret:  govde RET'i akista; jcc icin sona EK RET (dogrusal akis
       ulasmaz). Iki durumda da OP_RET bc-ofseti pc2ic[end]'e yazilir. */
    if (jcc_to_end) {
        u32 end_ret_bc;
        if (!last_ret) end_ret_bc = (u32)F.plain.size() - 1;   // kok-fix RET
        else         { end_ret_bc = (u32)F.plain.size(); L.eop(OP_RET); }
        pc2ic[end] = end_ret_bc;
        F.notes.push_back("  [1.1.0-FIX] jcc->bolge-sonu: son OP_RET'e yonlendirildi");
    }

    // 0.4.1 DÜZELTME (0.3.0 gizli bug): yerel retimm hicbir zaman F.retimm'e
    // aktarilmiyordu -> tum x86 stub'lari sentinel ile uretiliyordu (C3).
    // cdecl'de kazayla dogru; stdcall (ret imm16) fonksiyonlarda ESP kayiyordu.
    F.retimm = retimm;

    // fixup'lari uygula: rel32 = hedef_bc - (site + 4)
    for (auto& fx : F.fix) {
        auto it = pc2ic.find(fx.second);
        if (it == pc2ic.end()) { F.why = "fixup hedefi yok @0x" + hex32(fx.second); return F; }
        u32 site = fx.first;
        i64 rel = (i64)it->second - (i64)(site + 4);
        if (getenv("CPL_FIXDBG"))
            fprintf(stderr, "[fix] site=%u hedef_pc=0x%x hedef_ic=%u rel=%lld\n",
                    site, fx.second, it->second, (long long)rel);
        for (int k = 0; k < 4; k++)
            F.plain[site + k] = (u8)(((u64)rel >> (8 * k)) & 0xFF);
    }
    F.fix.clear();
    F.ok = true;
    return F;
}
