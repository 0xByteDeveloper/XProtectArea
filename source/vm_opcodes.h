// ============================================================
// vm_opcodes.h — VM bayt-kod formatinin TEK kaynagi.
// Hem CPlusPort engine (encoder) hem vm_core.c (decoder) kullanir.
// Her byte rolling-LCG anahtari ile sifrelenir:
//   cipher = b ^ (key & 0xFF);  key = key*A + C
// ============================================================
#ifndef VM_OPCODES_H
#define VM_OPCODES_H

// 0.8.0 crypt_command — IKI-KATMANLI konum keystream'i (VMProtect
// crypt_command'a es-karsilik): katman-1 ince (byte pozisyon), katman-2
// kaba (8-byte periyot, roll edilmis anahtar). Ikisi de SALT (key,pos)
// fonksiyonu oldugu icin JMP/JCC siralamasindan bagimsiz encoder/decoder
// uyumu korunur; tek-bayt tamper artik 8-byte blok degradesini de degistirir.
// NOT: eski tek-katman VM_KS kullanan tum ciktilar bu surumle yeniden
// sifrelenir (encoder + decoder ayni makrodan turetir).
#define VM_ROLL(k) ((((unsigned long long)(k)) * 0x100000001B3ULL) \
    ^ (((unsigned long long)(k)) >> 23) ^ 0x51ED270B4C5A3D0FULL)
#define VM_KS(key, pos) ((unsigned char)( \
    ( ((((unsigned long long)(key)) ^ ((unsigned long long)(pos)) * 0x9E3779B97F4A7C15ULL) \
        * 0x2545F4914F6CDD1DULL + 0x9E3779B97F4A7C15ULL) \
    ^ ( ((((VM_ROLL(key))) ^ ((unsigned long long)((pos) >> 3)) * 0xD1B54A32D192ED03ULL) \
        * 0x94D049BB133111EBULL) ) \
    ) >> 56))

// 0.8.0 crypt_command — CFB geribesleme katmani: her baytin akisi BIR
// ONCEKI SIFRELI bayta baglanir (cipher-feedback). encoder sira ile
// uretir (enc[i-1] elinde), decoder konumdan okur (bc[i-1] buffer'da) —
// JMP/JCC konum-degisikligi zinciri BOZMAZ (saf (key, prev, pos) fonksiyonu),
// tek-bayt tamper sonraki baytin cozumunu de degistirir (yayilim).
#define VM_KSC(key, prev, pos) VM_KS( \
    ((unsigned long long)(key)) ^ ((unsigned long long)(unsigned char)(prev)) * 0x2545F4914F6CDD1DULL, \
    (pos))

// 0.8.0 crypt_key — stub'in tasiydigi anahtar obfuscated: stub key^K2
// yazar; vm_entry giriste K2 ile geri cozer. K2 = (bc_rva, bc_len) purely
// fonksiyonu — encoder ve decoder ayni makrodan turetir; `mov rax,imm64`
// artik duz anahtar tasimaz. (splitmix64 finalizer; salt-ifade)
#define VM_KXI(rva, len) (0x5850424DULL \
    ^ ((unsigned long long)(unsigned int)(rva) << 32) \
    ^ (unsigned long long)(unsigned int)(len))
#define VM_KXA(x) ((x) ^ ((x) >> 30))
#define VM_KXB(x) ((x) * 0xBF58476D1CE4E5B9ULL)
#define VM_KXC(x) ((x) ^ ((x) >> 27))
#define VM_KXD(x) ((x) * 0x94D049BB133111EBULL)
#define VM_KXE(x) ((x) ^ ((x) >> 31))
#define VM_KEYXOR(bc_rva, bc_len) \
    (VM_KXE(VM_KXD(VM_KXC(VM_KXB(VM_KXA(VM_KXI(bc_rva, bc_len)))))))

// --- opcode numaralari ---
#define OP_NOP       0x00   // mutation junk / alignment
#define OP_MOV_RR    0x01   // sz r1 r2
#define OP_MOV_RI    0x02   // sz r1 imm32(sx)
#define OP_MOV_RM    0x03   // sz r1 mem
#define OP_MOV_MR    0x04   // sz mem r1
#define OP_MOV_MI    0x05   // sz mem imm32(sx)
#define OP_LEA_RM    0x06   // r1 mem
#define OP_ALU_RR    0x07   // alu sz r1 r2
#define OP_ALU_RI    0x08   // alu sz r1 imm32
#define OP_ALU_RM    0x09   // alu sz r1 mem
#define OP_ALU_MR    0x0A   // alu sz mem r1
#define OP_ALU_MI    0x0B   // alu sz mem imm32
#define OP_SHI_RI    0x0C   // shi sz r1 imm8
#define OP_SHI_CL    0x0D   // shi sz r1
#define OP_IMUL_RRI  0x0E   // sz r1 r2 imm32
#define OP_IMUL_RR   0x0F   // sz r1 r2
#define OP_INCDEC_R  0x10   // ud sz r1
#define OP_INCDEC_M  0x11   // ud sz mem
#define OP_MOVZX     0x12   // dsz ssz r1 form src
#define OP_MOVSX     0x13   // dsz ssz r1 form src
#define OP_PUSH_R    0x14   // r1
#define OP_PUSH_I    0x15   // imm32(sx)
#define OP_POP_R     0x16   // r1
#define OP_JMP       0x17   // rel32 (bytecode icinde)
#define OP_JCC       0x18   // cc rel32
#define OP_NCALL     0x19   // u32: target = base + rva
#define OP_RET       0x1A
#define OP_SETCC     0x1B   // cc r1
#define OP_CQO       0x1C   // RAX->RDX (x64) / EAX->EDX (x86)
#define OP_IDIV_R    0x1D   // sz r1
#define OP_ANTIDBG   0x1E
#define OP_STRDEC    0x1F   // u32 strRva u32 stateRva u32 key u32 len
#define OP_MOV_RI64  0x20   // r1 imm64
#define OP_CMOV      0x21   // cc sz r1 form (0: r2 | 1: mem)
#define OP_SHI_RM_RI 0x22   // shi sz mem imm8   (bellek shift)
#define OP_SHI_RM_CL 0x23   // shi sz mem        (bellek shift %cl)
#define OP_IMUL_RMRI 0x24   // sz r1 mem imm32   (imul r,[m],imm)
#define OP_NEG_R     0x25   // sz r1             (0 - r; CF=x!=0,ZF/SF/OF)
#define OP_NOT_R     0x26   // sz r1             (~r; bayrak etkisi yok)
#define OP_NEG_M     0x27   // sz mem
#define OP_NOT_M     0x28   // sz mem
#define OP_BSWAP_R   0x2A   // sz r1
#define OP_XCHG_RR   0x2B   // sz r1 r2        (bayrak etkisi yok)
// ROL/ROR: OP_SHI_RI/CL'nin shi=3/4 degeriyle (yeni op gerekmez)

// --- 0.9.0-DeepVM: UniversalObfuscator (VMProtect pub1 intel.cc) es-karsilik
//     kapsam genisletmesi. Tam EFLAGS (CF/PF/AF/ZF/SF/OF + DF) + 0F uzanti
//     + string ops + donguler. Akis formati encoder (engine_lift) ile
//     BIREBIR ayna — degisiklikler iki tarafta ayni commit'te.
#define OP_PUSHF     0x2C   // push EFLAGS imaji (CF PF AF ZF SF TF IF DF OF; bit1=1)
#define OP_POPF      0x2D   // pop -> VM flags (yalniz modelenen bitler)
#define OP_SAHF      0x2E   // flags <- AH (CF/PF/AF/ZF/SF)
#define OP_LAHF      0x2F   // AH <- SF:ZF:0:AF:0:PF:1:CF
#define OP_SETFLAG   0x30   // ud: 0=CLC 1=STC 2=CMC 3=CLD 4=STD
#define OP_MUL_R     0x31   // sz form [r1|mem]: RDX:RAX = RAX*r/m (sz1: AX=AL*r8)
#define OP_DIV_R     0x32   // sz form [r1|mem]: RDX:RAX / r/m (sz1: AL=AL/r8 AH=rem)
#define OP_BT_X      0x33   // ud sz form [r1|mem] srcform [r2|imm8]: 0=BT 1=BTS 2=BTR 3=BTC
#define OP_SHLD      0x34   // sz r1 r2 nmode [n]   (nmode 1 = CL)
#define OP_SHRD      0x35   // sz r1 r2 nmode [n]   (nmode 1 = CL)
#define OP_LOOP      0x36   // cc rel32 : --RCX; cc 0=loop 1=loope 2=loopne
#define OP_JECXZ     0x37   // rel32 : RCX==0
#define OP_XADD      0x38   // sz form [r1|mem] r2 : tmp=dst; dst+=src; src=tmp (ADD bayraklari)
#define OP_STR       0x39   // ud sz rep : 0=movs 1=stos 2=lods 3=scas 4=cmps; rep 0/1(repe)/2(repne)
#define OP_IMUL_RM   0x3A   // sz r1 mem : imul r1, [mem] (0F AF bellek formu)

// --- 1.0.0-UO: UniversalObfuscator (VMP pub1 intel.cc) cmNor/cmNand YIGIN
//     KAPILARI — birebir port. VMProtect VM'i yigin-makinesidir: cmAnd/
//     cmOr/cmXor dogrudan komut DEGILDIR, hepsi cmNor/cmNand kapilarindan
//     gecer (intel.cc CompileToVM case cmAnd/cmOr/cmXor +
//     AddRegistrAndValueSection/OrValueSection).
//     0.9.5/0.10.0 dersleri: temp-reg havuzu (r9/r10/r11) ve IR-junk YOK —
//     kapilar saf yigin ops (temp'siz, dengeli, dugum-siniri ici).
#define OP_NOR_ST    0x3B   // sz : pop b, pop a, push ~(a|b)&mask (mantik bayraklari)
#define OP_NAND_ST   0x3C   // sz : pop b, pop a, push ~(a&b)&mask
#define OP_POP_RP    0x3D   // sz r1 : kismi-yazim pop (cmPop otRegistr size_ es-karsiligi)

// --- 1.1.0-A4-FPU: UniversalObfuscator FPU paritesi (Phase A4) ---
// UO intel.cc CompileToVM FPU kumesi (beyaz-liste) 1:1 port + UST-KUME:
// UO'da ltNative-ada olarak KALAN FPU bellek-aritmetigi (fld/fst/fadd/fmul/
// fdiv/fcomp/fild/fi*/f*p) XProtect'te TAM SANALLASTIRILIR (OP_FPU_MEM:
// mem_addr ile cozulen gercek adrese gercek x87 talimati; x87 yigini
// gercekte kalir — VMP/UO semantigi, VM aritmetigi x87'ye dokunmaz).
// Calisma-mantigi (objdump ile dogrulanmis AT&T->Intel esleme):
//   - AT&T fsub/fsubr ve fdiv/fdivr Intel'e gore TERS; pop-formlarinda da ayni.
//   - FCOMI ailesi gercek EFLAGS yaziyor -> pushfq ile VM bayraklarina
//     senkron (fl_ bitleri gercek EFLAGS bitleriyle ayni konumda).
#define OP_FPU_ST    0x3E   // u8 subop u8 idx : yigin/kayit-formu x87 op
#define OP_FPU_MEM   0x3F   // u8 subop mem    : adres-formu x87 op

// --- 1.2.0-B1: mult-VM/Advanced (vtAdvanced + rel32 dis-akis) ---
// UO/VMP intel.cc VirtualMachineType {vtClassic, vtAdvanced}:
//   - Advanced: command_cryptor osDWord (VM_KSA — 4-byte periyot) + baska
//     mixing ailesi; klasik = osByte (VM_KS — 8-byte periyot). Decoder
//     kipi ctx->scratch[5]'ten okur (stub yazar); encoder ayni aileyi
//     kullanir — iki taraf ayni makro.
//   - mult-VM: VM gostergesi ctx->scratch[7] (vm_id); bytecode anahtari
//     K2'ye VM_VMK(vm_id) karisir (ayni VM'in butun fonksiyonlari AYNI
//     anahtar-alani + AYNI opcode-permutasyon ailesi tasir — VMP'nin
//     VirtualMachineList semantigi).
// rel32 dis-akis (UO ltJmp/ltCall disariga): bolge-disi JMP/JCC artik
// sanallastirilir — VM done=3 ile cikar, stub push_area'dan kayitlari
// geri yukledikten sonra volatile-register ile natgt hedefine KUYRUK
// atlama yapar (donus adresi yiginda KALIR — G ret ile cagirana döner).
#define OP_JMPEXT    0x41   // rva32 : disari kuyruk-jmp (done=3, scratch[6]=rva)
#define OP_JCCEXT    0x42   // cc rva32 : sartli disari kuyruk-jmp
#define OP_CHKRET    0x43   // (arg yok) : donus-adresi int3/uzun-int3/ud2 kontrolu —
                           //  UO AddCheckBreakpointSection (intel.cc:9305) 1:1

// Advanced command-cryptor: 4-byte kaba periyot (VM_KS 8-byte'in kardesi;
// baska sabit ailesi — vtAdvanced osDWord komut-sifreleyici karsiligi)
#define VM_ROLL_A(k) ((((unsigned long long)(k)) * 0x9E3779B97F4A7C15ULL) \
    ^ (((unsigned long long)(k)) >> 17) ^ 0x2545F4914F6CDD1DULL)
#define VM_KSA(key, pos) ((unsigned char)( \
    ( ((((unsigned long long)(key)) ^ ((unsigned long long)(pos)) * 0xD1B54A32D192ED03ULL) \
        * 0x100000001B3ULL + 0xA24BAED4963EE407ULL) \
    ^ ( ((((VM_ROLL_A(key))) ^ ((unsigned long long)((pos) >> 2)) * 0x9E3779B97F4A7C15ULL) \
        * 0x2545F4914F6CDD1DULL) ) \
    ) >> 56))
#define VM_KSCA(key, prev, pos) VM_KSA( \
    ((unsigned long long)(key)) ^ ((unsigned long long)(unsigned char)(prev)) * 0x100000001B3ULL, \
    (pos))

// mult-VM: VM gostergesi anahtar karisimi (splitmix cifti — salt-ifade)
#define VM_VMK(vm_id) ( (vm_id) ? ( \
    (0x5850424DULL ^ ((unsigned long long)(unsigned int)(vm_id)) * 0x9E3779B97F4A7C15ULL) \
    ^ (((unsigned long long)(unsigned int)(vm_id)) << 41) ) : 0ULL )

// ctx scratch slotlari (vm_core.c ile ayni):
//   scratch[3] = perm tohumu (0.8.0), scratch[4] = TEB (0.9.0)
//   scratch[5] = KS kipi (0=classic/1=advanced, 1.2.0-B1)
//   scratch[6] = natgt rva (OP_JMPEXT/JCCEXT cikisi, 1.2.0-B1)
//   scratch[7] = vm_id (mult-VM, 1.2.0-B1)
#define VMOFF_KSADV   0xF0   // scratch[5]
#define VMOFF_NATGT   0xF8   // scratch[6]
#define VMOFF_VMID    0x100  // scratch[7]

// OP_FPU_ST alt kodlari (implicit + reg-form; idx = st(i) 0..7)
#define FPU_FSQRT     0
#define FPU_FCHS      1
#define FPU_FABS      2
#define FPU_FSIN      3
#define FPU_FCOS      4
#define FPU_FSINCOS   5
#define FPU_FPTAN     6
#define FPU_FPATAN    7
#define FPU_FYL2X     8
#define FPU_FYL2XP1   9
#define FPU_F2XM1    10
#define FPU_FPREM    11
#define FPU_FPREM1   12
#define FPU_FRNDINT  13
#define FPU_FSCALE   14
#define FPU_FXTRACT  15
#define FPU_FTST     16
#define FPU_FXAM     17
#define FPU_FDECSTP  18
#define FPU_FINCSTP  19
#define FPU_FINIT    20
#define FPU_FCLEX    21
#define FPU_FNOP     22
#define FPU_FWAIT    23
#define FPU_FLD1     24
#define FPU_FLDZ     25
#define FPU_FLDPI    26
#define FPU_FLDL2T   27
#define FPU_FLDL2E   28
#define FPU_FLDLG2   29
#define FPU_FLDLN2   30
#define FPU_FCOMPP   31
#define FPU_FUCOMPP  32
// reg-form (idx=st(i))
#define FPU_FLD_ST   33   // fld st(i)
#define FPU_FXCH     34   // fxch st(i)
#define FPU_FADD_STI 35   // DC C0+i : ST(i) += ST(0)
#define FPU_FMUL_STI 36   // DC C8+i
#define FPU_FSUB_STI 37   // DC E8+i : ST(i) -= ST(0)
#define FPU_FSUBR_STI 38  // DC E0+i : ST(i) = ST(0)-ST(i)
#define FPU_FDIV_STI 39   // DC F8+i : ST(i) /= ST(0)
#define FPU_FDIVR_STI 40  // DC F0+i : ST(i) = ST(0)/ST(i)
#define FPU_FADD_ST0 41   // D8 C0+i : ST(0) += ST(i)
#define FPU_FMUL_ST0 42   // D8 C8+i
#define FPU_FSUB_ST0 43   // D8 E0+i : ST(0) -= ST(i)
#define FPU_FSUBR_ST0 44  // D8 E8+i : ST(0) = ST(i)-ST(0)
#define FPU_FDIV_ST0 45   // D8 F0+i : ST(0) /= ST(i)
#define FPU_FDIVR_ST0 46  // D8 F8+i : ST(0) = ST(i)/ST(0)
#define FPU_FCOM_STI 47   // D8 D0+i
#define FPU_FCOMP_STI 48  // D8 D8+i
#define FPU_FUCOM_STI 49  // DD E0+i
#define FPU_FUCOMP_STI 50 // DD E8+i
#define FPU_FST_STI  51   // DD D0+i
#define FPU_FSTP_STI 52   // DD D8+i
#define FPU_FFREE    53   // DD C0+i
#define FPU_FFREEP   54   // DF C0+i
// pop-formlar
#define FPU_FADDP    55   // DE C0+i
#define FPU_FMULP    56   // DE C8+i
#define FPU_FSUBP    57   // DE E8+i
#define FPU_FSUBRP   58   // DE E0+i
#define FPU_FDIVP    59   // DE F8+i
#define FPU_FDIVRP   60   // DE F0+i
// EFLAGS-formlari (gercek EFLAGS -> VM flags senkronu)
#define FPU_FCOMI    61   // DB F0+i
#define FPU_FCOMIP   62   // DF F0+i
#define FPU_FUCOMI   63   // DB E8+i
#define FPU_FUCOMIP  64   // DF E8+i
// FCMOV (idx=st(i); cc bytecode subop'inda ayri)
#define FPU_FCMOVB   65
#define FPU_FCMOVE   66
#define FPU_FCMOVBE  67
#define FPU_FCMOVU   68
#define FPU_FCMOVNB  69
#define FPU_FCMOVNE  70
#define FPU_FCMOVNBE 71
#define FPU_FCMOVNU  72
#define FPU_FSTSW_AX 73   // AX <- status word (VM reg yazimi)

// OP_FPU_MEM alt kodlari (adres akistan; sz subop'a gomulu)
#define FPU_M_FLD32   0
#define FPU_M_FLD64   1
#define FPU_M_FLD80   2
#define FPU_M_FST32   3
#define FPU_M_FST64   4
#define FPU_M_FSTP32  5
#define FPU_M_FSTP64  6
#define FPU_M_FSTP80  7
#define FPU_M_FILD16  8
#define FPU_M_FILD32  9
#define FPU_M_FILD64 10
#define FPU_M_FIST16 11
#define FPU_M_FIST32 12
#define FPU_M_FISTP16 13
#define FPU_M_FISTP32 14
#define FPU_M_FISTP64 15
#define FPU_M_FISTTP16 16
#define FPU_M_FISTTP32 17
#define FPU_M_FISTTP64 18
#define FPU_M_FADD32 19
#define FPU_M_FADD64 20
#define FPU_M_FSUB32 21
#define FPU_M_FSUB64 22
#define FPU_M_FSUBR32 23
#define FPU_M_FSUBR64 24
#define FPU_M_FMUL32 25
#define FPU_M_FMUL64 26
#define FPU_M_FDIV32 27
#define FPU_M_FDIV64 28
#define FPU_M_FDIVR32 29
#define FPU_M_FDIVR64 30
#define FPU_M_FCOM32 31
#define FPU_M_FCOM64 32
#define FPU_M_FCOMP32 33
#define FPU_M_FCOMP64 34
#define FPU_M_FIADD16 35
#define FPU_M_FIADD32 36
#define FPU_M_FIMUL16 37
#define FPU_M_FIMUL32 38
#define FPU_M_FICOM16 39
#define FPU_M_FICOM32 40
#define FPU_M_FICOMP16 41
#define FPU_M_FICOMP32 42
#define FPU_M_FISUB16 43
#define FPU_M_FISUB32 44
#define FPU_M_FISUBR16 45
#define FPU_M_FISUBR32 46
#define FPU_M_FIDIV16 47
#define FPU_M_FIDIV32 48
#define FPU_M_FIDIVR16 49
#define FPU_M_FIDIVR32 50
#define FPU_M_FSTSW  51
#define FPU_M_FSTCW  52
#define FPU_M_FLDCW  53
#define FPU_M_FBLD   54
#define FPU_M_FBSTP  55

// --- 0.8.0 polimorfik isleyiciler: opcode permütasyonu ---
// π = anahtar-turetilmis (Fisher-Yates; tohum = fonksiyon RVA'si).
// Encoder (engine_lift eop) gercel->raw yazar (vm_perm_enc); interpreter
// (vm_run) raw->gercek cozumler (vm_perm_dec). Her iki taraf AYNI
// fonksiyondan turer -> tablo tasimaya gerek yok (stub yalniz tohumu
// ctx->scratch[3]'e yazar). Tohum 0 = kimlik degil, gecerli permütasyon
// (determinizm iki tarafta da ayni fonksiyondan).
#define VM_OPN 0x44   // opcode uzayi (0x00..0x43) — 1.2.0-A8: 0x43 -> 0x44 (OP_CHKRET)
static void vm_perm_tab(unsigned int seed, unsigned char* t, int dec) {
    unsigned char p[VM_OPN]; int i, j;
    for (i = 0; i < VM_OPN; i++) p[i] = (unsigned char)i;
    {
        unsigned long long z = ((unsigned long long)seed ^ 0x5850424D9E3779B9ULL) | 1ULL;
        for (i = VM_OPN - 1; i > 0; i--) {
            z ^= z >> 30; z *= 0xBF58476D1CE4E5B9ULL;
            z ^= z >> 27; z *= 0x94D049BB133111EBULL; z ^= z >> 31;
            /* x86 freestanding: 64-bit modulo YOK (umoddi3) — yuksek 32B */
            j = (int)(((unsigned int)(z >> 32)) % (unsigned int)(i + 1));
            { unsigned char tmp = p[i]; p[i] = p[j]; p[j] = tmp; }
        }
    }
    if (dec) { for (i = 0; i < VM_OPN; i++) t[i] = p[i]; }          // raw->gercek
    else     { for (i = 0; i < VM_OPN; i++) t[p[i]] = (unsigned char)i; } // gercek->raw
}

// --- ALU alt kodlari ---
#define ALU_ADD 0
#define ALU_SUB 1
#define ALU_AND 2
#define ALU_OR  3
#define ALU_XOR 4
#define ALU_CMP 5
#define ALU_TEST 6
#define ALU_ADC 7   // 0.9.0: add + CF girdi (do_alu c->flags'tan okur)
#define ALU_SBB 8   // 0.9.0: sub - CF girdi

// --- shift alt kodlari ---
#define SHI_SHL 0
#define SHI_SHR 1
#define SHI_SAR 2
#define SHI_ROL 3   // 0.8.0: donusumler (RCL/RCR desteklenmez -> RED)
#define SHI_ROR 4

// --- condition kodlari (x86 Jcc sirasi! JP/NP dahil) ---
#define CC_O  0
#define CC_NO 1
#define CC_B  2
#define CC_AE 3
#define CC_E  4
#define CC_NE 5
#define CC_BE 6
#define CC_A  7
#define CC_S  8
#define CC_NS 9
#define CC_P  10
#define CC_NP 11
#define CC_L  12
#define CC_GE 13
#define CC_LE 14
#define CC_G  15

// --- bayrak bitleri (VMContext.flags) ---
// 0.9.0-DeepVM: TAM EFLAGS — CF/PF/AF/ZF/SF/OF + DF (string ops).
// VM dahili bitler; PUSHF/POPF x86 EFLAGS imajina cevirir (vm_core.c).
#define FCF 1u
#define FZF 2u
#define FSF 4u
#define FOF 8u
#define FPF 16u   // 0.9.0: parity (LSB 8-bit cift birlik)
#define FAF 32u   // 0.9.0: auxiliary carry (bit-3 tasiyici)
#define FDF 64u   // 0.9.0: direction (string ops yonu)

// --- register enc: 0..15 = x64 GPR sirasi ---
// rax rcx rdx rbx rsp rbp rsi rdi r8..r15
// 16..19 = ah ch dh bh (yuksek bayt); 8-bit yazmada kullanilir
#define REG_RAX 0
#define REG_RCX 1
#define REG_RDX 2
#define REG_RBX 3
#define REG_RSP 4
#define REG_RBP 5
#define REG_RSI 6
#define REG_RDI 7
#define REG_R8  8

// --- mem operand form'lari ---
#define MEMF_DISP 0   // addr = base + disp32(rva)   [rip-rel / abs32 donusturulmus]
#define MEMF_SIB  1   // base_reg, idx_reg, scale(0..3), disp32
#define MEMF_SIB_IMG 2  // MEMF_SIB gibi; disp32 IMAGE-RVA'dir -> c->base eklenir
                        // (x86 mutlak adresleme: [reg + VA] -> [reg + (VA-IB)])
#define SIB_NOBASE 0xFF
#define MEMF_SEG   3   // 0.9.0: seg(1) + alt-form. seg: 4=FS 5=GS (Intel sirasi)
                       // FS: x86=TEB, x64=0 | GS: x64=TEB, x86=0 (gercek Win semantics)
#define MEMF_DISP_SEG 4 // 0.9.0: addr = segbase + HAM disp32 (rva cevirimi YOK —
                        // TEB-relative erisim: gs:[0x30] = TEB + 0x30)

// --- VMContext offsetleri (engine stub'i ile BIREBIR ayni olmali) ---
#define VMOFF_BC        0x00
#define VMOFF_BCLEN     0x08
#define VMOFF_KEY       0x10
#define VMOFF_BASE      0x18
#define VMOFF_REGS      0x20      // 16 x 8 = 0x80
#define VMOFF_FLAGS     0xA0
#define VMOFF_PUSHAREA  0xA8
#define VMOFF_INITRSP   0xB0
#define VMOFF_EXTRAPOP  0xB8
#define VMOFF_DONE      0xC0
#define VMOFF_SCRATCH   0xC8      // 8 x 8
#define VMSIZE          0xE8      // toplam (align 0x10)

// --- XRT cfg sözleşme boyutu (0.6.1) ---
// xrt_core.c'deki XCFG_SIZE (0x48) ile BIREBIR ayni olmali. 0.6.0'da
// XCFG 0x40->0x48 büyütüldü ama engine rezervi 0x40'ta kalmisti: cfg'nin
// son 8B'si (pack_rva + reserved) ilk bytecode'un ilk 8 baytini eziyor,
// VM çöp opcode okuyor ve fonksiyon SESSIZCE no-op'a düşüyordu
// (kullanıcı kanıtı: metin2 ULTRA+loaderCRC = damage yok, crash yok).
#define XCFG_SIZE_E     0x60   // 0.8.0: +16B (unw 0x44/0x48, sectcrypt 0x4C/0x50/0x58 — xr_cipher.h)

// --- stub'in yigin rezervi (fonksiyonun kendi push/literal alani) ---
#define VM_CTX_SZ   0xE8
// Stub yigin duzeni (olcumlu):
//   x64: 15 push(0x78) + sub 0x330 (ctx 0xE8 + VM C cerceve marji) + call
//   x86: pushad(0x20) + sub 0x268 + push ctx(4) + call
// VM C cerceveleri olculecek kadar asagi inmez (x64 ~0x120, x86 ~0x90;
// 2x marj). Fonksiyonun mantiksal yazimlari C cercevelerinin ALTINA
// DELTA ile tasinir -> kesisme imkansiz.
#define VM_STUB_SUB64 0x330
#define VM_STUB_SUB86 0x268
#define VM_DELTA64  0x600   /* 0x78+0x330+8(ret)+0x240(C-frame) -> align16 */
#define VM_DELTA86  0x420   /* 0x20+0x268+4+4(ret)+0x180(C-frame) -> align16 */

#endif
