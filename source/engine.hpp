// ============================================================
// engine.hpp — CPlusPort koruma motoru arayuzleri
// ============================================================
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include "vm_opcodes.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

// ---------------- PE ----------------
struct Section {
    char name[9];
    u32 va, vsz, rawoff, rawsz, chars;
};

struct PEFile {
    std::vector<u8> buf;
    bool is64 = false;
    u16 machine = 0;
    u32 imagebase = 0, entry_rva = 0;
    u64 ib64 = 0;   // tam 64-bit ImageBase (PE32+ icin dogru deger, log/rapor)
    u32 secalign = 0x1000, filealign = 0x200, sizeofimage = 0, sizeofheaders = 0;
    u32 symtab_off = 0; u32 symtab_n = 0; u32 strtab_off = 0;
    u32 e_lfanew = 0;
    std::vector<Section> secs;

    bool load(const std::string& path, std::string& err);
    bool save(const std::string& path);
    u32  rva2raw(u32 rva, bool* ok = nullptr) const;
    Section* secbyrva(u32 rva);
    Section* secbyname(const char* n);
    const Section* secbyname_c(const char* n) const;
    bool add_section(const char* name, const std::vector<u8>& data, u32 chars,
                     u32& out_rva);
    void fix_checksum();
    // BUGFIX #13: sanallastirilan fonksiyon bolgelerine dusen eski
    // .reloc girdilerini siler (ASLR'da loader stub baytlarini bozuyordu)
    bool filter_relocs(const std::vector<std::pair<u32,u32>>& ranges,
                       u32& removed, std::string& note);
    // export tablosu
    void exports(std::vector<std::pair<std::string, u32>>& out);
    // COFF sembol tablosu (isim -> rva), fonksiyon olanlar
    void coff_symbols(std::vector<std::pair<std::string, u32>>& out);
};

// ---------------- Disassembler ----------------
enum XOp {
    XP_UNKNOWN = 0, XP_NOP, XP_INT3, XP_PUSH_R, XP_POP_R, XP_MOV_MR, XP_MOV_RM,
    XP_MOV_MI, XP_MOV_RI, XP_MOV_RI64, XP_LEA, XP_ALU, XP_SHIFT, XP_IMUL_RRI,
    XP_IMUL_RR, XP_INCDEC_R, XP_INCDEC_M, XP_MOVZX, XP_MOVSX, XP_JMP, XP_JCC,
    XP_CALL, XP_RET, XP_RETI16, XP_SETCC, XP_CWDE, XP_CDQ, XP_IDIV, XP_TEST_RM, XP_PUSH_I, XP_LEAVE, XP_CMOV,
    XP_NEG, XP_NOT, XP_CALLI, XP_JMPI, XP_XCHG, XP_BSWAP,
    // --- 0.9.0-DeepVM: UniversalObfuscator (VMProtect pub) intel.h spec'inden
    //     kapsam genisletmesi — lifter RED oranini dusturur ---
    XP_MUL,        // F7 /4 (+F6 /4): RDX:RAX = RAX * r/m   (sz=1: AX = AL*r8)
    XP_DIV,        // F7 /6 (+F6 /6): EDX:EAX / r/m        (sz=1: AL=AL/AH rem)
    XP_BT,         // 0F A3/AB/B3/BB r/m,r  |  0F BA /4-/7 r/m,imm8
                   //   ud: 0=BT 1=BTS 2=BTR 3=BTC; r1=dst(r/m), r2=bit-src veya imm
    XP_SHLD,       // 0F A4 (imm8) / 0F A5 (CL): r1 = r1:r2 sola
    XP_SHRD,       // 0F AC (imm8) / 0F AD (CL): r1:r2 sag (r1 <- r2:yuksek)
    XP_LOOP,       // E0/E1/E2: --rcx; jnz [&& zf == cc-1]; cc: 2=loop 1=loopz 0=loopnz? -> cc alanina direk yazilir
    XP_JECXZ,      // E3: rcx==0 -> jmp
    XP_SAHF,       // 9E: flags <- AH (yalniz CF/ZF/SF izlenir)
    XP_LAHF,       // 9F: AH <- SF:ZF:0:AF:0:PF:1:CF (AF/PF=0 yazilir)
    XP_PUSHF,      // 9C: push VM flags
    XP_POPF,       // 9D: pop VM flags
    XP_SETFLAG,    // F5/F8/F9/FC/FD: ud 0=CLC 1=STC 2=CMC 3=CLD 4=STD
    XP_XADD,       // 0F C1 r/m,r (0F C0 8-bit): tmp=dst; dst+=src; src=tmp
    XP_STR,        // A4/A5 movs AA/AB stos AC/AD lods AE/AF scas A6/A7 cmps
                   //   ud: 0=movs 1=stos 2=lods 3=scas 4=cmps; rep alanina bak
    XP_IMUL_RM,    // 0F AF imul r1, [mem] (0.9.0: mem form RED'den cikarildi)
    // --- 1.1.0-A4-FPU: UniversalObfuscator FPU paritesi (D8-DF uzayi) ---
    // Mem-formlar (I.mem + I.sz: 2/4/8/10; 10=TBYTE), reg-formlar
    // (I.r1 = st(i) 0..7), implicit-formlar (operand yok).
    XP_FLD,        // D9 /0 m32, DD /0 m64, DB /5 m80, D9 C0+i fld st(i)
    XP_FST,        // D9 /2 m32, DD /2 m64, DD D0+i fst st(i)
    XP_FSTP,       // D9 /3 m32, DD /3 m64, DB /7 m80, DD D8+i, D9 D8+i
    XP_FILD,       // DB /0 m32, DF /0 m16, DF /5 m64
    XP_FIST,       // DB /2 m32, DF /2 m16
    XP_FISTP,      // DB /3 m32, DF /3 m16, DF /7 m64
    XP_FISTTP,     // DB /1 m32, DF /1 m16 (SSE3 truncasyon store)
    XP_FADD,       // D8 /0 m32, DC /0 m64, D8 C0+i (ST0+=STi), DC C0+i (STi+=ST0)
    XP_FMUL,       // D8 /1 m32, DC /1 m64 + reg-formlar
    XP_FSUB,       // D8 /4 m32, DC /5 m64 (DC mem tablo TERS!) + reg
    XP_FSUBR,      // D8 /5 m32, DC /4 m64 + reg
    XP_FDIV,       // D8 /6 m32, DC /7 m64 + reg
    XP_FDIVR,      // D8 /7 m32, DC /6 m64 + reg
    XP_FIADD,      // DA /0 m32, DE /0 m16
    XP_FIMUL,      // DA /1 m32, DE /1 m16
    XP_FICOM,      // DA /2 m32, DE /2 m16
    XP_FICOMP,     // DA /3 m32, DE /3 m16
    XP_FISUB,      // DA /5 m32, DE /5 m16
    XP_FISUBR,     // DA /4 m32, DE /4 m16
    XP_FIDIV,      // DA /7 m32, DE /7 m16
    XP_FIDIVR,     // DA /6 m32, DE /6 m16
    XP_FCOM,       // D8 /2 m32, DC /2 m64, D8 D0+i, DC D0+i
    XP_FCOMP,      // D8 /3 m32, DC /3 m64, D8 D8+i, DC D8+i
    XP_FUCOM,      // DD E0+i
    XP_FUCOMP,     // DD E8+i
    XP_FBLD,       // DF /4 m80 (BCD yukle)
    XP_FBSTP,      // DF /6 m80 (BCD store+pop)
    XP_FSTSW,      // 9B DF E0 (AX) | DD /7 m16 (mem)
    XP_FSTCW,      // 9B D9 /7 m16
    XP_FLDCW,      // D9 /5 m16
    XP_FNOP,       // D9 D0
    XP_FWAIT,      // 9B
    XP_FCLEX,      // 9B DB E2
    XP_FINIT,      // 9B DB E3
    XP_FDECSTP,    // D9 F6
    XP_FINCSTP,    // D9 F7
    XP_FCHS,       // D9 E0
    XP_FABS,       // D9 E1
    XP_FSQRT,      // D9 FA
    XP_FTST,       // D9 E4
    XP_FXAM,       // D9 E5
    XP_FSIN,       // D9 FE
    XP_FCOS,       // D9 FF
    XP_FSINCOS,    // D9 FB
    XP_FPTAN,      // D9 F2
    XP_FPATAN,     // D9 F3
    XP_FYL2X,      // D9 F1
    XP_FYL2XP1,    // D9 F9
    XP_F2XM1,      // D9 F0
    XP_FPREM,      // D9 F8
    XP_FPREM1,     // D9 F5
    XP_FRNDINT,    // D9 FC
    XP_FSCALE,     // D9 FD
    XP_FXTRACT,    // D9 F4
    XP_FLD1,       // D9 E8
    XP_FLDZ,       // D9 EE
    XP_FLDPI,      // D9 EB
    XP_FLDL2T,     // D9 E9
    XP_FLDL2E,     // D9 EA
    XP_FLDLG2,     // D9 EC
    XP_FLDLN2,     // D9 ED
    XP_FXCH,       // D9 C8+i
    XP_FFREE,      // DD C0+i
    XP_FFREEP,     // DF C0+i
    XP_FADDP,      // DE C0+i (STi+=ST0, pop)
    XP_FMULP,      // DE C8+i
    XP_FSUBP,      // DE E8+i (STi-=ST0, pop)
    XP_FSUBRP,     // DE E0+i
    XP_FDIVP,      // DE F8+i
    XP_FDIVRP,     // DE F0+i
    XP_FCOMPP,     // DE D9
    XP_FUCOMPP,    // DA E9
    XP_FCOMI,      // DB F0+i (EFLAGS)
    XP_FCOMIP,     // DF F0+i
    XP_FUCOMI,     // DB E8+i
    XP_FUCOMIP,    // DF E8+i
    XP_FCMOV       // DA C0/CE/D0/D8/E0/E8/F0/F8+i; cc alaninda (x86 cc sira)

};

struct MemOp {
    bool present = false;
    int  base = -1, idx = -1, scale = 0;
    long long disp = 0;
    bool riprel = false;      // x64 rip-relative
    bool absimage = false;    // x86 mutlak, image araliginda -> base+rva'ya cevrilir
    u64  absval = 0;
};

struct Insn {
    XOp op = XP_UNKNOWN;
    u32 pc = 0, len = 0;
    int sz = 4;               // 1,2,4,8
    int r1 = -1, r2 = -1;
    u64 imm = 0; int immsz = 0;
    int cc = 0, alu = 0, shi = 0, ud = 0;
    int rep = 0;              // 0.9.0: 0=yok 1=rep 2=repe/repz 3=repne/repnz
    int seg = 0;              // 0.9.0: 0=yok 4=FS 5=GS (Intel segment sirasi)
    MemOp mem;
    u64 target = 0;           // jmp/jcc/call hedefi (VA)
    std::string text;         // okunur gosterim (log icin)
};

Insn disasm(const u8* p, int maxlen, bool is64, u32 pc, u64 imagebase, u32 imagesize);

// ---------------- Lifter ----------------
struct VFn {
    u32 rva = 0, size = 0;
    std::string name;
    bool ok = false;
    std::string why;
    std::vector<u8> plain;          // duz bayt-kod (sifreleme son adimda)
    std::vector<std::pair<u32, u32>> fix;   // (bc offset, hedef bc-ic)
    std::vector<std::string> notes;
    std::vector<u32> str_refs;      // .rdata string baslangic RVA'lari
    std::vector<std::pair<u32,u32>> str_sites; // 0.8.1: (plain-ofset, hedef RVA) — kopya yonlendirme
    u32 retimm = 0xFFFFFFFF;        // x86 stdcall ret imm16
};

// lifter: fonksiyonun makine kodunu VM bayt-koduna cevirir.
// junk_level: 0=kapali, 2=mutation junk; junk_seed: deterministik uretim
// pad_terminates: 0.4.1 — true: ret sonrasi dolgu (nop/int3) govdeyi bitirir
// (tarayici fonksiyonlari; komsuya tasma korumasi). false: MUTANT girdi —
// mutasyon junk'i dolgu benzeri bayt uretebilir; yuruyus kesin boyuta kadar
// devam eder, bilinmeyen opcode sessiz kisalma YERINE sesli hata verir.
VFn lift_function(const u8* code, u32 rva, u32 size, bool is64,
                  u64 imagebase, u32 imagesize, bool allow_call,
                  u32 rdata_rva, u32 rdata_size, int junk_level, u32 junk_seed,
                  bool pad_terminates, bool region_mode, u32 perm_seed = 0,
                  bool antidebug = false);   // 1.2.0-A8: OP_CHKRET yayimi

// ---------------- Mutasyon cekirdegi (0.3.0) ----------------
// VMProtect "Mutation" tipinin yerli uygulaması: fonksiyon makine
// kodunda kalir; talimat ikamesi + canlı-register analizi + JMP kapıları
// ile yeniden uretilir. Tum ikame/junk formlari aynı anda lifter-guvenli
// tutulur (Ultra = mutasyon + sanallastirma aynı akistan beslenir).
struct MutStats {
    u32 subst = 0, junk = 0, gates = 0;
    u32 orig_bytes = 0, new_bytes = 0;
    u32 nblocks = 0, ninsn = 0;
    u32 dead_spots = 0;    // junk sikistirilan olumlu nokta
};

struct MutFn {
    bool ok = false;
    std::string why;
    std::vector<u8> code;      // mutasyonlu native kod (base_rva tabanli)
    MutStats st;
    std::vector<std::string> notes;
    bool region_tail = false;  // 0.5.0: bolge kipi — sona region_end E9 eklendi
    // 0.8.0 SEH: prolog yigin-ayarlama haritasi (x64 .vmpx UNWIND_INFO)
    // kind 0=push reg (reg), 1=stack alloc (val bayt). off = cikis ofseti.
    struct MUW { u32 off; u8 kind; u8 reg; u32 val; };
    std::vector<MUW> uw;
    bool uw_ok = true;
    u32 prolog_out = 0;
};

// strength: 1=hafif 2=normal 3=agir (ikame/junk/kapi olasiliklari)
// base_rva: uretilen kodun yerleştirileceği RVA (dis cagri/riprel görecleri
// buna göre hesaplanir; M modunda iki geçişte çağrılır: ölçüm + gerçek)
MutFn mutate_function(const u8* code, u32 rva, u32 size, bool is64,
                      u64 imagebase, u32 imagesize, bool allow_call,
                      int strength, u32 seed, u32 base_rva, bool region_mode,
                      u32 prolog_size = 0);

// ---------------- Stub ureteci ----------------
// x64: 15 reg push + ctx + call vm_entry(RDI) + geri
// x86: pushad + ctx + push ctxptr + call vm_entry(cdecl) + popad + ret[imm16]
std::vector<u8> build_stub_x64(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len,
                               u32 xrt_entry_rva, u32 cfg_rva, u32 cont_rva,
                               u32 perm_seed = 0, u32 vm_id = 0, int ksadv = 0,
                               int regsenc = 0);   // 1.2.0-A9: Encrypt Registers
std::vector<u8> build_stub_x86(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len, u32 retimm,
                               u32 xrt_entry_rva, u32 cfg_rva, u32 cont_rva,
                               u32 perm_seed = 0, u32 vm_id = 0, int ksadv = 0,
                               int regsenc = 0);   // 1.2.0-A9: Encrypt Registers
// 0.5.0: M-govdesi onu runtime kapisI + gecikmeli import thunk'lari
std::vector<u8> build_mgate_x86(u32 gate_rva, u32 xrt_entry_rva, u32 cfg_rva, u32 body_rva);
std::vector<u8> build_mgate_x64(u32 gate_rva, u32 xrt_entry_rva, u32 cfg_rva, u32 body_rva);
std::vector<u8> build_thunk_x86(u32 thunk_rva, u32 resolve_rva, u32 cache_rva,
                                u32 dll_hash, u32 name_hash, u32 iat_rva);
std::vector<u8> build_thunk_x64(u32 thunk_rva, u32 resolve_rva, u32 cache_rva,
                                u32 dll_hash, u32 name_hash, u32 iat_rva);
// 0.7.0: SDK lisans API yamasi (isaret blogu -> lisans dispatch)
std::vector<u8> build_api_stub_x64(u32 site_rva, u32 fnid, u32 lsd_rva,
                                   u32 sdk_entry_rva, u32 span);
std::vector<u8> build_api_stub_x86(u32 site_rva, u32 fnid, u32 lsd_rva,
                                   u32 sdk_entry_rva, u32 span);
// 0.7.0: XRT lisans dispatch ofsetleri
// (gen_xrt_blob.py XRT_BLOB*_SDK_OFF uretir)
// 0.5.0: XProtect Runtime blob'u (xrt_core.c'den uretilir)
extern const unsigned char XRT_BLOB64[];
extern const unsigned char XRT_BLOBX86[];
extern const int XRT_BLOB64_LEN;
extern const int XRT_BLOBX86_LEN;
extern const u32 XRT_BLOB64_ENTRY_OFF;
extern const u32 XRT_BLOB64_RESOLVE_OFF;
extern const u32 XRT_BLOBX86_ENTRY_OFF;
extern const u32 XRT_BLOBX86_RESOLVE_OFF;
// 0.6.0: LZMA paket acici (xrt_unpack) blob ofsetleri
extern const u32 XRT_BLOB64_UNPACK_OFF;
extern const u32 XRT_BLOBX86_UNPACK_OFF;
// 0.7.0: lisans dispatch (xrt_sdk_entry / xrt_sdk_entry86)
extern const u32 XRT_BLOB64_SDK_OFF;
extern const u32 XRT_BLOBX86_SDK_OFF;
// 1.2.2-A20: xrt blob .bss statikleri icin SIFIR dolgu — gen_xrt_blob.py
// gercek bss extent'ini uretir (XRT_BLOB*_BSS_END); XRT_BSS_PAD minimum
// dolgudur (yoksa VR xvr_* statikleri cfg blokunu ezer).
#define XRT_BSS_PAD 0x200
extern const u32 XRT_BLOB64_BSS_END;
extern const u32 XRT_BLOBX86_BSS_END;

// ---------------- 0.6.0: Paketleme (cpPack) + strip ----------------
// LZMA1 (end-mark) ile sikistirir; props 5 bayt + sozluk boyutu doner.
// Tum akislar AYNI props ile sikistirilir (referans: tek
// LzmaDecodeProperties cagrisi).
bool lzma_compress(const u8* in, u32 inlen, u32 dict,
                   std::vector<u8>& out, u8 props[5]);
// EP redirect stub'lari (xrt_unpack cagirir, OEP'ye doner)
std::vector<u8> build_packstub_x64(u32 stub_rva, u32 unpack_rva, u32 cfg_rva, u32 oep_rva);
std::vector<u8> build_packstub_x86(u32 stub_rva, u32 unpack_rva, u32 cfg_rva, u32 oep_rva);
// cpPack ana adimi: bolumleri paketle, .vmp1 kur, EP'yi yonlendir,
// dosyayi sikistir. donus 0=tamam (pack_rva), 1=red (err)
int  do_pack(PEFile& pe, u32 cfg_rva, u32 unpack_rva,
             std::vector<std::string>& log, u32& pack_rva_out,
             u32 sectcrypt, u64 ck0, u64 ck1, std::string& err,
             bool resprot = false);   // 1.2.0-B3: cpResourceProtection
// cpStripFixups: .reloc dizinini kaldirir + ASLR bayraklarini temizler
bool strip_fixups(PEFile& pe, std::vector<std::string>& log);
// cpStripDebugInfo: debug dizini + COFF sembol tablosunu kaldirir
bool strip_debug(PEFile& pe, std::vector<std::string>& log);

// ---------------- Orkestrasyon ----------------
struct ManFn {               // 0.4.1: MANUEL fonksiyon (UI Add Function Base/End)
    u32 rva = 0, size = 0;   // Base ve End-Base (kesin boyut — tarayici tahmini degil)
    int  ty = 0;             // 0=V 1=M 2=U
    std::string name;        // log/dokumante icin (bos olabilir)
    bool is_region = false;  // 0.5.1: YALNIZ SDK isaretleri bolgedir (stub ret
                             // yerine region sonuna jmp). Kullanici Add Function
                             // TAM fonksiyondur -> false (0.5.0'da ayirt
                             // edilmiyordu; tum manuel VM stub'lari region
                             // kipinde uretiliyordu -> ret yerine jmp -> crash).
};

struct Options {
    int  level = 1;            // LEGACY 0.2.0: 1=Virt 2=UltraVirt+VMjunk (ftypes yoksa U fallback)
    int  default_type = 0;     // 0.3.0: 0=Virtualization 1=Mutation 2=Ultra (ftypes disi varsayilan)
    std::map<std::string,int> ftypes;  // 0.3.0: fonksiyon -> tip (anahtar opt.funcs formatıyla aynı)
    int  mut_strength = 2;     // 0.3.0: mutasyon gucu 1..3
    bool antidebug = false;
    bool checkvm = false;     // 1.1.0-A7: cpCheckVirtualMachine -> K7 CPUID
    bool kerneldbg = false;   // 1.2.2-A15: cpCheckKernelDebugger -> K5+K6 (bit2)
    bool vm_adv = false;      // 1.2.0-B1: VirtualMachineType vtAdvanced (VM_KSA)
    int  vmn = 1;             // 1.2.0-B1: mult-VM instance sayisi (1..8)
    bool debugmode = false;   // 1.2.0-B5: cpDebugMode — dolgu INT3 (0xCC)
    bool rsrcprot = false;    // 1.2.0-B3: cpResourceProtection
    bool vfiles = false;      // 1.2.0-B4: cpVirtualFiles (faLoad bundler)
    std::vector<std::string> vfile_paths;  // 1.2.0-B4: gomulu dosyalar
    bool vreg = false;        // 1.2.2-A17: cpVirtualRegistry (UO ftRegistry 1:1)
    std::vector<std::string> vregs;        // "HIVE\\Path:type:name=HEX|@file"
    bool strenc = false;
    bool memprot = false;
    bool mpveh = false;    // 1.2.2-A11: memprot VEH tamper-kill gate (cfg[0x09])
    bool vmenc = true;
    bool vmregs = true;   // 1.2.0-A9: Encrypt Registers (cpEncryptRegs) — VM register dosyasi bellekte sifreli
    std::vector<std::string> funcs;   // isim ya da rva(hex) listesi; bos -> hepsi uygun olanlar
    bool all = false;
    std::vector<ManFn> manual;        // 0.4.1: kesin {rva,boyut,tip} listesi — tarayici adayina bakilmaksizin derlenir
    // --- 0.5.0: runtime katmani + import korumasi + SDK ---
    bool rt_selfcrc = false;   // Loader CRC: motor kodu self-CRC
    bool rt_textcrc = false;   // Loader CRC: .text sayfa CRC (reloc-atlamali)
    bool rt_filecrc = false;   // disk dosyasi CRC
    bool rt_msg     = true;    // runtime hata: MessageBoxA
    bool rt_exit    = true;    // runtime hata: ExitProcess
    bool iat_prot   = false;   // 0.5.0 DENEYSEL: import (IAT) thunk korumasi
    bool sdk_scan   = true;    // SDK isaretlerini tara (VMProtect davranisi)
    bool sdk_only   = false;   // yalniz SDK/manual bolgeleri koru
    // --- 0.6.0: paketleme + PE temizligi (VMProtect cp* bayraklari) ---
    bool pack        = false;  // cpPack: LZMA paketleme (.vmp1 + EP redirect)
    bool sectcrypt   = false;  // 0.8.0 SectionCryptor: pakli akislari CFB-64 sifrele
    bool strip_fixups = false; // cpStripFixups: .reloc kaldir + ASLR temizle
    bool strip_debug  = false; // cpStripDebugInfo: debug dizini + COFF sembol
    // --- 0.7.0: lisans (RSA serial + HWID + watermark; cpIncludeWatermark) ---
    std::string lic_pubkey;    // 512 hex (256B modulus BE); bos = lisans yok
    std::string lic_prodcode;  // 16 hex (8B urun kodu); pubkey varken zorunlu
    std::string lic_watermark; // watermark metni (FNV-64 gomulur)
    // --- 1.2.2-A13: cpIncludeWatermark — UO Watermark::Compile 1:1 gomulmesi ---
    // Deger: hex dizisi ("5850726F.."); hex olmayan karakter = JOKER (maske 0,
    // her kopyada yeniden rastgelelenir). Motor IC watermark (surum imzasi)
    // her derlemeye gomulur; wm_values = kullanici watermarklari.
    std::vector<std::string> wm_values;
    u32 lic_builddate = 0;     // 0xYYYYMMDD; 0 = derleme gunu (2026-11-09 sabiti)
};

struct FnInfo {
    u32 rva = 0, size = 0;
    std::string name;
    bool selected = false;
    bool virtualized = false;
    bool exported = false;
    std::string note;
};

// koruma ana isi; log satirlarini log vektorune birikirir
int protect(const std::string& in, const std::string& out, const Options& opt,
            std::vector<std::string>& log);

// yardimcilar
std::string hexs(const u8* p, int n);
std::string hex32(u32 v);
const char* regname(bool is64, int enc);

extern const unsigned char VM_BLOB64[]; extern const int VM_BLOB64_LEN;
extern const unsigned char VM_BLOBX86[]; extern const int VM_BLOBX86_LEN;
extern const u32 VM_BLOB64_ENTRY_OFF;   // blob icinde vm_entry ofseti
extern const u32 VM_BLOBX86_ENTRY_OFF;
