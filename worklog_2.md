# Worklog_2 — XProtect Projesi (devam kaydi)

> Bu dosya, worklog.md (Worklog 1) tasdigi icin acildi (54KB / ~900 satir).
> Worklog 1'in ozeti asagida; bu oturumdan itibaren kayitlar BURAYA yazilir.

## Worklog 1 ozeti (Task 1-19, surum gezbisi)

| Task | Surum | Oz |
| --- | --- | --- |
| 1-4 | pre-0.1 | VMProtect 3.5.1 kaynak analizi; Test.exe sanallastirma zinciri (zig); wine kurulumu; 13 kok-hata (BUGFIX #1-#13: retimm u16, .reloc ezme, x86 64-bit key, SIB, pushmap...) |
| 5-9 | 0.1.0-0.3.0 | Win32 UI portu, Config_info, mutasyon cekirdegi (V/M/U tip sevkı, liveness, ikame+JMP) |
| 10-14 | 0.4.0-0.4.3 | UI tam kapsam (PDBScope, Manual Address), ULTRA manuel gercek, beyaz-ekran fix, sanal listview, Mutation x86 allow_call fix |
| 15-17 | 0.5.0-0.5.1 | XRT runtime katmani (PEB gezinme + FNV-1a + Loader CRC), SDK isaretleri, IAT deneysel, PIC duzeltmeleri; pipeline regresyon fix |
| 17b | 0.6.0-0.6.2 | LZMA pack (XPK1), cpStripFixups/StripDebugInfo; XCFG rezerv tasmasi fix (#14) |
| 17c | 0.7.0 | RSA lisans + HWID + watermark + SDK-40 API + #2 loaderCRC-stripFixups fix |
| 18 | 0.8.0 | VM derinlestirme: CFB crypt_command/key, polimorfik opcode perm (Fisher-Yates seed=RVA), SEH kaydi, SectionCryptor; ANTIDBG opcode YENI (perm bug'li) |
| 18b | 0.8.1 | KRITIK fix: ANTIDBG/STRDEC ham push'lari perm tablosundan gecirme; STRDEC format birlestirme. Windows debugger karsi koruma dogrulandi (kullanici: "0.8.1 calisiyor") |
| 18c | 0.8.2/0.8.3 | CE VEH yakalama denemeleri: tam batarya (QIP/guard/ntdll-CC/TF-probe) — BASARISIZ: x86 CONTEXT ofsetleri yanlis (EFLAGS=0xB8!), TF-probe dispatch carpismasi, wine yigin-baglam kaybi -> temiz oyun coktu |
| 19 | 0.8.4 | 0.8.1 tabani + SADECE K1 (giris 0xCC) + K2 (TF bayragi). 0.8.2/0.8.3 bataryasi ATILDI. Kullanici dogruladi: temiz oyun ✓, Windows debugger ✓, VEH debugger ✗ (hwbp yakalanmiyor) |

Kalici dersler (Worklog 1'den):
- symlinks TAM YASAKLI (bind-mount kullan); Xvfb ayni komut icinde baslat
- worklog'un REPO kopyasinda PAT maskele (GitHub secret-scanner)
- encoder/interpreter format eslesmesi (perm tablosu, STRDEC 2xu32) — bayt-bayt kanitla
- temiz-oyun guvenligi: istisna-dispatch devreye sokan anti-debug kontrolleri yorumlayici cerceveleriyle carpisir

---

## Task 20 — 0.8.5: CE VEH debugger hwbp yakalama (K3: DRx)
Agent: main (Z.ai) | Tarih: 2026-11-11 (oturum 9)

KULLANICI RAPORU (0.8.4 testi): temiz oyunda damage NORMAL ✓; CE Windows
debugger F5 -> damage DURDU ✓; CE VEH debugger -> damage devam ✗.
SORULAR x1-x5: UniversalObfuscator VEH'i algiliyor mu? eksikler gecirilsin mi?
VM/M/U seviye farki? hangi surum en stabil? simdi ne yapmali?

1) x1/x2 ANALIZ (upload/universalObfusPublicSrc*.zip + scripts/uosrc2):
   runtime/core.cc:764 PEB.BeingDebugged; :771 TF+__rdtsc __try/__except
   (yutulan tek-adim=debugger; istisna-baglamindan Dr0-3 okuma = VEH hwbp
   yakalayicisi); :785 NtQueryInformationProcess ProcessDebugPort/
   DebugObjectHandle (syscall yolunda "|| debug_object==0" tuhafligi
   alinmadi — temiz surecte yanlis-pozitif); :796+ kernel debugger
   (driver). loader.cc:2116 ntdll API 0xCC, :2246 PAGE_GUARD,
   :2510 TF-probu. EKSIK IMIZ: yalniz DRx/hwbp (kullanicinin senaryosu).
2) 0.8.5 TASARIM (kullanici doktrini: "sadece o kadar"):
   K3 = GetThreadContext(GetCurrentThread, CONTEXT_DEBUG_REGISTERS)
   -> DR0|DR1|DR2|DR3 != 0 -> zehir. core.cc:778 semantigi 1:1 fakat
   orijinalin istisna-baglam formu YERINE senkron API (0.8.2/0.8.3 cokme
   dersi: TF-probe + VEH yazimi dispatch ile carpisir). Yardimcilar
   xa_fnv_a/w, xa_module (DllBase-saglamlik), xa_export, xa_call4/86
   — 0.8.3'ten birebir alindi; K3 OP_ANTIDBG'ye K1/K2'den sonra eklendi
   (XProtectUI_Source + CPlusPort_Source vm_core.c). Surum 0.8.5.
3) TESTLER:
   - vm blob yeniden derlendi (vm64.bin 9564B, vmx86.bin 13634B; PIC
     kapisi temiz) + XProtectUI.exe (x64+x86) zig ile.
   - x86 Unicorn (OYUN MIMARISI PE32) 8/8 TAMAM: clean TEMIZ;
     beingdbg/ntglobal/kapicc/tf POISON; drx (DR0=0x004D7610) POISON;
     drx0 TEMIZ; drxfail TEMIZ. (unic_drx_x86.py YENI arac; sahte
     kernel32: LDR listesi + export tablosu + GetThreadContext stdcall
     taklidi — ret 8'e +4 eip popu dahil. init_rsp = STK tepesi - 0x8000:
     natcall cerceveleri icin headroom.)
   - x64 wine 8-modlu matris: clean/ceveh/gameveh TEMIZ; sw/tfstep/peb
     ZEHIR (0xDEADBEEF). DRx satirlari: wine SetThreadContext/resume
     DRx-apply FLAK (server kopyasi ARMALI, canli thread bazen 0 —
     main-verify vs worker-pre DIAG kaniti; pipe/redirect/isinma degisken
     degil). ISCI PROB UYARISI: is-parcaciginin KENDI GetThreadContext'i
     DRx durumunu bozuyor (probe'lu 0/3 vs probesuz 3/3) — harness
     probesuz busy-spin + main hw-handle verify. ARMALI yakalandiginda
     K3 ZEHIR (k3_drx_kanit.txt + worker-try1 dr0=0x3FFD9268 ->
     r=-559038737). Gercel Windows'ta apply deterministik (OS garantisi).
   - drprobe.c: wine DRx round-trip tezgahi (self-set + suspended-child
     iki yol da calisiyor — wine DRx makinesi saglam, apply-timing flak).
   - R5 ULTIMATE (V+M+U sdkonly + pack + sectcrypt + loadercrc + filecrc
     + stripfixups): RCODE=42 (a=78 b=0x16f9 c=0x1221 d=81) ✓
     NOT: zig CRT'si TLS callback ekler -> pack TLS'li RED rc=4 (0.6.0
     kurali) — test-prep'te TLS data-dir temizlendi (uygulama TLS kullanmaz).
   - R5-tamper (.vmp1 tek-bayt): RCODE=117 duru-ret ✓
   - SELFTEST OK (funcs=0 baseline) ✓
   - metin2 d7610 statik: seed=0xD7610 bc_rva=0x545548 bc_len=546
     bc[0]=0x0A->0x1E=ANTIDBG ✓ (bc_len 0.8.1 parite)
4) PAKET: XProtect_0.8.5.zip 72 dosya (md5 c3862d6ae0a83ad9a6d2e4582c4c6c59)
   -> download/XProtect/ + download/ + repo releases/. CHANGELOG_0.8.5.md
   + README_0.8.5.txt. Yeni arac: test/unic_drx_x86.py, test/drprobe.c,
   kanit_085/ (x64_wine_matris_085_final.txt + x86_unic_drx_085.txt + ...).
5) SURUM notu: CE VEH "bos bagli" hala bilincli yakalanmaz (0.8.4 dersi);
   hwbp/giris-CC/tek-adim kapali.

Stage Summary:
- 0.8.5 teslim: 0.8.4 + K3. Kullanici testi bekleniyor: temiz oyun
  (cokme YOK) -> Windows debugger F5 (DURDU) -> CE VEH debugger F5/hwbp
  (DURDU — YENI). Ceşitli senaryolar icin kapsam tablosu README_0.8.5.txt.
- Siradaki: kullanici VEH testi; 0.9.0 (memprot paketi / TLS-packer)
  kapsam karari.

---

## Task 21 — 0.9.0-DeepVM Faz A: UniversalObfuscator VM derinligi portu (Tam EFLAGS + komut kapsamı)
Agent: main (Z.ai) | Tarih: 2026-11-11 (oturum 10)

KULLANICI RAPORU (0.8.5): UC TESTI TAM — metin2 d7610 ULTRA, Check Debugger
Windows debugger + VEH debugger ikisini de yakaladi: "Check Debugger windows
debuggeri ve Veh i başarıyla algıladı teşekkürler". TALIMAT:
"şimdi UniversalObfuscator dan bunu geçirelim" (deep VM port).

1) KAYNAK TARAMASI (scripts/uobf/src1/vmp/core/intel.cc — 31.493 satir):
   VMProtect lifter'inin (CompileToVM, intel.cc:9744) mimarisi cozuldu:
   - Yigin makinesi + NOR/NAND fonksiyonel-tam primitifler
   - `if (rand() & 1)` esdeger-form dekompozisyonu (B-fazi mutasyonu lifter
     icine gomulu — fl_ sabitleri: CF=0x0001 PF=0x0004 AF=0x0010 ZF=0x0040
     SF=0x0080 OF=0x0800, regEFX'de tasiyor)
   - AddCorrectFlagSection/AddCombineFlagsSection/AddExtractFlagSection
   XProtect karsilastirmasi: 44 VM op, 4 bayrak (CF/ZF/SF/OF) — PF/AF yok
   (cond_eval CC_P hep 0 donduruyordu!), 0F uzantilari RED.
   ONCEKI OTURUMUN YARIM KALANI: engine.hpp'ye XP_* enum tanimlari eklenmis
   (02:50) ama disasm/lift/interpreter 0 satir — implementasyon bu oturumda.

2) 0.9.0-DEEPVM FAZ A IMPLEMENTASYONU (0.8.5 tabani KORUNDU, xb090 kopyasi):
   a) vm_opcodes.h: VM_OPN 0x2C -> 0x3B; 15 yeni op (PUSHF/POPF/SAHF/LAHF/
      SETFLAG/MUL_R/DIV_R/BT_X/SHLD/SHRD/LOOP/JECXZ/XADD/STR/IMUL_RM);
      FPF/FAF/FDF bayrak bitleri; MEMF_SEG/MEMF_DISP_SEG; ALU_ADC/ALU_SBB.
   b) vm_core.c: do_alu_c (cin parametreli; AF = kesin nibble tasiyicisi,
      PF = LSB-8 paritesi, ADC/SBB carry-in); cond_eval gercek parity;
      do_shift (ROL/ROR diger bayraklari KORUR — eski kod sifirliyordu;
      OF n==1; PF); PUSHF/POPF EFLAGS imaji (bit1=1, IF=1);
      TEB yakalama scratch[4] (x86 fs:[0x18] / x64 gs:[0x30]);
      KOK-FIX: IDIV x64 dd=YALNIZ RDX (RAX yok sayiliyor — cqo sonrasi
      bolum 0/cop) -> idiv128 (128/64 bit-dongu); x86 IDIV EDX:EAX ->
      div64_32; i386 freestanding __udivmoddi4 YASAK (blob linki).
   c) engine_disasm.cpp: 0x64/0x65 seg yakalama (yutulmaz oldu), F2/F3 rep
      yakalama, GRP3 MUL/DIV, 0F A3/AB/B3/BB + 0F BA (BT ailesi),
      0F A4/A5/AC/AD (SHLD/SHRD), 0F C0/C1 (XADD), E0-E3 (LOOP/JECXZ),
      9C/9D/9E/9F (PUSHF/POPF/SAHF/LAHF), F5/F8/F9/FC/FD (SETFLAG),
      A4-A7/AA-AF (string), 0F AF mem formu.
      KOK-FIXLER (0.8.x'ten kalıtılan gizli buglar):
      - 66 B8 imm16: 4 yerine 2 bayt okunmaliydi (akis desync!)
      - 66 C7 imm16 (mem+reg formu): ayni
      - 88/8A is8=true eksik: AH/BH/CH/DH (rm kod 4-7) RSP..RDI diye
        cozuluyordu (mov %sil,%%ah -> RSP'nin dusuk baytina yaziyordu!)
      - 67 E3 jecxz: hedef pc+2 yerine pc+i (onekli formda pc+3)
   d) engine_lift.cpp: yeni XP -> OP emitleri; MEMF_SEG emem'i (segmode'da
      disp HAM — TEB-relative rva'ya cevrilemez); LOOP/JECXZ fixup.
   e) engine_mut.cpp: ud_of'a yeni komutlarin uses/defs (muhafazakar):
      MUL/DIV R(0)R(2)RW(0)RW(2), BT CF+RW(ud!=0), XADD iki taraf RW,
      STR ESI/EDI/ECX/EAX, LOOP/JECXZ RCX, PUSHF/POPF/SAHF/LAHF/SETFLAG
      FFLAG. (0.8.5'te bu komutlar lifter RED oldugu icin mutator hic
      gormuyordu — default:break junk canli degeri eziyordu.)

3) TEST KANITLARI (kanit_090/):
   - test_deepvm.c (14 test fonksiyonu, ham __asm__): ADC/SBB zinciri,
     PUSHF/POPF/LAHF/SAHF, CLC/STC/CMC+JCC, MUL/DIV dword, BT ailesi
     reg+imm, SHLD/SHRD imm+CL, LOOP/JECXZ, XADD, REP movsb/stosb/scasb
     +STD/CLD, FS/GS TEB, PF/JP/JNP, IMUL mem (0F AF), 8-bit mul/div,
     izole mul/div.
   - x64 wine (V, fonksiyon-basi izole): 13/13 BIREBIR ESIT (rc=42).
   - x86 Unicorn (oyun mimarisi, unic_deepvm_x86.py YENI: korumali PE'nin
     stub+VM'ini sahte TEB/PEB ile kostirir, fs:[abs] siteleri hook'lar;
     cdecl yigin duzeltmesi): V 14/14 ESIT + U 14/14 ESIT (1 duru-RED:
     t_loop mutasyon fixup — bilinen acik, guvenli davranis).
   - R5 ULTIMATE: rc=42 "OK sdk_print 78 OK hepsi dogru" ✓
   - R5-tamper (.vmp1 tek-bayt): rc=117 duru-ret ✓
   - SELFTEST OK (Xvfb ayni komut icinde — kalici kural) ✓
   - metin2 d7610 ULTRA+antidebug statik: seed=0xD7610 bc_rva=0x547C28
     bc_len=541, bc[0]=0x03 -> itab -> 0x1E ANTIDBG ✓ (perm tablo boyutu
     degistigi icin bc byte'lar degisti — semantik ayni)

4) BILINEN ACIKLAR (Faz B/C icin):
   - mutator'un yeni-komut uzunluk/fixup tablosu (t_loop U-modu duru-RED)
   - IR-ustu mutasyon (B1-B4) ve obfiske handler (C1-C3) — UniversalObf.
     NOR/NAND dekompozisyonu lifter'a gecirilecek
   - FPU (A4): fld/fstp/fadd/fmul — ctx st[8] genislemesi gerekli
     (VMOFF/VMSIZE + stub sabitleri degisir) — sonraki oturum

5) NOT: wine x86 calistirma hala imkansiz (wine-root wow64'suz; Debian
   wow64 sessiz oluyor) — x86 dogrulama Unicorn diferansiyeliyle (kanit).
   /tmp/my-project (wine-root + prefix) sandbox resetinde SAG KALDI.

## Task 22 — 0.9.5-DeepVM Faz B: IR-katmani mutasyonu + B4 build-nonce

**Kapsam (UniversalObfuscator B1-B4 portu):**
- engine_lift.cpp (+608): IrNode ara-temsili — irm_decode_node / irm_memlen /
  irm_ncall_clobber / irm_uddef / irm_finish. Junk enjeksiyonu IR duzeyinde
  (uses/defs'ten turetilir; junk canli degeri bozamaz).
- engine_main.cpp (+30) + engine_util.cpp (+24): B4 build-nonce —
  perm_seed = XP_PERM_NONCE ^ fn_rva (handler-shuffle dahil). Varsayilan 0 =
  0.9.0 davranisi. XPROTECT_PERM_NONCE env ile sabitlenir.
- engine_mut.cpp (+21): LOOP/LOOPE/LOOPNE (E0-E2) + JECXZ (E3) rel8 yeniden
  kodlama + kind-2 dahili rel8 fixup; tasarsa sesli duru-RED.
  **0.9.0'in bilinen acigi (t_loop U-modu duru-RED) kapandi.**
- engine.hpp (+5): IrNode yapisalari.

**Ders (kalici):** 0.9.x x64 stub yerlesiminde bc_rva imm32 @stub+91
(48 05 imm32). 0.8.1 script'i 92 okuyordu — 1 bayt kayma "bc bolumu
bulunamadi" diye gorunuyordu. kanit_095/static_ad_095.py duzeltilmis.

**Kanit (kanit_095/regress_095.txt, verify_095.py ile taze dogrulama):**
PASS=11 FAIL=0 — T1 SELFTEST OK; T2/T3 deepvm bayt-bayt; T4 R5 rc=42
(taze derle: sdkonly+pack+sectcrypt+loadercrc+filecrc+stripfixups);
T5 tamper rc=117; T6 ayni-nonce md5 esit + rc=42; T7a antidebug KAYIT;
T7b statik ANTIDBG: seed=0x9A5B6C83 bc_rva=0x40EA0 bc_len=50,
bc[0]=0x13 -> itab -> 0x1E. Sabit nonce: XPROTECT_PERM_NONCE=0x9A5B7C31.

**Arac (bu oturum): xguard v2 — NO-KILL kaynak koruyucu**
Kullanicinin zorunlu kurali: hicbir surec oldurulmez. Sadece kademeli
kisitlama: CPU >=%90 → renice 19 → taskset tek-cekirdek → kisa STOP/CONT
nefes-molasi. RAM >=%90 → renice → SIGSTOP (buzla; RAM %85 altina inince
SIGCONT). Sizinti tespiti: RSS >512MB ve 6 orneklem %25+ buyume → taskset+
renice. Hedef: toplam CPU'nun ve RAM'in en az %10'u hep bos. Korumali ata
zinciri (PID 1'e kadar) asla dokunulmaz. `xguard watch 3` arka plan;
`xguard ensure` oturum basinda; `xguard rg`; `xguard run --tmo T --mem M`.

**Ortam yeniden-kurulum kilavuzu (sandbox reset sonrasi, kalici kural 3):**
1. pip: `pip install ziglang pefile` (zig cc = PE derleyici, pefile = kanit)
2. wine-10.0 chroot: `bash /home/z/my-project/scripts/wchroot.sh <exe>` —
   script /home/z/my-project'u Z:\ olarak baglar; wineprefix
   /home/z/my-project/scripts/xb095w altinda KALICI (home korunur)
3. Xvfb: `setsid Xvfb :99 -screen 0 1024x768x24 &` (UI/protect kosulari icin,
   DISPLAY=:99; regress script'leri otomatik baslatir)
4. wine x86 calistirma IMKANSIZ (wow64'suz root-wine) — x86 dogrulama
   Unicorn diferansiyeliyle (unic_deepvm_x86.py)
5. VM blob yeniden-uretim: `bash build_vmblob.sh` (xb095 dizini; gcc-32
   chroot icinde; vm64.bin 16028B / vmx86.bin 23776B / vm_blob.cpp 206797B)
6. UI derleme: `bash build_ui.sh` (mingw x64+x86; cikti XProtectUI.exe +
   XProtectUI32.exe ~10 dk, xguard acikken -j2 guvenli)
7. GitHub: token /home/z/my-project/scripts/gh_token.txt (chmod 600)

**Sonraki faz (Faz C + A4):** C1-C3 obfiske handler (NOR/NAND dekompozisyonu,
UniversalObfuscator core/lift*), C2 VM-in-VM, A4 FPU (fld/fstp/fadd/fmul;
ctx st[8] genislemesi → VMOFF/VMSIZE + stub sabitleri degisir).
Paket: releases/XProtect_0.9.5.zip. Depo: 0.9.5 commit.

## Task 23 — 0.10.0-FazC (C1): VMP cmNor/cmNand atomik mantik dekompozisyonu

**Kapsam (UniversalObfuscator intel.cc AddRegistrAndValueSection/OrValueSection 1:1):**
- vm_opcodes.h: OP_NOR_RR=0x3B, OP_NAND_RR=0x3C (bayraksiz atomik);
  VM_OPN 0x3B -> 0x3D (tum bytecode yeniden-kodlanir — bilincli kirilim)
- vm_core.c: yorumlayici ~((r1|r2)) / ~((r1&r2)) — sz-maskeli, bayraksiz
- engine_lift.cpp: IR uzunluk tablosu + uses/defs (fwr YOK) + dekomposizyon:
  AND → NAND(NAND(a,b),NAND(a,b)) | NOR(NOR(a,a),NOR(b,b));
  OR → NOR(NOR(a,b),NOR(a,b)); sonrasina TEST r,r (SF/ZF/PF birebir geri;
  CF=OF=0, AF undef — logic op semantigiyle ozdes). Gecici-reg havuzu
  r9/r10/r11 push/pop sarimli (liveness'tan bagimsiz). imm formu sz<=4.
  Yogunluk ~%21 (pick60 x pick35).
- B3 junk-guvenligi: 0.9.5 IR uses/defs altyapisi sayesinde ek islem gerekmedi.

**Kanit (kanit_100/):**
- regress_100.txt: PASS=10 FAIL=0 — t_norchain YENI test fonksiyonu
  (and/or + jz/js flag-tuketimi): 14/14 bayt-bayt. R5 rc=42, tamper 117,
  nonce md5-ozdes+rc=42, statik ANTIDBG 0x1E (VM_OPN 0x3D).
- nor_census_100.log: nor_probe bc akisi op-uzunluklariyla yurundu
  (17 stub, 292 op) — OP_NOR_RR op-konumlarinda dogrudan gorundu
  (beklenti 6x0.6x0.35=1.3 ile uyumlu). probe_walk.py = kanit araci.

**Ders:** nohup arka-plan derlemesi ara-cagri temizliginde OLUYOR — agir
derlemeler foreground + timeout ile adim-adim kosulmali (LZMA/x64/x86
ayri cagrilar). xguard v2 izleyici tum derleme/regresyon boyunca aktif;
hici kisitlama tetiklenmedi (yuk dagilimi yavas-yavas artiyor).

**Sonraki (Faz C devam + A4):** C2 VM-in-VM (kendi VM'ini kendisi korur),
A4 FPU lifter (ctx st[8]; fld/fstp/fadd/fmul; VMOFF/VMSIZE+stub sabitleri).
Paket: releases/XProtect_0.10.0.zip. Depo: 0.10.0 commit.

## Task 24 — 1.0.0-UO: 0.9.0'a donus + UniversalObfuscator yigin-kapilari + oyun-cokmesi KOK-DUZELTMESI

Agent: main (Z.ai) | Tarih: 2026-11-11 (oturum 11)

KULLANICI RAPORU: 0.9.5/0.10.0 BOZUK — "korumaya aldığım oyun fonksiyonu
çalışınca crash veriyor oyun". TALIMAT: XProtect_0.9.0'a geri dön (en iyi
optimize sürüm), UniversalObfuscator'un BIREBIR aynısı yap, sinir yok.
xguard v3 istegi: saatlerce calisabilen izleyici.

1) xguard v3 (scripts/xguard): 2 cekirdek/4GB'ye kalibre; %10 RAM+CPU
   garanti bolgesi; merdiven renice->taskset->duty-cycle; kill YALNIZ
   5+ strike'lik tekrar-eden suclu (son care); korumali-ata zinciri;
   log rotasyonu; ic-dongu olurse dis kokpu yeniden baslatir; run
   --tmo (dahili bash-alarm — harici `timeout` sureci YOK) + --mem
   (ulimit). Kullanici uyarisi: "timeout gibi dongulere dikkat".

2) UO KAYNAK ANALIZI (uobf/src1/vmp/core/intel.cc 31.493 satir):
   VMProtect VM'i YIGIN-MAKINESI. cmAnd/cmOr/cmXor dogrudan komut DEGIL:
   hepsi cmNor/cmNand kapilarindan gecer (case cmAnd dal-1: Nor(inv,inv);
   cmOr dal-2: Nand(inv,inv); cmXor dal-1: Nor uclu zincir). Bayrak
   bolumleri de yiginda (EFX/EIX OR/AND-plane). 47x `rand()&1`
   esdeger-form.

3) 1.0.0 KAPI PORTU (0.9.0 tabani; 0.9.5/0.10.0 ozellikleri GERI ALINDI):
   - vm_opcodes.h: OP_NOR_ST=0x3B, OP_NAND_ST=0x3C, OP_POP_RP=0x3D
     (kismi-yazim pop = cmPop otRegistr size_); VM_OPN 0x3B->0x3E
   - vm_core.c: yigin kapilari (PUSHSZ slot, sz-maskeli, mantik-bayraklari
     do_alu AND yolu ile bayt-bayt); POP_RP (sz<8 ust-bayt koruma);
     AKIS-TASMA KORUMASI (ic >= bc_len -> duru-cikis)
   - engine_lift.cpp: g_push_r/g_gate/g_pop_rp/g_inv_r yardimcilari;
     XP_ALU'da and/or/xor reg-reg + reg-imm dekompozisyonu (tum sz);
     AND: inv(b),inv(a),NOR | OR: inv(a),inv(b),NAND | XOR: 12-op Nor
     zinciri (intel.cc dal-1 birebir). mem-formlari yerel ALU (konservatif).
   - 0.9.5/0.10.0 DERSI UYGULANDI: temp-reg havuzu YOK (r9/r10/r11
     push/pop cokme suphesi), IR-junk YOK, nonce YOK. Kapilar dengeli
     (2 push + kapi + pop), dugum-siniri ici; JCC hedefi op-siniri.

4) *** OYUN-COKMESI KOK-NUDENI BULUNDU (kullanici kanitli sinif) ***
   bc_census_100.py (yeni arac) ile metin2 d7610 bytecode'u UCTAN-UCA
   yurundu. BULGU: --add D7610:D766C bolge-siniri son ret 8'i (0xD766C)
   DIYARIDA birakir -> lift izi "pop ebp"de biter -> bytecode RET'siz
   (0.9.0-ref: bc_len=194 son-op=POP_R KANIT). VM ic-sinir kontrolu
   YOKTU: bc[bc_len] OOB bayti op diye cozulur (itab[garcop] stack-OOB)
   -> rastgele op. 0.9.0 SANS LIYDI (OOB benign); 0.9.5/0.10.0'da IR-junk
   + kapilar bc boyutunu degistirdi -> OOB bayt degisti -> COKME. Kapilar
   suclu degildi; kesik akis 0.8.5'ten beri hastaydi.
   FIX (iki katman): (a) lifter akis sonunu RET ile garanti eder
   (last_ret bayragi; bolge-kesigine yapay OP_RET); (b) interpreter
   ic >= bc_len -> duru-cikis. Fix sonrasi census: bc_len=215, 51 op,
   son-op=RET, NOR_ST=5, POP_RP=1 — YAPI-SAGLAM + KAPI AKTIF.

5) KANIT (kanit_100/, regress_100.sh): PASS=14 FAIL=0 —
   T1 SELFTEST OK; T2 x64 V bayt-bayt (6 yeni GATE testi: t_gate32
   and/or/xor+jz/js/jp; t_gate816 sz1/2; t_gate_zr xor r,r+ZF;
   t_gate_loop geri-dalis zincir-BASINA; t_gate_stack misafir-yigin
   basinci; t_gate_imm sinir-imm 0x80/0x8000/0x80000000);
   T3 x86 Unicorn V+U tam eslesme (oyun mimarisi PE32);
   T4 R5 ULTIMATE rc=42; T5 tamper 117; T6 md5-ozdes;
   T7 metin2 KAYIT + ANTIDBG 0x1E + census YAPI-SAGLAM.
   NOT: zig CRT TLS callback'i tekrar cikti -> test-prep'te TLS data-dir
   temizligi regress_100.sh'e gomulu (0.8.5 dersi kaliciyor).
   NOT2: T5 tamper .vmp0 yerine .vmp1 (stub) secmeli — 117 altin standardi.

6) VERSIYON: XPROTECT_VERSION 0.8.5 -> 1.0.0 (0.9.x'te unutulmustu).
   Paket: releases/XProtect_1.0.0.zip (md5 fe5e13da) + download/.
   0.9.5/0.10.0 zip'leri download/'tan SILINDI (geri cekildi).
   Depo: 1.0.0-UO commit (uo-full branch, 0.9.0 tabani).

7) xguard izleme-notu: genis grep 120s timeout yedi (kullanici uyarisi
   yerinde) — dar-erisim kullan. Tum derleme/regresyon xguard v3
   gozetiminde sorunsuz (hic kisitlama tetiklenmedi).

Sonraki: kullanici Windows testi (temiz oyun + debugger baterisi + damage);
A4 FPU lifter (ctx st[8]; VMOFF/VMSIZE + stub sabitleri) — UO tam parite
kalan tek buyuk blok; C2 VM-in-VM (roadmap).

## Task 27 — 1.2.0-B1: mult-VM/Advanced (rel32 dis-akis) + B5 debugmode [SURUYOR]

Agent: main (Z.ai) | Tarih: 2026-11-12 (oturum 12 — sandbox reset sonrasi)

ORTAM KURTARMA (kalici kural 3 uygulandi):
- Repo taze clone (gh_token.txt): son commit 6371bd4 (1.1.0 release, md5 30ae1447).
  Kullanici verdigi URL zip'i ile repo releases/ zip'i md5-es (30ae14474f1c...).
- wine chroot yeniden: setup_env.sh mantigi (apt-get download wine64 libwine
  wine-binfmt -> dpkg -x -> setup_wine_root.sh). IKI YENI DERS:
  (a) Debian wine 10.0 repack'te /usr/lib/wine/wineserver SHELL SCRIPT — chroot'ta
      /bin/sh bind EDILMEDIgi icin "could not exec wineserver". COZUM: script'i
      wineserver64 ELF ile ez (wine-root/usr/lib/wine/wineserver).
  (b) wchroot.sh'e PATH=/usr/lib/wine:/usr/bin:/bin export eklendi.
- pip: ziglang 0.17.1 + pefile + unicorn -> site_pkgs (kalici) + venv.
- gcc -m32 LINK icin CRT istiyor; blob uretimi -c + ham ld kullandigindan
  multilib GEREKMEDI (gcc -m32 -c vm_core.c OK; ld -m elf_i386 host).
- Xvfb sistemde sag. xguard v4 yazildi (pid watch; %1 marj / %99 kullanilabilir;
  kademeli renice->taskset->pulsing; kill yalniz 3+ strike + RSS>256MB son care).

BASLINE KANITI (a4fpu/, regress_base.sh — wine --cli ERKEN DONUYOR:
cikti dosyasi POLL edilmeli; regress_base.sh bekleme-dongulu yazildi):
- B1 R5 ULTIMATE (sdkonly+pack+sectcrypt+loadercrc+filecrc+stripfixups):
  RCODE=42 + "OK hepsi dogru" (r5_110_p.exe)
- B2 tamper .vmp1 tek-bayt: RCODE=117 (duru-ret altin standart)
- B3 metin2 d7610 U+antidebug: koruma OK (m2_110.exe; stub seed=0xD7610,
  bc_rva=0x54B868 bc_len=567 — 1.1.0 blob degisimiyle anchor kaydi;
  static_m2_090.py'in 0.9.0 itab bekleyisi icin 1.2.0 yeniden-yazimi yapilacak)

KRITIK BULGU: repo vm_core.c COMMIT-BOZUK (c->regsap[k]] — derlenemez;
1.1.0 derlemesi pre-generate vm_blob.cpp'den yapilmisti). regs[map[k]]
duzeltildi; x64+x86 blob yeniden uretim kanitlandi.

B1 KOD (vm_opcodes.h + vm_core.c + engine_lift.cpp + engine_stub.cpp +
engine_main.cpp + engine.hpp + xprotect_ui.cpp):
- OP_JMPEXT=0x41 (rva32; done=3, scratch[6]=rva), OP_JCCEXT=0x42 (cc rva32);
  VM_OPN 0x40->0x43. Lifte: disari JMP artik OP_JMPEXT (ncall+ret yerine —
  yigin temiz, x86 yaprak kipinde de calisir); disari JCC artik duru-RED DEGIL.
- Stub natgt kolu (done==3): rcx=base+scratch[6] -> RCX push_area slot'una
  (ctx+0x338) yazilir; pop'lar F'nin SON degerlerini geri koyar; jmp rcx.
  Donus adresi yiginda KALIR (hedef kendi ret-imm'ini temizler). rcx volatile
  ezmesi ABI-gecerli. x86: edx hesap -> pushad ECX slot (esp+SUB+0x1C) ->
  popad'da ecx=hedef -> jmp ecx.
- vtAdvanced (UO/VMP intel.cc VirtualMachineType 1:1): VM_KSA komut-
  sifreleyici (4-byte kaba periyot, baska sabit ailesi — VM_KS 8-byte'in
  kardesi); kip ctx scratch[5] (stub C6 84 24 F0 00 00 00 01 disp32-form);
  encoder opt.vm_adv ile ayni aile. CLI: --vmadv.
- mult-VM (VirtualMachineList semantigi): opt.vmn (CLI --vmn N, 1..8);
  vm_id = rva % vmn; ayni VM'in fonksiyonlari AYNI opcode haritasi
  (perm_seed = ((vm_id+1)*0x9E3779B9 ^ 0x51ED270B)|1) + AYNI anahtar-alani
  (decoder anahtar = stub-tasiyan ^ K2 ^ VM_VMK(vm_id); encoder ekey =
  base ^ VM_VMK(vm_id); VM_VMK(0)=0 -> vmn=1 bayt-bayt 1.1.0 uyumlu).
  vm_id ctx scratch[7] (stub C7 84 24 00 01 00 00 <id>).
- B5 debugmode (VMP pefile.cc:4792 birebir): opt.debugmode -> .vmp0 bosluk
  dolumu 0xCC (INT3). CLI: --debugmode.

## Task 27 devam — B2 TAM-LOADER (TLS+pack) + B5 debugmode — TAMAMLANDI

**B2: TLS callback'leri + cpPack birlikte (VMP tarzi defer-tasarim):**
- engine_pack.cpp: TLS-callback RED'i kaldirildi; her callback icin .vmp1
  icinde trampoline uretildi (push regs + pushfq; cfg state-byte kontrol;
  state=0 (TLS zamani) -> NO-OP ret; state=1 (EP zamani) -> jmp orijinal
  callback). Callback DIZISI .vmp1'e tasindi; TLS-dir AddressOfCallBacks
  guncellendi. EP pack-stub'ina callback-dongusu eklendi (unpack SONRASI
  callback'ler cagirilir — arg'larla: rcx=0, rdx=DLL_PROCESS_ATTACH, r8=0 /
  x86 stdcall pushlar). ASLR notu: yeni dizi reloc tasimaz —
  --stripfixups ile kullanin (log'a yazildi).
- DERSLER (her biri canli-testle yakalandi):
  1. compaction raw kaymasi: tramp yazimi compaction ONCESI raw'a gidiyordu,
     compaction sonrasi farkli ofset — TLS blogu compaction SONRASINA tasindi.
  2. E9 self-rel formulu: `c.size()+5` YANLIS (E9 push sonrasi c.size()+1):
     dogrusu `c.size()+4` — OEP jmp 1 bayt kacyordu (0x145F vs 0x1460 kaniti).
  3. ModRM: cmp byte [r11+8] = `41 80 7B` (79 = r9 olur — junk-state erken
     callback -> unpack ezilmesi -> 0xC0000005).
  4. pushfq sirasi: push regs SONRA pushfq; popfq SONRA pop regs — tersinde
     popfq rax-slot'unu bayrak diye yukler (TF=1 -> 0x80000004 single-step).
  5. xrt_unpack state byte SET ETMEZ (o XRT-gate'in isiydi): EP-stub kendisi
     state=1 yazmali — aksi halde tramp'lar EP'de de defer (tls_ran=0 kaniti).
  6. TLS callback cagri-args: dongude (h=0, reason=DLL_PROCESS_ATTACH, pv=0)
     verilmeli — reason=cop olursa callback govdesi atlanir (tls_ran=0).
  7. jz mesafeleri: arg-set blogu eklenince .done kayar — jz'ler guncellenmeli.
- KANIT: tls_test (TLS callback + pack + stripfixups) RCODE=42
  ("TLS OK: callback EP'den once calisti") — eski davranis: pack+TLS = RED
  ya da crash. tls_test_nocb izolasyonuyla pack-yolu ayri dogrulandi.

**B5 cpDebugMode (--debugmode):**
- .vmp0 IC-dolumu YAPILMADI: cfg'nin sifir-alanlari canli — tam-dolum state
  byte'i 0xCC'e ezer (ilk-denemede rc=1 kaniti). INT3 dolumu BOLGE-KALANINDA
  zaten uygulanir (yerinde-stub govde kalan + tramp junk = 0xCC — disasm
  int3'lerle kanitli). Bayrak log'a islenir.

**REGRESYON (final motor):** sdk_b1 (JMPEXT/JCCEXT/gates + --debugmode)
rc=42; R5 ULTIMATE + --debugmode rc=42; mult-VM vmn=4 + vmadv rc=42;
tamper 117; determinizm md5-ozdes; metin2 d7610 U+antidebug koruma OK
(statik: seed=0xD7610, bc_rva=0x54BD00, bc_len=567 — anahtar/seed boru
hatti bayt-bayt dogrulandi; x86 stub desenleriyle).

**IKILI:** XProtectUI.exe 1,275,392B; XProtectUI32.exe 1,326,080B.

**KALAN (Faz C'den):** B3 cpResourceProtection (resource sifreleme +
FindResource/LoadResource/LoadString/EnumResource* yonlendirme — VMP
IsInternal semantigi), B4 cpVirtualFiles (bundler: gomulu dosya agaci +
faLoad/faRegister/faInstall — UO file_manager.cc modeli). GitHub token
olmus (API 401) — commit'ler lokalde, token yenilenince push.

**Ortam notu (kurtarma):** wine-root'ta wineserver SHELL SCRIPT'tir —
chroot'ta /bin/sh bind edilmediginden wineserver64 ELF ile ezmek zorunlu;
wchroot.sh'e PATH export eklendi. gcc -m32 LINK icin CRT ister ama blob
uretimi -c + ham ld kullandigindan multilib gerekmez.

## Task 28 — 1.2.0-B3: cpResourceProtection — TAMAMLANDI

Agent: main (Z.ai) | Tarih: 2026-11-12 (oturum 13 — A/B zip birlesimi sonrasi)

KULLANICI ISTEGI: A/B zip karsilastirma (A en yeni; B'nin kanit_b1 loglari
merge edildi) + checkpoint sistemi (cp_daemon.py 240 sn, GitHub push token
401 oldugu icin lokal birikmeli) + zbridge 20-sn dinleme kurali
(senkron20.py) + bulunan hatalarin duzeltmesi.

ORTAM KURTARMA (5 ders):
- A zip'i eksik dosyali geldi: gen_blob.py, lzma/, engine_sym.hpp —
  B zip'inden + 0.6.1 kaynak agacindan tamamlandi (merge -n).
- vm_core.c: A kaynakta regsap fix yerinde; iki mimari derleme rc=0.
- wine-root: wineserver script->ELF ezme + wchroot.sh PATH export;
  wine cmd sıcak başlatmada asili kalirsa pkill -9 wine + wineboot.
- Test dizini Z:\home\z\my-project altinda OLMALI (/tmp yolu Z:'de gorunmez).

B3 KOD (engine_pack.cpp + engine.hpp + engine_main.cpp + xprotect_ui.cpp):
- do_pack'e resprot param; skip hesabinda RESOURCE (di==2) istisnasi:
  .rsrc icerigi LZMA+CFB paket-akisina girer, unpack geri yazar.
  RDT+DataEntry RVA'lari bolum yerinde kaldigindan degismez (VMP
  Resources semantigi: statikte sifreli, RAM'de acik).
- [RESPROT] log + OZET'e resprot=ACIK/kapali + GUI cap->opt koprusu.

KANIT (kanit/1.2.0/):
- res_test.c + add_rsrc.py (PE'ye RCDATA gomme; dersler: dir hdr 16B,
  entry 8B {id,off|0x80000000}, RT_RCDATA=10, DataEntry {rva,size,cp,res}
  sirasi, SizeOfImage guncelleme — yoksa loader rc=6).
- "[PACK] .rsrc 512 B -> LZMA 69 B [CFB]"; statikte .rsrc raw sifreli;
  calisma: RES DOGRU + RCODE=42.
- REGRESYON (B3'lü build): R1=42, R2 tamper=117, R3=42, R4=42 TLS OK,
  R5 mvm=42 — 5/5.
- IKILI: XProtectUI.exe 1,276,416B; XProtectUI32.exe 1,327,104B.

Sonraki: B4 cpVirtualFiles (bundler: gomulu dosya agaci + faLoad/
faRegister/faInstall — UO file_manager.cc modeli).
