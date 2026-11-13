# XProtect 1.2.2 — CheckDebugger Kök-Neden Düzeltmesi

**Tarih:** 2026-11-12
**Öncelik:** KRİTİK (kullanıcı bulgusu: metin2client 0xD7610 ULTRA(M+V) + CheckDebugger=True iken oyunda damage atınca ÇÖKME)

---

## 1. Kullanıcı Raporu

> "XProtect_1.2.1'de metin2client.exe'yi seçtim, 0xD7610 adresindeki fonksiyonu ULTRA(M+V) olarak ekledim.
> Normal derledim, oyuna girip damage attım — çalışıyor, sorun yok.
> CheckDebugger True olarak derledim; metin2client_vmp_CheckDebugger.exe'yi açtım, oyunda damage attığımda ÇÖKÜYOR.
> Önceki sürümlerde Check Debugger başarılıydı, çökmüyordu; 'güçlendir' dediğim için hata oldu."

Diğer özellikler Yes iken çalışıyor; yalnızca Loader CRC oyunu çöktürüyor (ayrı konu, sonraki tur).

## 2. Kök Neden (Kanıtlı)

**Hata:** `vm_core.c` içindeki x86 anti-debug API sarmalayıcıları
(`xa_call1_86`, `xa_call2_86`, `xa_call4_86`, `xa_call5_86`) GCC inline-asm
clobber listelerinde **ECX/EDX'i bildirmiyordu**.

**Mekanizma:**
1. Gerçek Windows API'leri (kernel32/ntdll) stdcall'da ECX/EDX'i
   (caller-saved registerler) serbestçe **EZER** — bu ABI'ye tamamen uygundur.
2. GCC, clobber bildirimi olmadığı için "API çağrısının ECX/EDX'i yok
   edeceğini" BİLMİYOR; bu yüzden canlı değerleri (en kritik olarak:
   **sıradaki API çağrısının fonksiyon işaretçisini**) ECX'te tutuyor.
3. 1.2.0-A8 "güçlendirme"si K8'i ekledi: **ardı ardına İKİ**
   `NtQueryInformationProcess` çağrısı (ProcessDebugPort=7, sonra
   ProcessDebugObjectHandle=30) — derlenmiş blob'da işaretçi ECX'te
   önbelleklendi: ilk çağrı ECX'i ezdi, ikinci `call *%ecx` çöp adrese
   atladı → **0xC0000005 ACCESS VIOLATION → oyun çökmesi.**
4. 0.8.5'te (kullanıcının doğruladığı eski çalışan sürüm) batarya küçüktü
   ve GCC'nin o derleme tesadüfen canlı değeri ECX'te tutmadı — hata
   LATENT'ti; K8 çift-çağrısı tetikledi. "Güçlendirince bozuldu"
   izlenimi tam olarak bu.

**Kanıt zinciri (Unicorn diferansiyeli, `kanit_122/m2vm_repro2.py`):**
- Kullanıcının çöken exe'si + GERÇEK-Windows-benzeri API stub'ları
  (ECX/EDX'i bilinçli yok eden): **EIP=0xDEAD0001** — `call *%ecx` çöp
  işaretçiye atladı (UC_ERR fetch) → çökme birebir yeniden üretildi.
- Aynı stub'larla 1.2.2 ile üretilmiş exe: **eax=1, temiz** — iki yol da
  (erken-çıkış + tam-gövde) geçti.
- Bayt-kod çözümleyici (`kanit_122/bcd.c`): CHKRET yerleşimi ve ANTIDBG
  öneki doğru; lifter fixup'ları sapmasız — çökme bytekodda DEĞİL,
  bataryanın native çağrı disiplinindeydi.

## 3. Düzeltme (vm_core.c — 1.2.2)

Dört sarmalayıcı tek düzende biçime geçirildi:

```c
static long xa_call5_86(u32 t, u32 a1, u32 a2, u32 a3, u32 a4, u32 a5) {
    u32 args[5] = { a1, a2, a3, a4, a5 };   /* C tarafında kurulur */
    u32 ret;
    __asm__ volatile(
        "pushl 16(%2)\n\tpushl 12(%2)\n\tpushl 8(%2)\n\tpushl 4(%2)\n\tpushl (%2)\n\tcall *%1\n\t"
        : "=a"(ret) : "r"(t), "r"(args) : "memory", "cc", "ecx", "edx");
    return (long)ret;
}
```

- Argümanlar C tarafında `args[]` dizisine yazılır; asm onları
  **register-göstergeli** adresemeyle (esp kaymasından bağımsız) push eder.
- Clobber listesi `"ecx","edx"` içerir → GCC'in canlı değerleri
  caller-saved registerlerde tutması **imkânsız** olur.
- Derlenmiş blob'da işaretçi artık **EBX**te (Windows API'lerinin
  koruduğu callee-saved register) taşınır — disassembly ile doğrulandı.
- `vm_natcall86` zaten doğruydu (a/c/d çıktı kısıtları modeli) — dokunulmadı.

## 4. Etki + Doğrulama

| Test | Sonuç |
|------|-------|
| Kullanıcının eski CheckDebugger exe'i + clobber-stub | ÇÖKER (EIP=çöp) — kontrol grubu |
| **1.2.2 CheckDebugger exe + clobber-stub** | **GEÇER (eax=1, iki yol)** |
| 1.2.2 normal (antidebug kapalı) | GEÇER |
| x64 blob | bayt-bayt aynı (md5) — x64 yolu değişmedi |
| x64 sdk_ornek + antidebug (wine64) | a=78 b=0x16f9 c=0x1221 d=81, rc=42 ✓ |
| Kullanıcı senaryosu birebir (ULTRA + CheckDebugger, end=D766F) | bc=574B, ANTIDBG+3×CHKRET, temiz |

**Not:** Check Debugger'in *algılama gücü* korunuyor — K1..K9 tam
batarya (UO 1:1) çalışır durumda; yalnızca çökme kaldırıldı.

## 5. Güncellenen Dosyalar

- `source/vm_core.c` — 4 sarmalayıcı yeniden yazıldı (yukarıdaki yorum bloğuyla)
- `source/vmx86.bin`, `source/vm_blob.cpp` — yeniden üretildi (x86: 48866→49122 B)
- `source/vm64.bin` — değişmedi (md5 özdeş)
- `source/XProtectUI.exe` (1 290 752 B), `source/XProtectUI32.exe` (1 340 928 B)
- `kanit_122/` — m2vm_repro.py, m2vm_repro2.py (Unicorn diferansiyelleri),
  bcd.c (bytekod çözümleyici), bc_diff121.py, m2_122_normal.exe,
  m2_122_checkdbg.exe (kullanıcının senaryosuyla üretilmiş test ikilisi)

## 6. Sonraki Tur (bilinen backlog)

1. **Loader CRC çökmesi** (kullanıcı bulgusu: damage'te çökme — bu turda
   ele alınmadı; ScanDebugger testi ile ayrı kök-neden avı gerekiyor)
2. mult-VM(vmadv) × antidebug birlikte SEH istisnası (1.2.0 bilinen sınır)
3. UO tam kapsam portlama devamı: Encrypt ByteCode/Registers paritesi
   %100 (A9 zaten işlevsel) + özellik listesi eksik taraması

## 1.2.2-K9 (2026-11-12) — File CRC çökmesi kök-neden düzeltmesi
- KULLANICI: "File CRC True → oyunda damage atınca çöküyor" (errorlog:
  0xC0000005 @ 0x010e093d, edx=0x002a0028) + metin2client_vmp_FileCrc.exe.
- KÖK NEDEN: xrt_core.c x86 `ENT_FULLBUF_OFF=0x2C` → FullDllName.Buffer
  (+0x28) yerine BaseDllName.Length+MaxLen (0x002A0028) işaretçi sanıldı;
  peb_path_for_base geniş→ANSI döngüsü AV. (EIP RVA 0x55093D = .vmp0
  xrt-blob; ASLR base 0x00B90000 ebp'ten okundu.)
- DÜZELTME: ENT_FULLBUF_OFF 0x2C→0x28 (tek satır + belge blok).
- KANIT: Unicorn A/B (eski blob: AV@0x2A0028 birebir reprodüksiyon; yeni:
  yol+CRC+tamper ExitProcess 0x73) + wine64 regresyon R1=42 R2=115
  R2b=42 R3-statik=0x28 yerinde R4-determinizm.
- İKİLİLER: XProtectUI.exe 1.290.752B, XProtectUI32.exe 1.340.928B.

## 1.2.2-A10 (2026-11-13) — OP_NCALLI: dolaylı doğal çağrı (çoklu-fonksiyon RED'i kök-düzeltmesi)
- KULLANICI (cp34 raporu): 0xD7610 ULTRA + tüm özellikler = sorunsuz, çoğu çalışıyor.
  İkinci fonksiyon 0xE96D0 ULTRA eklendi → koruyamadı; tek başına derlendiğinde
  rc=3: "[RED] sub_e96d0 @0x000E96D0: RED: lifter: bilinmeyen islem".
- KÖK NEDEN: metin2 E96D0 gövdesindeki `FF 90 88000000`
  (call dword ptr [eax+00000088] — vtable-thiscall, C++ sanal çağrısı)
  disasm'da XP_CALLI üretiyordu; lifter switch'inde XP_CALLI case'i YOKTU →
  default → "bilinmeyen islem" RED. (VM'de yalnız OP_NCALL = sabit base+rva
  hedef vardı; çalışma-zamanı hedefi taşıyacak opcode hiç yoktu.)
- DÜZELTME (3 dosya, tek opcode):
  1) vm_opcodes.h: OP_NCALLI=0x44, VM_OPN 0x44→0x45. Kodlama:
     u8 form (0=u32 mem, 1=u64 mem, 2=u8 reg-idx) [+ mem/reg operand];
     hedef MUTLAK VA — base EKLENMEZ (OP_NCALL'den tek farkı bu).
  2) vm_core.c: OP_NCALLI işleyicisi — mem_addr ile hedef belleği/kaydı oku,
     x64: vm_natcall(tgt,ncr), x86: vm_natcall86(ncr86,(u32)tgt,...);
     Encrypt Registers yolu OP_NCALL ile birebir (çözülmüş kopya çağrısı,
     dönüş kayıtçileri yeniden şifreli). VM_TRACE harness sahte-dönüş yolu da var.
  3) engine_lift.cpp: case XP_CALLI — mem-form (form 0/1, L.emem ile birebir)
     + reg-form (form 2, "call eax" — FF D0). allow_call politikası aynen.
     engine_disasm.cpp: FF /2 reg-form artık XP_CALLI üretir (eski: "grp5").
     XP_JMPI (jmp [mem]): DURU RED — natgt base+rva matematği image-dışı
     hedefte (IAT thunk) yanlış atama üretir ("sessiz yanlış-sonuç yerine
     duru RED" geleneği; 607 RED'in bir kısmı artık bu net mesajla).
- KANITLAR (hepsi yeni ikililerle):
  K1 lift: test_e96d0.cpp — E96D0'nun 0x40 baytı (kullanıcının ChatDrn
  dökümü birebir) lift PASS rc=42; trace: "call em] (ncalli sz4) @0xE96E4";
  çift ret 0x4 + retimm=4 doğru.
  K2 CLI: XProtectUI.exe --cli metin2client.exe --add E96D0:E9710:U →
  [LIFT] 1/1, rc=0, m2_E96D0_U.exe kaydedildi (RED YOK; Ultra ön-mutasyon
  dolaylı-çağrıyı RED edip saf V'ye düşüyor — tasarım gereği).
  K3 ÇOKLU: --add D7610:D766C:U --add E96D0:E9710:U → [LIFT] 2/2, rc=0,
  m2_coklu_U.exe — kullanıcının çoklu-fonksiyon isteği YOLDA.
  K4 RUNTIME (Unicorn x86): test_calli_rt.c (SDK-V bölge içinde FF 90
  88000000 + FF 90 8C000000) korundu (tcalli0_p.exe, [LIFT] 183/790,
  VM_OPN=0x45) → ncalli_unicorn.py: korumalı bölge OP_NCALLI ile sahte
  vtable'dan MUTLAK hedefi okudu; vtcall VA native ÇALIŞTI; do_calli=777
  slot-0x88, do_calli2=888 slot-0x8C → hedef bellekten okunuyor (hardcode
  yok), doğru dönüş değeri, bölge-native geçişi temiz.
- DERS: inline-asm "r"(vt) kısıtı GCC'nin ESI seçimini çakıştırabiliyor
  (test kodunda 2 sahte-fault üretti); "a"(vt) + "=a"(out) ile kesildi —
  motor hatası DEĞİLDİ, test harness hatasıydı (bulgular log'da).
- İKİLİLER: XProtectUI.exe 1.292.800B, XProtectUI32.exe 1.342.976B;
  vm_blob 428.533B (x64 vm_entry=30960, x86=49104).
- SONRAKİ: çoklu-fonksiyon×pack ölçek izolasyonu → Internal Memory
  Protection portu → Check Debugger UO-parite %'sine kalanlar.

## 1.2.2-A11 (2026-11-13) — Internal Memory Protection: loader-seviyesi .vmp0 koruması + VEH altyapısı
- KULLANICI (önceki oturum sorusu): "Memory Protection true yaptım, 0xD7610'da jmp var,
  jmp'in götürdüğü yerdeki disassembly'i değiştirebiliyorum." — Kök-neden: Memory
  Protection yalnız .text chars'ını EXECUTE_READ yapıyordu; jmp'in hedefi olan
  **.vmp0** (VM stub/bc/blob) 0xE0000060 (YAZILABİLİR) idi.
- DÜZELTME (3 dosya):
  1) engine_main.cpp: memprot-YALIN kipte (CRC yok) .vmp0 chars = 0x60000020 —
     **jmp hedefi DISK-seviyesinden yazılamaz**. CRC kipinde .vmp0 yazılabilir
     kalır (cfg state yazısı çalışır — VEH yine kurulu).
  2) xrt_core.c: XFLAG_MEMPROT=0x20; xrt_entry A11 penceresi — cfg sayfası
     geçici RW'ye alınır (VirtualProtect), ilk çağrıda (state==0) kurulum
     yapılır, state=1 yazılır, eski koruma döner; stub state-kilidi sonraki
     çağrılarda xrt_entry'yi tamamen atlar (sıfır-maliyet tek-kurulum).
     mp_veh (x86/x64): 0xC0000005 YAZMA (ExcInfo[0]==1) ve adres bir yüklü
     modülün KOD bölümündeyse (mp_is_code: PEB modül-yürüyüşü + bölüm tablosu,
     CNT_CODE) → tamper → ExitProcess(0x75). rt_fatal XFLAG_EXIT ile.
     ENT_SIZE_OFF (x64 0x40 / x86 0x20) + XH_ADDVECTEH hash eklendi.
  3) engine.hpp/xprotect_ui.cpp: --mpveh CLI gate; cfg[0x09]=veh-gate baytı.
- KANITLAR (wine64):
  W1: memprot-YALIN + .vmp0 RX altında VM DOĞRU hesap: test_mp2.c sdk_v(13,3)
  = 5142 (zincir: 42^55=127; rol2=508; +0x1234=5168; -26=5142) rc=42 PASS.
  W2: t42 + sdkonly + memprot temiz koşu rc=42 PASS (A11-final ikilisi).
  W3: çıktı PE: .text=0x60000020 AND .vmp0=0x60000020 (pefile doğrulama).
- BİSECT BULGULARI (dürüst kayıt): wine'da VEH kaydı (AddVectoredExceptionHandler)
  VM akışını bozuyor — BOŞ handler bile (v5: saf return-0) VM çağrısında exit-1
  üretir (t42_v5.log). v4 (VEH'siz pencere+state+VP.text) rc=42 PASS (t42_v4.log).
  → VEH kaydı cfg[0x09]-gated: varsayılan KAPALI (wine-güvenli); --mpveh ile
  gerçek-Windows testi mümkün (kullanıcıya bırakıldı).
- BİLİNEN SINIRLAR: WPM (WriteProcessMemory) yazımları user-mode'dan
  savunulamaz (kernel-yolu) — Check Debugger bağlamsalı; VEH katmanı
  yalnız in-process kullanıcı-modu yazmayı keser (gerçek-Windows'ta --mpveh).
- NOT: tam-tarama kipi (tüm CRT fonksiyonlarının lift'i — CLI'da --add/sdkonly
  olmadan) cp38-A10'da da sağlıksızdı (RC=1) — A11 ile ilgisiz; UI fonksiyon-
  seçimi (manuel add / SDK bölgeleri) normal yol. Sonraki checkpoint konusu.
- İKİLİLER: XProtectUI.exe 1.293.824B, XProtectUI32.exe 1.344.512B.

## 1.2.2-A12 (2026-11-13) — çoklu-fonksiyon×Pack ölçek izolasyonu (kullanıcı yolu)
- KULLANICI YOLU: "çoklu-fonksiyon×pack ölçek izolasyonu" (cp39 CHECKPOINT madde 1).
- KANIT S1: metin2client.exe + D7610:D766C:U + E96D0:E9710:U + --pack →
  [LIFT] 2/2 (V=1 U=1, U-mutdus=1) | [PACK] .text 3.881.472B → LZMA 1.253.548B
  (%32.3), .data %35.4, .data1 %14.6 | EP 0x239B82 → unpack stub 0x6972E0 (.vmp1)
  | compaction 5.286.400 → 3.853.824 bayt | rc=0 → m2_coklu_pack.exe.
- KANIT S3 (tekrar-koşu): aynı komut → [LIFT] 2/2, rc=0, aynı boyut (3.853.824B)
  → m2_coklu_pack2.exe. (Bayt-özdeşlik BEKLENMEZ: derleme-başına rastgele VM
  anahtarı tasarım gereği — determinizmden kastedilen akış-sağlığı.)
- SONUÇ: A10 OP_NCALLI + çoklu-fonksiyon + Pack + LZMA + unpack-tramp zinciri
  birlikte sağlıklı. Kullanıcının "sadece tek fonksiyon değil birkaç fonksiyon
  koruyabilme" yolu pack ile de çalışıyor.

## 1.2.2-A13 (cp41) — Watermark Motoru: GOMME tarafı UO 1:1
- **UO core.cc Watermark::Compile 1:1**: değer hex dizisi; hex olmayan karakter = JOKER
  (maske 0, bayt rastgele). "5850726F.." gibi değer → baytlar; "AA??CC" → AA,joker,CC.
- **UO processors.cc BaseFunction::AddWatermark 1:1**: her derlemeye İÇ SÜRÜM imzası
  ("XProtect1.2.2" = 5850726F74656374312E322E32) otomatik gömülür (UO version_watermark
  davranışı); cpIncludeWatermark işaretliyken kullanıcı watermark'ları da gömülür.
- Kopya sayısı UO il.cc:4667 ile aynı: runtime katmanlı 8, yalın 10.
- Yerleşim: .vmp0 sonu slotlu alan (dump+16B slot, slot içi rastgele kayma); her kopya
  yeniden Compile() edilir → jokerler kopya-başına farklı. FileCRC .vmp0'ı zaten atlar.
- UI: cpIncludeWatermark → g_proj.wms tüm değerleri motora; CLI --wmvalue <hex>.
- Kanıtlar (regress_a13.sh → a13_kanit.txt):
  W1 ULTRA+wm=10+10 kopya statik + rc=42; W2 loadercrc=8+8 kopya + rc=42;
  W3 pack=8+8 + rc=42; W4 metin2 D7610+E96D0 ULTRA+wm → [LIFT] 2/2 rc=0 + 10+10.
- Doğrulayıcı: wm_verify.py (SearchByte durum makinesi 1:1 — maske eşleşmesi).

## 1.2.2-A14 (cp42) — Watermark ARAMA (UI) — UO SearchWatermarks 1:1
- **Watermarks diyalogu yukseltildi**: 3. sutun "Bulundu/Found" (LS_WMFOUND eklendi,
  EN+TR tablolar); "Tara/Scan" dugmesi (UO watermarks_window.cc scanButtonClicked karsiligi).
- **Tarama kapsami**: acik hedef dosyanin TAM ham baytlari (UO dosya-tarama kipi) —
  durum makinesi WM listesi: IC SURUM imzasi ("XProtect1.2.2" hex) + proje watermarklari
  (joker '?/' destekli — UO Watermark::SearchByte 1:1).
- Sonuc: her satir icin "Bulundu" sutunu + ozet MessageBox (watermark: N kopya).
- UI dogrulama (VLM, kanit_122/wm4_*.png): diyalog acildi; sutunlar Name|Value|Found;
  satir "XProtect (surum imzasi) | 5850726F74656374312E322E32 | -"; dugmeler
  Add Watermark | Delete | Scan | Close gorundu.
- BILINEN SINIR: wine10+Xvfb (WM'siz) ortaminda modal diyaloga fare/klavye GISI
  ulasmadi (Add dugmesi de dahil — ortam siniri, kod yolu degil; tum diyaloglar ayni
  modal desen). Kullanici gercek-Windows testi bekleniyor. Tarama mantigi wm_verify.py
  ile ayni durum makinesi — W1-W4'te 3 dosyada dogrulandi.
