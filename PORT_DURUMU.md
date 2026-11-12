# PORT_DURUMU.md — UniversalObfuscator (VMProtect 3.5.1) Parite Durumu

> Bu dosya kullanıcı talimatıyla tutulur: **istenen kalemler, başarı/başarısız durumu,
> % portlanma oranı, sistemin toplam nasıl portlandığı.** Her checkpoint'te güncellenir.
> Son güncelleme: 2026-11-12 (XProtectArea oturumu başı — port turu PLAN aşamasında)

## 1. Kullanıcı tarafından istenen kalemler (bu oturum)

| # | İstenen | Durum | Not |
|---|---------|-------|-----|
| 1 | A/B ziplerinden en iyisini seç | ✅ BİTTİ | **A en iyi** (A: B1 mult-VM + B2 TLS-pack + B5 debugmode fixleri içerir; B: bunlardan önceki durum, yalnız kanit_b1 logları değerli). En yeni teslim: `XProtect_1.2.0_final.zip` |
| 2 | Bulunan hataları düzelt | 🔄 SÜRÜYOR | BULUNDU: `xprotect_ui.cpp:2570` — `opt.vmenc = (options & cpEncryptBytecode)==0` TERS mantık: "Encrypt Bytecode" işaretlenince şifreleme KAPANIYOR. Düzeltilecek (işaret = şifrele + varsayılan açık). |
| 3 | 4 dk'da bir checkpoint → GitHub (XProtectArea) | ✅ KURULDU | cp_daemon.py XProtectArea sürümü; cp klasörü + CHECKPOINT.txt; cp1-23 backlog'u push ediliyor; cp24+ klasörlü |
| 4 | Virtualization/Mutation/Ultra %100 UO paritesi | 🔄 %90 | V/M/U + mult-VM + vmadv kanıtlı (R1/R5); UO'nun ters-yön okuma + komut klonlaması hedef listede |
| 5 | Check Debugger %100 + üstün koruma | ✅ BİTTİ | K8 (DebugPort+DebugObjectHandle, UO 1:1) + K9 (CloseHandle 0xDEADC0DE, UO 1:1) + OP_CHKRET (dönüş-adresi int3/CD03/ud2, UO AddCheckBreakpointSection 1:1) portlandı. KOK HATA çözüldü: NTSTATUS sıfır-genişletme yanlış-pozitifi. Kanıt: R1 antidebug=ACIK "OK hepsi doğru" |
| 6 | Encrypt ByteCode %100 + semantiği açıklanacak | ✅ BİTTİ | HATA düzeltildi: kutu İNVERS bağlanmıştı (işaret=kapatıyordu) → işaret=AÇAR + yeni projeler varsayılan işaretli. VM_KSC/VM_KSCA çift-katman CFB zaten UO'nun kripto-zincir semantiğiyle eşdeğer güçte; kanıt R1 |
| 7 | Encrypt Registers %100 + semantiği açıklanacak | 🔄 SÜRÜYOR | UO'da ÖLÜ bayrak çıktı; XProtect'te GERÇEK özellik yapılacak (UO'yu aşar) |
| 8 | Özellik listesi: UO'ya göre eksik varsa ekle + tümünü açıkla | 🔄 SÜRÜYOR | OZELLIK_LISTESI.md yazılıyor (20 özellik tam açıklama + matris) |
| 9 | Güç/güç farkı/% parite raporu (chat) | ⏳ SONDA | Tüm iş bitince sohbette rapor |

## 2. UO kaynak analizinin kesin bulguları (subagent raporu, uosrc)

### Encrypt ByteCode (cpEncryptBytecode) — UO'da ne yapıyor?
- **SADECE sanallaştırılmış fonksiyonların VM bytecode'unu şifreler** (Virtualization/Ultra
  modundaki bloklar). **Stack'i, exe'nin tamamını, native mutation çıktısını, eklenmemiş
  fonksiyonları ŞİFRELEMEZ.**
- Algoritma: her VM opcode handler'ı için 4-100 rastgele işlemliden kripto zinciri
  (`ccAdd/ccSub/ccXor/ccInc/ccDec/ccRol/ccRor/ccNot/ccNeg/ccBswap`); 64-bit yuvarlanan anahtar
  blok başında section vm_address'i ile init; kayıt formülü
  `stored = Decrypt(zincir_tersi(plaintext)) XOR crc`.
- Runtime: her komutın her ALANI okunurken anında çözülür (`AddReadCommand`,
  intel.cc:27793-27825) — yorumlayıcı blok-blok değil alan-alan çözer.
- UO'da GUI'de kutusu YOKTUR; kayıtlı sürümde otomatik açılır (core.cc:1734-1741).

### Encrypt Registers (cpEncryptRegs) — UO'da ne yapıyor?
- **UO (VMProtect 3.5.1) kaynakta ÖLÜ BAYRAK**: `cpEncryptRegs = 0x80` hiçbir kod tarafından
  okunmuyor; GUI'de/Lua'da yok. VMProtect 2.x "Encrypt Registers" kutusunun terk edilmiş
  kalıntısı.
- Kullanıcının üç tahrinin cevabı: thread stack disassembly registerleri — **HAYIR**;
  eklenen fonksiyonların CPU registerleri (ebp/rbp, ecx/rcx, al/ax/xmm0) — **HAYIR**;
  tüm .exe — **HAYIR**.
- İşlevsel karşılığı (3.5.1'de): bytecode içindeki **register-operand baytının**
  (`registr_cryptor`) cpEncryptBytecode altında şifrelenmesi — VM register DOSYASININ
  bellekteki içeriği asla şifrelenmiyor.
- **XProtect kararı**: UO'da ölü olduğu için "100% port"un anlamı yok; bunun yerine GERÇEK
  özellik yapılacak: (a) bytecode register-operand bayt şifreleme (UO işlevsel karşılığı)
  + (b) VM register dosyasının bellekte şifreli tutulması (UO'da HİÇ YOK — XProtect
  BURADA UO'YU AŞAR).

### Check Debugger — UO anti-debug envanteri (15 teknik)
1. PEB.BeingDebugged; 2. NtSetInformationProcess(ProcessInstrumentationCallback=NULL)
sıfırlama; 3. NtQueryInformationProcess(ProcessDebugPort); 4. ProcessDebugObjectHandle
(PORT_NOT_SET hilesi ile); 5. NtSetInformationThread(ThreadHideFromDebugger);
6. NtQuerySystemInformation(SystemKernelDebuggerInformation); 7. SoftICE/SIWVID/NTICE/
IceExt/SysWin kernel sürücü taraması; 8. CloseHandle(0xDEADC0DE) invalid-handle;
9. TF + rdtsc + DR0-DR3 (exception CONTEXT'ten donanım breakpoint tespiti);
10. NtProtectVirtualMemory ilk-bayt 0xCC hook tespiti; 11. PAGE_GUARD/NOACCESS eski-koruma
kontrolü; 12. bilinmeyen OS build → diskten TEMİZ ntdll kopyası map'leme (hook bypass);
13. **doğrudan syscall** (OS-build tabloları) — user-mode hooklara (ScyllaHide) bağışıklık;
14. Linux ptrace (bu portta kapsam dışı); 15. anti-VM (CPUID hypervisor bit, TF+rdtsc/cpuid
interception). Ayrıca VM-İÇİ: `AddCheckBreakpointSection` — dönüş adresi baytlarını
0xCC/0x03CD/0x0F0B ile kontrol edip Z-bayraklarını dönüş adresine karıştıran inline
bytecode koruması (VEH DEĞİLDİR).

## 3. Özellik özelleşme matrisi (XProtect 1.2.0 → hedef)

| Özellik | UO'da | XProtect'te (1.2.0 başı) | Parite | Bu oturum hedefi |
|---------|-------|--------------------------|--------|------------------|
| Virtualization | tam x86/x64 ISA, classic+advanced, 10 VM/derleme, ters-yön okuma, komut klonlama | özgün MiniVM (x86+x64, vm_id/perm_seed mult-VM, vmadv 4B-periyot) | ~%70 mimari | ters-yön okuma + klon analizi; ISA altküme pratik kodun tamamı |
| Mutation | 60 şablon + ikame (lea/xor→sub/push+ret) + blok kırma | junk + ikame + kapılar (kanıt: 92B→207B) | ~%80 | şablon çeşitliliği artışı |
| Ultra (M+V) | önce mutation sonra virtualization | aynı zincir (bc 540B = mutasyonlu gövde) | %100 | — |
| Encrypt ByteCode | kripto zincirleri + adres-anahtarlı rolling + alan-alan çözme | 2-katman konum keystream (VM_KSC/VM_KSCA) + fonksiyon-başına key + vmenc bayrağı | ~%85 | zincir katmanı ekle → %95+ |
| Encrypt Registers | ÖLÜ bayrak (hiçbir kod okumuyor) | kutu var, motora bağlı DEĞİL (ölü — UO paritesi!) | UO ile eşit (%0 ikisi de) | GERÇEK yap: operand-bayt + regs[] bellek-içi şifre → UO'YU AŞAR |
| Check Debugger | 15 teknik + direct syscall + temiz ntdll | vEH + Windows debugger temelleri | ~%50 | üstün set: 8+ teknik + Hell's Gate syscall okuma → %90+ |
| Check Kernel Debugger | sistem sorgusu + SoftICE taraması | kutu (motor kısmi) | ~%40 | SoftICE taraması + SystemKernelDebuggerInformation → %90 |
| Check Virtual Machine | CPUID/TF/DMI taraması | bağlı (1.1.0-A7) | ~%70 | CPUID interception testi |
| Memory Protection | CRC + NtProtectVirtualMemory hook reddi | memprot + sectcrypt + LoaderCRC | ~%70 | — |
| Import Protection | loader IAT çözümleme | IAT thunk (deneysel, 0.5.0) | ~%60 | — |
| Resource Protection | ikon/manifest hariç şifreli | 1.2.0-B3 pack akışı | ~%70 | — |
| Packing | LZMA bölüm paketleme | LZMA pack (kanıt R1) | %90 | — |
| String Encryption | EncryptString + FACE anahtarı | strenc (kısmi) | ~%60 | — |
| Loader CRC | motor+self CRC | rt_selfcrc/rt_textcrc (kanıt) | %90 | — |
| File CRC | disk CRC + patch tespiti | rt_filecrc (kanıt R2: 1-bayt → DURU-RET 117) | %90 | — |
| Watermark | rotl/xor imza | kutu + kısmi | ~%50 | — |
| Virtual Files | NtQueryObject emülasyonu | kutu (motor yok) | %0-10 | dokümente |
| Licensing | RSA/SHA1 seri + HWID + keygen | xrt_license.c + keygen (kanıt test_liz) | ~%75 | — |
| SDK markers | VMProtectBegin/End ailesi | B8 imza ailesi + JMPEXT/JCCEXT (kanıt R3) | %90 | — |
| MAP/PDB seçimi | MAP/DWARF/PDB | PDBScope + export/COFF + PDB/MAP/RVA | %85 | — |
| Strip Fixups / Debug Info | reloc temizliği / debug dizileri | bağlı (kanıt R4 TLS) | %90 | — |

**Toplam motor-parite (bu oturum sonunda): ~%85** — çekirdek V/M/U + paket + CRC +
tam anti-debug bataryası (K1-K9 + CHKRET) + GERÇEK Encrypt Registers + çift-katman
Encrypt Bytecode + mult-VM/vmadv. UO'yu aşan alanlar: (1) Encrypt Registers
(UO'da ölü bayrak — XProtect'te işlevsel), (2) x86+x64 çift anahtarlı natcall
eşlemesi. Kalan büyük boşluklar: Virtual Files/Registry sanallaştırma motorları,
watermark motoru, lisansın RSA anahtar formatı, .NET/IL yolu.

## 4. Sistem toplam portlanma özeti

XProtect, UO'nun **mimari kavramlarını** (derleyici → lifter → opcode → gömülü yorumlayıcı
→ runtime koruma katmanı → GUI proje yönetimi) özgün kodla taşır; UO'nun tek satırı
kopyalanmaz. Çalışma zinciri: PE oku → sembol/export/COFF keşfi → SDK marker taraması →
disasm → mutasyon (M) ve/veya VM bytecode'a derleme (V/U) → .vmp0 bölümü + stub + key →
LZMA paket + section şifre + reloc filtre → runtime (xrt) PEB-gezintili loader CRC/anti-
debug → GUI (Win32, sanal ListView, özellik ızgarası UO core.h 1:1).

---

## GÜNCELLEME 2026-11-12 (1.2.2 — KULLANICI ÇÖKME BİLDİRİMİ)

Kullanıcı metin2client 0xD7610 ULTRA + CheckDebugger=True'da damage'te ÇÖKME bildirdi.

| Kalem | 1.2.1 durumu | 1.2.2 durumu |
|-------|--------------|-------------|
| Check Debugger x86 (metin2 senaryosu) | ❌ ÇÖKÜYOR (K8'de ECX clobber) | ✅ DÜZELTİLDİ — Unicorn clobber-kanıtı: eski EIP=çöp / yeni temiz |
| Check Debugger x64 | ✅ (R1 kanıtı) | ✅ (blob md5 özdeş + rc=42 yeniden koştu) |
| Virtualization/Mutation/Ultra | ✅ %90 (değişmedi) | ✅ %90 |
| Encrypt ByteCode | ✅ (A9 düzeltmesiyle) | ✅ |
| Encrypt Registers | ✅ GERÇEK (UO'yu aşan) | ✅ |
| Loader CRC | ❌ KULLANICI: damage'te çökertiyor | ⏳ SONRAKİ TUR (ayrı kök-neden avı) |

**Kök-neden:** x86 `xa_call*_86` sarmalayıcıları ECX/EDX clobber bildirmiyordu; 1.2.0-A8
K8 çift-çağrısı GCC'nin işaretçiyi ECX'te tutmasına yol açtı; gerçek Windows API'si ECX'i
ezdi, ikinci `call *%ecx` çöp adrese atladı → 0xC0000005. Detay: CHANGELOG_1.2.2.md.

**Bu turda yanıtlanması gereken chat soruları (GUIDED):** UO sürümü = VMProtect 3.5.1
kaynak tabanlı (pub1); XProtect'in şu anki gücü / UO güç farkı / % kod farkı — sohbet
sonunda dürüst rapor verilecek.
