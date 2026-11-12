# OZELLIK_LISTESI.md — XProtect Özellik Listesi (tam açıklama)

> Kullanıcı talimatı: "özellikler listesindeki tüm özelliklerin tamamını açıkla ve ne işe
> yaradıklarını açıkla" + "UO'ya göre eksik varsa ekle". Aşağıdaki liste XProtect GUI
> özellik ızgarasındaki 20 özelliğin (UO core.h 1:1) her birinin ne yaptığını, UO'daki
> karşılığını ve XProtect'teki bağlantı durumunu açıklar.
> Son güncelleme: 2026-11-12 (port turu başı — güncellemeler checkpoint'te gelir)

## Derleme modları (fonksiyon başına)

| Mod | Ne yapar |
|-----|----------|
| **Virtualization (V)** | Fonksiyonun x86/x64 makine kodunu özgün MiniVM'nin bytecode'una çevirir; kod artık CPU'da değil gömülü yorumlayıcıda çalışır → statik analiz/decompiler işe yaramaz. 0xD7610 örneğinde: 0xCC bayt govde yerine bytecode (bc=193B) + stub geçidi. |
| **Mutation (M)** | Fonksiyon native CPU kodunda KALIR ama gövde çöp kod, koşullu kapılar, komut ikamesi (add→lea, xor r,r→sub r,r) ve blok kırma ile obfuscate edilir. Kanıt: 92B→207B (junk=13, kapi=5, ikame=6). |
| **Ultra (M+V)** | ÖNCE mutation SONRA virtualization — mutasyonlu gövde bytecode'a kaldırılır (bc 540B = 2.8x). En yüksek anti-analiz. UO ile aynı sıra (intel.cc Compile: Mutate→CompileToVM). |

## 20 özellik — tek tek tam açıklama

### 1. Debug Mode (cpDebugMode)
**Ne işe yarar:** Korunan fonksiyonun *çıkarıldığı* yerde boş doldurma yerine `int3` (0xCC)
koyar; uygulama debugger altında adım adım çalıştırılabilsin diye GELİŞTİRİCİ kolaylığı.
**Koruma değildir** (UO'da da aynı: ters amaçlı). XProtect: 1.2.0-B5'te `--debugmode`
kanıtlı (R1 regresyonunda kullanıldı).

### 2. Crypt Values (cpCryptValues)
**Ne işe yarar:** Bytecode içindeki **anlık değerleri** (immediate sabitler), loader
mesajlarını ve string sabitlerini şifreler → bellek dökümünde düz anlamlı sabit görünmez.
UO'da bayrak 3.5.1'de ölü, işlevi `value_cryptor`/`EncryptString`'e dağıtılmış. XProtect:
`strenc` motor bayrağı (kısmi bağlı). Bu oturumda VM_KS katmanına değer maskesi ekleniyor.

### 3. Include Watermark (cpIncludeWatermark)
**Ne işe yarar:** Binary'ye rotl/xor şifreli **imza** gömer → korunan dosyanın hangi
XProtect/kullanıcı tarafından üretildiği tespit edilir (sürüm kaçak takibi). UO: WM'ler
dosyada arar (`SearchWatermarks`). XProtect: kutu var, motor bağlantısı kısmi.

### 4. Runner CRC (cpRunnerCRC)
**Ne işe yarar:** Korunan süreç **çalışırken** bellekteki kritik bölgelerin CRC'sini
yeniden hesaplayıp bozulma (runtime patch) tespit eder. UO: `cmCrc` VM komutu + rdtsc
indeks. XProtect: motorCRC altyapısı hazır; regresyonda selfcrc=42 kanıtlı.

### 5. Encrypt Registers (cpEncryptRegs) — bu oturumun odak noktası
**UO'da ne yapar:** HİÇBİR ŞEY — VMProtect 3.5.1 kaynakta **ölü bayrak** (hiçbir kod
okumuyor, GUI'de yok). 2.x'in terk edilmiş kutusu. İşlevsel karşılığı: bytecode'taki
register-operand baytının şifrelenmesi.
**XProtect'te (yeni):** GERÇEK özellik yapılıyor → (a) bytecode register-operand bayt
şifreleme (UO işlevsel karşılığı) + (b) **VM register dosyasının bellekte şifreli
tutulması** (regs[16] her okumada çözülüp yazımda yeniden şifrelenir) → bellek dökümünde
sanal register değerleri düz görünmez. (b) UO'da HİÇ YOK → XProtect burada UO'yu AŞAR.
**Kapsam:** ne thread stack registerleri ne tüm exe — VM'NİN KENDİ sanal register
dosyası (16 slot) + bytecode operand baytları.

### 6. Strip Fixups (cpStripFixups)
**Ne işe yarar:** Ezilen fonksiyonların eski .reloc (ASLR yeniden-basım) girdilerini
siler → Windows loader yanlış delta uygulayıp VM anahtarını bozamaz (BUGFIX #13'ün
kok aldığı yer). XProtect: bağlı, kanıt R4 (TLS pack + stripfixups rc=42).

### 7. Pack the Output File (cpPack)
**Ne işe yarar:** Bölümleri LZMA ile sıkıştırıp loader'da açılır hale getirir → statik
aracın dosyada gezineceği düz içerik azalır. XProtect: lzma/ SDK + packer, kanıt R1
(sdkonly+pack rc=42) + R4. Parite %90.

### 8. Import Protection (cpImportProtection)
**Ne işe yarar:** IAT girişlerini gizler — importlar yüklenirken hash ile çözümlenir,
düz IAT tablosu kalmaz → import tablosundan ne çağrıldığı okunamaz. XProtect: 0.5.0
deneysel thunk üreticisi + FF15→E8 yaması (kanıt: thunktest.py). UO loader-IAT çözümüne
göre ~%60.

### 9. Check Debugger (cpCheckDebugger) — bu oturumda güçlendiriliyor
**Ne işe yarar:** Korumalı exe hata ayıklayıcı altında çalışınca tespit edip çıkar/bozar.
XProtect mevcut: vEH tabanlı + Windows debugger tespiti (kullanıcı canlı doğruladı).
Bu oturumda eklenen üstün set (UO envanterinden): ProcessDebugPort +
ProcessDebugObjectHandle (NtQueryInformationProcess), ThreadHideFromDebugger
(NtSetInformationThread), CloseHandle(0xDEADC0DE) invalid-handle, TF+rdtsc+DR0-DR3
donanım breakpoint, ProcessInstrumentationCallback sıfırlama, NtProtectVirtualMemory
0xCC hook tespiti + **doğrudan syscall okuma (Hell's Gate deseni — ntdll stub'ından
syscall numarasını okuma)** → ScyllaHide-tipi user-mode hook'lara dayanıklılık. UO'nun
temiz-ntdll-from-disk deseni not edildi (ileriki tur).

### 10. Check Virtual Machine (cpCheckVirtualMachine)
**Ne işe yarar:** Uygulamanın VMware/VirtualBox/Hyper-V gibi sanal makinede çalışıp
çalışmadığını tespit (CPUID hypervisor biti, TF+rdtsc/cpuid interception). XProtect:
1.1.0-A7'de motora bağlı; güçlendirme sırasında.

### 11. Memory Protection (cpMemoryProtection)
**Ne işe yarar:** Kritik bellek bölgelerini CRC + erişim kontrolüyle korur; debugger'ın
guard-page koymasına karşı NtProtectVirtualMemory dönüşü denetlenir. XProtect: memprot +
sectcrypt (bölüm şifreleme) — kanıt R1 (sectcrypt rc=42).

### 12. Resource Protection (cpResourceProtection)
**Ne işe yarar:** .rsrc bölümünü şifreler (ikon/manifest hariç — Explorer'ın görmesi
için), kaynak talep anında çözülür. XProtect: 1.2.0-B3 (pack akışına katılır), kanıt
resprot logları.

### 13. Check Kernel Debugger (cpCheckKernelDebugger)
**Ne işe yarar:** Kernel modda hata ayıklayıcı (SoftICE, SIWVID, NTICE, IceExt, SysWin)
tespiti: NtQuerySystemInformation(SystemKernelDebuggerInformation) + sürücü modül
taraması. XProtect: kutu var; bu oturumda motor bağlantısı ekleniyor (UO'da Check
Debugger açıksa otomatik dahil olur — aynı kural alınıyor).

### 14. Strip Debug Information (cpStripDebugInfo)
**Ne işe yarar:** Debug dizilerini (.debug, COFF debug) temizler → sembol/parça
bilgisini sızmaz. XProtect: bağlı (PE temizliği, pack akışı içinde).

### 15. Loader CRC (cpLoaderCRC)
**Ne işe yarar:** **Motorun kendisinin** (loader/xrt/VM kodu) bellek içi CRC'si — biri
koruma kodunu yamalarsa tespit. XProtect: rt_selfcrc + rt_textcrc; kanıt R1 (loadercrc
rc=42), R2 (tek bayt .vmp1 yaması → DURU-RET 117). Parite %90.

### 16. Encrypt Bytecode (cpEncryptBytecode) — bu oturumun odak noktası
**Ne işe yarar:** Sanallaştırılmış fonksiyonların **VM bytecode'unu** şifreler → bellek
dökümünde bytecode okunamaz. UO'da otomatik (kayıtlı sürüm); GUI kutusu yok. XProtect:
vmenc bayrağı + 2-katman konum keystream (VM_KSC/VM_KSCA) + fonksiyon-başına 64-bit key
(stub'taki mov eax,imm çiftleri). Bu oturumda: UO'nun per-opcode **kripto zinciri**
katmanı ekleniyor + vmenc ters-mantık hatası düzeltiliyor (işaret=sifrele).
**Kapsam (kullanıcı sorusunun cevabı):** eklenen (V/U ile derlenen) fonksiyonların
bytecode'u — ne tüm exe ne stack; M çıktısı native olduğu için onu da şifrelemez.

### 17. Virtual Files (cpVirtualFiles)
**Ne işe yarar:** Dosyaları binary içine gömer; çalışma anında NtQueryObject-hook
emülasyonuyla gerçek dosya gibi sunar (dosya dışarı çıkamaz). UO Ultimate özelliği.
XProtect: kutu var, motor bağlantısı yok — dokümante edildi (parite gap).

### 18. Internal Memory Protection (cpInternalMemoryProtection)
**Ne işe yarar:** Motorun iç veri yapılarının (VM durum tablosu, anahtar bölgesi)
bellek koruması. XProtect: sectcrypt + cfg sözleşmesiyle kısmi.

### 19. Loader (cpLoader)
**Ne işe yarar:** PEB-gezintili, hash-çözümlü, rodata'sız PIC loader katmanı —
tüm runtime koruma (CRC, anti-debug, unpack) bu katmanda yürür. XProtect: xrt_core.c
(api1/3/4/5/7 sarmalayıcı, 64B cfg sözleşmesi) — tam bağlı.

### 20. File CRC (cpFileCRC)
**Ne işe yarar:** Diskteki dosyanın CRC'si — dosya yamalanınca (crack/patch) tespit.
XProtect: rt_filecrc; kanıt: loaderCRC+filecrc+stripfixups kombinasyonu rc=42.

## UO'ya göre EKSIK/eksik kalan (bu oturumda ele alınıyor)

1. Encrypt Registers → ölü kutu → GERÇEK yapıyor (üstte #5)
2. Encrypt Bytecode kripto-zincir katmanı → ekleniyor (#16)
3. Check Debugger üstün teknikleri → ekleniyor (#9)
4. Check Kernel Debugger SoftICE taraması → ekleniyor (#13)
5. Virtual Files / Registry sanallaştırma → dokümante (motor yok — sıradaki sürüm)
6. Watermark motor bağlantısı → kısmi (sıradaki sürüm)

## Öncelikli özellik sırası (kullanıcı talimatı)

TAM KAPSAMLI PORT: Virtualization/Mutation/Ultra + Check Debugger + Encrypt ByteCode +
Encrypt Registers %100 (UO'dan eksiği varsa geçir, UO'yu geçebiliyorsak geç).
"Hiçbir sınır yok, tüm güç çalış."
