# MVPArea / Debug — KozDbg karşı XProtect (VMProtect 3.5.1 parite) testi

## Soru

KozDbg (https://github.com/ivanpotatoes/KozDbg — x64dbg için anti-anti-debug
eklentisi, VMProtect 3.3.1–3.10.1 profilleri) **bizim XProtect** motorumuzda
(= UniversalObfuscator = VMProtect **3.5.1** parite) işe yarar mı?

**Cevap: Temel anti-debug katmanında EVET — kanıtı aşağıda (Test C, rc=0).**
Buna ek olarak motorumuzun 3.5.1'in üstündeki ek bütünlük katmanı, tam kancalı
modda KozDbg yaklaşımının int3'lerini yakalıyor (Test C2) — yani bizim motor,
stock VMProtect 3.5.1'den bu noktada daha sıkı.

## KozDbg → konsol uygulaması (KozDbg-c)

KozDbg bir x64dbg **eklentisidir** (plugin.cpp / x86_plugin.cpp); x64dbg'nin
breakpoint-komut sistemi, GUI ve SDK'sına bağlıdır. Bu klasörde eklentilikten
çıkarılıp **bağımsız konsol hata ayıklayıcıya** çevrildi (`kozdbg_console.cpp`):

- x64dbg SDK'sı / GUI / bp-komut sistemi **yok** — saf Win32 debug API:
  `CreateProcessW(DEBUG_ONLY_THIS_PROCESS)` + `WaitForDebugEvent` +
  `Read/WriteProcessMemory` + `Get/SetThreadContext`.
- Kapsanan profiller: **331 / 340 / 350 (Engine::Api / legacy)** — kullanıcının
  senaryosu VMProtect 3.5.1 → profile 350. 360+ profilleri syscall
  enstrümantasyonu ister (Engine::Clustered/ScatteredSyscalls) — kapsam dışı.
- Kontroller KozDbg 1:1 (aynı 13-bit maske / 8191):
  0 PEB.BeingDebugged+IsDebuggerPresent · 1 RemoteDebugger/DebugPort(7)/
  DebugFlags(0x1f) · 2 DebugObject(0x1e)→PORT_NOT_SET · 3 ThreadHide(0x11) ·
  4 KernelDebugger(0x23)→00 01 · 5 modül listesi filtresi (5 surucu adi) ·
  6 NtClose/CloseHandle(0xDEADC0DE)→0xC0000008 · 7 TF probe (9d 0f 31 90)
  teslimi.
- KozDbg ile aynı yerden arm: **sistem kesme noktasında** (giriş noktasından
  önce) → hedef "temiz-ntdll kopyası" üretirse int3'ler kopyaya taşınır;
  rva-tabanlı eşleme (findCopyHit) kopyadaki kesmeleri aynı mantıktan geçirir.
- Derleme (llvm-mingw, statik):
  `x86_64-w64-mingw32-clang++ -O1 -std=c++17 -static kozdbg_console.cpp -o KozDbgC.exe`
  `i686-w64-mingw32-clang++ -O1 -std=c++17 -static kozdbg_console.cpp -o KozDbgC32.exe`
- Kullanım: `KozDbgC32.exe [--profile 331|340|350|off] [--controls N] [--verbose]
  [--log dosya] hedef.exe [args]`

## Test ortamı ve hedef

- Kum havuzu: Debian 13 + **wine 11.22 (wow64)** — gerçek Windows DEĞİL;
  sonuçların Windows yorumu aşağıda.
- Hedef: `victim64.exe` (llvm-mingw ile derlenmiş gerçek PE64; sentetik
  mini-PE'ler wine yükleyicisinde c000007b verdiği için gerçek PE kullanıldı) →
  XProtect host_cli ile korundu: `host_cli victim64.exe t_victim64.exe
  --antidebug --rt` (Check Debugger=true, kapatma=true).
- XProtect'in runtime bataryası (xrt_core.c, UO loader.cc 1:1):
  K1 PEB.BeingDebugged+NtGlobalFlag (doğrudan okuma) · K8
  ProcessDebugPort(7)/DebugObjectHandle(0x1e) **temiz-ntdll kopyası üzerinden**
  · K9 CloseHandle(0xDEADC0DE) · K5 SystemKernelDebuggerInformation(0x23) ·
  tetiklenince ExitProcess(0x70+err) — antidebug err=5 → **0x75 (117)**.

## Sonuç matrisi (wine, x64)

| Test | Ayar | Çıkış kodu | Sonuç |
|---|---|---|---|
| A | Debuggersız düz koşum | 0 | "victim64 calisiyor" — temiz koşum; koruma tetiklenmedi ✓ |
| B | KozDbg-c `--profile off` (düz debugger, kanca yok) | **117 (0x75)** | XProtect antidebug debugger'ı YAKALADI — ürün çalışıyor ✓ |
| **C** | KozDbg-c `--profile 350 --controls 0x1` (PEB/API katmanı) | **0** | **BY-PASS BAŞARILI**: hedef debugger altında sonuna kadar koştu ("victim64 calisiyor", kod=0) — tahmin doğru ✓ |
| C2 | KozDbg-c `--profile 350` tüm 13 kontrol (0x1FFF) | 1 | int3 kancaları motorumuzun bütünlük/tamper katmanına takıldı — stock VMProtect 3.5.1'de olmayan ek savunma (A21 temiz-ntdll + CRC) |

Loglar: `logs/testA_plain.log`, `logs/testB_plain_debugger*.log`,
`logs/testC_peb_bypass*.log` (C, GEÇTİ), `logs/testC_full_controls_console.log` (C2).

## Yorum — 3.5.1'de "işe yarar mı?"

1. **K1 (doğrudan PEB) katmanı**: KozDbg yaklaşımı geçti (Test C, rc=0). VMProtect
   3.5.1'in PEB/IsDebuggerPresent tabanlı tespiti, anti-anti-debug aracıyla
   gizlenebiliyor — bu beklenen ve KozDbg'nin 3.5.0 profilinin tasarım hedefi.
2. **K8/K5 (temiz-ntdll kopyası)**: sorgular motorumuzun DISK'ten map ettiği
   temiz kopya üzerinden gidiyor; bellek-içi int3 kancaları bu sorgulara
   girmiyor. Ayrıca kancalı ntdll, bütünlük/tamper kontrolünde yakalanıyor
   (C2'de görüldü). Yani bizim motor bu katmanda stock 3.5.1'den sıkı.
3. **Pratik sonuç**: Check Debugger=true iken düz debugger (Test B) anında
   yakalanıyor (0x75). KozDbg tarzı araçlar PEB katmanını geçebilir; tam
   kancalı modda motorumuzun ek katmanları devreye giriyor. Kapatma=false
   (cp282) ile tetikte kapanma yerine devam davranışı da ayrı kontrol edilir.

## v1.1 GÜÇLENDİRME — "takılmaz" mod (2026-11-16, cp284)

C2'de (tüm 13 kontrol) int3 kancalarının neden sorun çıkardığı kök-nedenine
indi ve motor ikiye ayrıldı:

### Motor 1: `--engine dr` (VARSAYILAN, Windows) — belleğe SIFIR yazma
- int3 YOK (CRC/tamper imzası oluşmaz). Donanım kesme noktaları DR0-DR3
  (execute-only, DR7=0x55) + tam-çağrı-emülasyonu:
  - **DR0 = ntdll!NtQueryInformationProcess**: sınıf 7/0x1f → buffer=0 yazılıp
    çağrı HİÇ çalıştırılmadan dönüş (0); sınıf 0x1e → STATUS_PORT_NOT_SET
    (0xC0000353). xrt'nin K8 **gerçek-ntdll** sorgularını da yakalar (K8 her
    zaman gerçek NtQIP'i de çağırır — xrt_core.c:2394).
  - **DR1 = ntdll!NtQuerySystemInformation**: 0x23 → {00,01} yaz + emüle dönüş.
  - **DR2 = ntdll!NtClose**: 0xDEADC0DE → STATUS_INVALID_HANDLE; CloseHandle
    (K9) dahili NtClose üzerinden aynı DR ile kapsanır (4 slot yeter).
  - **DR3 = kernel32!CreateFileA**: yolu "ntdll.dll" içeren açılışlar
    INVALID_HANDLE döner → **xrt A21 temiz-ntdll kopyası kurulamaz**
    (xrt_core.c:2238 CreateFileA → h==INVALID → clean_nqip=0 → kopya yolu
    komple atlanır). KozDbg bu sayede A21 katmanını da aşar.
- PEB.BeingDebugged + NtGlobalFlag temizliği (K1) DR modunda da yapılır —
  tek bellek-yazması bu (gerekli ve zararsız: K1 doğrudan okur).
- Yeni thread'ler otomatik DR alır (CREATE_THREAD). DR6 durum bitleri
  temizlenerek devam edilir; DR'siz SS = hedefin TF probe'u → teslim.
- sınırlama: wine 11.22-wow64 donanım DR'yi UYGULAMAZ ve DR7-etkin thread'i
  sessizce öldürür (deney: DR7=0 → rc=0, DR7=0x55 → rc=1). DR modu gerçek
  Windows'ta doğrulanmalıdır (TitanHide/ScyllaHide de DR temellidir).

### Motor 2: `--engine int3` (wine-uyumlu yedek) — tam-emülasyon
- v1.0'dan farklar:
  1. **Tam-emülasyon**: NtQIP 7/0x1f → buffer=0 + emüle dönüş (TF-step yok);
     NtQSI 0x23 → {00,01} + emüle dönüş. İstisna-bağlamı içinde stepping
     kalmadı.
  2. **Yeni action 7**: kernel32!CreateFileA(intdll) → INVALID_HANDLE —
     int3 motoru da A21 kopyasını bloklayabilir.
  3. **Passthrough stepping'siz**: eşleşmeyen sınıflarda bayt kalıcı restore +
     talimat başından normal devam (iç içe istisna/stack-overflow yok — kanıt:
     v1.0'da +seh izinde `virtual_setup_exception stack overflow`).
  4. **W^X-güvenli yazma**: wine 11 wow64'te WriteProcessMemory, +X sayfayı
     +X'siz bırakıp loader'ı sessizce öldürüyordu (exit 1); artık sayfa
     koruması yazma sonrası GERİ YÜKLENİyor (VirtualProtectEx).

### Wine kısıtının tam açıklaması (önemli bulgu)
wine, `PEB.BeingDebugged=0` yapılınca **debug-event kanalını kapatıyor**:
istisnalar artık debugger'a teslim edilmiyor. Bu yüzden wine'da "PEB temizle +
kendi int3'ümüzle kes" aynı anda mümkün değil (int3 ölümcül). Gerçek Windows'ta
yönlendirme debug-object üzerinden yapılır ve BeingDebugged'dan bağımsızdır —
bu kısıt Windows'ta YOK. Sonuç: wine'da yalnız K1 katmanı geçilebilir (C
testi, rc=0 ✓); K8/K5/K9'un tam bypass doğrulaması Windows'ta yapılır.

## Gerçek Windows'ta tam doğrulama protokolü (öneri)

1. x32dbg/x64dbg + orijinal KozDbg (dp32/dp64) plugin; profil **3.5.0** seçili,
   Auto-enable açık.
2. `t_victim64.exe` (bu klasördeki hedef benzeri, XProtect ile
   `--antidebug --rt` korunmuş) yükle; sistem kesme noktasında logda
   `profile armed` gör; F9.
3. Beklenen (wine bulgusuyla tutarlıysa): PEB katmanı geçilir; kancalı tam modda
   motorumuzun tamper yanıtı devreye girer. Referans: stock VMProtect 3.5.1
   ile korunmuş örnekle aynı prosedür KozDbg'nin kendi testlerinde geçiyor.

## Dosyalar

- `kozdbg_console.cpp` — KozDbg-c kaynağı (tek dosya, x86+x64)
- `KozDbgC.exe` (x64), `KozDbgC32.exe` (x86) — statik derlemeler
- `logs/` — Test A/B/C/C2 koşum kayıtları
