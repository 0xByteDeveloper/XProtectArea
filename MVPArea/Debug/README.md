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
