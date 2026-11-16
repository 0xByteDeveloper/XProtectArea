# MVPArea / VmpStaticTests — vmpstatic (VMPStatic.exe) testi

## Araç

Forumda paylaşılan **statik VMProtect detector + unpacker** (vmpstatic):
C++17'ye portlanmış tam kaynak + release build. Kapsam (kendilerinin beyanı):
VMP 1.60–3.10+ tespit; VMP 3.x LZMA packer katmanının statik açılması
(3.0–3.8 legacy `{src,dst}` + 3.9+/3.10+ `rol32(va^key,(i*7)&31)` şifreli
`{src,dst^key}` packer_info). Virtualization açma/IAT rebuild YAPMAZ.

- İndirme: `dosya.co/p9dy8g3ogrr0/vmp_unpacker.zip.html` — küçük dosyada
  captcha YOK; `GET sayfa → POST op=download2 (formdaki rand/dt) → 302 →
  dosya` akışı curl ile çalıştı (498MB'lık Collection'da countdown döngüsü
  otomasyona kapalı, bkz. aşağıda).
- Bu klasörde: `VMPStatic.exe` (araç binary), `logs/sweep_all_uploads.txt`
  (24 binary'nin tam çıktısı), `logs/` altında test kayıtları.
- Çalıştırma (sandbox): `wine VMPStatic.exe <packed.exe> <output.exe>`

## Test matrisi (wine 11.22, 24 binary)

| Grup | Dosyalar | Tespit | LZMA unpack |
|---|---|---|---|
| **XProtect korumalı (bizim)** | `t_victim64.exe` (--antidebug --rt, x64), `metin2client_xp.exe` (5.2MB gerçek client), `Test32_vmp.exe`, `Test_vmp.exe` | **"VMProtect v2.XX-3.XX [Min protection]"** / "v1.X-3.XX [Min protection]" — VMP-AİLESİ olarak tanıyor (UO/VMP 3.5.1 paritesinin doğal sonucu) | **YAPILAMAZ** — "No virtual-only sections found; no LZMA blocks" |
| **Gerçek VMProtect çıktıları** | `metin2client_vmp*.exe` (12 varyant: Ultra, d7610, CheckDebugger, FileCrc, LoaderCRC, StripFixups, importfalse...) | "VMProtect v1.X-3.XX" — hepsi tanındı | **YAPILAMAZ** — kullanıcı derlemlerinde "Pack the Output File" kapalı → LZMA katmanı yok |
| **Korumasız** | `metin2client.exe`, `XProtectUI32.exe`, `pdbscope.exe`, `VMPHelper.exe`, `RunPEForm*.exe` | VMP imzası YOK (yalnız "Unpacked image size" raporu) — gerçek PE'lerde yanlış-pozitif yok | — |
| **Sentetik mini-PE** | `fake64.exe` (eski test PE'miz) | "VMProtect v1.X-3.XX" + section-bounds uyarıları — sentetik PE'de yanlış-pozitif (gerçek PE'lerde görülmedi) | — |

## Cevaplar (sorusu net sorulardan)

1. **"UO'yu ve XProtect'i unpackleyebilecek mi?"** → **HAYIR.** Tespit
   katmanı korumalı dosyalarımızı VMP-ailesi ("Min protection") olarak
   işaretliyor (beklenen: loader-side bataryamız UO/VMP 3.5.1 paritesi ve
   section-manzarası benzer), ama bizim motor **VMP'nin LZMA packer
   katmanını hiç kullanmıyor** — açacak `packer_info` tablosu yok.
   Statik unpack imkânsız; dynamic dump da bizim koruma altındaki bölümler
   sanal olmadan (GLOBAL-only loader bataryası) diskin aynası olduğu için
   araç kapsamının dışında kalıyor.
2. **"Diğer 11 VMP sürümünü unpackleyecek mi?"** → Kullanıcının elindeki
   gerçek VMP çıktılarının **hepsinde** (Ultra/d7610 dahil) packer katmanı
   kapalı olduğu için araç şu an mevcut hiçbir örnekten LZMA bloğu
   çıkaramıyor. Pack-enabled VMP çıktılarında (VMP GUI "Pack the Output
   File") 3.9+/3.10+ şifreli packer_info dahil açması bekleniyor — bu
   senaryo VMProtect Collection'daki sürümlerle test edilecek (indirme
   durumu aşağıda).

## VMProtect Collection indirme durumu (x2)

- `workupload.com/file/tc3ecZ7QCy9` (498.57 MB): sayfa agent-browser ile
  açıldı (JS challenge geçildi) ama indirme butonu rewarded-ad + overlay
  arkasında; API (`/api/file/start`) puzzle-captcha (cookie'de
  `captcha={"puzzle",...,"find":[...]}`) istiyor — kum havuzunda çözülemedi.
- `dosya.co/o1n2pajvza7x/VMProtect_Collection.zip.html`: küçük dosyada
  çalışan curl akışı (bkz. vmp_unpacker) büyük dosyada countdown döngüsünde
  kalıyor (her POST yeni 5sn sayfası; 65sn bekleme + aynı rand/dt ile de
  aynı). Tarayıcıda da buton indirme başlatmıyor.
- **Kısmi takas**: Collection'ın "1 tanede VMProtect 3.5.1 [Source Code]"
  parçası önceki oturumdan `scripts/vmpsrc/pub1` + `pub2` olarak mevcut
  (1.449 dosya / ~1.13M satır; VMProtect GUI + VMProtectCon + core).
  Linux build denemesi: `core/lin_core64.mak` + `VMProtectCon/lin_console64.mak`
  var (clang hedefli; g++ için `-target` yaması uygulandı, derleme sürüyor).
  Bağlantı başarılı olursa **yerli Linux VMProtectCon** ile 3.5.1 kaynak
  derlemesinden Pack-enabled çıktılar üretilebilir → VMPStatic'in LZMA
  unpacker'ı (legacy 3.0-3.8 deseni) gerçek 3.5.1 çıktısına karşı test
  edilmiş olur.
- Kullanıcının kendi makinesinde indirme komutu (küçük dosya akışı
  doğrulanmıştı): `curl` ile GET → form rand/dt → POST download2 → 302'nin
  `Location`'ı; Collection için countdown penceresi UI'dan geçmek gerekir.
