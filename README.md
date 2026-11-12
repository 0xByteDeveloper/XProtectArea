# XProtectArea — XProtect Checkpoint & Kaynak Deposu

Bu depo **XProtect** ana projesinin checkpoint ve kaynak kodu deposudur.

## Yapı

```
source/               XProtect tam kaynak kodu (C++ + saf Win32 API)
                      engine_*.cpp (motor), xprotect_ui.cpp (GUI), vm_core.c (VM),
                      xrt_core.c (runtime katmanı), lzma/ (paketleme), build betikleri
kanit/ + kanit_b1/    Koruma/regresyon kanıt logları (R1-R5, iso, prot, run logları)
checkpoints/          Checkpoint zip'leri:
                        XProtect_1.2.0_cp1.zip ... cp23.zip   (geçmiş birikim)
                        Xprotect_1.2.0_cpN/                    (cp24+'dan itibaren klasör)
                          ├── XProtect_1.2.0_cpN.zip            (tam o anki ağaç)
                          └── CHECKPOINT.txt                   (plan-önce log:
                                                                yapılacaklar, sorunlar,
                                                                düzeltmeler, dosya
                                                                değişimleri, son endpoint)
ILERLEME_NOTLARI.md   Canlı ilerleme defteri (iş YAPILMADAN ÖNCE yazılır → SONUC eklenir)
PORT_DURUMU.md        UniversalObfuscator (VMProtect 3.5.1) parite durumu: % tablosu,
                      istenen kalemlerin başarı/başarısız kaydı
OZELLIK_LISTESI.md    XProtect özellik listesi — tam açıklama + UO karşılaştırma matrisi
CHECKPOINTS.md        Checkpoint indeksi
```

## Checkpoint sistemi

Kullanıcı talimatı: **her 4 dakikada bir** checkpoint alınır, zip'lenip buraya push edilir
(`scripts/cp_daemon.py`). Amaç: araştırma/çalışma her an kesilirse bile ilerleme, plan ve
son endpoint dosyada kalır. Her checkpoint'in CHECKPOINT.txt'i "yapılacaklar listesi /
bulunan sorunlar / ne düzeltildi / hangi dosyalar güncellendi / en son nerede kalındı"
bilgisini taşır.

## Proje kimliği

- **Ana proje: XProtect** (özgün C++ + saf Win32 API — VMProtect tarzı koruma motoru + GUI).
- **Referans hedef: UniversalObfuscator** (VMProtect 3.5.1 kaynak arşivi) — 1:1 özellik
  paritesi hedefi. XProtect kopya değil, referans davranışına parite hedefleyen özgün
  uygulamadır.
- Son teslim sürüm: `XProtect_1.2.0_final.zip` (A/B değerlendirmesi: **A en iyi** —
  A, B1 mult-VM + B2 TLS-pack + B5 debugmode düzeltmelerini içerir; B, onlardan önceki
  durumdur).

## Sunucu/derleme

Derleme: `source/build_ui.sh` (zig 0.17) → XProtectUI.exe (x64) + XProtectUI32.exe (x86).
VM blob: `build_vmblob.sh`, runtime: `build_xrt.sh`.
