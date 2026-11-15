# DOSYA_DENETIMI.md — UO (VMProtect 3.5.1 agaci) vs XProtect dosya denetimi (x4)

> Otomatik uretim: scripts/x4_dosya_denetimi.py — UO referansi: `vmpsrc/pub2` (intel.cc dahil tam agac).
> XProtect'te UO'nun TEK SATIRI kopyalanmaz: karsiliklar kavram/yapisal parite ile ozgun yazildi.

## Ozet

| Durum | Dosya | Yorum |
|---|---|---|
| PORTLU | 54 | karsiligi var — kavram/yapisal parite |
| KISMEN | 1004 | islevin parcasi var, bolumu yok (asarla kapanan farklar) |
| EKSIK | 15 | hicbir karsilik yok — asagida tek-tek listeli |
| N/A | 96 | UO-araci/Qt/derleme/belge — porta konu degil |
| **TOPLAM** | **1169** | porta-konu dosya: **1073** |

Porta-konu dosya kapsam katsayisi: **%51.8** (PORTLU=1, KISMEN=0.5 agirligi).

**Birebir dosya denetimi** (core/ motor + ust-duzey dosyalar; klasor-paritesi HARIC):

| Durum | Adet |
|---|---|
| PORTLU | 10 |
| KISMEN | 413 |
| EKSIK | 15 |
| N/A | 52 |

Klasor-paritesi gruplari (tek karsilik cok dosya kapsar): 679 dosya — VMProtect/ Qt GUI, help/, runtime/ C#, langs/, unit-tests/, examples/.

## EKSIK dosyalar (tek-tek)

| UO dosyasi | Not |
|---|---|
| core/dotnet20_runtime32.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/dotnet20_runtime64.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/dotnet40_runtime32.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/dotnet40_runtime64.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/dwarf.cc | DWARF sembol cozumleme (Linux/Mac hedef) |
| core/elffile.cc | ELF (Linux) hedef destegi |
| core/macfile.cc | Mach-O (macOS) hedef destegi |
| core/netcore_runtime32.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/netcore_runtime64.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/netstandard_runtime32.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/netstandard_runtime64.dll.inc | managed .NET runtime DLL enjeksiyon yolu (bizim yol: IL->native derleme) |
| core/objc.cc | Objective-C segment/selector analizi |
| core/objects.cc | objects (CALPHA) destegi |
| core/objects.h | objects baslik |
| core/script.cc | Lua script API'si (GUI script destegi) |

## KISMEN dosyalar (tek-tek)

| UO dosyasi | XProtect karsiligi | Not |
|---|---|---|
| .gitattributes | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| .gitignore | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| VMProtect/about_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/about_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/app_icon.mm | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/application.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/application.qrc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/export_key-pair.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/export_key_pair_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/export_key_pair_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/folder_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/function_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/function_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/help_browser.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/help_browser.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/add.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/add_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/add_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/add_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/back.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/back_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/back_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/boot_examples.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/boot_help.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/boot_open.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/box.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/branch_closed.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/branch_open.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/browse.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/bullet_delete.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/bullet_import.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/bullet_key.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/bullet_link.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/bullet_warning.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/calc.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cancel.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cancel_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cancel_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/check_off.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/check_off_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/check_on.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/check_on_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/checkbox.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/checkbox_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/code.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/compile.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/compile_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/compile_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/copy.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/copy_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/copy_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cut.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cut_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/cut_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/database.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/database_export.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/database_import.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/delete.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/details.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/details_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/details_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/disk.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/disk_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/disk_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/down_arrow.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/down_arrow_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/down_arrow_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/down_arrow_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/dump.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/error.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/execute.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/execute_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/execute_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/export.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/file_open.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/file_open_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/folder.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/folder_close.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/forward.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/forward_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/forward_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/functions.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/functions_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/functions_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/gear.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/goto.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/goto_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/goto_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/help_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/help_icon.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/import.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/information.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_code.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_export.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_file.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_import.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_key.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_load_command.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_m.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_property.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_resource.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_u.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/item_v.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/key.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/key_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/lightning.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/link.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/logo.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/menu_arrow.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/menu_arrow_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/menu_arrow_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/next.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/open.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/open_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/open_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/paste.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/paste_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/paste_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/previous.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/processor.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/project.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/project_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/project_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/radiobutton.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/radiobutton_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/reference.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/script.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_down.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_down_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_left.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_left_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_right.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_right_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_up.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/scroll_up_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/search.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/search_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/star.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/star_gray.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/tool.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_arrow.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_arrow_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_down.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_down_checked.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_down_disabled.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/up_down_hover.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/images/warning.png | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/import_license_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/import_license_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/license_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/license_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/lin_gui.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/lin_gui32.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/lin_gui64.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/mac_gui.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/mac_gui32.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/mac_gui64.mak | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/main.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/mainwindow.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/mainwindow.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/message_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/message_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/models.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/models.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/precompiled.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/precompiled.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/progress_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/progress_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/property_editor.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/property_editor.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/remotecontrol.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/remotecontrol.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/remotecontrol_win.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/res.bat | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/settings_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/settings_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/styles.qss | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/template_save_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/template_save_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/templates_window.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/templates_window.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/wait_cursor.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/watermark_dialog.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/watermark_dialog.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/watermarks_window.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/watermarks_window.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/widgets.cc | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtect/widgets.h | xprotect_ui.cpp | Win32 tek-dosya UI: fonksiyon listesi, ozellik grid, .vmp proje uyumu, watermark, lisans diyaloglari; Lua editor, .ui formlari, help entegrasayonu yok (klasor-paritesi) |
| VMProtectCon.Tests/Test_CommandLineParser.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| VMProtectCon.Tests/main.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| VMProtectCon.Tests/precompiled.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| VMProtectCon.Tests/precompiled.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/VMProtectLicense.ini | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/dotnet.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/dotnetfile.cc | xprotect_dotnet.cpp | CLR header + #~ + TypeDef/MethodDef + govde; ImplMap/MemberRef/GenericParam/#US yok |
| core/dotnetfile.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/dwarf.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/elf.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/elffile.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/files.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/gen_inc.bat | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/help.ico | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/il.cc | xprotect_il.cpp | IL->x86: 58-op alt kumesi; nesne/GC yollari duru-RED |
| core/il.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/inifile.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/intel.cc | engine_lift.cpp + engine_disasm.cpp + engine_mut.cpp + vm_blob.cpp | x86 derleyici: pratik-derleyici ISA kumesi + dolayi-cagri ailesi; UO tam-ISA + ters-yon okuma + komut klonlama yok |
| core/intel.h | engine.hpp + engine_lift.cpp | opcode tablolari alt kume |
| core/invariant/lin_invariant_core.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/lin_invariant_core32.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/lin_invariant_core64.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/mac_invariant_core.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/mac_invariant_core32.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/mac_invariant_core64.mak | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/precompiled.cc | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/precompiled.h | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/precompiled_c.c | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/invariant/precompiled_c.h | vm_blob.cpp + gen_blob.py | kalici-blob uretimi kavramsal karsilik (klasor-paritesi) |
| core/lang.bat | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/lang.cc | xprotect_ui.cpp (TR/EN) | 2 dil gomulu; UO 5+ dil + lang.bat |
| core/lang.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/macfile.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/mach-o.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/main.ico | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/objc.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/osutils.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/packer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/pe.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/pefile.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/processors.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/script.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/streams.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/version.bat | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/vmp.ico | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| core/vmprotect.rc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| examples/dotnet/dotnet.sln | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/App.config | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/Form1.Designer.cs | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/Form1.cs | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/Form1.resx | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/Program.cs | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/Properties/AssemblyInfo.cs | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_cil/forms_cil.csproj | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_mixed/AssemblyInfo.cpp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_mixed/Form1.cpp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/dotnet/forms_mixed/forms_mixed.vcxproj | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/scripts/Delphi Resources/Project1.exe.vmp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/scripts/Environment Variables/Project1.exe.vmp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/scripts/External DLL/Project1.exe.vmp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/scripts/Random Section Names/Project1.exe.vmp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| examples/scripts/Script Events/Project1.exe.vmp | sdk_ornek_test_rt.c + trt/vf_probe/vreg_kanit | ornek app'ler temel duzeyde (klasor-paritesi) |
| help/en/about_vmprotect.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/contacts.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/create_project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/default.css | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/dictionary.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/en.qhcp | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/en.qhp | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/faq.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/history.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/activation_setup.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_action.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_compilation.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_execute.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_open.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_save.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/button_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/codelock_error.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/delphi_map.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/delphi_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/depends.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/expert_find.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/export_keys.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/functions.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/import_key.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/licenses1.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/lock_to_serial.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/main_window.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_edit.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_file.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_help.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_project_import.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/menu_tools.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/preferences.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_add_folder.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_add_function.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_add_license.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_file_delete.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_file_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_file_protection.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_file_settings.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_content.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_content2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_menu2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_menu3.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_functions_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_generate_keys.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_options.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/project_script.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_calc.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_directory.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_dump.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_dump_goto.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_export.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_import.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_resources.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/properties_segments.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/visual_studio_map.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/watermarks_add.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/watermarks_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/watermarks_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/watermarks_setup.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/weblm_1.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/images/weblm_2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_calc.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_directories.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_dump.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_exports.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_imports.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_resources.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/info_segments.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/main_menu.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/main_window.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/activation.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/activation/api.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/activation/vmprotect.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/activation/weblm.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/features.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/howitworks.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/algorithms.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/keygen_dll.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/keygen_net.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/keygen_php.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/keygen/serial_format.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/licenses.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/api.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step11_app.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step12_code.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step13_flags.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step14_name.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step15_exp.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step16_time.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step17_maxbuild.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step18_blacklist.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step19_hwid.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step1A_userdata.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step21_src.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step22_vmp.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step23_product.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step24_test.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/manager/usage/step25_codelock.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/menu_edit.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/menu_file.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/menu_help.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/menu_project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/menu_tools.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/mode_console.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project_files.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project_options.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project_options_external_addresses.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/project_script.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/recommendations.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/script.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/script_classes.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/script_events.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/script_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/sdk_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/software_protection.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/terms.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/toolbar.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/use_map_file.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/use_markers.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/watermarks.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/watermarks_search.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/watermarks_setup.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/en/work.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/pyblog.py | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/pyblog.pyc | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/about_vmprotect.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/contacts.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/create_project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/default.css | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/dictionary.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/faq.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/history.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/activation_setup.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_action.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_compilation.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_execute.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_open.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_save.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/button_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/codelock_error.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/delphi_map.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/delphi_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/depends.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/expert_find.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/export_keys.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/functions.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/import_key.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/licenses1.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/lock_to_serial.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/main_window.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_edit.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_file.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_help.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_project.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_project_import.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/menu_tools.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/preferences.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_add_folder.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_add_function.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_add_license.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_file_delete.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_file_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_file_protection.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_file_settings.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_content.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_content2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_menu2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_menu3.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_functions_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_generate_keys.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_options.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/project_script.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_calc.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_directory.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_dump.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_dump_goto.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_export.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_import.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_resources.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/properties_segments.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/visual_studio_map.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/watermarks_add.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/watermarks_menu.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/watermarks_search.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/watermarks_setup.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/weblm_1.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/images/weblm_2.png | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_calc.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_directories.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_dump.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_exports.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_imports.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_resources.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/info_segments.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/main_menu.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/main_window.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/activation.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/activation/api.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/activation/vmprotect.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/activation/weblm.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/features.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/howitworks.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/algorithms.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/keygen_dll.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/keygen_net.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/keygen_php.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/keygen/serial_format.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/licenses.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/api.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/index.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step11_app.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step12_code.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step13_flags.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step14_name.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step15_exp.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step16_time.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step17_maxbuild.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step18_blacklist.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step19_hwid.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step1A_userdata.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step21_src.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step22_vmp.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step23_product.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step24_test.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/manager/usage/step25_codelock.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/menu_edit.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/menu_file.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/menu_help.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/menu_project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/menu_tools.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/mode_console.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project_files.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project_options.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project_options_external_addresses.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/project_script.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/recommendations.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/ru.qhcp | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/ru.qhp | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/script.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/script_classes.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/script_events.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/script_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/sdk_functions.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/software_protection.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/terms.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/toolbar.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/use_map_file.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/use_markers.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/watermarks.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/watermarks_search.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/watermarks_setup.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/ru/work.htm | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/struct.json | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/sync.py | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| help/syncVMProtect.bat | PORT_DURUMU.md + OZELLIK_LISTESI.md + CHANGELOG | UI-ici help sistemi yok; belgeler repo-doc (klasor-paritesi) |
| langs/en.lng | xprotect_ui.cpp (TR/EN gomulu) | harici .lng dosya sistemi yok (klasor-paritesi) |
| langs/fr.lng | xprotect_ui.cpp (TR/EN gomulu) | harici .lng dosya sistemi yok (klasor-paritesi) |
| langs/ru.lng | xprotect_ui.cpp (TR/EN gomulu) | harici .lng dosya sistemi yok (klasor-paritesi) |
| langs/zh.lng | xprotect_ui.cpp (TR/EN gomulu) | harici .lng dosya sistemi yok (klasor-paritesi) |
| minidumpfixer/main.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| minidumpfixer/minidumpfixer.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| minidumpfixer/minidumpfixer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| minidumpfixer/precompiled.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| minidumpfixer/precompiled.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| runtime/CFGregorianDateCreate.hpp | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Core.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/CpuId.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Crypto.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Faces.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/HardwareID.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/LicensingManager.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Loader.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/LzmaDecoder.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Numerics/BigInteger.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Numerics/BigIntegerBuilder.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Numerics/NumericHelpers.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Properties/AssemblyInfo.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/StringManager.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/LicensingManagerTests.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/LoaderTests.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/MsilToVmTestCompiler.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/Properties/AssemblyInfo.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/ElementedTypeHelper.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/MyBuffer.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/MyBufferReader.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/MyCollection.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/SdMetadataTokens.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/SdTemplateStuff.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/SimpleTypeHelper.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/StringDecryptor.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/TypeCompatibility.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VariantBase.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VariantFactory.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VmExecutor.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VmInstrCodesDb.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VmMethodHeader.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VmPosParser.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/RefVm/VmStreamWrapper.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/UnitTest1.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/UnitTestCombine.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/UnitTestProject.csproj | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Tests/UnitTestProject/UnitTestProject.csproj.bak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/VMProtect.Netcore.csproj | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/VMProtect.Runtime.csproj | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/VirtualMachine.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/VMProtect.Runtime/Win32.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/common.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/core.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/core.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/crypto.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/crypto.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/file_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/file_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/hook_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/hook_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/hwid.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/hwid.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/licensing_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/licensing_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/lin_runtime.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/lin_runtime32.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/lin_runtime64.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/loader.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/loader.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/mac_runtime.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/mac_runtime32.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/mac_runtime64.mak | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/objects.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/objects.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/precommon.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/precompiled.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/precompiled.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/registry_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/registry_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/resource_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/resource_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/runtime.def | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/string_manager.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/string_manager.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/utils.cc | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| runtime/utils.h | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok (klasor-paritesi) |
| sdk/VMProtect.SDK/Properties/AssemblyInfo.cs | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtect.SDK/Sdk.cs | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtect.SDK/VMProtect.SDK.csproj | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtectDDK.h | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtectSDK.bas | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtectSDK.h | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtectSDK.inc | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/VMProtectSDK.pas | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/lin_sdk.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/lin_sdk32.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/lin_sdk64.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/mac_sdk.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/mac_sdk32.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/mac_sdk64.mak | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/precompiled.cc | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/precompiled.h | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/sdk.cc | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/sdk.def | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| sdk/sdk.h | sdk_ornek_test_rt.c + engine_main.cpp scan_sdk | SDK marker (B8/Begin/End) tarayici var; VMProtectSDK32/64.dll cikti-yani SDK paketi yok (klasor-paritesi) |
| shellext/bitmap_utils.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/bitmap_utils.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/context_menu.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/context_menu.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/main.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/main.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/resource.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/shellext.def | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| shellext/shellext.rc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/Project1-linux-x64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/Project1-linux-x86 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/delphi-map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/exc-linux-x64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/exc-linux-x86 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/exc-osx-x64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/exc-osx-x86 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/gcc-apple-map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/gcc-linux-map-1 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/gcc-linux-map-2 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/ios-app-test1-i386 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/ios-app-test2-arm | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/macos-app-test1-amd64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/macos-dll-test1-i386 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/msvc-map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/msvc-x64-map-2 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/seh-x64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/seh-x86 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/win32-app-delphi-i386 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/win32-app-test1-i386 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/win32-app-test1-i386.vmp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/win32-dll-test1-i386 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| test-binaries/win64-app-msvc-amd64 | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/ansidecl.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/cp-demangle.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/cp-demangle.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/demangle.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/libiberty.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/undname.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/undname.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/unmangle.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/demangle/unmangle.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/diskid/diskid.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-actions.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-cardinalities.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-actions.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-actions.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-function-mockers.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-function-mockers.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-matchers.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-matchers.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-nice-strict.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-generated-nice-strict.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-matchers.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-more-actions.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-more-matchers.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock-spec-builders.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/gmock.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/internal/gmock-generated-internal-utils.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/internal/gmock-generated-internal-utils.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/internal/gmock-internal-utils.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/include/gmock/internal/gmock-port.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock-all.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock-cardinalities.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock-internal-utils.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock-matchers.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock-spec-builders.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gmock/src/gmock_main.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-death-test.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-message.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-param-test.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-param-test.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-printers.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-spi.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-test-part.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest-typed-test.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest_pred_impl.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/gtest_prod.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-death-test-internal.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-filepath.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-internal.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-linked_ptr.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-param-util-generated.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-param-util-generated.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-param-util.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-port.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-string.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-tuple.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-tuple.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-type-util.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/include/gtest/internal/gtest-type-util.h.pump | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-all.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-death-test.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-filepath.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-internal-inl.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-port.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-printers.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-test-part.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest-typed-test.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/gtest/src/gtest_main.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/ffi.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/ffitarget.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi32.a | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi32.lib | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi32d.lib | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi64.a | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi64.lib | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libffi/libffi64d.lib | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/Makefile | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/Makefile.lnx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/Sources | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/decode.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/decode.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/extern.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/input.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/input.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/itab.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/itab.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/libudis86.vcproj | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/mnem.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/mnem.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/read.me | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/syn-intel.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/syn.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/syn.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/types.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/libudis86/udis86.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/Makefile | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lapi.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lapi.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lauxlib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lauxlib.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lbaselib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lbitlib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lcode.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lcode.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lcorolib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lctype.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lctype.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldblib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldebug.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldebug.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldo.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldo.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ldump.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lfunc.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lfunc.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lgc.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lgc.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/linit.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/liolib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/llex.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/llex.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/llimits.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lmathlib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lmem.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lmem.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/loadlib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lobject.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lobject.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lopcodes.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lopcodes.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/loslib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lparser.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lparser.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lprefix.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lstate.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lstate.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lstring.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lstring.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lstrlib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ltable.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ltable.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ltablib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ltm.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/ltm.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lua.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lua.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lua.hpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/luac.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/luaconf.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lualib.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lundump.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lundump.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lutf8lib.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lvm.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lvm.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lzio.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lua/lzio.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/7zTypes.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Alloc.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Alloc.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Compiler.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzFind.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzFind.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzFindMt.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzFindMt.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzHash.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzmaDecode.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzmaDecode.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzmaEnc.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/LzmaEnc.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Precomp.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Threads.c | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/lzma/Threads.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/qt/callx64.bat | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/qt/callx86.bat | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/qt/qtbase/mkspecs/common/msvc-desktop.conf | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Accessor.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Accessor.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/AutoComplete.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/AutoComplete.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CallTip.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CallTip.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CaseConvert.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CaseConvert.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CaseFolder.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CaseFolder.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Catalogue.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Catalogue.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CellBuffer.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CellBuffer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharClassify.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharClassify.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharacterCategory.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharacterCategory.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharacterSet.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/CharacterSet.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ContractionState.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ContractionState.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Decoration.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Decoration.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Document.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Document.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Editor.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Editor.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ExternalLexer.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ExternalLexer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/FontQuality.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ILexer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Indicator.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Indicator.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/KeyMap.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/KeyMap.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexAccessor.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexLua.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerBase.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerBase.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerModule.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerModule.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerSimple.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LexerSimple.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LineMarker.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/LineMarker.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/OptionSet.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Partitioning.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PerLine.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PerLine.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PlatQt.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PlatQt.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Platform.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PositionCache.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PositionCache.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PropSetSimple.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/PropSetSimple.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/RESearch.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/RESearch.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/RunStyles.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/RunStyles.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/SciLexer.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/SciTE.properties | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Scintilla.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaBase.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaBase.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaEditBase.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaEditBase.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaQt.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaQt.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ScintillaWidget.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Selection.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Selection.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/SparseState.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/SplitVector.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/StringCopy.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Style.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/Style.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/StyleContext.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/StyleContext.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/SubStyles.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/UniConversion.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/UniConversion.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/UnicodeFromUTF8.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ViewStyle.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/ViewStyle.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/WordList.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/WordList.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/XPM.cxx | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/scintilla/XPM.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinystr.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinystr.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinyxml.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinyxml.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinyxmlerr.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| third-party/tinyxml/tinyxmlparser.cpp | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/arm-32bit.py | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/arm-thumb.py | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/intel-x86.py | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/LogItem.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Taggant.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/TaggantWebService.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/VmpLicenseKey.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Web References/certificateManagementService/BulkUpdateCertificateStatusResponseType1.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/CertificateManagementService.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/CertificateManagementService.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/Reference.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Web References/certificateManagementService/Reference.map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/RequestKeyRecoveryResponseMessageType1.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/SearchCertificateResponseType1.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/certificateManagementService/UpdateCertificateStatusResponseType1.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/policyService/CertificateEnrollmentPolicy.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/policyService/CertificateEnrollmentPolicy.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/policyService/Reference.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Web References/policyService/Reference.map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/policyService/getPoliciesResponse.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/PrepSignDataResponse.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/Reference.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Web References/signDataService/Reference.map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/SignerAPI.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/SignerAPI.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/ToBeSignedClientPKCS7BlobType.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/signDataService/VerifySignedDataResponse.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/userManagementService/Reference.map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/userManagementService/UserManagementService.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/userManagementService/UserManagementService.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/Reference.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/Reference.map | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/RequestSecurityTokenResponseCollectionType.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/RequestSecurityTokenResponseType.datasource | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/VS_WSTEP.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/certificateService.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/oasis-200401-wss-wssecurity-secext-1.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/oasis-200401-wss-wssecurity-utility-1.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/ws-addr.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/ws-authorization.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/ws-policy.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/ws-trust-1.wsdl | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/ws-trust-1.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/xml.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/Web References/veriSignCertIssuingService/xmldsig-core-schema.xsd | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/XmlReaderSpy.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_sqlclr/ipn_sqlclr.sqlproj | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_sqlclr/keygen.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_tool/App.config | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/ipn_tool/CheckSsvTest.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_tool/Program.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_tool/Properties/AssemblyInfo.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_tool/Watermarks.cs | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/ipn_tool/ipn_tool.csproj | xrt_core.c | native PIC runtime kavram-parite; C# managed SDK runtime (VirtualFiles/Registry/String .NET-icinde) yok |
| utils/x86disasm/Sconstruct-x86disasm | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/x86disasm/disasm.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/x86disasm/disasm.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/x86disasm/main.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| utils/x86disasm/make-x86disasm.py | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| win_runtime.Tests/core_tests.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| win_runtime.Tests/crypto_tests.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| win_runtime.Tests/main.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| win_runtime.Tests/precompiled.cc | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |
| win_runtime.Tests/precompiled.h | - | esleme tablosunda birebir karsiligi yok — klasor paritesi |

## PORTLU dosyalar (tek-tek)

| UO dosyasi | XProtect karsiligi | Not |
|---|---|---|
| VMProtectCon/console.cc | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/console.h | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/lin_console.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/lin_console32.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/lin_console64.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/mac_console.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/mac_console32.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/mac_console64.mak | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/main.cc | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/main.h | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/precompiled.cc | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| VMProtectCon/precompiled.h | xprotect_ui.cpp CLI modu | --* arguman ailesi + log (klasor-paritesi) |
| core/core.cc | engine_main.cpp + engine_pe.cpp | proje/ozellik matrisi, loader akisi kavram 1:1 |
| core/core.h | engine.hpp | cp* sabit matrisi 1:1 (cpVirtualization..cpPack) |
| core/files.cc | engine_pe.cpp | PE oku/yaz/bolum ekle |
| core/inifile.cc | xprotect_ui.cpp ini_write/ini_read | ayar saklama kavrami |
| core/osutils.cc | engine_util.cpp | os yardimcilari |
| core/packer.cc | engine_pack.cpp | LZMA pack (bizde C SDK tek-iplik) |
| core/pdb.h | engine_sym.cpp | PDB cozumleme (bizde pdb_parse) |
| core/pefile.cc | engine_pe.cpp | PE cozumleme |
| core/processors.h | engine.hpp | mimari sabitleri |
| core/streams.cc | engine_util.cpp | stream okuma |
| unit-tests/arm_tests.cpp | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/core_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/elffile_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/files_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/il_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/intel_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Properties/AssemblyInfo.cs | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/CertificateEnrollmentPolicy.wsdl | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/CertificateEnrollmentPolicy.xsd | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/Reference.cs | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/Reference.svcmap | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/configuration.svcinfo | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/configuration91.svcinfo | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/Service References/policyService/ipn_sqlclr.Test.policyService.getPoliciesResponse.datasource | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/TaggantWebTest.cs | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/VmpLicenseKeyTest.cs | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/app.config | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/ipn_sqlclr.Test/ipn_sqlclr.Test.csproj | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/lin_unit-tests.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/lin_unit-tests32.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/lin_unit-tests64.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/mac_unit-tests.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/mac_unit-tests32.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/mac_unit-tests64.mak | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/macfile_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/pefile_tests.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/precompiled.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/precompiled.h | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/test1.cc | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/testfile.h | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/testfileil.h | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |
| unit-tests/testfileintel.h | regress_110.sh + test_*.c + kanit_suitleri | bizde wine-E2E + bilesen suitleri daha kapsamli (klasor-paritesi) |

## N/A dosyalar (porta konu degil)

| UO dosyasi | Not |
|---|---|
| NetX64.testsettings | VS test ayari |
| NetX86.testsettings | VS test ayari |
| New Text Document.txt | bos not |
| README | UO README |
| app/vmprotect_dmg_1a.png | VS çözum ayar dosyalari (klasor-paritesi) |
| app/vmprotect_gui.app/Contents/Resources/logo.icns | VS çözum ayar dosyalari (klasor-paritesi) |
| core/lin_core.mak | Linux/mac derleme sablonu |
| core/lin_core32.mak | Linux/mac derleme sablonu |
| core/lin_core64.mak | Linux/mac derleme sablonu |
| core/lin_runtime32.so.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/lin_runtime64.so.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/mac_core.mak | Linux/mac derleme sablonu |
| core/mac_core32.mak | Linux/mac derleme sablonu |
| core/mac_core64.mak | Linux/mac derleme sablonu |
| core/mac_runtime32.dylib.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/mac_runtime64.dylib.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/precompiled.cc | PCH sablonu |
| core/precompiled.h | PCH sablonu |
| core/runtime.vmp | UO'nun runtime-ini koruma projesi |
| core/vmprotect.vmp | UO ornek proje sablonu |
| core/win_runtime32.dll.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime32.sys.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime32demo.dll.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime32demo.sys.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime64.dll.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime64.sys.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime64demo.dll.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| core/win_runtime64demo.sys.inc | on-derlenmis runtime varligi; bizim runtime KAYNAKTAN derlenir (xrt_core.c) |
| gnu_simple.mak | Linux make sablonu |
| lin_common.mak | Linux make sablonu |
| mac_common.mak | macOS make sablonu |
| make_dmg.sh | macOS paketleme |
| third-party/diskid/diskid.sln | VS proje dosyalari |
| third-party/diskid/diskid.vcxproj | VS proje dosyalari |
| third-party/diskid/diskid.vcxproj.filters | VS proje dosyalari |
| third-party/libffi/win32/vc14_x64/libffi/libffi.vcxproj | VS proje dosyalari |
| third-party/libffi/win32/vc14_x86/libffi/libffi.vcxproj | VS proje dosyalari |
| third-party/lin_google.Tests.mak | Linux/mac derleme sablonu |
| third-party/lin_google32.Tests.mak | Linux/mac derleme sablonu |
| third-party/lin_google64.Tests.mak | Linux/mac derleme sablonu |
| third-party/mac_google.Tests.mak | Linux/mac derleme sablonu |
| third-party/mac_google32.Tests.mak | Linux/mac derleme sablonu |
| third-party/mac_google64.Tests.mak | Linux/mac derleme sablonu |
| utils/ipn_tool/ipn_tool.sln | VS proje dosyalari |
| utils/x86disasm/x86disasm.sln | VS proje dosyalari |
| utils/x86disasm/x86disasm.vcxproj | VS proje dosyalari |
| utils/x86disasm/x86disasm.vcxproj.filters | VS proje dosyalari |
| vcproj/MiniDumpFixer.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/MiniDumpFixer.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/ShellExt.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/ShellExt.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtect.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtect.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtectCon.Tests.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtectCon.Tests.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtectCon.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtectCon.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/VMProtectSDK.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/build-debug.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/build-release.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/checked.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/core.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/core.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/demo.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/driver.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/gen_inc.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/gtest.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/gtest.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/invariant_core.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/invariant_core.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/lite.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/precompiled.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/qt-debug.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/qt-debug64.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/qt-release.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/qt-release64.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/runtime.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/target-bin.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/target-temp.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/test1.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/test1.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/ultimate.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/unit-tests.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/unit-tests.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/use-gtest.props | VS proje dosyalari (klasor-paritesi) |
| vcproj/win_runtime.Tests.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/win_runtime.Tests.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vcproj/win_runtime.vcxproj | VS proje dosyalari (klasor-paritesi) |
| vcproj/win_runtime.vcxproj.filters | VS proje dosyalari (klasor-paritesi) |
| vmprotect.sln | VS proje dosyalari |
| win_runtime.Tests/lin_runtime.Tests.mak | Linux/mac derleme sablonu |
| win_runtime.Tests/lin_runtime32.Tests.mak | Linux/mac derleme sablonu |
| win_runtime.Tests/lin_runtime64.Tests.mak | Linux/mac derleme sablonu |
| win_runtime.Tests/mac_runtime.Tests.mak | Linux/mac derleme sablonu |
| win_runtime.Tests/mac_runtime32.Tests.mak | Linux/mac derleme sablonu |
| win_runtime.Tests/mac_runtime64.Tests.mak | Linux/mac derleme sablonu |
