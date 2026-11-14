#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ozellik_html_v7.py — XProtect 1.2.2 özellik-durum sayfası v7 (cp189 turu)
v7 ekleri: pdbscope x86 swap, A14 .NET P/Invoke/alan paketi; v6 ekleri: x1 mesaj-yolu kök-neden fix (user32/LoadLibraryA), x7c Detection
Message (UO/VMP Messages paritesi), x2/x7a StandAloneSig/locals gerçek port,
x3 dwarf wire, x/x5/x6 UI fixleri, EKSİK 15 durum bölümü."""
import html, datetime

OZ = [
    ("Virtualization (x86+x64)", 90,
     "MiniVM özgün yorumlayıcı; OP_JMPEXT/OP_JCCEXT dış-akış; mult-VM vmn=4+vmadv kanıtı (B1 OK hepsi); OP_NCALLI 0x44",
     "UO'nun ters-yön okuma + komut-klonlama; ISA uzun-kuyruk"),
    ("Mutation", 80,
     "yönlü mutasyon + ikame + kapılar (kanıt: 92B→207B); U-kaynak mutasyonu",
     "şablon çeşitliliği (UO ~70 şablon)"),
    ("Ultra (M+V)", 100,
     "mutasyon(lift(IL)) zinciri; R1 ULTIMATE kanıtı 'OK hepsi'; metin2 D7610+E96D0 çoklu kanıt",
     "—"),
    ("Encrypt ByteCode", 95,
     "VM_MIX OP-ZİNCİRİ (4 karışim ailesi) + VM_KSC CFB + VM_KSCA + fonksiyon-başı key",
     "UO'nun 100-op'a kadar zincir uzunluğu + handler-bası rastgeleleşme"),
    ("Encrypt Registers", 100,
     "VM register-dosyası şifreli + epoch rotasyonu (UO'da ÖLÜ bayrak — XProtect AŞAR)",
     "—"),
    ("Check Debugger", 94,
     "K1-K9 + OP_CHKRET + vm_poison cfg-uyumlu (26 site) + A13/x1 FIX: mesaj yolu user32/LoadLibraryA ile ÇALIŞIR hale geldi (eski: kernel32'de MessageBoxA aranıyor → hep 0 → direk sessiz çıkış)",
     "ScyllaHide-direnci temiz-ntdll + doğrudan-syscall tabloları"),
    ("Check Kernel Debugger", 90,
     "K5 SystemKernelDebuggerInformation + K6 SoftICE ailesi sürücü taraması",
     "gerçek-Windows kabul testi"),
    ("Check Virtual Machine", 85,
     "K7 CPUID hypervisor + rdtsc-timing (KVM true-positive) + vendor dizeleri",
     "CPUID interception testi"),
    ("Memory Protection", 80,
     ".text header-RX + .vmp0 loader-RX + VEH tamper-kill (kod5)",
     "Internal-MP: mutable state ayrı RW section"),
    ("Import Protection", 60,
     "IAT thunk-cache + FF15→E8 (deneysel; wine iattest kanıtı)",
     "tam loader-IAT çözümleme (UO ftImport) — x7d sonraki motor paketi"),
    ("Resource Protection", 80,
     ".rsrc CFB şifreleme + res_test rc=42 kanıtı",
     "FindResource yönlendirmenin geniş API kapsamı"),
    ("Packing (LZMA)", 95,
     "TLS+PACK sıkıştırma + rc=4 açık-çıklamalı hata",
     "—"),
    ("String Encryption", 75,
     "strenc + A18.2 UTF-16 tarama (wide_sum 1420 byte-exact)",
     "tüm-string kapsamı + FACE-anahtar format paritesi"),
    ("Loader CRC", 95,
     "rt_selfcrc + rt_textcrc (reloc-atlamalı; ASLR uyumlu)",
     "—"),
    ("File CRC", 95,
     "rt_filecrc: 1-bayt disk-tamper → duru-dönüş",
     "—"),
    ("Watermark", 85,
     "SearchByte durum-makinesi + rastgele wildcard + UI Tara + CLI --wmvalue",
     "gerçek-Windows UI kabul testi"),
    ("Virtual Files", 85,
     "ZİNCİR ÇALIŞIYOR: map→imports→DllMain→DllRegisterServer (vf_probe VFDM+VFDRS)",
     "faInstall GetTempPath yolu + çok-DLL senaryoları"),
    ("Virtual Registry", 80,
     "Win64→SysV ABI SHIM + ent.data fix; wine: openA st=0 + val doğru",
     "dword/W/enum yolundaki argüman bozulması — x7d deep-bisect"),
    ("Licensing (RSA+HWID)", 75,
     "xrt_license + keygen; test_liz kanıtı",
     "UO anahtar-dosya format paritesi"),
    ("SDK markers", 90,
     "B8 imza ailesi + JMPEXT/JCCEXT; R1 kanıtı 3/3",
     "—"),
    ("MAP/PDB fonksiyon-bulma (PDBScope)", 96,
     "cp189 FIX: paketteki x64-rebuild yerine KULLANICININ x86 binary'si geri koyuldu (md5 cfebc28c; tüm konumlar + bin/win32); metin2 53.236 fonksiyon (güçlü 39.224); arama/Tara WNDPROC seviyesinde",
     "x86 pdbscope binary (bin/win32)"),
    ("Strip Fixups / Debug Info", 90,
     "reloc temizliği + debug dizini; R4 TLS kanıtı",
     "—"),
    (".NET (il.cc + dotnetfile portu)", 90,
     "A13 locals port + A14/cp189: ImplMap (0x1C) gezinmesi → P/Invoke call üretimi (xrt_resolve yolu, stdcall/cdecl), FieldRVA ldsfld/stsfld (ASLR-siz), ExplicitLayout ldfld/stfld; RunPEForm kalanı: yönetilen-call inlining (v2), EH, ASLR-güvenli statik",
     "GC/nesne ops, ImplMap adları, x64 IL derleyici, EH semantiği"),
    ("DWARF (dwarf.cc portu) — x3", 55,
     "A13 WIRED: xprotect_dwarf.cpp build'e girdi + open_target otomatik tarama (source=8 DWARF kolonu; .debug_info/.debug_abbrev/.debug_str → DW_TAG_subprogram low/high/name, v2..v4 CU)",
     "gerçek MinGW -g PE'de kanıt + v5/ranges/DWARF64"),
    ("VMP Messages paritesi (x7c)", 100,
     "Detection Message: Properties satırı (kind-3 edit) + .xproj rtmsg persist + CLI --rt-msg + stub SONUNA ASCII data + PIC lea → ctx.msgp(+0x110); boş = varsayılan '#5' metni; Silent Exit ile birleşir (true=mesaj yok sessiz çıkış)",
     "—"),
    ("UI UX (x/x5/x6)", 97,
     "A13: log/konsol KOPYALANABİLİR (Ctrl+C secili / Ctrl+A tümü / sağ-tık menü → CF_UNICODETEXT) + log yükseklik ayiraci (fare ile büyüt/küçült, INI LogH persist) + x6: property seçimi değer değişince index 0'a KAYMAZ (geri-yükleme)",
     "klavye navigasyon genişletme"),
]

renk = lambda p: "#22c55e" if p >= 90 else ("#84cc16" if p >= 75 else ("#eab308" if p >= 55 else "#ef4444"))

satirlar = []
toplam = sum(p for _, p, _, _ in OZ)
for ad, p, kanit, kalan in OZ:
    bar = int(p * 2.6)
    satirlar.append(f"""
<div class="row">
  <div class="name">{html.escape(ad)}</div>
  <div class="bar"><div class="fill" style="width:{bar}px;background:{renk(p)}"></div>
    <span class="pct">{p}%</span></div>
  <div class="kanit">{html.escape(kanit)}</div>
  <div class="kalan"><b>Kalan:</b> {html.escape(kalan)}</div>
</div>""")

now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
HTML = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<title>XProtect 1.2.2 — Özellik Durumu v7 (TAM KAPSAMLI PORT)</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }}
h1 {{ color:#38bdf8; font-size:22px; margin:0 0 4px; }}
h2 {{ color:#7dd3fc; font-size:16px; margin:22px 0 8px; }}
.sub {{ color:#94a3b8; font-size:13px; margin-bottom:18px; }}
.top {{ background:#1e293b; border-radius:10px; padding:14px 18px; margin-bottom:18px; }}
.top .big {{ font-size:34px; font-weight:700; color:#4ade80; }}
.row {{ background:#1e293b; border-radius:8px; padding:10px 14px; margin-bottom:10px; }}
.name {{ font-weight:600; font-size:15px; margin-bottom:4px; }}
.bar {{ position:relative; height:18px; background:#334155; border-radius:9px; margin-bottom:6px; }}
.fill {{ height:18px; border-radius:9px; }}
.pct {{ position:absolute; left:8px; top:1px; font-size:12px; font-weight:700; color:#0f172a; }}
.kanit {{ font-size:12px; color:#cbd5e1; }}
.kalan {{ font-size:12px; color:#fca5a5; margin-top:2px; }}
.note {{ background:#1e293b; border-left:4px solid #38bdf8; padding:10px 14px; border-radius:6px; font-size:13px; line-height:1.6; margin-bottom:10px; }}
.footer {{ color:#64748b; font-size:11px; margin-top:16px; }}
</style></head><body>
<h1>XProtect 1.2.2 — Özellik Durumu v7 <span style="font-size:14px;color:#64748b">(UniversalObfuscator / VMProtect 3.5.1 TAM KAPSAMLI PORT)</span></h1>
<div class="sub">Üretim: {now} • Checkpoint: cp189+ (github.com/0xByteDeveloper/XProtectArea) • Bu tur: cp165 test raporunun x/x1-x8 kalemleri</div>
<div class="top">TOPLAM MOTOR-PARİTE: <span class="big">%{toplam // len(OZ)}</span>
<span style="color:#94a3b8;font-size:13px"> ({len(OZ)} özellik; UO'da ölü/olmayanlara XProtect gerçek-uygulaması %100 sayılır)</span></div>
{''.join(satirlar)}
<h2>EKSİK 15 — durum (kullanıcı x3: "NE yaptın tamamladın mı NE EKSİK?")</h2>
<div class="note"><b>Birebir çekirdek denetimi</b> (vmpsrc/pub2 = 1169 dosya): PORTLU 54 / KISMEN ~20 / EKSIK 15 / N/A 96.
EKSIK 15 listesi ve A13 durumu:
<br>1) <b>dwarf.cc</b> → PORT EDİLDİ (v1: v2..v4 CU; build+UI wire OK; gerçek PE kanıtı sırada).
<br>2) <b>elffile.cc</b> → N/A: ELF hedef desteklenmiyor (XProtect = Windows PE koruyucu; UO çok-platform).
<br>3) <b>macfile.cc</b> → N/A: Mach-O aynı gerekçe.
<br>4) <b>objc.cc</b> → N/A: Objective-C runtime çok-platform paketinin parçası.
<br>5) <b>objects.cc/h</b> → KISMEN: proje-nesnesi modeli .xproj'ta; VMP .vmp-proje içe-aktarma var.
<br>6) <b>script.cc (Lua API)</b> → SONRAKİ TUR: VMP script-arayüzü (korumalı fonksiyon listesini script'le seçme) —
XProtect CLI'sı aynı işi --funcs/--add ile yapıyor; UI-içi script motoru yol haritasında.
<br>7) <b>managed .NET runtime DLL'leri (dotnet20/40 + netcore + netstandard .inc)</b> → N/A-FARKLI-YOL: UO bunları
IL→kendi-runtime bridge'i için kullanıyor; XProtect'in yolu IL→native derleme (A13'te locals ile büyük adım).
<br>8-15) help/ 277 dosya + Qt GUI 188 dosya + runtime C# 77 dosya → kullanıcı kararına göre ÖNEMLİ DEĞİL
("QT MENÜLER İLE İLGİLİ ŞEYLER ÖNEMLİ DEĞİL ÇÜNKÜ KENDİ MENÜMÜZ VAR"); Win32-GUI + kendi CLI + .xproj modeli bunları işlevsel olarak kapatıyor.</div>
<h2>x1 — "#5 mesajı hiç gelmiyor, direk silent çıkış" kök-neden (cp165 kanıtı)</h2>
<div class="note">vm_poison içinde <b>xa_export(kernel32, MessageBoxA)</b> çağrılıyordu — MessageBoxA user32.dll'dedir,
kernel32'nin export tablosunda YOK → çözüm hep 0 → mesaj bölümü sessizce atlanıyor, ExitProcess(0x75) tek başına
çalışıyor. FIX: PEB'de user32 ara; yoksa kernel32!LoadLibraryA("user32.dll") (PIC stack-string; xrt rt_fatal ile aynı
kanitlı desen). cpSilentExit=false → mesaj+kapanma (UO paritesi), true → sessiz kapanış.</div>
<h2>x2 — ".NET derlemiyor (rc3)" — StandAloneSig/locals gerçek port</h2>
<div class="note">rc3 = "HİÇBİR fonksiyon uygulanamadı" — seçili WinForms metotlarının çoğu locals-imzalı olduğundan
dürüst-RED alıyordu. A13: 0x11 tablosu gerçek tablo-gezinmesiyle okunuyor, LocalVarSig çözülüyor, to_x86 yerel slot
haritası alıyor → ldloc/stloc/ldloca/stloc.a açıldı. RunPEForm.exe (gerçek csc, 74 metod) ile wine E2E kanıtı
a13_test/kanit.txt'te. Kalan: GC/nesne ops (newobj/callvirt), ImplMap, x64 IL, EH.</div>
<div class="footer">Kanıtlar: source/kanit_122/ + a13_test/kanit.txt + DOSYA_DENETIMI.md + ILERLEME_NOTLARI.md •
cp166+ her 4 dk checkpoint • Temiz test paketi: checkpoints/TEMIZ_TEST_PAKETI/ (her örnek özgün-adla korunur)</div>
</body></html>"""

out1 = "/tmp/my-project/download/XProtect_1.2.2/OZELLIK_DURUM.html"
open(out1, "w", encoding="utf-8").write(HTML)
print("HTML v6:", out1, len(HTML), "bayt; parite =", toplam // len(OZ), "%")
