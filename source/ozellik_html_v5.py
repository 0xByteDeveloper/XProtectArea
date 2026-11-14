#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ozellik_html_v5.py — XProtect 1.2.2 özellik-durum sayfası v5 (cp142 test-turu)
Kullanıcı talimatı: 'en sonda bana HTML yap özellikleri liste halinde göreyim
ne ne kadar eksik alt alta sırala progressbar ile % şu kadar var'
v5 ekleri: .NET gerçek-csc fixleri (%82→%88), VEH-path mesaj-paritesi (x1),
Silent Exit seçeneği (x2), UI UX fixleri (x4/x5), dwarf portu başlangıcı (x3)."""
import html, datetime

OZ = [
    ("Virtualization (x86+x64)", 90,
     "MiniVM özgün yorumlayıcı; OP_JMPEXT/OP_JCCEXT dış-akış; mult-VM vmn=4+vmadv kanıtı (B1 OK hepsi); OP_NCALLI 0x44",
     "UO'nun ters-yön okuma + komut-klonlama; ISA uzun-kuyruk"),
    ("Mutation", 80,
     "yönlü mutasyon + ikame + kapılar (kanıt: 92B→207B); U-kaynak mutasyonu",
     "şablon çeşitliliği (UO ~70 şablon)"),
    ("Ultra (M+V)", 100,
     "mutasyon(lift(IL)) zinciri; R1 ULTIMATE kanıtı 'OK hepsi'; metin2 D7610 kanıt",
     "—"),
    ("Encrypt ByteCode", 95,
     "VM_MIX OP-ZİNCİRİ (4 karışim ailesi) + VM_KSC CFB + VM_KSCA + fonksiyon-başı key; R1/TLS+PACK/MULT-VM yeşil",
     "UO'nun 100-op'a kadar zincir uzunluğu + handler-bası rastgeleleşme"),
    ("Encrypt Registers", 100,
     "VM register-dosyası şifreli + epoch rotasyonu (UO'da ÖLÜ bayrak — XProtect AŞAR)",
     "—"),
    ("Check Debugger", 92,
     "K1-K9 + OP_CHKRET + x1 FIX: VM tespit yolları (26 site: ANTIDBG/CHKRET/K7) artık cfg'ye uyar — VEH-debugger'da da mesaj+kapanma (UO history.htm:492 paritesi; eski: sessiz zehir)",
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
     "tam loader-IAT çözümleme (UO ftImport)"),
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
     "dword/W/enum yolundaki argüman bozulması"),
    ("Licensing (RSA+HWID)", 75,
     "xrt_license + keygen; test_liz kanıtı",
     "UO anahtar-dosya format paritesi"),
    ("SDK markers", 90,
     "B8 imza ailesi + JMPEXT/JCCEXT; R1 kanıtı 3/3",
     "—"),
    ("MAP/PDB fonksiyon-bulma (PDBScope)", 96,
     "pdbscope pakette; metin2 30.078 fonksiyon; x4-1 DATA/LABEL/INLINE filtresi; x4-2 arama kutusu: isim + HEX-RVA ('d7610'/'sub_5123') canlı filtre",
     "x86 pdbscope binary (bin/win32)"),
    ("Strip Fixups / Debug Info", 90,
     "reloc temizliği + debug dizini; R4 TLS kanıtı",
     "—"),
    (".NET (il.cc + dotnetfile portu)", 88,
     "cp142 TURU 5 KÖK-NEDEN FIX: PE32 DD offset 0x60 (eski 0x48=stack-reserve!), root Flags(2), popcount satır-sayısı (23 tablo), Module-genişlik KALİBRASYONU (4/6/8/10), EH hizalama quirk'i (+4, sane-dsz, EH-BELİRSİZ). Kanıt: RunPEForm.exe (gerçek csc) = 15 typedef/74 metod gerçek adlar (PayloadLoader::LoadFromVBFile, RunPE::InjectCode rva 0x2264 eh=2); minidn+minidn_fat PASSED",
     "locals/StandAloneSig (ldloc/stloc), GC/nesne ops, ImplMap, x64 IL derleyici"),
    ("DWARF (dwarf.cc portu) — x3 BAŞLADI", 15,
     "xprotect_dwarf.h/.cpp: .debug_info/.debug_abbrev/.debug_str → DW_TAG_subprogram low/high/name (v2..v4 CU); MinGW -g PE'lerde PDB'siz keşif hedefi",
     "wire (engine+UI) + test + v5/ranges/DWARF64"),
    ("UI UX (x4/x5)", 95,
     "Silent Exit kutusu (cpSilentExit); fonksiyon listesi DATA/LABEL/INLINE filtresi; arama: isim+hex-RVA canlı filtre; Property: value tam-satır seçimi + SPACE/RETURN toggle",
     "klavye navigasyon genişletme (açılır menüler)"),
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
<title>XProtect 1.2.2 — Özellik Durumu v5 (TAM KAPSAMLI PORT)</title>
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
.note {{ background:#1e293b; border-left:4px solid #38bdf8; padding:10px 14px; border-radius:6px; font-size:13px; line-height:1.6; }}
.footer {{ color:#64748b; font-size:11px; margin-top:16px; }}
</style></head><body>
<h1>XProtect 1.2.2 — Özellik Durumu v5 <span style="font-size:14px;color:#64748b">(UniversalObfuscator / VMProtect 3.5.1 TAM KAPSAMLI PORT)</span></h1>
<div class="sub">Üretim: {now} • Checkpoint: cp149+ (github.com/0xByteDeveloper/XProtectArea) • Bu tur: cp142 test raporunun x/x1-x6 kalemleri</div>
<div class="top">TOPLAM MOTOR-PARİTE: <span class="big">%{toplam // len(OZ)}</span>
<span style="color:#94a3b8;font-size:13px"> ({len(OZ)} özellik; UO'da ölü/olmayanlara XProtect gerçek-uygulaması %100 sayılır)</span></div>
{''.join(satirlar)}
<h2>x — ".NET hâlâ aynı" kök-nedenleri (RunPEForm.exe ile teşhis)</h2>
<div class="note">cp142'deki minidn testleri sentezleyicinin kendi hatalarıyla self-consistent'tı; GERÇEK csc çıktısı 5 farklı
kırıldı: (1) PE32 DataDirectory 0x4C yerine <b>0x60</b> (0x48 = SizeOfStackReserve — "CLR yok" sanılıyordu),
(2) metadata root Flags(2) alanı atlanıyordu, (3) satır-sayısı dizisi <b>tüm</b> valid tabloları kapsar (23 tablo → popcount),
(4) Module satır genişliği üreticiye göre 4/6/8/10 (kalibrasyon), (5) EH bölümü bazı üreticilerde kod-sonu+4'te (sane-dsz aday
araması). Hepsi fixlendi; RunPEForm.exe artık <b>74 metodun gerçek adlarıyla</b> listeleniyor. "2 fonksiyon + hatalı size" =
pdbscope'un IL'i-x86-sanan çöp listesiydi; gerçek MethodDef listesi artık onun yerine geçiyor.</div>
<h2>x1 — VEH debugger'da mesaj yok</h2>
<div class="note">VM tespit yolları (OP_ANTIDBG bataryası, OP_CHKRET int3/ud2 dönüş-adresi, K7) eskiyalarda sadece
done=2 (sessiz zehir) yapıyordu → "fonksiyonun kullanımı duruyor". Artık <b>vm_poison()</b> cfg'ye uyar: mesaj kutusu
("butunluk kontrol kod = #5") + ExitProcess(0x75) — Windows debugger'daki davranışın aynısı, UO/VMP paritesi
(help/en/history.htm:492). Silent Exit (x2) kutusu true ise mesaj YOK, sessiz kapanış.</div>
<div class="footer">Kanıtlar: source/kanit_122/ + DOSYA_DENETIMI.md + ILERLEME_NOTLARI.md • cp149+ her 4 dk checkpoint •
".NET %88": gerçek-csc keşfi tam; derleme kapsamı locals/GC/x64-IL sonrası genişleyecek</div>
</body></html>"""

out1 = "/tmp/my-project/download/XProtect_1.2.2/OZELLIK_DURUM.html"
open(out1, "w", encoding="utf-8").write(HTML)
print("HTML v5:", out1, len(HTML), "bayt; parite =", toplam // len(OZ), "%")
