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
