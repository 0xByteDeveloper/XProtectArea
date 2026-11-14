TEMİZ TEST PAKETİ (1.2.5-A13, cp166 turu)
==========================================
KURAL (kullanici x7e): her denemede kullanicilan ornek exe'yi AYRI isimle
koru — korunmus ciktilar ornekleri ezmesin (cift-koruma testleri
yaniltici oluyor). Her oturum bu klasore temiz kopyayi birakir.

metin2client.exe        — temiz C++ hedef (x86, ImageBase 0x400000;
                          0xd7610 Damage / 0xE96D0 vtable-thiscall)
metin2client_vmp3.exe   — kullanicinin UO(VMP 3.5.1) ciktisi (parite kiyasi)
RunPEForm.exe           — GERCEK csc C# WinForms benzeri cikti (74 metod;
                          x2/.NET locals testi icin temiz kopya)

Korunmus ciktilar ASLA buraya yazilmaz; test dizini kullanilir.
