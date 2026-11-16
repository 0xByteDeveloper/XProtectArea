
## 2026-11-16 05:00 — cp268: "HICBIR FONKSIYON UYGULANAMADI" KÖK-ONARIM
- KÖK: GUI derlemesi işaretli olmayan pdbscope listesini motora geçirmiyordu
  (motor yalnızca export/COFF/<hedef>.map keşfini okur → metin2client'ta 2
  export → "0 aday" → rc=3). CLI --all hep geçtiği için regresyonlara görünmüştü.
- FIX 1 (UI): write_engine_map — derleme öncesi tarama listesi LINK-map
  biciminde <hedef>.map olarak yazılır (VA→RVA imagebase-normalizasyonu,
  ezme-yasak, exec-bölge filtresi) → motorun mevcut +PDB/MAP yolu devreye girer.
- FIX 2 (UI): işaretsiz-liste istemi "Compile ALL suitable functions?" artık
  liste boş DEĞİL hiçbir fonksiyon işaretli değilken de çıkar.
- FIX 3 (motor): yol-ayracı taşınabilir (host-kanıt için; WIN32 davranışı aynı).
- HOST KANIT: metin2client.exe — before: 0 aday rc=3; after: +PDB/MAP=15078 →
  [FONKSIYON] 15078 aday → LIFT 7462/15071 V=15071 → KAYIT m2_fix.exe
  (8953856 bayt, .vmp0 eklendi, EP korundu) rc=0.
- Sorumlu dosyalar: xprotect_ui.cpp (write_engine_map + istem), engine_main.cpp
  (sep), host_cli.cpp (yeni: host-kanıt koşucusu).
