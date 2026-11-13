/* ============================================================
 * xr_cipher.h — 0.8.0 SectionCryptor ortak şifre sözleşmesi
 * Motor (engine_pack.cpp, C++) ve runtime (xrt_core.c, C freestanding)
 * AYNI kodu kullanır. Tek kaynak; iki tarafı asla ayrı düzenleme.
 *
 * Tasarım: CFB-64 akış şifresi (VM'deki crypt_command/key ile aynı
 * tasarım dili):
 *   ks_i   = E(K, state_i)          E = 4 tur Feistel64 + splitmix64
 *   C_i    = P_i ^ ks_i             (şifre çözme = aynı formül)
 *   state_{i+1} = C_i               (şifre-geribesleme: tamper yayılımı)
 *   nonce  = f(k0, dst_rva)         (kayıt-bağı: akış yer değiştirme /
 *                                    çapraz-splice imkânsız)
 * Uzunluk: XPK1 kaydına srcsz eklendi (12B -> 16B kayıt).
 * Anahtar: cfg 0x50/0x58'de m ile maskeli (m = xr_mix64(cfg_rva^T)).
 * Tablosuz, dal-tablosuz, PIC-güvenli (runtime blob'u freestanding).
 * ============================================================ */
#ifndef XR_CIPHER_H
#define XR_CIPHER_H

/* splitmix64 finalizer — tablosuz 64B karıştırıcı */
static unsigned long long xr_mix64(unsigned long long x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

/* 4 tur Feistel64 — yalnız İLERİ yön (CFB için ters gerekmez) */
static unsigned long long xr_block(unsigned long long k0, unsigned long long k1,
                                   unsigned long long blk) {
    unsigned int L = (unsigned int)blk;
    unsigned int R = (unsigned int)(blk >> 32);
    unsigned int i;
    for (i = 0; i < 4; i++) {
        unsigned long long kk = (i & 1) ? k1 : k0;
        unsigned int f = (unsigned int)(xr_mix64(kk + ((unsigned long long)R * 0x9E3779B1ULL)) >> 32);
        unsigned int t = L ^ f;
        L = R; R = t;
    }
    return ((unsigned long long)R << 32) | (unsigned long long)L;
}

/* CFB-64 uygula. dec=0: sifreleme (p: duz->sifreli); dec=1: cozme
 * (p: sifreli->duz). GERI BESLEME HER ZAMAN SIFRELI BLOKTUR:
 *   sifreleme tarafinda cikis (XOR sonrasi), cozme tarafinda GIRIS
 *   (XOR oncesi). In-place tek fonksiyonda yön bilgisi olmadan geri
 *   besleme, cozme tarafinda düz metinden alinir ve akis 1. bloktan
 *   sonra saptar (0.8.0 bulgusu: ilk 8 bayt özdeş, sonrası çöp). */
static void xr_cfb(unsigned long long k0, unsigned long long k1,
                   unsigned long long nonce, unsigned char* p, unsigned int n,
                   int dec) {
    unsigned long long st = nonce;
    unsigned int off = 0;
    while (off < n) {
        unsigned long long ks = xr_block(k0, k1, st);
        unsigned char kb[8], sv[8];
        unsigned int j, m = n - off, q;
        if (m > 8) m = 8;
        for (q = 0; q < 8; q++) {
            kb[q] = (unsigned char)(ks >> (8 * q));
            sv[q] = p[off + q];              /* XOR öncesi (giriş) */
        }
        for (j = 0; j < m; j++) p[off + j] ^= kb[j];
        {   /* geribesleme = sifreli blok: sifrelemede cikis, cozmede giris */
            unsigned long long fb = 0;
            for (q = 0; q < 8; q++) {
                unsigned char c = (off + q < n)
                    ? (dec ? sv[q] : p[off + q]) : 0;
                fb |= (unsigned long long)c << (8 * q);
            }
            st = fb;
        }
        off += m;
    }
}

/* kayıt-bağı nonce: dst_rva ile türet (motor ve runtime aynı formül) */
#define XRC_NONCE(k0, dstrva) \
    ((k0) ^ 0x5854505343525950ULL ^ (unsigned long long)(unsigned int)(dstrva))

/* cfg anahtar maskesi: cfg_rva'dan türet (cfg içinde CFGRVA 0x3C'te var) */
#define XRC_KEYMASK(cfgrva)  (xr_mix64((unsigned long long)(unsigned int)(cfgrva) ^ 0x5EC7B10BULL))

/* cfg alanları (XCFG_SIZE_E=0x60 sözleşmesi): */
#define XRC_CFG_FLAG   0x4C    /* u32: 1 = akışlar şifreli */
#define XRC_CFG_KEY0   0x50    /* u64 maskeli (XRC_KEYMASK) */
#define XRC_CFG_KEY1   0x58    /* u64 maskeli */
#define XRC_HDR_FLAG   12      /* XPK1 header +12 (eski 'rezerve'): 1 = şifreli */

/* ============================================================
 * 1.2.2-A16: Virtual Files (cpVirtualFiles) — ortak sözleşme.
 * Düzen: cfg'nin hemen ardından (cfg+0x60):
 *   [0]  u32 magic 'XVF1' (0x31565658)
 *   [4]  u32 count
 *   [8]  u32 names_off  (bloğa göre)
 *   [12] u32 data_off    (bloğa göre)
 *   [16] entries: count × 16B {name_off, data_off, size, action}
 *         action: 1=faLoad (bellekte yükle) 2=faRegister 3=faInstall
 *   [...] isimler: UTF-16LE, UO InternalFile::WriteName 1:1:
 *         w[i] ^ (u16)(_rotl32(key, i) + i), key = xvf_namekey(cfg,idx)
 *   [...] veri: xr_cfb(k0,k1,nonce) ile şifreli dosya baytları
 * Anahtarlar cfg_rva'dan türetilir (motor ve runtime aynı formül).
 * ============================================================ */
#define XVF_HDR_MAGIC 0x31565658u               /* 'XVF1' */
#define XVF_MAX_FILES 64
#define XVF_MAX_SIZE  0x04000000ull             /* dosya başına 64MB */

static unsigned long long xvf_k0(unsigned int cfg_rva) {
    return xr_mix64((unsigned long long)cfg_rva ^ 0xA5A5A5A5A5A5A5A5ull);
}
static unsigned long long xvf_k1(unsigned int cfg_rva) {
    return xr_mix64((unsigned long long)cfg_rva ^ 0x5A5A5A5A5A5A5A5Aull);
}
static unsigned long long xvf_nonce(unsigned int data_off) {
    return xr_mix64((unsigned long long)data_off ^ 0xC0FFEE00ull);
}
/* isim anahtarı: cfg + indeks karışımı (her iki taraf aynı) */
static unsigned int xvf_namekey(unsigned int cfg_rva, unsigned int idx) {
    return (unsigned int)xr_mix64(((unsigned long long)cfg_rva << 32)
                                   ^ ((unsigned long long)(idx + 1) * 0x9E3779B9ull)
                                   ^ 0x1B873593D5ull);
}

#endif /* XR_CIPHER_H */
