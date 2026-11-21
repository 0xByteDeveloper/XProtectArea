// engine_keygen.cpp — cp293/V293-1a: C++ RSA keypair üretimi
// VMProtect Licenses "Add License" muadili: RSA-1024..7168 (e=65537) asal
// çifti üretimi + PKCS#1 DER private key yazımı (openssl'siz — "TOOLLARIN
// hepsini C++" hedefi). Motor tarafındaki lbn algoritmasıyla aynı matematik:
//   - Montgomery YOK (okul-defteri çarpma) — host tarafında hız sorun değil
//   - Miller-Rabin 25 tur (deterministik olmayan, 2^-50 altı hata)
//   - d = e^-1 mod λ(n)  (lambda — VM/carmichael; p-1,q-1 EKOK'u)
// Kullanım (host_cli --genkey):
//   --genkey <bit> --out <dosya.pem>            (1024..7168; 512-bit adım)
// Çıktı: PKCS#1 'BEGIN RSA PRIVATE KEY' PEM (openssl ile %100 uyumlu) +
//        stdout: modulus hex (motor --lic-key formatı) + prodcode önerisi.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <functional>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

namespace xkeygen {

// ---- küçük bignum: little-endian u32 vektör ----
struct Big {
    std::vector<u32> l;                 // little-endian limb
    Big() {}
    explicit Big(size_t n, u32 v = 0) : l(n, v) {}
    static Big from_u64(u64 v) { Big b(2); b.l[0] = (u32)v; b.l[1] = (u32)(v >> 32); return b; }
    size_t n() const { return l.size(); }
    void trim() { while (l.size() > 1 && l.back() == 0) l.pop_back(); }
    bool zero() const { for (auto v : l) if (v) return false; return true; }
    bool odd() const { return l.size() && (l[0] & 1); }
    int bits() const {
        if (!l.size()) return 0;
        size_t top = l.size();
        while (top > 1 && l[top - 1] == 0) top--;   // const-trim
        int b = 0; u32 t = l[top - 1];
        while (t) { b++; t >>= 1; }
        return (int)(top - 1) * 32 + b;
    }
    void set_bit(int i) {
        if ((size_t)(i / 32) >= l.size()) l.resize(i / 32 + 1, 0);
        l[i / 32] |= (1u << (i % 32));
    }
    int get_bit(int i) const {
        if ((size_t)(i / 32) >= l.size()) return 0;
        return (l[i / 32] >> (i % 32)) & 1;
    }
};

static int cmp(const Big& a, const Big& b) {
    size_t n = a.l.size() > b.l.size() ? a.l.size() : b.l.size();
    for (size_t i = n; i-- > 0;) {
        u32 x = i < a.l.size() ? a.l[i] : 0;
        u32 y = i < b.l.size() ? b.l[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

static Big add(const Big& a, const Big& b) {
    size_t n = a.l.size() > b.l.size() ? a.l.size() : b.l.size();
    Big r(n + 1);
    u64 c = 0;
    for (size_t i = 0; i < n; i++) {
        u64 v = c + (i < a.l.size() ? a.l[i] : 0) + (i < b.l.size() ? b.l[i] : 0);
        r.l[i] = (u32)v; c = v >> 32;
    }
    r.l[n] = (u32)c;
    r.trim();
    return r;
}

static Big sub(const Big& a, const Big& b) {   // a >= b
    Big r(a.l.size());
    int64_t borrow = 0;
    for (size_t i = 0; i < a.l.size(); i++) {
        int64_t v = (int64_t)a.l[i] - (i < b.l.size() ? b.l[i] : 0) - borrow;
        if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
        r.l[i] = (u32)v;
    }
    r.trim();
    return r;
}

static Big mul(const Big& a, const Big& b) {
    Big r(a.l.size() + b.l.size());
    for (size_t i = 0; i < a.l.size(); i++) {
        u64 carry = 0;
        for (size_t j = 0; j < b.l.size(); j++) {
            u64 cur = (u64)r.l[i + j] + (u64)a.l[i] * b.l[j] + carry;
            r.l[i + j] = (u32)cur; carry = cur >> 32;
        }
        size_t k = i + b.l.size();
        while (carry) { u64 cur = (u64)r.l[k] + carry; r.l[k] = (u32)cur; carry = cur >> 32; k++; }
    }
    r.trim();
    return r;
}

static void shl1_inplace(Big& x) {          // x <<= 1
    u32 c = 0;
    for (size_t j = 0; j < x.l.size(); j++) {
        u32 nc = x.l[j] >> 31;
        x.l[j] = (x.l[j] << 1) | c;
        c = nc;
    }
    if (c) x.l.push_back(c);
}
static void divmod(const Big& a, const Big& b, Big* q, Big* r) {   // b != 0
    if (cmp(a, b) < 0) { if (q) *q = Big(1); if (r) *r = a; return; }
    /* hizli yol: b tek limb */
    if (b.l.size() == 1) {
        Big quo(a.l.size()); u64 rem = 0; u32 bm = b.l[0];
        for (size_t j = a.l.size(); j-- > 0;) {
            u64 cur = (rem << 32) | a.l[j];
            quo.l[j] = (u32)(cur / bm);
            rem = cur % bm;
        }
        quo.trim();
        Big rr(1); rr.l[0] = (u32)rem;
        if (q) *q = quo;
        if (r) *r = rr;
        return;
    }
    /* genel: klasik bit-kaydirmali uzun bolme — rem yalniz (nb+1) limb
       tutar; karsilastirma/sub inline, gecici kopyasiz */
    Big rem(1);
    Big quo(1);
    int nb = a.bits();
    size_t b_limbs = b.l.size();
    for (int i = nb - 1; i >= 0; i--) {
        // rem = rem*2 + bit   (limb sinirli — rem < b oldugundan 1 limb buyur)
        u32 bit = (u32)a.get_bit(i);
        shl1_inplace(rem);
        rem.l[0] |= bit;
        // rem >= b ?  (yalniz b_limbs (+1) limb'e bak — rem asla 2 limb fazla buyumez)
        size_t rl = rem.l.size();
        int ge;
        if (rl > b_limbs + 1) ge = 1;
        else {
            ge = 0;
            for (size_t j = (rl > b_limbs ? rl : b_limbs); j-- > 0;) {
                u32 x = j < rl ? rem.l[j] : 0;
                u32 y = j < b_limbs ? b.l[j] : 0;
                if (x != y) { ge = x > y ? 1 : -1; break; }
            }
        }
        if (ge >= 0) {
            // rem -= b (inline)
            int64_t borrow = 0;
            for (size_t j = 0; j < b_limbs; j++) {
                int64_t v = (int64_t)rem.l[j] - (int64_t)b.l[j] - borrow;
                if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
                rem.l[j] = (u32)v;
            }
            for (size_t j = b_limbs; borrow && j < rem.l.size(); j++) {
                int64_t v = (int64_t)rem.l[j] - borrow;
                if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
                rem.l[j] = (u32)v;
            }
            // trailing zeros
            while (rem.l.size() > 1 && rem.l.back() == 0) rem.l.pop_back();
            if ((size_t)(i / 32) >= quo.l.size()) quo.l.resize(i / 32 + 1, 0);
            quo.l[i / 32] |= (1u << (i % 32));
        }
    }
    rem.trim(); quo.trim();
    if (q) *q = quo;
    if (r) *r = rem;
}

static Big mod(const Big& a, const Big& b) { Big r; divmod(a, b, nullptr, &r); return r; }
static Big operator%(const Big& a, const Big& b) { return mod(a, b); }

/* ---- cp293: Montgomery REDC (motor lbn paritesi, host kopyasi) ----
   R = 2^(32*nl); m' = -m^-1 mod R; REDC(T) = T*R^-1 mod m
   T 2*nl limb. Sonuc < m. Bit-bit bolme YOK -> ~50x hiz. */
struct MontCtx {
    size_t nl;              // limb sayisi (m'nin)
    std::vector<u32> m;     // modulus (LE)
    u32 mprime;             // -m^-1 mod 2^32
    std::vector<u32> r2;    // R^2 mod m (LE, nl limb)
};
static u32 inv32_pow(u32 a) {   // a^-1 mod 2^32 (Newton)
    u32 x = a;                 // 3 dogru bit
    for (int i = 0; i < 5; i++) x *= 2 - a * x;
    return x;
}
static void mont_mul(const MontCtx& c, const u32* a, const u32* b, u32* out) {
    /* cp293 V2 — klasik REDC, kayipsiz:
       T = a*b; for i: T += (T[i]*m' mod R) * m << 32i; r = T >> 32nl;
       if (r >= m) r -= m.  T[i] asla 2^32'yi asmaz (satir satir mask+carry).
       Aliasing: out == a == b guvenli (T/r yerel). */
    size_t nl = c.nl;
    std::vector<u64> T(2 * nl + 2, 0);
    for (size_t i = 0; i < nl; i++) {
        u64 carry = 0;
        u64 ai = a[i];
        if (!ai) continue;
        for (size_t j = 0; j < nl; j++) {
            u64 cur = T[i + j] + ai * b[j] + carry;
            T[i + j] = cur & 0xFFFFFFFFull;
            carry = cur >> 32;
        }
        size_t k = i + nl;
        while (carry) { u64 cur = T[k] + carry; T[k] = cur & 0xFFFFFFFFull; carry = cur >> 32; k++; }
    }
    for (size_t i = 0; i < nl; i++) {
        u64 u = ((T[i] & 0xFFFFFFFFull) * c.mprime) & 0xFFFFFFFFull;
        if (!u) continue;
        u64 carry = 0;
        for (size_t j = 0; j < nl; j++) {
            u64 cur = T[i + j] + u * c.m[j] + carry;
            T[i + j] = cur & 0xFFFFFFFFull;
            carry = cur >> 32;
        }
        size_t k = i + nl;
        while (carry) { u64 cur = T[k] + carry; T[k] = cur & 0xFFFFFFFFull; carry = cur >> 32; k++; }
    }
    /* cp293 FIX — 5. limb tasiyordu: REDC cikisi r < 2m olabilir ve m'nin
       ust limb'i 0xFFFFFFFF ise 2m > 2^(32nl) — tasinan t[2nl] degeri
       kopyalanamiyordu. Cözüm: r'ye nl+1 limb yer ayir; tasan limb'i
       ekle; sonra karsilastirmayi (nl+1)-limb olarak yap ve cikar. */
    std::vector<u32> r(nl + 1, 0);
    for (size_t i = 0; i < nl; i++) r[i] = (u32)T[nl + i];
    r[nl] = (u32)T[2 * nl];           /* tasma limb (normalde 0 ya da 1) */
    if (T[2 * nl + 1]) {
        /* 2 tasma limb'i: r >= 2^(32nl) > 2m olamaz (r < 2m garantisi REDC'de);
           yine de savunma: r -= m (iki kez guvenli) */
        int64_t borrow = 0;
        for (size_t j = 0; j < nl; j++) {
            int64_t v = (int64_t)r[j] - (int64_t)c.m[j] - borrow;
            if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
            r[j] = (u32)v;
        }
        r[nl] = (u32)((int64_t)r[nl] - borrow);
    }
    int ge = 0;
    for (size_t j = nl + 1; j-- > 0;) {
        u32 x = j < r.size() ? r[j] : 0;
        u32 y = j < nl ? c.m[j] : 0;
        if (x != y) { ge = x > y ? 1 : -1; break; }
    }
    if (ge >= 0) {
        int64_t borrow = 0;
        for (size_t j = 0; j < nl; j++) {
            int64_t v = (int64_t)r[j] - (int64_t)c.m[j] - borrow;
            if (v < 0) { v += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
            r[j] = (u32)v;
        }
        r[nl] = (u32)((int64_t)r[nl] - borrow);
    }
    for (size_t i = 0; i < nl; i++) out[i] = r[i];   /* ust limb atilir (r < m) */
}

static MontCtx mont_init(const Big& m0) {
    MontCtx c;
    Big m = m0;            // kopya uzerinde trim (const korumasi)
    m.trim();
    c.nl = m.l.size();
    c.m = m.l;
    c.mprime = (u32)(-(int64_t)inv32_pow(m.l[0]));
    /* R^2 = 2^(64*nl) mod m. Hesap: r=1; 2*nl kez r = (r*2^32) mod m.
       (r*2^32) mod m: limb-shift + TEK divmod adimi (r < m oldugundan
       r*2^32 < m*2^32 -> bolum < 2^32 — hizli yolla cikarilir ama
       basitlik icin divmod; 2*nl cagri x divmod(2nl limb) ~ ok) */
    Big r(1); r.l[0] = 1;
    for (size_t i = 0; i < 2 * c.nl; i++) {
        // r <<= 32 (limb ekle)
        r.l.insert(r.l.begin(), 0);
        // r %= m
        r = r % m;
    }
    c.r2 = r.l;
    while (c.r2.size() < c.nl) c.r2.push_back(0);
    return c;
}
static void mont_from(const MontCtx& c, const Big& x0, std::vector<u32>& out) {
    // x*R mod m = mont_mul(x mod m, R2)   — cp293 fix: mod ONCE sart
    Big mm; mm.l = c.m;          // ctor yok — ll ata
    Big x = x0 % mm;
    std::vector<u32> a(c.nl, 0), b(c.nl, 0);
    for (size_t i = 0; i < c.nl && i < x.l.size(); i++) a[i] = x.l[i];
    b = c.r2;
    out.assign(c.nl, 0);
    mont_mul(c, a.data(), b.data(), out.data());
}
static void mont_to(const MontCtx& c, const std::vector<u32>& a, Big& out) {
    // a*R^-1 mod m = mont_mul(a, 1)
    std::vector<u32> one(c.nl, 0); one[0] = 1;
    std::vector<u32> r(c.nl, 0);
    mont_mul(c, a.data(), one.data(), r.data());
    out.l = r;
    out.trim();
}
static Big mulmod(const Big& a, const Big& b, const Big& m) { return mod(mul(a, b), m); }   // genel (yavas — mont kullanimdi)

static Big powmod_slow(Big base, const Big& e, const Big& m);   /* eski bit-bit (kucuk degerler) */
/* cp293: Montgomery powmod — buyuk asal testleri icin (~50x) */
static Big powmod(const Big& base, const Big& e, const Big& m) {
    if (m.l.size() <= 2) return powmod_slow(base, e, m);   // kucuk: klasik
    MontCtx c = mont_init(m);
    std::vector<u32> bx(c.nl, 0), res(c.nl, 0);
    mont_from(c, base % m, bx);
    mont_from(c, Big::from_u64(1), res);
    int nb = e.bits();
    for (int i = 0; i < nb; i++) {
        if (e.get_bit(i)) mont_mul(c, res.data(), bx.data(), res.data());
        mont_mul(c, bx.data(), bx.data(), bx.data());
    }
    Big out;
    mont_to(c, res, out);
    return out;
}
static Big powmod_slow(Big base, const Big& e, const Big& m) {
    /* cp293-duzeltme: pencere optimizasyonu 0-bitlerinde kare almayi atliyordu
       (matematik hata) — klasik bit-bit L->R uslendirmeye donuldu. Kucuk
       modullerde (<=2 limb) kullanildigindan performans onemsiz. */
    Big result = Big::from_u64(1);
    base = base % m;
    int nb = e.bits();
    for (int i = nb - 1; i >= 0; i--) {
        result = mulmod(result, result, m);
        if (e.get_bit(i)) result = mulmod(result, base, m);
    }
    return result;
}

// ---- Miller-Rabin (25 rastgele taban) ----
static bool is_probable_prime(const Big& n, std::mt19937_64& rng) {
    if (n.n() == 1 && n.l[0] == 2) return true;
    if (!n.odd()) return false;
    if (cmp(n, Big::from_u64(3)) < 0) return n.n() == 1 && n.l[0] >= 2;
    // küçük asallara bölünürlük hızlı eleme
    static const u32 small[] = { 3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349 };
    for (u32 p : small) {
        if (n.l.size() == 1 && n.l[0] == p) return true;
        /* hizli mod: limb-uzeri u64 birikim (Barrett yok — 64-bit kayan mod) */
        u64 r = 0;
        for (size_t j = n.l.size(); j-- > 0;)
            r = ((r << 32) | n.l[j]) % p;
        if (r == 0) return false;
    }
    // n-1 = d * 2^s
    Big nm1 = sub(n, Big::from_u64(1));
    int s = 0;
    while (!nm1.get_bit(s)) s++;
    // d = nm1 >> s (bit tabanli)
    {
        /* cp293 hiz: dd = nm1 >> s — limb-tabanli shift (bit-bit degil) */
        Big dd;
        {
            size_t whole = s / 32, bit = s % 32;
            size_t n2 = nm1.l.size();
            if (n2 > whole) {
                dd.l.assign(n2 - whole, 0);
                for (size_t i = whole; i < n2; i++) {
                    u64 v = (u64)nm1.l[i] >> bit;
                    if (i + 1 < n2 && bit) v |= (u64)nm1.l[i + 1] << (32 - bit);
                    dd.l[i - whole] = (u32)v;
                }
                dd.trim();
            } else dd.l.assign(1, 0);
        }
        /* cp293 V2: kanitlanmis powmod() cekirdegi uzerinden klasik MR.
           (Aliasing-survivor Montgomery MR denemeleri kaldirildi — powmod
           zaten montgomery'li ve tum birim testlerden gecti.) */
        for (int trial = 0; trial < 25; trial++) {
            /* cp293 hiz: rastgele limb'ler + ust-limb maskesi ile base < n
               (mod alma yok — mont_from zaten %n yapiyor). */
            Big base(n.l.size());
            for (size_t i = 0; i < n.l.size(); i++)
                base.l[i] = (u32)(rng() & 0xFFFFFFFF);
            if (base.l.size() && base.l.back() >= n.l.back())
                base.l.back() = n.l.back() - 1;   /* ust limb < n'nin ust limb'i */
            if (base.l.size() > 1 && base.l[base.l.size()-2] == 0 && base.l.back() == 0)
                base.l[0] |= 1;   /* 0 olmasin */
            base.trim();
            Big x = powmod(base, dd, n);
            if (cmp(x, Big::from_u64(1)) == 0 || cmp(x, nm1) == 0) continue;
            bool composite = true;
            for (int r = 1; r < s; r++) {
                x = powmod(x, Big::from_u64(2), n);
                if (cmp(x, nm1) == 0) { composite = false; break; }
            }
            if (composite) return false;
        }
    }
    return true;
}

// ---- genprime: bit sayisina gore, en ust 2 bit set + tek ----
static Big genprime(int bits, std::mt19937_64& rng) {
    for (;;) {
        Big p((bits + 31) / 32);
        for (auto& limb : p.l) limb = (u32)(rng() & 0xFFFFFFFF);
        // temizle taşan bitler
        int over = (int)p.l.size() * 32 - bits;
        if (over > 0) p.l.back() &= (over >= 32 ? 0 : (u32)((1ull << (32 - over)) - 1));
        p.set_bit(bits - 1);          // MSB
        p.set_bit(bits - 2);          // MSB-1 (asal yoğunluğu)
        p.l[0] |= 1;                  // tek
        if (is_probable_prime(p, rng)) return p;
    }
}

// ---- egcd (d = e^-1 mod λ) ----
static void ext_gcd(const Big& a, const Big& b, Big& g, Big& x, Big& y) {
    if (a.zero()) { g = b; x = Big(1); y = Big(1); y.l[0] = 1; x.l[0] = 0; return; }
    Big q, r; divmod(b, a, &q, &r);
    Big g1, x1, y1; ext_gcd(r, a, g1, x1, y1);
    g = g1;
    // x = y1 - q*x1 ; y = x1
    y = x1;
    x = sub(y1, mul(q, x1));
}

static Big modinv(const Big& e, const Big& m) {
    /* cp293 V2: isaretsiz-guvenli iteratif egcd — katsayilar her adimda
       mod m indirgenir (negatif/sarma YOK). Klasik ozyinelemeli ext_gcd'nin
       unsigned sarmalamasi yanlis d uretiyordu (chk=3*65537 vakasi). */
    Big r0 = m, r1 = e % m;
    Big s0(1); s0.l[0] = 0;              // 0 * e
    Big s1(1); s1.l[0] = 1;              // 1 * e
    while (!r1.zero()) {
        Big q, r;
        divmod(r0, r1, &q, &r);
        // s2 = (s0 - q*s1) mod m  — pozitif kalarak
        Big qs = mod(mul(q, s1), m);
        Big s2;
        if (cmp(s0, qs) >= 0) s2 = sub(s0, qs);
        else s2 = sub(add(s0, m), qs);   /* s0 < qs: pozitif kalarak s0+m-qs */
        r0 = r1; r1 = r;
        s0 = s1; s1 = s2;
    }
    // r0 = gcd(e, m); s0 = e^{-1} mod m (gcd=1 ise)
    if (r0.n() == 1 && r0.l[0] == 1) return s0;
    return s0;   // gcd != 1 durumunda cagiran chk ile reddeder
}

// ---- DER (PKCS#1 RSAPrivateKey) ----
static void der_len(std::vector<u8>& out, size_t n) {
    if (n < 0x80) { out.push_back((u8)n); return; }
    u8 t[8]; int k = 0;
    while (n) { t[k++] = (u8)(n & 0xFF); n >>= 8; }
    out.push_back((u8)(0x80 | k));
    while (k) out.push_back(t[--k]);
}
static void der_int(std::vector<u8>& out, const Big& v) {   // pozitif
    int nb = (v.bits() + 7) / 8;
    if (nb == 0) nb = 1;
    std::vector<u8> be(nb);
    for (int i = 0; i < nb * 8; i++)
        if (v.get_bit(i)) be[nb - 1 - i / 8] |= (u8)(1 << (i % 8));
    if (be[0] & 0x80) { out.push_back(0x02); der_len(out, nb + 1); out.push_back(0); }
    else { out.push_back(0x02); der_len(out, nb); }
    out.insert(out.end(), be.begin(), be.end());
}
static void der_wrap(std::vector<u8>& out, u8 tag, const std::vector<u8>& body) {
    out.push_back(tag); der_len(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
}

struct KeyPair {
    int bits;
    Big n, e, d, p, q, dp, dq, qinv;
};

static bool gen_keypair(int bits, KeyPair& out, std::mt19937_64& rng) {
    if (bits < 1024 || bits > 7168 || (bits % 256) != 0) return false;
    int hb = bits / 2;
    Big e = Big::from_u64(65537);
    for (int attempt = 0; attempt < 4096; attempt++) {   /* cp293: 512-bit asal ~1/355; 4096 guvenli */
        Big p = genprime(hb, rng);
        Big q = genprime(hb, rng);
        if (cmp(p, q) == 0) continue;
        if (cmp(p, q) < 0) std::swap(p, q);   // p > q (qinv < p)
        Big n = mul(p, q);
        if (n.bits() != bits) continue;
        // λ = (p-1)*(q-1) / gcd(p-1, q-1)
        Big p1 = sub(p, Big::from_u64(1));
        Big q1 = sub(q, Big::from_u64(1));
        Big phi = mul(p1, q1);
        // gcd
        Big a = p1, b = q1;
        while (!b.zero()) { Big t = a % b; a = b; b = t; }
        Big lam; divmod(phi, a, &lam, &b);
        Big g, x, y;
        // d = e^-1 mod lam
        Big d = modinv(e, lam);
        // dogrulama: (e*d) mod lam == 1
        Big chk = mod(mul(e, d), lam);
        if (chk.n() != 1 || chk.l[0] != 1) continue;
        out.bits = bits;
        out.n = n; out.e = e; out.d = d; out.p = p; out.q = q;
        out.dp = d % p1; out.dq = d % q1;
        out.qinv = powmod(q, sub(p, Big::from_u64(2)), p);
        return true;
    }
    return false;
}

// PEM yazimi (PKCS#1: RSAPrivateKey ::= SEQUENCE { ver, n, e, d, p, q, dp, dq, qinv })
static std::string to_pem_pkcs1(const KeyPair& kp) {
    std::vector<u8> seq;
    der_int(seq, Big::from_u64(0));
    der_int(seq, kp.n);
    der_int(seq, kp.e);
    der_int(seq, kp.d);
    der_int(seq, kp.p);
    der_int(seq, kp.q);
    der_int(seq, kp.dp);
    der_int(seq, kp.dq);
    der_int(seq, kp.qinv);
    std::vector<u8> der;
    der_wrap(der, 0x30, seq);
    // base64
    static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (size_t i = 0; i < der.size(); i += 3) {
        u32 v = der[i] << 16;
        if (i + 1 < der.size()) v |= der[i + 1] << 8;
        if (i + 2 < der.size()) v |= der[i + 2];
        b64 += B64[(v >> 18) & 63]; b64 += B64[(v >> 12) & 63];
        b64 += (i + 1 < der.size()) ? B64[(v >> 6) & 63] : '=';
        b64 += (i + 2 < der.size()) ? B64[v & 63] : '=';
    }
    std::string pem = "-----BEGIN RSA PRIVATE KEY-----\n";
    for (size_t i = 0; i < b64.size(); i += 64)
        pem += b64.substr(i, 64) + "\n";
    pem += "-----END RSA PRIVATE KEY-----\n";
    return pem;
}

// modulus BE hex (motor --lic-key formatı)
static std::string modulus_hex_be(const KeyPair& kp) {
    int nb = (kp.n.bits() + 7) / 8;
    std::string hex;
    for (int i = nb * 8 - 1; i >= 0; i -= 4) {
        int v = 0;
        for (int b = 0; b < 4; b++)
            if (kp.n.get_bit(i - b)) v |= 1 << (3 - b);
        hex += "0123456789ABCDEF"[v];
    }
    return hex;
}

} // namespace xkeygen

// ---- host_cli cagrisi ----
// dönüş: 0=OK. pem yolu + modulus hex + bit uzunluğu log'lanır.
int xprotect_genkey(int bits, const std::string& out_pem,
                    std::string& out_modhex, std::function<void(const char*)> logf) {
    std::random_device rd;
    std::mt19937_64 rng(rd() ^ 0x9E3779B97F4A7C15ull);
    xkeygen::KeyPair kp;
    if (!xkeygen::gen_keypair(bits, kp, rng)) { logf("[genkey] HATA: asal cifti uretilemedi"); return 2; }
    FILE* f = fopen(out_pem.c_str(), "wb");
    if (!f) { logf("[genkey] HATA: pem yazilamadi"); return 2; }
    std::string pem = xkeygen::to_pem_pkcs1(kp);
    fwrite(pem.data(), 1, pem.size(), f);
    fclose(f);
    out_modhex = xkeygen::modulus_hex_be(kp);
    char b[128];
    snprintf(b, sizeof b, "[genkey] RSA-%d: pem=%s modulus=%d-bayt BE hex uretildi",
             bits, out_pem.c_str(), bits / 8);
    logf(b);
    return 0;
}
