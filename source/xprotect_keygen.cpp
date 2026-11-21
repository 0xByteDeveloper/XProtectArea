// xprotect_keygen.cpp — cp294/V294-1: XProtect serial üretici — TAM C++
// xprotect_keygen.py'nin birebir portu (VMProtect keygen muadili):
//   blok formatı: [01 01][02 len name][03 len email][04 len hwid]
//                 [05 date][06 runtime][07 prodcode 8B][08 len data][09 maxbuild]
//                 [FF sha1[0..3] ters-sıra]
//   imza: 00 02 NN..(8-16 nonzero) 00 blocks <MM dolgu> = keylen/8 bayt
//   RSA private-encrypt (d, n) — PEM'den openssl'siz okunur (PKCS#1/#8 DER parse)
// Çıktı: base64(serial)
// Kullanım:
//   xprotect_keygen --key key.pem --prodcode 0102030405060708 [alanlar...]
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <random>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

namespace xkg {

// ---- SHA-1 (xrt_license.c ile birebir) ----
struct sha1_ctx { u32 h[5]; u64 len; u8 buf[64]; u32 buflen; };
static u32 rl(u32 v, int r) { return (v << r) | (v >> (32 - r)); }
static void sha1_init(sha1_ctx* c) {
    c->h[0]=0x67452301u; c->h[1]=0xEFCDAB89u; c->h[2]=0x98BADCFEu;
    c->h[3]=0x10325476u; c->h[4]=0xC3D2E1F0u; c->len=0; c->buflen=0;
}
static void sha1_block(sha1_ctx* c, const u8* p) {
    u32 w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((u32)p[i*4]<<24)|((u32)p[i*4+1]<<16)|((u32)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 80; i++) w[i] = rl(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    u32 a=c->h[0],b=c->h[1],d=c->h[2],e=c->h[3],f=c->h[4];
    for (int i = 0; i < 80; i++) {
        u32 t;
        if (i < 20)      t = ((b&d)|(~b&e)) + 0x5A827999u;
        else if (i < 40) t = (b^d^e) + 0x6ED9EBA1u;
        else if (i < 60) t = ((b&d)|(b&e)|(d&e)) + 0x8F1BBCDCu;
        else             t = (b^d^e) + 0xCA62C1D6u;
        t += rl(a,5) + f + w[i];
        f = e; e = d; d = rl(b,30); b = a; a = t;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=d; c->h[3]+=e; c->h[4]+=f;
}
static void sha1_update(sha1_ctx* c, const u8* p, u32 n) {
    c->len += n;
    while (n) {
        u32 k = 64 - c->buflen; if (k > n) k = n;
        memcpy(c->buf + c->buflen, p, k);
        c->buflen += k; p += k; n -= k;
        if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
    }
}
static void sha1_final(sha1_ctx* c, u8 out[20]) {
    u64 bits = c->len * 8;
    u8 pad = 0x80;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->buflen != 56) sha1_update(c, &pad, 1);
    u8 l[8];
    for (int i = 0; i < 8; i++) l[i] = (u8)(bits >> (56 - 8*i));
    sha1_update(c, l, 8);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (u8)(c->h[i] >> 24);
        out[i*4+1] = (u8)(c->h[i] >> 16);
        out[i*4+2] = (u8)(c->h[i] >> 8);
        out[i*4+3] = (u8)c->h[i];
    }
}

// ---- base64 ----
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string b64enc(const u8* d, size_t n) {
    std::string o;
    for (size_t i = 0; i < n; i += 3) {
        u32 v = (u32)d[i] << 16;
        if (i+1 < n) v |= (u32)d[i+1] << 8;
        if (i+2 < n) v |= d[i+2];
        o += B64[(v>>18)&63]; o += B64[(v>>12)&63];
        o += (i+1<n) ? B64[(v>>6)&63] : '=';
        o += (i+2<n) ? B64[v&63] : '=';
    }
    return o;
}
static int b64val(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}
static std::vector<u8> b64dec(const std::string& s) {
    std::vector<u8> o; u32 acc = 0; int nb = 0;
    for (char ch : s) {
        if (ch == '=' || ch == '\n' || ch == '\r') continue;
        int v = b64val(ch);
        if (v < 0) continue;
        acc = (acc << 6) | (u32)v; nb += 6;
        if (nb >= 8) { nb -= 8; o.push_back((u8)(acc >> nb)); }
    }
    return o;
}

// ---- bignum (LE u32) — keygen imzasi için minimal ----
struct Big {
    std::vector<u32> l;
    Big() {}
    explicit Big(size_t n, u32 v = 0) : l(n, v) {}
    static Big from_u64(u64 v) { Big b(2); b.l[0]=(u32)v; b.l[1]=(u32)(v>>32); b.trim(); return b; }
    void trim() { while (l.size() > 1 && l.back() == 0) l.pop_back(); }
    bool zero() const { for (auto v : l) if (v) return false; return true; }
    int bits() const {
        if (!l.size()) return 0;
        size_t top = l.size();
        while (top > 1 && l[top-1] == 0) top--;
        int b = 0; u32 t = l[top-1];
        while (t) { b++; t >>= 1; }
        return (int)(top-1)*32 + b;
    }
    int get_bit(int i) const {
        if ((size_t)(i/32) >= l.size()) return 0;
        return (l[i/32] >> (i%32)) & 1;
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
    Big r(n+1); u64 c = 0;
    for (size_t i = 0; i < n; i++) {
        u64 v = c + (i<a.l.size()?a.l[i]:0) + (i<b.l.size()?b.l[i]:0);
        r.l[i] = (u32)v; c = v >> 32;
    }
    r.l[n] = (u32)c; r.trim(); return r;
}
static Big sub(const Big& a, const Big& b) {
    Big r(a.l.size()); int64_t borrow = 0;
    for (size_t i = 0; i < a.l.size(); i++) {
        int64_t v = (int64_t)a.l[i] - (i<b.l.size()?(int64_t)b.l[i]:0) - borrow;
        if (v < 0) { v += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
        r.l[i] = (u32)v;
    }
    r.trim(); return r;
}
static Big mul(const Big& a, const Big& b) {
    Big r(a.l.size()+b.l.size());
    for (size_t i = 0; i < a.l.size(); i++) {
        u64 carry = 0;
        for (size_t j = 0; j < b.l.size(); j++) {
            u64 cur = (u64)r.l[i+j] + (u64)a.l[i]*b.l[j] + carry;
            r.l[i+j] = (u32)cur; carry = cur >> 32;
        }
        size_t k = i + b.l.size();
        while (carry) { u64 cur = (u64)r.l[k] + carry; r.l[k]=(u32)cur; carry = cur>>32; k++; }
    }
    r.trim(); return r;
}
static void divmod(const Big& a, const Big& b, Big* q, Big* r) {
    if (cmp(a, b) < 0) { if (q) *q = Big(1); if (r) *r = a; return; }
    if (b.l.size() == 1) {
        Big quo(a.l.size()); u64 rem = 0; u32 bm = b.l[0];
        for (size_t j = a.l.size(); j-- > 0;) {
            u64 cur = (rem << 32) | a.l[j];
            quo.l[j] = (u32)(cur / bm); rem = cur % bm;
        }
        quo.trim(); Big rr(1); rr.l[0] = (u32)rem;
        if (q) *q = quo; if (r) *r = rr;
        return;
    }
    Big rem(1), quo(1);
    int nb = a.bits();
    size_t bl = b.l.size();
    for (int i = nb-1; i >= 0; i--) {
        u32 bit = (u32)a.get_bit(i);
        u32 c = bit;
        for (size_t j = 0; j < rem.l.size(); j++) {
            u64 v = (u64)rem.l[j]*2 + c;
            rem.l[j] = (u32)v; c = (u32)(v >> 32);
        }
        if (c) rem.l.push_back(c);
        size_t rl = rem.l.size();
        int ge = 0;
        if (rl > bl+1) ge = 1;
        else for (size_t j = (rl>bl?rl:bl); j-- > 0;) {
            u32 x = j<rl?rem.l[j]:0, y = j<bl?b.l[j]:0;
            if (x != y) { ge = x>y?1:-1; break; }
        }
        if (ge >= 0) {
            int64_t borrow = 0;
            for (size_t j = 0; j < bl; j++) {
                int64_t v = (int64_t)rem.l[j] - (int64_t)b.l[j] - borrow;
                if (v < 0) { v += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
                rem.l[j] = (u32)v;
            }
            for (size_t j = bl; borrow && j < rem.l.size(); j++) {
                int64_t v = (int64_t)rem.l[j] - borrow;
                if (v < 0) { v += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
                rem.l[j] = (u32)v;
            }
            while (rem.l.size() > 1 && rem.l.back() == 0) rem.l.pop_back();
            if ((size_t)(i/32) >= quo.l.size()) quo.l.resize(i/32+1, 0);
            quo.l[i/32] |= (1u << (i%32));
        }
    }
    rem.trim(); quo.trim();
    if (q) *q = quo; if (r) *r = rem;
}
static Big operator%(const Big& a, const Big& b) { Big r; divmod(a, b, nullptr, &r); return r; }

// ---- Montgomery REDC (engine_keygen.cpp ile ayni kanitli cekirdek) ----
struct MontCtx {
    size_t nl; std::vector<u32> m; u32 mprime; std::vector<u32> r2;
};
static u32 inv32_pow(u32 a) {
    u32 x = a;
    for (int i = 0; i < 5; i++) x *= 2 - a*x;
    return x;
}
static void mont_mul(const MontCtx& c, const u32* a, const u32* b, u32* out) {
    size_t nl = c.nl;
    std::vector<u64> T(2*nl+2, 0);
    for (size_t i = 0; i < nl; i++) {
        u64 carry = 0; u64 ai = a[i];
        if (!ai) continue;
        for (size_t j = 0; j < nl; j++) {
            u64 cur = T[i+j] + ai*b[j] + carry;
            T[i+j] = cur & 0xFFFFFFFFull; carry = cur >> 32;
        }
        size_t k = i + nl;
        while (carry) { u64 cur = T[k]+carry; T[k]=cur&0xFFFFFFFFull; carry=cur>>32; k++; }
    }
    for (size_t i = 0; i < nl; i++) {
        u64 u = ((T[i] & 0xFFFFFFFFull) * c.mprime) & 0xFFFFFFFFull;
        if (!u) continue;
        u64 carry = 0;
        for (size_t j = 0; j < nl; j++) {
            u64 cur = T[i+j] + u*c.m[j] + carry;
            T[i+j] = cur & 0xFFFFFFFFull; carry = cur >> 32;
        }
        size_t k = i + nl;
        while (carry) { u64 cur = T[k]+carry; T[k]=cur&0xFFFFFFFFull; carry=cur>>32; k++; }
    }
    std::vector<u32> r(nl+1, 0);
    for (size_t i = 0; i < nl; i++) r[i] = (u32)T[nl+i];
    r[nl] = (u32)T[2*nl];
    if (T[2*nl+1]) {
        int64_t borrow = 0;
        for (size_t j = 0; j < nl; j++) {
            int64_t v = (int64_t)r[j] - (int64_t)c.m[j] - borrow;
            if (v < 0) { v += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
            r[j] = (u32)v;
        }
        r[nl] = (u32)((int64_t)r[nl] - borrow);
    }
    int ge = 0;
    for (size_t j = nl+1; j-- > 0;) {
        u32 x = j<r.size()?r[j]:0, y = j<nl?c.m[j]:0;
        if (x != y) { ge = x>y?1:-1; break; }
    }
    if (ge >= 0) {
        int64_t borrow = 0;
        for (size_t j = 0; j < nl; j++) {
            int64_t v = (int64_t)r[j] - (int64_t)c.m[j] - borrow;
            if (v < 0) { v += ((int64_t)1<<32); borrow = 1; } else borrow = 0;
            r[j] = (u32)v;
        }
        r[nl] = (u32)((int64_t)r[nl] - borrow);
    }
    for (size_t i = 0; i < nl; i++) out[i] = r[i];
}
static MontCtx mont_init(const Big& m0) {
    MontCtx c; Big m = m0; m.trim();
    c.nl = m.l.size(); c.m = m.l;
    c.mprime = (u32)(-(int64_t)inv32_pow(m.l[0]));
    Big r(1); r.l[0] = 1;
    for (size_t i = 0; i < 2*c.nl; i++) {
        r.l.insert(r.l.begin(), 0);
        r = r % m;
    }
    c.r2 = r.l;
    while (c.r2.size() < c.nl) c.r2.push_back(0);
    return c;
}
static void mont_from(const MontCtx& c, const Big& x0, std::vector<u32>& out) {
    Big mm; mm.l = c.m;
    Big x = x0 % mm;
    std::vector<u32> a(c.nl, 0);
    for (size_t i = 0; i < c.nl && i < x.l.size(); i++) a[i] = x.l[i];
    out.assign(c.nl, 0);
    mont_mul(c, a.data(), c.r2.data(), out.data());
}
static void mont_to(const MontCtx& c, const std::vector<u32>& a, Big& out) {
    std::vector<u32> one(c.nl, 0); one[0] = 1;
    std::vector<u32> r(c.nl, 0);
    mont_mul(c, a.data(), one.data(), r.data());
    out.l = r; out.trim();
}
/* powmod — d ile imza: m = n (asal degil!), klasik sagdan-sola Montgomery */
static Big powmod(const Big& base, const Big& e, const Big& m) {
    MontCtx c = mont_init(m);
    std::vector<u32> bx, res;
    mont_from(c, base % m, bx);
    mont_from(c, Big::from_u64(1), res);
    int nb = e.bits();
    for (int i = 0; i < nb; i++) {
        if (e.get_bit(i)) mont_mul(c, res.data(), bx.data(), res.data());
        mont_mul(c, bx.data(), bx.data(), bx.data());
    }
    Big out; mont_to(c, res, out);
    return out;
}

// ---- PEM okuma (PKCS#1 veya PKCS#8 DER) ----
static bool der_parse_privkey(const std::vector<u8>& der, Big& n, Big& e, Big& d) {
    auto rdlen = [&](size_t& i) -> size_t {
        u8 l = der[i++];
        if (l & 0x80) {
            int k = l & 0x7F; size_t v = 0;
            while (k--) v = (v << 8) | der[i++];
            return v;
        }
        return l;
    };
    auto rdint = [&](size_t& i, Big& out) {
        if (i >= der.size() || der[i] != 0x02) return false;
        i++;
        size_t l = rdlen(i);
        if (i + l > der.size()) return false;
        // BE -> LE limb
        out.l.assign((l + 3) / 4, 0);
        for (size_t k = 0; k < l; k++) {
            u8 byte = der[i + l - 1 - k];
            out.l[k / 4] |= (u32)byte << (8 * (k % 4));
        }
        out.trim();
        i += l;
        return true;
    };
    size_t i = 0;
    if (der.size() < 4 || der[0] != 0x30) return false;
    i = 1; rdlen(i);
    if (i < der.size() && der[i] == 0x02) {
        // PKCS#1: ver, n, e, d
        Big ver;
        if (!rdint(i, ver)) return false;
        if (!rdint(i, n)) return false;
        if (!rdint(i, e)) return false;
        if (!rdint(i, d)) return false;
        return true;
    }
    // PKCS#8: ver, algSEQ, OCTET( PKCS#1 )
    if (i < der.size() && der[i] == 0x30) {
        size_t skip_end;
        i++; skip_end = i + rdlen(i);
        i = skip_end;
        if (i < der.size() && der[i] == 0x04) {
            i++;
            size_t l = rdlen(i);
            std::vector<u8> inner(der.begin() + i, der.begin() + i + l);
            return der_parse_privkey(inner, n, e, d);
        }
    }
    return false;
}
static bool load_pem(const std::string& path, Big& n, Big& e, Big& d) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    std::string pem;
    char buf[4096];
    size_t k;
    while ((k = fread(buf, 1, sizeof buf, f)) > 0) pem.append(buf, k);
    fclose(f);
    size_t b = pem.find("-----BEGIN");
    size_t epos = pem.find("-----END");
    if (b == std::string::npos || epos == std::string::npos) return false;
    b = pem.find('\n', b);
    if (b == std::string::npos) return false;
    b++;
    std::string b64;
    for (size_t i = b; i < epos; i++)
        if (pem[i] != '\n' && pem[i] != '\r') b64 += pem[i];
    std::vector<u8> der = b64dec(b64);
    return der_parse_privkey(der, n, e, d);
}

// ---- Big <-> BE bayt ----
static Big from_be(const u8* p, size_t n) {
    Big r; r.l.assign((n+3)/4, 0);
    for (size_t k = 0; k < n; k++) {
        u8 byte = p[n-1-k];
        r.l[k/4] |= (u32)byte << (8*(k%4));
    }
    r.trim(); return r;
}
static std::vector<u8> to_be(const Big& v, size_t n) {
    std::vector<u8> o(n, 0);
    for (size_t k = 0; k < n; k++) {
        int bitidx = (int)(n-1-k);
        if (v.get_bit(bitidx*8 + 7)) o[k] |= 0x80;
        for (int b = 0; b < 8; b++)
            if (v.get_bit(bitidx*8 + b)) o[k] |= (u8)(1 << b);
    }
    return o;
}

// ---- tarih: YYYY-MM-DD -> (y<<16)|(m<<8)|d LE 4B (py date_enc birebir) ----
static bool date_enc(const std::string& s, u8 out[4]) {
    int y, m, d;
    if (sscanf(s.c_str(), "%d-%d-%d", &y, &m, &d) != 3) return false;
    u32 v = ((u32)y << 16) | ((u32)m << 8) | (u32)d;
    out[0]=(u8)v; out[1]=(u8)(v>>8); out[2]=(u8)(v>>16); out[3]=(u8)(v>>24);
    return true;
}

// ---- ana API ----
struct SerialArgs {
    std::string name, email, hwid_b64, exp, expire, maxbuild, data_hex, prodcode_hex;
    int runtime = 0;
    bool badhwid = false, badsum = false;
};

static std::vector<u8> build_blocks(const SerialArgs& a) {
    std::vector<u8> b;
    b.push_back(0x01); b.push_back(0x01);
    auto putstr = [&](u8 id, const std::string& s) {
        b.push_back(id); b.push_back((u8)s.size());
        b.insert(b.end(), s.begin(), s.end());
    };
    if (!a.name.empty()) putstr(0x02, a.name);
    if (!a.email.empty()) putstr(0x03, a.email);
    if (!a.hwid_b64.empty()) {
        std::vector<u8> hb = b64dec(a.hwid_b64);
        if (a.badhwid) for (auto& x : hb) x ^= 0xFF;
        b.push_back(0x04); b.push_back((u8)hb.size());
        b.insert(b.end(), hb.begin(), hb.end());
    }
    std::string exp = a.expire.empty() ? a.exp : a.expire;
    if (!exp.empty()) {
        u8 d[4];
        if (date_enc(exp, d)) {
            b.push_back(0x05);
            b.insert(b.end(), d, d+4);
        }
    }
    if (a.runtime) {
        b.push_back(0x06); b.push_back((u8)(a.runtime & 0xFF));
    }
    // prodcode (zorunlu, 8B)
    b.push_back(0x07);
    for (int i = 0; i < 8; i++) {
        std::string hx = a.prodcode_hex.substr(i*2, 2);
        b.push_back((u8)strtoul(hx.c_str(), nullptr, 16));
    }
    if (!a.data_hex.empty()) {
        std::vector<u8> db;
        for (size_t i = 0; i + 1 < a.data_hex.size(); i += 2) {
            std::string hx = a.data_hex.substr(i, 2);
            db.push_back((u8)strtoul(hx.c_str(), nullptr, 16));
        }
        b.push_back(0x08); b.push_back((u8)db.size());
        b.insert(b.end(), db.begin(), db.end());
    }
    if (!a.maxbuild.empty()) {
        u8 d[4];
        if (date_enc(a.maxbuild, d)) {
            b.push_back(0x09);
            b.insert(b.end(), d, d+4);
        }
    }
    sha1_ctx c; u8 h[20];
    sha1_init(&c);
    sha1_update(&c, b.data(), (u32)b.size());
    sha1_final(&c, h);
    b.push_back(0xFF);
    if (a.badsum) {
        b.push_back(h[3]^0xFF); b.push_back(h[2]); b.push_back(h[1]); b.push_back(h[0]);
    } else {
        b.push_back(h[3]); b.push_back(h[2]); b.push_back(h[1]); b.push_back(h[0]);
    }
    return b;
}

// imza: keylen/8 bayt — 00 02 pad 00 blocks MM...
static std::vector<u8> sign_blocks(const std::vector<u8>& blocks, const Big& n, const Big& d) {
    size_t k = (n.bits() + 7) / 8;          // modulus bayti
    std::mt19937_64 rng((u64)(uintptr_t)&k ^ 0x9E3779B97F4A7C15ull);
    int nn = 8 + (int)(rng() % 9);          // 8..16
    std::vector<u8> body;
    body.push_back(0x00); body.push_back(0x02);
    for (int i = 0; i < nn; i++) {
        u8 v;
        do { v = (u8)(rng() & 0xFF); } while (!v);
        body.push_back(v);
    }
    body.push_back(0x00);
    body.insert(body.end(), blocks.begin(), blocks.end());
    // dolgu: keylen/8'a tamamla (py: rastgele 0..255)
    while (body.size() < k) body.push_back((u8)(rng() & 0xFF));
    body.resize(k);
    Big m = from_be(body.data(), body.size());
    Big s = powmod(m, d, n);
    return to_be(s, k);
}

} // namespace xkg

// ---- kütüphane API (cp295/V295-1: UI "Add License" serial üretimi) ----
// UI, lisans alanlarından serial üretir; imzalama xkg::sign_blocks ile
// (keygen PEM'i yüklenir — private key). Çıktı: base64(serial).
int xprotect_make_serial(const char* pem_path, const char* prodcode_hex,
                         const char* name, const char* email,
                         const char* expire, const char* maxbuild,
                         int runtime_min, std::string& out_b64) {
    using namespace xkg;
    if (!pem_path || !prodcode_hex || strlen(prodcode_hex) != 16) return 2;
    Big n, e, d;
    if (!load_pem(pem_path, n, e, d)) return 3;
    SerialArgs a;
    if (name) a.name = name;
    if (email) a.email = email;
    if (expire) a.expire = expire;
    if (maxbuild) a.maxbuild = maxbuild;
    a.runtime = runtime_min;
    a.prodcode_hex = prodcode_hex;
    std::vector<u8> blocks = build_blocks(a);
    std::vector<u8> sig = sign_blocks(blocks, n, d);
    out_b64 = b64enc(sig.data(), sig.size());
    return 0;
}

// ---- CLI ----
// cikis: stdout = base64(serial). Hata: stderr + rc!=0.
int xprotect_keygen_main(int argc, char** argv) {
    using namespace xkg;
    std::string keypath = "key.pem";
    SerialArgs a;
    for (int i = 1; i < argc; i++) {
        std::string s = argv[i];
        auto nx = [&]() -> std::string { return (i+1 < argc) ? argv[++i] : ""; };
        if (s == "--key") keypath = nx();
        else if (s == "--prodcode") a.prodcode_hex = nx();
        else if (s == "--hwid") a.hwid_b64 = nx();
        else if (s == "--name") a.name = nx();
        else if (s == "--email") a.email = nx();
        else if (s == "--exp") a.exp = nx();
        else if (s == "--expire") a.expire = nx();
        else if (s == "--maxbuild") a.maxbuild = nx();
        else if (s == "--runtime") a.runtime = atoi(nx().c_str());
        else if (s == "--data") a.data_hex = nx();
        else if (s == "--badhwid") a.badhwid = true;
        else if (s == "--badsum") a.badsum = true;
        else if (s == "--pubkey") {
            // sadece modulus bas (py paritesi)
            Big n, e, d;
            if (!load_pem(keypath, n, e, d)) { fprintf(stderr, "[keygen] PEM okunamadi\n"); return 2; }
            std::vector<u8> be = to_be(n, (n.bits()+7)/8);
            std::string hx;
            static const char* H = "0123456789ABCDEF";
            for (u8 c : be) { hx += H[c>>4]; hx += H[c&15]; }
            printf("%s\n", hx.c_str());
            return 0;
        }
    }
    if (a.prodcode_hex.size() != 16) {
        fprintf(stderr, "[keygen] --prodcode 16 hex (8 bayt) zorunlu\n");
        return 2;
    }
    Big n, e, d;
    if (!load_pem(keypath, n, e, d)) {
        fprintf(stderr, "[keygen] PEM okunamadi: %s\n", keypath.c_str());
        return 2;
    }
    std::vector<u8> blocks = build_blocks(a);
    std::vector<u8> sig = sign_blocks(blocks, n, d);
    printf("%s\n", b64enc(sig.data(), sig.size()).c_str());
    return 0;
}
#ifndef XKG_NO_MAIN
int main(int argc, char** argv) { return xprotect_keygen_main(argc, argv); }
#endif
