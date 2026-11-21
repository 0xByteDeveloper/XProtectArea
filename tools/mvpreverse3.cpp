// ============================================================
// mvpreverse3.cpp — cp289 (Python mvpreverse3.py birebir C++ portu)
// MOD 1 analyze + MOD 2 reverse (VM_MIX/CFB/itab/18 opcode + capstone)
// Derleme: g++ -O2 -std=c++17 -o mvpreverse3 mvpreverse3.cpp \
//   -I$CS/include -L$CS/lib -lcapstone   (CS = pip capstone dizini)
// Calistirma: LD_LIBRARY_PATH=$CS/lib (veya /tmp/cslib — soname syml)
// ============================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <capstone/capstone.h>

typedef uint8_t  u8;  typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t  s32; typedef int64_t  s64;

static std::string hex(u64 v) { char b[32]; snprintf(b, sizeof b, "%llX", (unsigned long long)v); return b; }
static std::string jstr(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c=='"'||c=='\\') { o+='\\'; o+=c; }
        else if ((unsigned char)c < 0x20) { char b[8]; snprintf(b,8,"\\u%04x",c); o+=b; }
        else o+=c;
    }
    return o;
}
static double entropy(const u8* p, size_t n) {
    if (!n) return 0.0;
    size_t cnt[256]={0};
    for (size_t i=0;i<n;i++) cnt[p[i]]++;
    double e=0.0;
    for (int i=0;i<256;i++) if (cnt[i]) { double pr=(double)cnt[i]/n; e-=pr*log2(pr); }
    return e;
}

// ---------------- PE cekirdegi ----------------
struct Sec { std::string name; u32 vs=0, va=0, rs=0, ptr=0; };
struct PE {
    std::string path;
    std::vector<u8> d;
    u16 machine=0; int nsec=0; bool is64=false;
    u32 opt=0, ep=0; u64 imgbase=0;
    u32 dd[16][2]={{0}};
    std::vector<Sec> secs;
    PE(const std::string& p) : path(p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) { fprintf(stderr, "acilamadi: %s\n", p.c_str()); exit(2); }
        d.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        u32 pe; memcpy(&pe, &d[0x3C], 4);
        if (memcmp(&d[pe], "PE\0\0", 4)) { fprintf(stderr, "PE degil\n"); exit(2); }
        memcpy(&machine, &d[pe+4], 2);
        memcpy(&nsec, &d[pe+6], 2);
        is64 = (machine == 0x8664);
        opt = pe+24;
        u16 magic; memcpy(&magic, &d[opt], 2);
        memcpy(&ep, &d[opt+16], 4);
        if (magic == 0x20b) memcpy(&imgbase, &d[opt+24], 8);
        else { u32 b32; memcpy(&b32, &d[opt+28], 4); imgbase=b32; }
        u32 ddoff = opt + (is64? 112 : 96);
        for (int i=0;i<16;i++) memcpy(dd[i], &d[ddoff+i*8], 8);
        u16 optsz; memcpy(&optsz, &d[pe+20], 2);
        u32 so = opt + optsz;
        for (int i=0;i<nsec;i++) {
            Sec s;
            char nb[9]; memcpy(nb, &d[so+40*i], 8); nb[8]=0;
            s.name=nb; while(!s.name.empty()&&s.name.back()=='\0') s.name.pop_back();
            memcpy(&s.vs, &d[so+40*i+8], 4);
            memcpy(&s.va, &d[so+40*i+12], 4);
            memcpy(&s.rs, &d[so+40*i+16], 4);
            memcpy(&s.ptr, &d[so+40*i+20], 4);
            secs.push_back(s);
        }
    }
    long rva2off(u32 rva) const {
        for (auto& s : secs)
            if (s.va <= rva && rva < s.va + (s.vs>s.rs?s.vs:s.rs)) {
                long o=(long)rva-s.va+s.ptr;
                if (o>=0 && (size_t)o<d.size()) return o;
            }
        return -1;
    }
    const Sec* sec(const char* nm) const {
        std::string l=nm; for (auto&c:l) c|=0x20;
        for (auto& s : secs) { std::string n=s.name; for(auto&c:n)c|=0x20; if (n==l) return &s; }
        return nullptr;
    }
    bool has(const char* needle) const {
        return std::search(d.begin(), d.end(), needle, needle+strlen(needle)) != d.end();
    }
};

// ---------------- cipher (cp289 — Python birebir) ----------------
static const u64 M64 = 0xFFFFFFFFFFFFFFFFull;
static u64 vm_mix(u64 key, u64 pos) {
    u64 h = (key ^ (pos * 0x9E3779B97F4A7C15ull)) & M64;
    h = (h * 0x2545F4914F6CDD1Dull) & M64;
    h = (h + 0x9E3779B97F4A7C15ull) & M64;
    h ^= h >> 29;
    u64 sel = ((key ^ ((pos >> 3) * 0xD1B54A32D192ED03ull)) & M64) >> 61; sel &= 3;
    if (sel == 0) { h = (h * 0x94D049BB133111EBull) & M64; h ^= h >> 31; }
    else if (sel == 1) { h = (h + 0xA24BAED4963EE407ull) & M64; h ^= h >> 27; }
    else if (sel == 2) { h = ((h << 13) | (h >> 51)) & M64; h = (h * 0xFF51AFD7ED55814Dull) & M64; h ^= h >> 33; }
    else { h ^= (~(h << 7)) & M64; h = (h * 0x9E3779B97F4A7C15ull) & M64; h ^= h >> 25; }
    return h & M64;
}
static u8 vm_ks(u64 key, u64 pos) { return (u8)(vm_mix(key, pos) >> 56); }
static u8 vm_ksc(u64 key, u8 prev, u64 pos) {
    return vm_ks((key ^ ((u64)prev * 0x2545F4914F6CDD1Dull)) & M64, pos);
}
static u64 vm_keyxor(u32 bc_rva, u32 bc_len) {
    u64 x = (0x5850424Dull ^ ((u64)bc_rva << 32) ^ bc_len) & M64;
    x ^= (x >> 30) & M64;
    x = (x * 0xBF58476D1CE4E5B9ull) & M64;
    x ^= (x >> 27) & M64;
    x = (x * 0x94D049BB133111EBull) & M64;
    x ^= (x >> 31) & M64;
    return x;
}
static u64 vm_vmk(u32 vm_id) {
    if (!vm_id) return 0;
    return ((0x5850424Dull ^ ((u64)vm_id * 0x9E3779B97F4A7C15ull))
            ^ ((u64)vm_id << 41)) & M64;
}
static std::vector<u8> vm_perm_tab(u32 seed) {   // dec=1: raw->gercek
    const int VM_OPN = 0x45;
    std::vector<u8> p(VM_OPN);
    for (int i=0;i<VM_OPN;i++) p[i]=(u8)i;
    u64 z = ((u64)seed ^ 0x5850424D9E3779B9ull) | 1ull;
    for (int i=VM_OPN-1;i>0;i--) {
        z ^= z>>30; z = (z * 0xBF58476D1CE4E5B9ull) & M64;
        z ^= z>>27; z = (z * 0x94D049BB133111EBull) & M64; z ^= z>>31;
        int j = (int)(((u32)(z >> 32)) % (u32)(i + 1));
        u8 t=p[i]; p[i]=p[j]; p[j]=t;
    }
    return p;
}
static void cfb_decrypt(const u8* enc, size_t n, u64 key, std::vector<u8>& out, int vm_rev=1) {
    out.assign(n, 0);
    if (vm_rev) {
        for (long long k=(long long)n-1;k>=0;k--) {
            u8 pv = (size_t)(k+1)<n ? enc[k+1] : 0;
            out[k] = enc[k] ^ vm_ksc(key, pv, (u64)k);
        }
    } else {
        u8 prev = 0;
        for (size_t k=0;k<n;k++) { out[k]=enc[k]^vm_ksc(key,prev,k); prev=enc[k]; }
    }
}

// ---------------- MOD 1: analyze (Python paritesi) ----------------
static bool g_an_ad_found = false;   /* cp292: OP_ANTIDBG bytecode bulundu (analyze kapsami) */
static int  g_tlscb_n = 0;          /* cp298: TLS callback sayısı (features.tls_callback) */
static std::string lc_hex(u32 v) { char b[16]; snprintf(b, sizeof b, "0x%x", v); return std::string(b); }
/* cp298: JSON string escape — binary isimli export'lar (PE32 ALL'da isim şifreli) JSON'u kırmasın */
static std::string json_esc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c < 0x20 || c == 0x7F || c >= 0x80) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }  /* cp298: >=0x80 latin1 baytlar da escape — UTF-8 güvenliği */
        else o += (char)c;
    }
    return o;
}
// ---------------- stub parse (Python birebir) ----------------
struct StubInfo {
    bool ok = false;
    u64 key = 0; u32 bc_rva = 0, bc_len = 0, l1_rva = 0, vm_entry = 0;
};
static StubInfo parse_xprotect_stub(const PE& pe, const std::vector<u8>& d, long fo, u32 rva);
std::string analyze(const std::string& path, const std::string& jout) {
    PE pe(path);
    std::ostringstream J;
    J << "{\n  \"file\": \"" << jstr(path) << "\",\n  \"bit\": " << (pe.is64?64:32)
      << ",\n  \"image_base\": \"0x" << hex(pe.imgbase) << "\""
      << ",\n  \"entry_rva\": \"0x" << hex(pe.ep) << "\""
      << ",\n  \"entry_va\": \"0x" << hex(pe.imgbase+pe.ep) << "\"";
    J << ",\n  \"sections\": [";
    for (size_t i=0;i<pe.secs.size();i++) {
        auto& s = pe.secs[i];
        /* cp298: py:163 section alan paritesi — rva + entropy eklendi
           (py round(e,2) yuvarlaması birebir) */
        double sent = 0.0;
        if (s.rs > 0 && (size_t)s.ptr + s.rs <= pe.d.size())
            sent = (double)(long)(entropy(&pe.d[s.ptr], s.rs) * 100.0 + 0.5) / 100.0;
        J << (i? ",\n    " : "\n    ") << "{\"name\": \"" << json_esc(s.name) << "\", \"rva\": \"" << lc_hex(s.va)
          << "\", \"vsize\": \"" << lc_hex(s.vs) << "\", \"rawsize\": \"" << lc_hex(s.rs)
          << "\", \"entropy\": " << sent << "}";
    }
    J << "\n  ]";
    std::string product;   /* cp298: boş = JSON null (py product=None paritesi) */
    const Sec* vmp0 = pe.sec(".vmp0");
    bool mnk=false;
    for (auto& s : pe.secs) { std::string n=s.name; for(auto&c:n)c|=0x20; if (n.rfind(".mnk",0)==0) mnk=true; }
    bool has_cpl = pe.has("CPlusPort") || pe.has("XPROTECT");
    bool real_vmp=false; std::vector<std::string> rvr;
    /* cp292/V292-4: mingw-DLL false-positive kapatmasi. Eski kural: .vmp0 basi
       55 8B/55 89 (push rbp; mov) gorunce 'gercek VMProtect' diyordu — mingw
       uretim DLL'lerde .vmp0 ilk baytlari tesadufen bu kaliaba dusebiliyor.
       Yeni kural (3 sartin HEPSI):
         a) SDK-marker YOK (CPlusPort/XPROTECT) — varsa kesin XProtect
         b) VM bolumu gercek boyutta (rs >= 0x1000; VMP'te .vmp0 buyuktur)
         c) PE mingw-GNU degil: .eh_frame bolumu veya 'GCC:' stringi yok
       ayrica FPO kurali ayni sartlara baglandi. */
    bool mingw_pe = pe.has(".eh_frame") || pe.has("GCC:") || pe.has("mingw");
    bool vm_big = vmp0 && vmp0->rs >= 0x1000;
    if (vmp0 && !has_cpl && vm_big && !mingw_pe) {
        const u8* h = &pe.d[vmp0->ptr];
        /* cp292/V292-4: derleyici-prolog suzgeci — push ebp; mov ebp,esp'den
           SONRA 'mov eax,edx' (89 d0 / 8b c2) geliyorsa bu mingw fonksiyon
           prologudur, VMP stub'i degil (TestDllX86 vakasi: 55 89 c5 89 d0). */
        bool compiler_prolog = h[0]==0x55 && (h[1]==0x8b || h[1]==0x89)
            && ((h[2]==0x89 && h[3]==0xd0) || (h[2]==0x8b && h[3]==0xc2)
             || (h[3]==0x89 && h[4]==0xd0) || (h[3]==0x8b && h[4]==0xc2));
        if (h[0]==0x55 && (h[1]==0x8b || h[1]==0x89) && !compiler_prolog) { real_vmp=true; rvr.push_back(".vmp0 ebp-frame stub"); }
        else if (h[0]==0x55 && h[1]>=0x50 && h[1]<=0x57 && h[2]>=0x50 && h[2]<=0x57
                 && h[3]>=0x50 && h[3]<=0x57 && h[4]==0x83) { real_vmp=true; rvr.push_back(".vmp0 FPO stub"); }
        else if (compiler_prolog) rvr.push_back(".vmp0 derleyici-prolog (mingw — kanit degil)");
    } else if (vmp0 && !has_cpl && (mingw_pe || !vm_big)) {
        /* mingw/kucuk bolumde ebp-frame kanidi tek basina YETMEZ — sadece not */
        const u8* h = &pe.d[vmp0->ptr];
        if (h[0]==0x55 && (h[1]==0x8b || h[1]==0x89))
            rvr.push_back(".vmp0 ebp-frame (zayif — mingw/kucuk bolum, tek basina kanit degil)");
    }
    if (vmp0) product = real_vmp ? "VMProtect (gerçek — native VM)" : "XProtect (CPlusPort motoru)";
    else if (mnk) product = "VMProtect (unregistered — MNK section)";
    else if (pe.has("UniversalObfuscator")) product = "UniversalObfuscator";
    /* cp292/V292-4: tespit gerekceleri JSON'a (false-positive denetimi icin) */
    if (vmp0 && rvr.empty()) rvr.push_back(".vmp0 VM-interpreter prolog (XProtect)");
    { std::string rj;
      for (size_t i=0;i<rvr.size();i++) { if(i) rj += ", "; rj += "\"" + rvr[i] + "\""; }
      J << ",\n  \"real_vmp_reasons\": [" << rj << "]"; }
    J << ",\n  \"product\": " << (product.empty() ? "null" : "\"" + product + "\"");
    // IAT isimleri
    std::set<std::string> iat_set;
    {
        /* cp298 FIX: descriptor+0 = OriginalFirstThunk (INT) — pefile/pyp paritesi;
           +16 FirstThunk (IAT) değil! OFT=0 ise FirstThunk'a düş (bazı linkerler) */
        u32 irva = pe.dd[1][0];
        if (irva) {
            long io = pe.rva2off(irva);
            while (io>=0 && (size_t)io+20<=pe.d.size()) {
                u32 oft; memcpy(&oft, &pe.d[io+0], 4);
                if (!oft) { memcpy(&oft, &pe.d[io+16], 4); }   /* FirstThunk fallback */
                if (!oft) break;
                long t = pe.rva2off(oft);
                while (t>=0 && (size_t)t+(pe.is64?8:4)<=pe.d.size()) {
                    u32 fn; memcpy(&fn, &pe.d[t], 4);
                    if (!fn) break;
                    if (!(fn & 0x80000000u)) {
                        long no = pe.rva2off(fn);
                        if (no>=0) {
                            /* cp298 FIX: Hint/Name tablosunda isim +2'den başlar
                               (2 bayt hint) — pefile/parite; x64 INT girişi 8 bayt */
                            no += 2;
                            size_t e=no; while (e<pe.d.size() && pe.d[e]) e++;
                            if (e>no && e-no<64) iat_set.insert(std::string((char*)&pe.d[no], e-no));
                        }
                    }
                    t += pe.is64 ? 8 : 4;
                }
                io += 20;
            }
        }
    }
    bool dbg = iat_set.count("IsDebuggerPresent")||iat_set.count("CheckRemoteDebuggerPresentA")
            || iat_set.count("CheckRemoteDebuggerPresentW")||iat_set.count("NtQueryInformationProcess")
            || iat_set.count("OutputDebugStringA")||iat_set.count("OutputDebugStringW")
            || iat_set.count("NtSetInformationThread")||pe.has("IsDebuggerPresent");
    bool pk = iat_set.count("VirtualProtect")||iat_set.count("VirtualProtectEx")
           || iat_set.count("VirtualAlloc")||iat_set.count("VirtualAllocEx")
           || iat_set.count("VirtualFree")||iat_set.count("VirtualQuery")
           || pe.has("VirtualProtect");
    bool lzma = false;
    /* cp298: py:129-134 birebir — .vmp* section'ları entropi taramasının DIŞINDA
       (şifreli VM kodu doğal yüksek entropilidir ama packer değildir) + sig taraması */
    {
        for (auto& s : pe.secs) {
            if (!(s.rs > 0x400 && (size_t)s.ptr+s.rs<=pe.d.size())) continue;
            std::string ln = s.name; for (auto& c : ln) c |= 0x20;
            if (ln==".vmp0"||ln==".vmp1"||ln==".vmp2"||ln==".vmp") continue;
            if (entropy(&pe.d[s.ptr], s.rs) > 7.2) { lzma=true; break; }
        }
        if (!lzma) {
            static const unsigned char sigs[5][6] = {
                {0x37,0x7A,0xBC,0xAF,0x27,0x1C}, {'P','K',3,4,0,0},
                {'L','Z','M','A',0,0}, {'M','S','C','F',0,0}, {'R','a','r','!',0,0} };
            int sl[5] = {6,4,4,4,4};
            for (int si=0; si<5 && !lzma; si++) {
                const unsigned char* sp = sigs[si];
                for (size_t o=0; o+sl[si]<=pe.d.size(); o++)
                    if (!memcmp(&pe.d[o], sp, sl[si])) { lzma=true; break; }
            }
        }
    }
    // vm_wrapped (py paritesi): E9-gate + inline-stub sarmalanan fonksiyon sayaci
    int vm_wrapped = 0;
    {
        const Sec* vt = pe.sec(".text");
        if (vmp0 && vt) {
            u32 v0 = vmp0->va, v1 = vmp0->va + vmp0->vs;
            // E9 gate taramasi
            for (u32 va = vt->va; va + 5 < vt->va + vt->vs; va++) {
                long o = pe.rva2off(va);
                if (o < 0) continue;
                if (pe.d[o] == 0xE9) {
                    s32 rel; memcpy(&rel, &pe.d[o+1], 4);
                    u32 tgt = va + 5 + rel;
                    if (v0 <= tgt && tgt < v1) { vm_wrapped++; va += 4; }
                } else if ((pe.d[o] == 0x41 && o+1 < (long)pe.d.size() && (pe.d[o+1] & 0xF8) == 0x50)
                           || pe.d[o] == 0x9C || pe.d[o] == 0x60) {
                    // inline stub (x64 push rV / x86 pushad / pushfq) — .vmp0'a E9
                    // ile baglanmiyorsa dogrudan stub; export listesindeyse say
                    va += 7;
                }
            }
        }
    }
    J << ",\n  \"features\": {";
    /* cp298: py:107-119 birebir — VM koşullu anahtarlar yalnız vmp0 VARken yazılır
       (korumasız exe'de py bu anahtarları hiç yazmaz). İlk anahtar öncesi virgül yok;
       sonrakiler ',' ile — bool ilk anahtar izleme */
    bool _fk = true;   /* features ilk anahtar */
    if (vmp0) {
        J << "\n    \"sanal_makine_korumasi\": true";
        J << ",\n    \"vm_section_vmp0\": true";
        _fk = false;
    }
    J << (_fk ? "\n    " : ",\n    ") << "\"check_debugger\": " << (dbg?"true":"false")    /* cp292: tarama sonrasi guncellenir */
       << ",\n    \"lzma_pack\": " << (lzma?"true":"false");
    J << ",\n    \"memprot_flag\": " << (pk?"true":"false");
    J << ",\n    \"sdk_marker\": " << ((pe.has("VMProtectBegin")||pe.has("XPROTECT")||pe.has("CPlusPort"))?"true":"false");
    /* cp298: py:138 birebir — mutation: '.vmp0' baytı İLK 0x400'te VE .vmp0 section var
       (has() tüm dosyada arıyordu — vf_packed'da .vmp1 adı .vmp0 substring'i içerdiğinden
       yanlış-pozitif True basıyordu) */
    {
        bool hdr_vmp0 = pe.d.size() >= 0x400 &&
            memmem(&pe.d[0], 0x400, ".vmp0", 5) != nullptr;
        J << ",\n    \"mutation\": " << ((hdr_vmp0 && vmp0)?"true":"false");
    }
    J << ",\n    \"iat_destroyed\": " << ((pe.dd[1][0]==0 && pe.dd[12][0]==0)?"true":"false");
    /* cp298: py:158 birebir — TLS dizini VARSA 'tls' alanı + features'ta tls_callback.
       (tlscb bloğu features'tan SONRA koştuğu için sayıyı burada hesapla — py:141) */
    {
        u32 trva = pe.dd[9][0];
        if (trva) {
            int ncb = 0;
            long to = pe.rva2off(trva);
            if (to >= 0 && (size_t)to + (pe.is64?24:20) + 8 <= pe.d.size()) {
                u64 cbv = pe.is64 ? (*(u64*)&pe.d[to+24]) : (u64)(*(u32*)&pe.d[to+20]);
                u32 crva = (u32)((cbv - pe.imgbase) & 0xFFFFFFFFull);
                long co = pe.rva2off(crva);
                while (co >= 0 && (size_t)co + (pe.is64?8:4) <= pe.d.size()) {
                    u64 v = pe.is64 ? (*(u64*)&pe.d[co]) : (u64)(*(u32*)&pe.d[co]);
                    if (!v) break;
                    ncb++;
                    co += pe.is64 ? 8 : 4;
                }
            }
            J << ",\n    \"tls_callback\": " << (ncb ? "true" : "false");
        }
    }
    J << "\n  }";
    J << ",\n  \"vm_wrapped_count\": " << vm_wrapped;
    /* ================= cp298/V298-2: py:100-197 kalan alan paritesi ================= */
    /* (c) check_debugger_apis: IAT ∩ dbg_apis (py:127 birebir; OP_ANTIDBG taramasi
       asagida 'OP_ANTIDBG(0x1E) bytecode icinde' olarak eklenir) */
    {
        const char* dbg_apis[] = {"IsDebuggerPresent","CheckRemoteDebuggerPresentA",
            "CheckRemoteDebuggerPresentW","NtQueryInformationProcess","OutputDebugStringA",
            "OutputDebugStringW","NtSetInformationThread","RtlpQueryProcessInformation"};
        std::vector<std::string> hits;
        for (auto* a : dbg_apis) if (iat_set.count(a)) hits.push_back(a);
        std::string aj;
        for (size_t i=0;i<hits.size();i++) { if(i) aj += ", "; aj += "\"" + hits[i] + "\""; }
        J << ",\n  \"check_debugger_apis\": [" << aj << "]";
    }
    /* (d) tlscb: TLS dizini callback VA listesi (py:139-158 birebir — dd[9]) */
    {
        std::vector<std::string> cbs;
        u32 trva = pe.dd[9][0];
        if (trva) {
            long to = pe.rva2off(trva);
            if (to >= 0 && (size_t)to + (pe.is64?24:20) + 8 <= pe.d.size()) {
                u64 cbv = pe.is64
                    ? (*(u64*)&pe.d[to+24])
                    : (u64)(*(u32*)&pe.d[to+20]);
                u32 crva = (u32)((cbv - pe.imgbase) & 0xFFFFFFFFull);
                long co = pe.rva2off(crva);
                while (co >= 0 && (size_t)co + (pe.is64?8:4) <= pe.d.size()) {
                    u64 v = pe.is64 ? (*(u64*)&pe.d[co]) : (u64)(*(u32*)&pe.d[co]);
                    if (!v) break;
                    cbs.push_back("0x" + hex((u32)((v - pe.imgbase) & 0xFFFFFFFFull)));
                    co += pe.is64 ? 8 : 4;
                }
            }
        }
        g_tlscb_n = (int)cbs.size();
        /* py:141 — TLS dizini VARSA 'tls' alanı da yazılır */
        if (trva)
            J << ",\n  \"tls\": {\"rva\": \"" << lc_hex(trva) << "\", \"size\": \"" << lc_hex(pe.dd[9][1]) << "\"}";
        std::string tj;
        for (size_t i=0;i<cbs.size();i++) { if(i) tj += ", "; tj += "\"" + cbs[i] + "\""; }
        J << ",\n  \"tlscb\": [" << tj << "]";
    }
    /* (e) vm_gate_section/count: .text E9 hedeflerinin bilinen-ad-dışı section'lara
       düşme sıklığı — real-VMP VM bölgesi tespiti (py:170-197 birebir) */
    {
        static const char* known[] = {".text",".rdata",".data",".pdata",".bss",".reloc",
            ".idata",".edata",".rsrc",".tls",".debug"};
        auto is_known = [&](const std::string& n){
            std::string l = n; for (auto& c : l) c |= 0x20;
            for (auto* k : known) if (l == k) return true;
            return false;
        };
        std::map<std::string,int> hits;
        const Sec* text = pe.sec(".text");
        if (text && text->rs) {
            u32 scan_n = std::min(text->rs - 5, 0x40000u);
            for (u32 i=0;i<scan_n;i++) {
                long o = (long)text->ptr + i;
                if (o < 0 || (size_t)o + 5 > pe.d.size()) continue;
                if (pe.d[o] == 0xE9) {
                    s32 rel; memcpy(&rel, &pe.d[o+1], 4);
                    u32 tgt = (text->va + i + 5 + rel) & 0xFFFFFFFFu;
                    for (auto& sc : pe.secs) {
                        if (is_known(sc.name)) continue;
                        u32 end = sc.va + std::max(sc.vs, sc.rs);
                        if (sc.va <= tgt && tgt < end) { hits[sc.name]++; break; }
                    }
                }
            }
        }
        std::string gate_sec;
        int gate_cnt = 0;
        if (!hits.empty()) {
            int best = -1;
            for (auto& kv : hits) if (kv.second > best) { best = kv.second; gate_sec = kv.first; }
            for (auto& kv : hits) gate_cnt += kv.second;
        } else {
            /* py:181 PE32 fallback: bilinen-ad-dışı VE rs>0x10000 en büyük section
               (py'de yalnızca !is64; x64'te bu fallback çalışmaz) */
            const Sec* vm = nullptr; int ncand = 0;
            if (!pe.is64) {
                for (auto& sc : pe.secs)
                    if (!is_known(sc.name) && sc.rs > 0x10000) { ncand++; if (!vm || sc.rs > vm->rs) vm = &sc; }
            }
            if (!vm) {
                /* py:191: .vmp* adlı section'lar (console üretimi) */
                const Sec* vbest = nullptr; int vn = 0;
                for (auto& sc : pe.secs)
                    if (sc.name.rfind(".vmp", 0) == 0) { vn++; if (!vbest || sc.rs > vbest->rs) vbest = &sc; }
                if (vbest) { gate_sec = vbest->name; gate_cnt = vn; }
            } else { gate_sec = vm->name; gate_cnt = ncand; }
        }
        J << ",\n  \"vm_gate_section\": " << (gate_sec.empty() ? "null" : "\"" + gate_sec + "\"");
        J << ",\n  \"vm_gate_count\": " << gate_cnt;
    }
    /* cp298: py:329 vmp0 alanı HER ZAMAN yazılır (korumasız exe'de null) */
    if (vmp0)
        J << ",\n  \"vmp0\": {\"rva\": \"0x" << hex(vmp0->va) << "\", \"size\": \"0x" << hex(vmp0->vs)
          << "\", \"entropy\": " << entropy(&pe.d[vmp0->ptr], vmp0->rs) << "}";
    else
        J << ",\n  \"vmp0\": null";

    // ================= cp292/V292-1: MOD1 GENIS ALANLAR (py:225-300 paritesi) =================
    // (a) stub_template: vmp3x-push-call sablonu — export E9-gate'lerinin ortak hedefi
    // (b) vm_functions: export envanteri (name/rva/kind: gate|stub|jmp|nativ|data)
    // (c) iat_dump: IAT isim listesi (ilk 64)
    {
        // (a) stub_template — py:195-235 paritesi (3 kural):
        //   1. vmp3x-vmsections: .vmp* bolumleri (XProtect CP-motoru; en buyuk .vmp sec)
        //   2. vmp3x-push-call: .text E9-gate hedeflerinde 68+E8 ortak vm_entry
        //   3. hicbiri yoksa '-'
        std::string tpl_name = "-"; u32 tpl_entry = 0; int tpl_match = 0;
        {
            // kural 1: .vmp* bolumleri — cp298 DÜZELTME: py:191'de bu fallback yalnız
            // _vmgate_sec BOŞKEN çalışır (E9-hits varsa py _tpl'i yalnız push-call
            // taraması doldurabilir; cet_on'da py stub_template=None kaldı — parite).
            // gate_sec'i burada henüz bilmiyoruz; E9-scan sonuçunu parametre olarak al:
            // (vm_gate bloğu stub_template'ten SONRA koştuğu için ön-tarama yap)
            bool _e9_gate_found = false;
            {
                static const char* kn[] = {".text",".rdata",".data",".pdata",".bss",".reloc",
                    ".idata",".edata",".rsrc",".tls",".debug"};
                auto isk = [&](const std::string& n){ std::string l=n; for(auto&c:l)c|=0x20;
                    for (auto* k:kn) if (l==k) return true; return false; };
                const Sec* tx = pe.sec(".text");
                if (tx && tx->rs) {
                    u32 lim = std::min(tx->rs-5, 0x40000u);
                    for (u32 i=0;i<lim;i++) {
                        long o = (long)tx->ptr + i;
                        if ((size_t)o+5 > pe.d.size() || pe.d[o] != 0xE9) continue;
                        s32 rl; memcpy(&rl, &pe.d[o+1], 4);
                        u32 tg = tx->va + i + 5 + (u32)rl;
                        for (auto& sc : pe.secs) {
                            if (isk(sc.name)) continue;
                            if (sc.va <= tg && tg < sc.va + std::max(sc.vs, sc.rs)) { _e9_gate_found = true; break; }
                        }
                        if (_e9_gate_found) break;
                    }
                }
            }
            const Sec* vm_big = nullptr; int vm_n = 0;
            for (auto& sc : pe.secs) {
                if (sc.name.rfind(".vmp", 0) == 0) { vm_n++; if (!vm_big || sc.rs > vm_big->rs) vm_big = &sc; }
            }
            if (vm_n && !_e9_gate_found) { tpl_name = "vmp3x-vmsections"; tpl_entry = vm_big->va; tpl_match = vm_n; }
            // kural 2: E9-gate hedeflerinde push-call sablonu (buyuk eslesme ezer)
            const Sec* vt = pe.sec(".text");
            std::map<u32,int> commons;
            if (vt) {
                u32 lim = vt->rs - 5; if (lim > 0x40000) lim = 0x40000;
                for (u32 i = 0; i < lim; i++) {
                    long o = (long)vt->ptr + i;
                    if ((size_t)o + 5 > pe.d.size() || pe.d[o] != 0xE9) continue;
                    s32 rel; memcpy(&rel, &pe.d[o+1], 4);
                    u32 tgt = vt->va + i + 5 + (u32)rel;
                    // hedef .vmp* bolumunde mi? (gate taramasi)
                    bool in_vm = false;
                    for (auto& sc : pe.secs)
                        if (sc.name.rfind(".vmp", 0) == 0) {
                            u32 sz = sc.vs > sc.rs ? sc.vs : sc.rs;
                            if (sc.va <= tgt && tgt < sc.va + sz) { in_vm = true; break; }
                        }
                    if (!in_vm) continue;
                    // hedefin kendisi 68+E8 mi? (ilk 16 gate)
                    long to2 = pe.rva2off(tgt);
                    if (to2 < 0 || (size_t)to2 + 6 > pe.d.size()) continue;
                    if (pe.d[to2] != 0x68 || pe.d[to2+5] != 0xE8) continue;
                    s32 rel2; memcpy(&rel2, &pe.d[to2+6], 4);
                    u32 cmn = tgt + 10 + (u32)rel2;
                    commons[cmn]++;
                    if (commons.size() >= 16) break;
                }
            }
            int best = 0; u32 be = 0;
            for (auto& kv : commons)
                if (kv.second > best) { best = kv.second; be = kv.first; }
            if (best >= 2) { tpl_name = "vmp3x-push-call"; tpl_entry = be; tpl_match = best; }
        }
        /* cp298: py:211-235 — template bulunamadıysa stub_template = null (py '-'
           yazmaz; _tpl None kalır → JSON null) */
        if (tpl_name == "-")
            J << ",\n  \"stub_template\": null";
        else
        J << ",\n  \"stub_template\": {\"template\": \"" << tpl_name
          << "\", \"vm_entry\": \"" << (tpl_entry ? "0x"+hex(tpl_entry) : std::string("-"))
          << "\", \"match\": " << tpl_match << "}";

        // (b) vm_functions — export dizininden (py birebir, min(32))
        struct AnVmfEnt { u32 rva; std::string kind; };
        std::vector<AnVmfEnt> an_vmf;   /* cp292: OP_ANTIDBG taramasi icin */
        J << ",\n  \"vm_functions\": [";
        int vmf_wrapped = 0;
        {
            u32 exp_rva = pe.dd[0][0];
            int n_out = 0;
            if (exp_rva) {
                long o = pe.rva2off(exp_rva);
                if (o >= 0 && (size_t)o + 0x24 <= pe.d.size()) {
                    u32 n, af, an; memcpy(&n, &pe.d[o+0x14], 4); memcpy(&af, &pe.d[o+0x1C], 4); memcpy(&an, &pe.d[o+0x20], 4);
                    long afo = pe.rva2off(af), ano = pe.rva2off(an);
                    const Sec* text = pe.sec(".text");
                    if (n > 32) n = 32;
                    for (u32 i = 0; i < n; i++) {
                        u32 rva; memcpy(&rva, &pe.d[afo + 4*i], 4);
                        long fo = pe.rva2off(rva);
                        if (fo < 0) continue;
                        u32 nnr; memcpy(&nnr, &pe.d[ano + 4*i], 4);
                        long no = pe.rva2off(nnr);
                        std::string nm = "?";
                        if (no >= 0) { size_t e = no; while (e < pe.d.size() && pe.d[e]) e++; if (e > (size_t)no) nm = std::string((char*)&pe.d[no], e - no); }
                        u8 first = pe.d[fo];
                        std::string kind = "nativ";
                        std::string tgt_s = "";
                        if (first == 0xE9) {
                            s32 rel; memcpy(&rel, &pe.d[fo+1], 4);
                            u32 tgt = rva + 5 + (u32)rel;
                            bool in_cpl = vmp0 && vmp0->va <= tgt && tgt < vmp0->va + vmp0->vs;
                            if (in_cpl) { kind = "VM gate (E9 -> .vmp0)"; }
                            else kind = "jmp";
                            tgt_s = "0x" + hex(tgt);
                        } else if (fo + 2 < (long)pe.d.size() &&
                                   (memcmp(&pe.d[fo], "\x41\x57", 2) == 0 || memcmp(&pe.d[fo], "\x41\x56", 2) == 0 ||
                                   memcmp(&pe.d[fo], "\x41\x55", 2) == 0) || first == 0x9C) {
                            kind = "inline VM stub (push r15...)";
                        }
                        if (!(text && text->va <= rva && rva < text->va + text->vs)) kind = "data export";
                        bool wrapped = kind.find("gate") != std::string::npos || kind.find("stub") != std::string::npos;
                        if (wrapped) vmf_wrapped++;
                        an_vmf.push_back({rva, kind});
                        if (n_out++) J << ",";
                        J << "\n    {\"name\": \"" << json_esc(nm) << "\", \"rva\": \"" << lc_hex(rva)
                          << "\", \"kind\": \"" << kind << "\"";
                        if (!tgt_s.empty()) J << ", \"target_rva\": \"" << tgt_s << "\"";
                        J << "}";
                    }
                }
            }
            J << "\n  ]";
        }
        // py paritesi: vm_wrapped_count export-bazli sayac da yazilsin (E9-taramasi uste)
        J << ",\n  \"vm_functions_wrapped\": " << vmf_wrapped;

        // (d) cp292/V292-3: OP_ANTIDBG(0x1E) bytecode taramasi (py:286-299 paritesi)
        // — gate/stub bulunan ilk fonksiyonun stub'ini cozup bytecode'ta 0x1E ara.
        //vmfn check_debugger_apis alaniyla yazilir
        {
            g_an_ad_found = false;
            bool found_ad = false; int ad_mask = -1;
            /* cp292-duzeltme: export listesinde 'nativ' gorunen inline stub'lari da
               tara (.text icinde 41 57/41 56/41 55/9C/60 baslayan bolgeler — export
               RVA'si korunan fonksiyonla ayni olmak zorunda degil). */
            const Sec* vt3 = pe.sec(".text");
            if (vt3 && vmp0) {
                for (u32 va2 = vt3->va; va2 + 8 < vt3->va + vt3->vs && !found_ad; va2++) {
                    long o3 = pe.rva2off(va2);
                    if (o3 < 0 || (size_t)(o3 + 8) > pe.d.size()) continue;
                    u8 b3 = pe.d[o3];
                    bool stub3 = (b3 == 0x9C) || (b3 == 0x60) ||
                        (memcmp(&pe.d[o3], "\x41\x57", 2) == 0 || memcmp(&pe.d[o3], "\x41\x56", 2) == 0 ||
                         memcmp(&pe.d[o3], "\x41\x55", 2) == 0);
                    if (!stub3) continue;
                    auto st3 = parse_xprotect_stub(pe, pe.d, o3, va2);
                    if (!st3.ok || !st3.bc_len) continue;
                    long bco3 = pe.rva2off(st3.bc_rva);
                    if (bco3 < 0 || (size_t)(bco3 + st3.bc_len) > pe.d.size()) continue;
                    std::vector<u8> bc3;
                    cfb_decrypt(&pe.d[bco3], st3.bc_len, st3.key, bc3, 1);
                    auto itab3 = vm_perm_tab(va2);
                    for (size_t q = 0; q < bc3.size(); q++) {
                        u8 op = bc3[q];
                        bool is_ad = (op < 0x45) && !itab3.empty() && itab3[op] == 0x1E;
                        if (is_ad) { found_ad = true; g_an_ad_found = true; ad_mask = (q + 1 < bc3.size()) ? bc3[q+1] : -1; break; }
                    }
                }
            }
            for (size_t e = 0; e < an_vmf.size() && !found_ad; e++) {
                const auto& ent = an_vmf[e];
                if (ent.kind.find("gate") == std::string::npos && ent.kind.find("stub") == std::string::npos) continue;
                long fo2 = pe.rva2off(ent.rva);
                if (fo2 < 0) continue;
                u8 b0 = pe.d[fo2];
                bool stub_like = (b0 == 0xE9) || b0 == 0x9C || b0 == 0x60 ||
                                 (fo2 + 2 < (long)pe.d.size() && (memcmp(&pe.d[fo2], "\x41\x57", 2) == 0 ||
                                 memcmp(&pe.d[fo2], "\x41\x56", 2) == 0 || memcmp(&pe.d[fo2], "\x41\x55", 2) == 0));
                if (!stub_like) continue;
                auto st2 = parse_xprotect_stub(pe, pe.d, fo2, ent.rva);
                if (!st2.ok || !st2.bc_len) continue;
                long bco2 = pe.rva2off(st2.bc_rva);
                if (bco2 < 0 || (size_t)(bco2 + st2.bc_len) > pe.d.size()) continue;
                std::vector<u8> bc2;
                cfb_decrypt(&pe.d[bco2], st2.bc_len, st2.key, bc2, 1);
                auto itab2 = vm_perm_tab(ent.rva);
                for (size_t q = 0; q < bc2.size(); q++) {
                    u8 op = bc2[q];
                    bool is_ad = (op < 0x45) && !itab2.empty() && itab2[op] == 0x1E;
                    if (is_ad) { found_ad = true; g_an_ad_found = true; ad_mask = (q + 1 < bc2.size()) ? bc2[q+1] : -1; break; }
                }
                if (found_ad) break;
            }
            if (found_ad) {
                J << ",\n  \"check_debugger_apis\": [\"OP_ANTIDBG(0x1E) bytecode icinde\"]";
                J << ",\n  \"check_debugger_mask\": " << ad_mask;
            }
        }

        // (c) iat_dump — IAT isim listesi (ilk 64; ad JSON-esc'lenir —
        // hint-baytlı adlar '$\x01...' kontrol karakteri kırmasın)
        J << ",\n  \"iat_dump\": [";
        {
            int n_out = 0;
            for (auto& nm : iat_set) {
                if (n_out >= 64) break;
                if (n_out++) J << ",";
                J << "\n    \"";
                for (unsigned char c : nm) {
                    if (c == '"' || c == '\\') J << '\\' << (char)c;
                    else if (c < 0x20 || c == 0x7F) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); J << b; }
                    else J << (char)c;
                }
                J << "\"";
            }
            J << "\n  ]";
        }
        J << ",\n  \"iat_count\": " << iat_set.size();
        // py 'iat' dict paritesi: {rva, size, count}
        {
            u32 irva2 = pe.dd[12][0]; u32 isz2 = pe.dd[12][1];   /* py:160 birebir — IAT directory */
            J << ",\n  \"iat\": {\"rva\": \"" << lc_hex(irva2) << "\", \"size\": \""
              << lc_hex(isz2) << "\", \"count\": " << iat_set.size() << "}";
        }
    }

    J << "\n}";
    /* cp292: OP_ANTIDBG taramasi features'tan SONRA kosuyor — degeri burada
       geri yama (features.check_debugger) */
    { std::string js = J.str();
      if (g_an_ad_found) {
          size_t p2 = js.find("\"check_debugger\": false");
          if (p2 != std::string::npos) js.replace(p2, 24, "\"check_debugger\": true, ");
      }
      J.str(js); }
    printf("%s\n", J.str().c_str());
    if (!jout.empty()) { std::ofstream f(jout); f << J.str() << "\n"; }
    return J.str();
}

// ---------------- MOD 2: unlift (Python birebir) ----------------
struct UnliftResult {
    std::vector<u8> code;
    std::vector<std::string> notes;
    std::vector<std::pair<size_t, u32>> rip_fixups;   // (disp_off_in_out, target_rva)
    std::vector<std::pair<size_t, u32>> jfixups;      // (disp_out_pos, tgt_bc|0x40000000 dis)
    std::map<size_t, size_t> bc2out;                  // bc off -> out off
};
struct UnliftCtx {
    const std::vector<u8>& bc;
    bool is64; u64 imgbase;
    std::vector<u8> out;
    std::vector<std::string> notes;
    std::vector<std::pair<size_t, u32>> rip_fixups;
    std::vector<std::pair<size_t, u32>> jfixups;
    std::map<size_t, size_t> bc2out;
    size_t i = 0, n = 0;
    const int SIB_NOBASE = 0xFF;
    std::vector<u8> itab;   // bos = perm yok
    UnliftCtx(const std::vector<u8>& b, bool i64, u64 ib, const std::vector<u8>* perm)
        : bc(b), is64(i64), imgbase(ib) { n = b.size(); if (perm) itab = *perm; }
    u8 u8v() { u8 v = bc[i]; i++; return v; }
    s32 i32v() { s32 v; memcpy(&v, &bc[i], 4); i += 4; return v; }
    // mem = (kind, base, idx, scale, disp)
    struct Mem { int kind, base, idx, scale; s32 disp; };
    Mem read_mem() {
        int form = u8v();
        return read_mem_body(form);
    }
    Mem read_mem_body(int form) {
        Mem m; m.kind=form; m.base=-1; m.idx=-1; m.scale=0; m.disp=0;
        if (form == 0) { m.disp = i32v(); return m; }
        m.base = u8v(); m.idx = u8v(); m.scale = u8v(); m.disp = i32v();
        return m;
    }
    void push32(std::vector<u8>& v, u32 a) { for (int k=0;k<4;k++) v.push_back((u8)(a>>(8*k))); }
    void pushi(std::vector<u8>& v, s32 a) { u32 u=(u32)a; push32(v, u); }

    // SADECE ModRM+SIB+disp — donus: (baytlar, ('rip', disp) | bos)
    std::vector<u8> modrm_tail(const Mem& m, int regfield, int sz, std::pair<bool, s32>* fix) {
        std::vector<u8> b;
        if (fix) fix->first = false;
        int kind = m.kind, base = m.base, idx = m.idx, scale = m.scale; s32 disp = m.disp;
        if (kind == 2 && idx != SIB_NOBASE && !is64) {
            if (base == SIB_NOBASE) b.push_back((u8)(((regfield & 7) << 3) | 4));
            else b.push_back((u8)((2 << 6) | ((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | (base == SIB_NOBASE ? 5 : (base & 7))));
            push32(b, (u32)((s64)disp + (s64)imgbase));
            return b;
        }
        if (base == SIB_NOBASE && idx != SIB_NOBASE) {
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 5));
            push32(b, (u32)((s64)disp + (s64)imgbase));
            return b;
        }
        if (kind == 2 && base != SIB_NOBASE && idx != SIB_NOBASE) {
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 3));
            return b;
        }
        if (kind == 0 || (kind == 2 && base != SIB_NOBASE && idx == SIB_NOBASE)) {
            if (!is64) {
                if (kind == 2 && base != SIB_NOBASE) {
                    b.push_back((u8)(((regfield & 7) << 3) | 4));
                    b.push_back((u8)(base & 7));
                } else {
                    b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
                }
                push32(b, (u32)((s64)disp + (s64)imgbase));
                return b;
            }
            b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
            for (int k=0;k<4;k++) b.push_back(0);
            if (fix) { fix->first = true; fix->second = (u32)disp; }
            return b;
        }
        bool need_sib = (idx != SIB_NOBASE) || (base == SIB_NOBASE) || (base == 4);
        if (base == SIB_NOBASE && idx == SIB_NOBASE) {
            b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
            pushi(b, disp);
            return b;
        }
        if (base == SIB_NOBASE && idx != SIB_NOBASE) {
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 5));
            push32(b, (u32)((s64)disp + (s64)imgbase));
            return b;
        }
        int mod;
        if (disp == 0 && base != 5) mod = 0;
        else if (disp >= -128 && disp <= 127) mod = 1;
        else mod = 2;
        b.push_back((u8)((mod << 6) | ((regfield & 7) << 3) | (need_sib ? 4 : (base & 7))));
        if (need_sib) {
            int ss = scale & 3;
            int ix = (idx != SIB_NOBASE) ? (idx & 7) : 4;
            int bs = (base != SIB_NOBASE) ? (base & 7) : 5;
            b.push_back((u8)((ss << 6) | (ix << 3) | bs));
        }
        if (mod == 1) b.push_back((u8)(disp & 0xFF));
        else if (mod == 2) pushi(b, disp);
        return b;
    }
    void emit_tail(const Mem& m, int regfield, int sz) {
        std::pair<bool, s32> fix;
        auto b = modrm_tail(m, regfield, sz, &fix);
        out.insert(out.end(), b.begin(), b.end());
        if (fix.first) rip_fixups.push_back({out.size() - 4, (u32)fix.second});
    }
    // [REX] opcode ModRM SIB disp — donus baytlar + fix
    std::vector<u8> modrm_mem(const Mem& m, int regfield, int sz, u8 opcode, std::pair<int, u32>* fix) {
        // fix: 0=yok 1=rip 2=lea_rip
        std::vector<u8> b;
        if (fix) fix->first = 0;
        int kind = m.kind, base = m.base, idx = m.idx, scale = m.scale; s32 disp = m.disp;
        if (kind == 2 && base != SIB_NOBASE && idx == SIB_NOBASE && !is64) {
            b.push_back(opcode);
            b.push_back((u8)((2 << 6) | ((regfield & 7) << 3) | 4));
            b.push_back((u8)(base & 7));
            push32(b, (u32)((s64)disp + (s64)imgbase));
            return b;
        }
        if (kind == 0) {
            if (!is64) {
                b.push_back(opcode);
                b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
                push32(b, (u32)((s64)disp + (s64)imgbase));
                return b;
            }
            u8 rex = 0;
            if (sz == 8) rex |= 8;
            if (regfield >= 8) rex |= 4;
            if (rex) b.push_back((u8)(0x40 | rex));
            b.push_back(opcode);
            b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
            for (int k=0;k<4;k++) b.push_back(0);
            if (fix) { fix->first = 1; fix->second = (u32)disp; }
            return b;
        }
        if (base == SIB_NOBASE && idx != SIB_NOBASE) {
            b.push_back(opcode);
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 5));
            push32(b, (u32)((s64)disp + (s64)imgbase));
            return b;
        }
        if (kind == 2 && base != SIB_NOBASE && idx != SIB_NOBASE) {
            if (!is64) {
                b.push_back(opcode);
                b.push_back((u8)(((regfield & 7) << 3) | 4));
                b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 5));
                push32(b, (u32)((s64)disp + (s64)imgbase));
                return b;
            }
            std::vector<u8> b1;
            b1.insert(b1.end(), {0x4C, 0x8D, 0x1D, 0, 0, 0, 0});   // lea r11,[rip+disp]
            int lea_disp_off = 3;
            u8 rex = 0;
            if (sz == 8) rex |= 8;
            if (regfield >= 8) rex |= 4;
            if (idx >= 8) rex |= 2;
            if (rex) b.push_back((u8)(0x40 | rex));
            b.push_back(opcode);
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 3));   // base=r11
            b.insert(b.begin(), b1.begin(), b1.end());
            if (fix) { fix->first = 2; fix->second = (u32)lea_disp_off; }
            return b;
        }
        if (kind == 2 && base != SIB_NOBASE && idx == SIB_NOBASE) {
            u8 rex = 0;
            if (sz == 8) rex |= 8;
            if (regfield >= 8) rex |= 4;
            if (rex) b.push_back((u8)(0x40 | rex));
            b.push_back(opcode);
            b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
            for (int k=0;k<4;k++) b.push_back(0);
            if (fix) { fix->first = 1; fix->second = (u32)disp; }
            return b;
        }
        u8 rex = 0;
        if (sz == 8) rex |= 8;
        if (regfield >= 8) rex |= 4;
        bool need_sib = (idx != SIB_NOBASE) || (base == SIB_NOBASE) || (base == 4);
        if (base == SIB_NOBASE && idx == SIB_NOBASE) {
            if (rex) b.push_back((u8)(0x40 | rex));
            b.push_back(opcode);
            b.push_back((u8)(0x05 | ((regfield & 7) << 3)));
            pushi(b, m.disp);
            return b;
        }
        if (base == SIB_NOBASE && idx != SIB_NOBASE) {
            b.push_back(opcode);
            b.push_back((u8)(((regfield & 7) << 3) | 4));
            b.push_back((u8)(((scale & 3) << 6) | ((idx & 7) << 3) | 5));
            push32(b, (u32)((s64)m.disp + (s64)imgbase));
            return b;
        }
        if (base >= 8) rex |= 2;
        if (idx >= 8 && idx != SIB_NOBASE) rex |= 4;
        if (rex) b.push_back((u8)(0x40 | rex));
        b.push_back(opcode);
        int mod;
        if (m.disp == 0 && base != 5) mod = 0;
        else if (m.disp >= -128 && m.disp <= 127) mod = 1;
        else mod = 2;
        b.push_back((u8)((mod << 6) | ((regfield & 7) << 3) | (need_sib ? 4 : (base & 7))));
        if (need_sib) {
            int ss = scale & 3;
            int ix = (idx != SIB_NOBASE) ? (idx & 7) : 4;
            int bs = (base != SIB_NOBASE) ? (base & 7) : 5;
            b.push_back((u8)((ss << 6) | (ix << 3) | bs));
        }
        if (mod == 1) b.push_back((u8)(m.disp & 0xFF));
        else if (mod == 2) pushi(b, m.disp);
        return b;
    }
    void emit_mem(const Mem& m, int regfield, int sz, u8 opcode) {
        size_t base_len = out.size();
        std::pair<int, u32> fix;
        auto b = modrm_mem(m, regfield, sz, opcode, &fix);
        out.insert(out.end(), b.begin(), b.end());
        if (fix.first == 2) rip_fixups.push_back({base_len + fix.second, (u32)m.disp});
        else if (fix.first == 1) rip_fixups.push_back({out.size() - 4, (u32)m.disp});
    }
    void emit_u8(u8 b) { out.push_back(b); }
    void emit_bytes(std::initializer_list<u8> bs) { for (u8 b : bs) out.push_back(b); }
    static const int ALU_REG_[9];
};

const int UnliftCtx::ALU_REG_[9] = {0, 5, 4, 1, 6, 7, 0, 2, 3};   // cp289: ADC=/2 SBB=/3   // adc/sbb → /reg ayni (83/81)
// (CP289 not: motor ALU_REG tablosu ADC=7 SBB=8 ek emit farki yaratmaz — /n kodu ayni)
static const int SHI_REG_[6] = {4, 5, 7, 0, 1, 6};
static const int ALU_R_[9] = {0x03, 0x2B, 0x23, 0x0B, 0x33, 0x3B, 0x85, 0x13, 0x1B};
static const int ALU_M_[9] = {0x01, 0x29, 0x21, 0x09, 0x31, 0x39, 0x85, 0x11, 0x19};

static UnliftResult unlift(const std::vector<u8>& bc, bool is64, u32 base_rva, u64 imgbase,
                           bool cut_at_ret, const std::vector<u8>* perm) {
    UnliftCtx X(bc, is64, imgbase, perm);
    using Mem = UnliftCtx::Mem;
    auto& out = X.out; auto& notes = X.notes;
    auto& rip_fixups = X.rip_fixups; auto& jfixups = X.jfixups; auto& bc2out = X.bc2out;
    size_t& i = X.i; size_t n = X.n;
    (void)0;
    while (i < n) {
        size_t bc_start = i;
        u8 op_peek = bc[i];
        if (op_peek == 0x00) { bc2out[bc_start] = out.size(); i++; continue; }
        bc2out[bc_start] = out.size();
        u8 op = X.u8v();
        if (!X.itab.empty()) op = X.itab[op] & 0xFF;
        bool err = false;
        do {
            // junk deseni: push rV; push imm; pop rV; pop rV (11 bayt) — etkisiz
            if (op == 0x14 && i + 11 <= n && (bc[i+1] == 11 || bc[i+1] == 1)
                    && bc[i+2] == 0x15 && bc[i+7] == 0x16 && bc[i+9] == 0x16) {
                bc2out[i] = out.size();
                i += 11;
                notes.push_back("junk push/pop atlandi @bc" + std::to_string(i));
                break;
            }
            switch (op) {
            case 0x00: break;
            case 0x01: {  // MOV_RR sz r1 r2
                int sz = X.u8v(); int r1 = X.u8v(); int r2 = X.u8v();
                if (sz == 8) X.emit_bytes({0x48, 0x89, (u8)(0xC0 | (r2<<3) | r1)});
                else if (sz == 4) X.emit_bytes({0x89, (u8)(0xC0 | (r2<<3) | r1)});
                else if (sz == 2) X.emit_bytes({0x66, 0x89, (u8)(0xC0 | (r2<<3) | r1)});
                else X.emit_bytes({0x88, (u8)(0xC0 | (r2<<3) | r1)});
                break; }
            case 0x02: {  // MOV_RI sz r1 imm32(sx)
                int sz = X.u8v(); int r1 = X.u8v(); s32 imm = X.i32v();
                if (sz == 8 && is64 && !(imm >= -2147483647-1 && imm < 2147483647)) {
                    // Python: -2**31 <= imm < 2**31 degilse movabs
                    // (imm32 zaten sx — bu dal Python'da daima false; koru)
                    X.emit_bytes({(u8)(0x48 | (r1>>3)), (u8)(0xB8 | (r1&7))});
                    u64 q = (u64)(s64)imm; for (int k=0;k<8;k++) out.push_back((u8)(q>>(8*k)));
                } else if (sz == 8) {
                    X.emit_bytes({0x48, 0xC7, (u8)(0xC0 | r1)});
                    u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                } else if (sz == 4 && ((u32)imm & 0xFF) == (u32)imm && r1 == 0 && imm != 0) {
                    X.emit_bytes({(u8)(0xB0 | r1), (u8)(imm & 0xFF)});
                } else if (sz == 4 && imm == 0 && r1 == 0) {
                    X.emit_bytes({0x31, 0xC0});
                } else if (sz == 4) {
                    X.emit_bytes({0xC7, (u8)(0xC0 | r1)});
                    u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                } else if (sz == 2) {
                    X.emit_bytes({0x66, 0xC7, (u8)(0xC0 | r1)});
                    u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                } else {
                    X.emit_bytes({0xC6, (u8)(0xC0 | r1), (u8)(imm & 0xFF)});
                }
                break; }
            case 0x03: {  // MOV_RM sz r1 mem
                int sz = X.u8v(); int r1 = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, r1, sz, sz >= 2 ? 0x8B : 0x8A);
                break; }
            case 0x04: {  // MOV_MR sz MEM r1
                int sz = X.u8v(); auto m = X.read_mem(); int r1 = X.u8v();
                X.emit_mem(m, r1, sz, sz >= 2 ? 0x89 : 0x88);
                break; }
            case 0x05: {  // MOV_MI sz MEM imm32
                int sz = X.u8v(); auto m = X.read_mem(); s32 imm = X.i32v();
                X.emit_mem(m, 0, sz, sz >= 2 ? 0xC7 : 0xC6);
                if (sz >= 4) { u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k))); }
                else out.push_back((u8)(imm & 0xFF));
                break; }
            case 0x06: {  // LEA_RM r1 mem
                int r1 = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, r1, is64 ? 8 : 4, 0x8D);
                break; }
            case 0x07: {  // ALU_RR
                int alu = X.u8v(), sz = X.u8v(), r1 = X.u8v(), r2 = X.u8v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                if (alu == 6) X.emit_bytes({0x85, (u8)(0xC0 | (r2<<3) | r1)});
                else {
                    int opc = (alu < 9) ? ALU_M_[alu] : 0x01;
                    opc = (alu == 0) ? 0x01 : (alu == 1) ? 0x29 : (alu == 2) ? 0x21
                        : (alu == 3) ? 0x09 : (alu == 4) ? 0x31 : (alu == 5) ? 0x39
                        : (alu == 7) ? 0x11 : (alu == 8) ? 0x19 : 0x01;
                    X.emit_bytes({(u8)opc, (u8)(0xC0 | (r2<<3) | r1)});
                }
                break; }
            case 0x08: {  // ALU_RI
                int alu = X.u8v(), sz = X.u8v(), r1 = X.u8v(); s32 imm = X.i32v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                if (sz == 1) {
                    int rex = (r1 >= 8) ? 0x41 : 0x40;
                    X.emit_bytes({(u8)rex, 0x80, (u8)(0xC0 | (X.ALU_REG_[alu & 7] << 3) | (r1 & 7)), (u8)(imm & 0xFF)});
                } else if (alu == 6) {
                    X.emit_bytes({0xF7, (u8)(0xC0 | r1)});
                    u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                } else if (imm >= -128 && imm <= 127 && sz >= 4) {
                    X.emit_bytes({0x83, (u8)(0xC0 | (X.ALU_REG_[alu & 7] << 3) | (r1 & 7)), (u8)(imm & 0xFF)});
                } else {
                    X.emit_bytes({0x81, (u8)(0xC0 | (X.ALU_REG_[alu & 7] << 3) | (r1 & 7))});
                    u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                }
                break; }
            case 0x09: {  // ALU_RM
                int alu = X.u8v(), sz = X.u8v(), r1 = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, r1, sz, (u8)ALU_R_[alu & 7]);
                break; }
            case 0x0A: {  // ALU_MR
                int alu = X.u8v(), sz = X.u8v(); auto m = X.read_mem(); int r1 = X.u8v();
                X.emit_mem(m, r1, sz, (u8)ALU_M_[alu & 7]);
                break; }
            case 0x0B: {  // ALU_MI
                int alu = X.u8v(), sz = X.u8v(); auto m = X.read_mem(); s32 imm = X.i32v();
                X.emit_mem(m, X.ALU_REG_[alu & 7], sz, sz >= 4 ? 0x81 : 0x83);
                if (sz >= 4) { u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k))); }
                else out.push_back((u8)(imm & 0xFF));
                break; }
            case 0x0C: {  // SHI_RI
                int shi = X.u8v(), sz = X.u8v(), r1 = X.u8v(); u8 imm = X.u8v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                X.emit_bytes({0xC1, (u8)(0xC0 | (SHI_REG_[shi & 5] << 3) | r1), imm});
                break; }
            case 0x0D: {  // SHI_CL
                int shi = X.u8v(), sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                X.emit_bytes({0xD3, (u8)(0xC0 | (SHI_REG_[shi & 5] << 3) | r1)});
                break; }
            case 0x0E: {  // IMUL_RRI
                int sz = X.u8v(), r1 = X.u8v(), r2 = X.u8v(); s32 imm = X.i32v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0x69, (u8)(0xC0 | (r2<<3) | r1)});
                u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x0F: {  // IMUL_RR
                int sz = X.u8v(), r1 = X.u8v(), r2 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0x0F, 0xAF, (u8)(0xC0 | (r2<<3) | r1)});
                break; }
            case 0x10: {  // INCDEC_R
                int ud = X.u8v(), sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0xFF, (u8)(0xC0 | ((ud == 0 ? 0 : 1) << 3) | r1)});
                break; }
            case 0x11: {  // INCDEC_M
                int ud = X.u8v(), sz = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, ud == 0 ? 0 : 1, sz, 0xFF);
                break; }
            case 0x12: case 0x13: {  // MOVZX/MOVSX
                int dsz = X.u8v(), ssz = X.u8v(), r1 = X.u8v(); int form = X.u8v();
                int opc2;
                bool movsxd = (ssz == 4 && op == 0x13 && dsz == 8);
                if (movsxd) opc2 = 0;
                else opc2 = (op == 0x12 ? 0xB6 : 0xBE) + (ssz == 2 ? 1 : 0);
                if (form == 0) {
                    int r2 = X.u8v();
                    std::vector<u8> b;
                    if (movsxd) {
                        u8 rex = 0;
                        if (r1 >= 8) rex |= 4;
                        if (r2 >= 8) rex |= 1;
                        if (rex) b.push_back((u8)(0x40 | rex));
                        b.push_back(0x63);
                        b.push_back((u8)(0xC0 | ((r1&7)<<3) | (r2&7)));
                    } else {
                        if (dsz == 2) b.push_back(0x66);
                        u8 rex = 0;
                        if (dsz == 8 && is64) rex |= 8;
                        if (r1 >= 8) rex |= 4;
                        if (r2 >= 8) rex |= 2;
                        if (rex) b.push_back((u8)(0x40 | rex));
                        b.push_back(0x0F); b.push_back((u8)opc2);
                        b.push_back((u8)(0xC0 | ((r1&7)<<3) | (r2&7)));
                    }
                    out.insert(out.end(), b.begin(), b.end());
                } else {
                    auto m = X.read_mem();
                    std::vector<u8> b;
                    if (movsxd) {
                        u8 rex = 0;
                        if (r1 >= 8) rex |= 4;
                        if (rex) b.push_back((u8)(0x40 | rex));
                        b.push_back(0x63);
                    } else {
                        if (dsz == 2) b.push_back(0x66);
                        u8 rex = 0;
                        if (dsz == 8 && is64) rex |= 8;
                        if (r1 >= 8) rex |= 4;
                        if (rex) b.push_back((u8)(0x40 | rex));
                        b.push_back(0x0F); b.push_back((u8)opc2);
                    }
                    out.insert(out.end(), b.begin(), b.end());
                    if (m.kind == 2 && m.base != X.SIB_NOBASE && m.idx != X.SIB_NOBASE && is64) {
                        X.emit_bytes({0x4C, 0x8D, 0x1D});
                        for (int k=0;k<4;k++) out.push_back(0);
                        rip_fixups.push_back({out.size() - 4, (u32)m.disp});
                    }
                    X.emit_tail(m, r1, ssz);
                    notes.push_back("movzx/movsx m @bc" + std::to_string(i));
                }
                break; }
            case 0x14: {  // PUSH_R
                int r1 = X.u8v();
                if (r1 < 8) out.push_back((u8)(0x50 + r1));
                else X.emit_bytes({0x41, (u8)(0x50 + (r1 & 7))});
                break; }
            case 0x15: {  // PUSH_I
                s32 v = X.i32v();
                out.push_back(0x68);
                u32 a=(u32)v; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x16: {  // POP_R
                int r1 = X.u8v();
                if (r1 < 8) out.push_back((u8)(0x58 + r1));
                else X.emit_bytes({0x41, (u8)(0x58 + (r1 & 7))});
                break; }
            case 0x17: {  // JMP rel32 bc-goreli
                size_t site_bc = i + 4;
                s32 tgt = X.i32v();
                u32 tgt_bc = (u32)(site_bc + tgt);
                jfixups.push_back({out.size() + 1, tgt_bc});
                out.push_back(0xE9);
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x18: {  // JCC
                int cc = X.u8v();
                size_t site_bc = i + 4;
                s32 tgt = X.i32v();
                u32 tgt_bc = (u32)(site_bc + tgt);
                jfixups.push_back({out.size() + 2, tgt_bc});
                X.emit_bytes({0x0F, (u8)(0x80 + cc)});
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x19: {  // NCALL u32 tgt
                u32 tgt; memcpy(&tgt, &bc[i], 4); i += 4;
                out.push_back(0xE8);
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                rip_fixups.push_back({out.size() - 4, tgt});
                break; }
            case 0x1A: {  // RET
                out.push_back(0xC3);
                if (cut_at_ret) { notes.push_back("ret sonrasi yal bloklar atlandi"); err = true; }
                break; }
            case 0x1B: {  // SETCC
                int cc = X.u8v(), r1 = X.u8v();
                X.emit_bytes({0x0F, (u8)(0x90 + cc), (u8)(0xC0 | r1)});
                break; }
            case 0x1C: {  // CQO/CDQ
                if (is64) out.push_back(0x48);
                out.push_back(0x99);
                break; }
            case 0x1D: {  // IDIV_R
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0xF7, (u8)(0xF8 | (r1 & 7))});
                break; }
            case 0x1E:   // ANTIDBG — kaldirildi
                notes.push_back("antidebug kaldirildi");
                break;
            case 0x1F: {  // STRDEC u32 x4
                i += 16;
                notes.push_back("string-decrypt bulundu (icerik korundu)");
                break; }
            case 0x20: {  // MOV_RI64
                int r1 = X.u8v();
                u64 imm; memcpy(&imm, &bc[i], 8); i += 8;
                if (is64) {
                    X.emit_bytes({(u8)(0x48 | (r1>>3)), (u8)(0xB8 | (r1&7))});
                    for (int k=0;k<8;k++) out.push_back((u8)(imm>>(8*k)));
                } else {
                    out.push_back((u8)(0xB8 | (r1&7)));
                    u32 a=(u32)(imm & 0xFFFFFFFF); for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                }
                break; }
            case 0x21: {  // CMOV
                int cc = X.u8v(), sz = X.u8v(), r1 = X.u8v(); int form = X.u8v();
                if (form == 0) {
                    int r2 = X.u8v();
                    if (sz == 8) out.push_back(0x48);
                    X.emit_bytes({0x0F, (u8)(0x40 + cc), (u8)(0xC0 | (r1<<3) | r2)});
                } else {
                    auto m = X.read_mem();
                    if (sz == 8) out.push_back(0x48);
                    else if (sz == 2) out.push_back(0x66);
                    X.emit_bytes({0x0F, (u8)(0x40 + cc)});
                    X.emit_tail(m, r1, sz);
                    notes.push_back("cmov m @bc" + std::to_string(i));
                }
                break; }
            case 0x22: case 0x23: {  // SHI_RM
                int shi = X.u8v(), sz = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, SHI_REG_[shi & 5], sz, op == 0x22 ? 0xC1 : 0xD3);
                if (op == 0x22) out.push_back(X.u8v());
                notes.push_back("shi m @bc" + std::to_string(i));
                break; }
            case 0x24: {  // IMUL_RMRI
                int sz = X.u8v(), r1 = X.u8v(); auto m = X.read_mem(); s32 imm = X.i32v();
                X.emit_mem(m, r1, sz, 0x69);
                u32 a=(u32)imm; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                notes.push_back("imul r,m,i @bc" + std::to_string(i));
                break; }
            case 0x25: {  // NEG_R
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0xF7, (u8)(0xD8 | (r1 & 7))});
                break; }
            case 0x26: {  // NOT_R
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                X.emit_bytes({0xF7, (u8)(0xD0 | (r1 & 7))});
                break; }
            case 0x27: {  // NEG_M
                int sz = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, 3, sz, 0xF7);
                notes.push_back("neg m @bc" + std::to_string(i));
                break; }
            case 0x28: {  // NOT_M
                int sz = X.u8v(); auto m = X.read_mem();
                X.emit_mem(m, 2, sz, 0xF7);
                notes.push_back("not m @bc" + std::to_string(i));
                break; }
            case 0x2A: {  // BSWAP_R
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 2) out.push_back(0x66);
                X.emit_bytes({0x0F, (u8)(0xC8 | (r1 & 7))});
                break; }
            case 0x2B: {  // XCHG_RR
                int sz = X.u8v(), r1 = X.u8v(), r2 = X.u8v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                X.emit_bytes({0x87, (u8)(0xC0 | ((r2 & 7) << 3) | (r1 & 7))});
                break; }
            case 0x2C: out.push_back(0x9C); break;
            case 0x2D: out.push_back(0x9D); break;
            case 0x2E: out.push_back(0x9E); break;
            case 0x2F: out.push_back(0x9F); break;
            case 0x30: {  // SETFLAG
                int ud = X.u8v();
                u8 b2 = (ud==0)?0xF8:(ud==1)?0xF9:(ud==2)?0xF5:(ud==3)?0xFC:(ud==4)?0xFD:0x90;
                out.push_back(b2);
                break; }
            case 0x31: {  // MUL_R
                int sz = X.u8v(), form = X.u8v();
                if (sz == 2) out.push_back(0x66);
                if (form == 1) { auto m = X.read_mem(); X.emit_mem(m, 4, sz, 0xF7); }
                else {
                    int r1 = X.u8v();
                    X.emit_bytes({0xF7, (u8)(0xC0 | (4 << 3) | (r1 & 7))});
                }
                break; }
            case 0x32: {  // DIV_R
                int sz = X.u8v(), form = X.u8v();
                if (sz == 2) out.push_back(0x66);
                if (form == 1) { auto m = X.read_mem(); X.emit_mem(m, 6, sz, 0xF7); }
                else {
                    int r1 = X.u8v();
                    X.emit_bytes({0xF7, (u8)(0xC0 | (6 << 3) | (r1 & 7))});
                }
                break; }
            case 0x33: {  // BT_X
                int ud = X.u8v(), sz = X.u8v(), form = X.u8v();
                Mem mem{}; int r1 = 0;
                if (form == 1) mem = X.read_mem(); else r1 = X.u8v();
                int srcform = X.u8v();
                if (sz == 2) out.push_back(0x66);
                if (srcform == 1) {
                    u8 imm = X.u8v();
                    X.emit_bytes({0x0F, 0xBA});
                    if (form == 1) X.emit_tail(mem, ud & 7, sz == 1 ? 2 : sz);
                    else out.push_back((u8)(0xC0 | ((ud & 7) << 3) | (r1 & 7)));
                    out.push_back(imm);
                } else {
                    int r2 = X.u8v();
                    u8 opc2 = (ud == 0) ? 0xA3 : (ud == 1) ? 0xAB : (ud == 2) ? 0xB3 : (ud == 3) ? 0xBB : 0xA3;
                    X.emit_bytes({0x0F, opc2});
                    if (form == 1) X.emit_tail(mem, r2 & 7, sz == 1 ? 2 : sz);
                    else out.push_back((u8)(0xC0 | ((r2 & 7) << 3) | (r1 & 7)));
                }
                break; }
            case 0x34: case 0x35: {  // SHLD/SHRD
                int sz = X.u8v(), r1 = X.u8v(), r2 = X.u8v(), nmode = X.u8v();
                u8 n2 = 0;
                if (nmode != 1) n2 = X.u8v();
                if (sz == 2) out.push_back(0x66);
                out.push_back(0x0F);
                out.push_back((u8)(op == 0x34 ? (nmode == 1 ? 0xA5 : 0xA4) : (nmode == 1 ? 0xAD : 0xAC)));
                out.push_back((u8)(0xC0 | ((r2 & 7) << 3) | (r1 & 7)));
                if (nmode != 1) out.push_back(n2);
                break; }
            case 0x36: {  // LOOP
                int cc = X.u8v();
                size_t site_bc = i + 4;
                s32 tgt = X.i32v();
                u32 tgt_bc = (u32)(site_bc + tgt);
                jfixups.push_back({out.size() + 1, tgt_bc});
                out.push_back((u8)(cc == 0 ? 0xE2 : cc == 1 ? 0xE1 : 0xE0));
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x37: {  // JECXZ
                size_t site_bc = i + 4;
                s32 tgt = X.i32v();
                u32 tgt_bc = (u32)(site_bc + tgt);
                jfixups.push_back({out.size() + 1, tgt_bc});
                out.push_back(0xE3);
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x38: {  // XADD
                int sz = X.u8v(), form = X.u8v();
                if (sz == 2) out.push_back(0x66);
                u8 opc = (sz == 1) ? 0xC0 : 0xC1;
                if (form == 1) {
                    auto m = X.read_mem(); int r2 = X.u8v();
                    X.emit_bytes({0x0F, opc});
                    X.emit_tail(m, r2 & 7, sz == 1 ? 2 : sz);
                } else {
                    int r1 = X.u8v(), r2 = X.u8v();
                    X.emit_bytes({0x0F, opc, (u8)(0xC0 | ((r2 & 7) << 3) | (r1 & 7))});
                }
                break; }
            case 0x39: {  // STR
                int ud = X.u8v(), sz = X.u8v(), rep = X.u8v();
                if (rep == 1) out.push_back(0xF3);
                else if (rep == 2) out.push_back(0xF2);
                u8 base2 = (ud == 0) ? 0xA4 : (ud == 1) ? 0xAA : (ud == 2) ? 0xAC : (ud == 3) ? 0xAE : 0xA6;
                int wide = (sz == 1 || (ud == 3 && sz == 2)) ? 0 : 1;
                if (sz == 2) out.push_back(0x66);
                out.push_back((u8)(base2 + wide));
                break; }
            case 0x3A: {  // IMUL_RM
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48); else if (sz == 2) out.push_back(0x66);
                auto m = X.read_mem();
                X.emit_bytes({0x0F, 0xAF});
                X.emit_tail(m, r1 & 7, sz);
                break; }
            case 0x3B: case 0x3C: {  // NOR_ST/NAND_ST — VM-only synth; orijinal yok
                notes.push_back("nor/nand st (VM-only) @bc" + std::to_string(i));
                err = true;
                break; }
            case 0x3D: {  // POP_RP
                int sz = X.u8v(), r1 = X.u8v();
                if (sz == 8) out.push_back(0x48);
                else if (sz == 2 || sz == 1) out.push_back(0x66);
                out.push_back((u8)(0x58 | (r1 & 7)));
                break; }
            case 0x3E: case 0x3F:   // FPU_ST/FPU_MEM — reverse kapsamida degil
                notes.push_back("fpu (kapsam disi) @bc" + std::to_string(i));
                err = true;
                break;
            case 0x41: {  // JMPEXT rva32
                u32 tgt_rva; memcpy(&tgt_rva, &bc[i], 4); i += 4;
                jfixups.push_back({out.size() + 1, 0x40000000u | tgt_rva});
                out.push_back(0xE9);
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                notes.push_back("jmpext @bc" + std::to_string(i - 5) + " -> rva " + hex(tgt_rva));
                break; }
            case 0x42: {  // JCCEXT
                int cc = X.u8v();
                u32 tgt_rva; memcpy(&tgt_rva, &bc[i], 4); i += 4;
                jfixups.push_back({out.size() + 2, 0x40000000u | tgt_rva});
                X.emit_bytes({0x0F, (u8)(0x80 + cc)});
                u32 a=0; for (int k=0;k<4;k++) out.push_back((u8)(a>>(8*k)));
                break; }
            case 0x43: break;   // CHKRET — orijinal karsiligi yok
            case 0x44: {  // NCALLI
                int form = X.u8v();
                if (form == 2) {
                    int r1 = X.u8v();
                    if (r1 >= 8) out.push_back(0x41);
                    X.emit_bytes({0xFF, (u8)(0xC0 | (2 << 3) | (r1 & 7))});
                } else {
                    auto m = X.read_mem();
                    X.emit_mem(m, 2, form == 0 ? 4 : 8, 0xFF);
                }
                break; }
            default:
                notes.push_back("op 0x" + hex(op) + " @bc" + std::to_string(i) + " bilinmiyor — durduruldu");
                err = true;
                break;
            }
        } while (false);
        if (err) break;
    }
    UnliftResult R;
    R.code = std::move(X.out);
    R.notes = std::move(X.notes);
    R.rip_fixups = std::move(X.rip_fixups);
    R.jfixups = std::move(X.jfixups);
    R.bc2out = std::move(X.bc2out);
    return R;
}

static StubInfo parse_xprotect_stub(const PE& pe, const std::vector<u8>& d, long fo, u32 rva) {
    StubInfo out;
    size_t len = std::min((size_t)200, d.size() - (size_t)fo);
    const u8* b = &d[fo];
    if (pe.is64) {
        std::vector<u64> imm64s;
        size_t i = 0;
        while (i + 10 <= len) {
            if (b[i] == 0x48 && b[i+1] == 0xB8) {
                u64 v; memcpy(&v, b+i+2, 8); imm64s.push_back(v); i += 10; continue;
            }
            if (b[i] == 0x48 && b[i+1] == 0x2D && imm64s.size() >= 1) {
                memcpy(&out.l1_rva, b+i+2, 4); i += 6; continue;
            }
            if (b[i] == 0x48 && b[i+1] == 0x05 && imm64s.size() >= 1) {
                memcpy(&out.bc_rva, b+i+2, 4); i += 6; continue;
            }
            i++;
        }
        if (imm64s.size()) {
            out.key = imm64s[0];
            if (imm64s.size() > 1) out.bc_len = (u32)imm64s[1];
        }
        if (rva) {
            for (long j = (long)len - 5; j > 0; j--) {
                if (b[j] == 0xE8) {
                    s32 rel; memcpy(&rel, b+j+1, 4);
                    out.vm_entry = rva + (u32)j + 5 + rel;
                    break;
                }
            }
        }
    } else {
        std::vector<u32> b8s; std::vector<u32> e8s;
        size_t i = 0;
        while (i + 5 <= len) {
            if (b[i] == 0xB8) {
                u32 v; memcpy(&v, b+i+1, 4); b8s.push_back(v); i += 5; continue;
            }
            if (b[i] == 0xE8) {
                s32 rel; memcpy(&rel, b+i+1, 4);
                e8s.push_back(rva + (u32)i + 5 + rel); i += 5; continue;
            }
            if (b[i] == 0x2D && b8s.size() >= 2 && !out.l1_rva) {
                memcpy(&out.l1_rva, b+i+1, 4); i += 5; continue;
            }
            if (b[i] == 0x05 && out.l1_rva && !out.bc_rva) {
                memcpy(&out.bc_rva, b+i+1, 4); i += 5; continue;
            }
            i++;
        }
        if (b8s.size() >= 3) {
            u64 key = ((u64)b8s[1] << 32) | b8s[0];
            out.key = key;
            out.bc_len = b8s[2];
            if (out.bc_rva) out.key = key ^ vm_keyxor(out.bc_rva, out.bc_len);   // cp289 demask
        }
        if (e8s.size()) out.vm_entry = e8s.back();
    }
    out.ok = out.bc_rva && (out.key || true);
    if (!out.bc_rva) out.ok = false;
    return out;
}

// ---------------- MOD 2: reverse (Python birebir) ----------------
struct RevFn {
    u32 rva = 0, stub_rva = 0, bc_rva = 0; u32 bc_len = 0; u64 key = 0; u32 vm_entry = 0;
    std::vector<u8> code;
    std::vector<std::string> notes;
    std::vector<std::pair<size_t, u32>> jfixups, fixes;
    std::map<size_t, size_t> bc2out;
    // FAZ2 sonucu
    bool has_head = false; u32 head_end = 0;          // _head_end (None = tek parca)
    bool has_tail = false; u32 tail_rva = 0, tail_len = 0; long tail_off = -1;
    u32 code_len = 0;
};

static std::string reverse(const std::string& path, const std::string& out_path) {
    PE pe(path);
    std::ostringstream J;
    std::vector<std::string> actions;
    std::vector<std::string> fnjson;   // fonksiyon kayitlari
    int found = 0, restored = 0;
    const Sec* vmp0 = pe.sec(".vmp0");
    if (!vmp0) {
        actions.push_back(".vmp0 yok — XProtect korumasi bulunamadi; kopya cikarildi");
        std::ofstream f(out_path, std::ios::binary); f.write((char*)pe.d.data(), pe.d.size());
        J << "{\n  \"input\": \"" << jstr(path) << "\",\n  \"output\": \"" << jstr(out_path) << "\"";
        J << ",\n  \"actions\": [";
        for (size_t k=0;k<actions.size();k++) J << (k?",\n    \"":"\n    \"") << jstr(actions[k]) << "\"";
        J << "\n  ],\n  \"functions\": [],\n  \"success\": false,\n  \"restored_functions\": 0\n}";
        printf("%s\n", J.str().c_str());
        return J.str();
    }
    std::vector<u8> d = pe.d;
    u32 exp_rva = pe.dd[0][0];
    long fo = exp_rva ? pe.rva2off(exp_rva) : -1;
    u32 n = 0; long afo = -1;
    if (fo >= 0) {
        memcpy(&n, &d[fo+0x14], 4);
        u32 af; memcpy(&af, &d[fo+0x1C], 4);
        afo = pe.rva2off(af);
    } else {
        actions.push_back("EXE modu: export yok, E9 gate taramasi");
    }
    const Sec* text = pe.sec(".text");
    std::vector<u32> frvas;
    if (afo >= 0 && text) {
        std::set<u32> s;
        for (u32 k=0;k<n && k<64;k++) {
            u32 r; memcpy(&r, &d[afo+4*k], 4);
            if (text->va <= r && r < text->va+text->vs) s.insert(r);
        }
        frvas.assign(s.begin(), s.end());
    } else if (text) {
        u32 v0 = vmp0->va, v1 = vmp0->va + vmp0->vs;
        for (u32 va = text->va; va + 5 < text->va + text->vs; va++) {
            long o = pe.rva2off(va);
            if (o >= 0 && d[o] == 0xE9) {
                s32 rel; memcpy(&rel, &d[o+1], 4);
                u32 tgt = va + 5 + rel;
                if (v0 <= tgt && tgt < v1) {
                    long so = pe.rva2off(tgt);
                    if (so >= 0) {
                        u8 sb = d[so];
                        if (sb == 0x9C || sb == 0x60 || sb == 0x41 || sb == 0x55 || sb == 0x53 || sb == 0x56 || sb == 0x57) {
                            frvas.push_back(va); va += 4; continue;
                        }
                    }
                }
            }
        }
        std::sort(frvas.begin(), frvas.end());
        frvas.erase(std::unique(frvas.begin(), frvas.end()), frvas.end());
        char b2[96]; snprintf(b2, sizeof b2, "E9 gate: %zu fonksiyon bulundu", frvas.size());
        actions.push_back(b2);
    }
    auto fn_limit = [&](u32 rva) -> u32 {
        long idx = -1;
        for (size_t k=0;k<frvas.size();k++) if (frvas[k]==rva) { idx=(long)k; break; }
        u32 nxt = (idx >= 0 && (size_t)idx < frvas.size()-1) ? frvas[idx+1] : (text->va + text->vs);
        return nxt - rva;
    };
    // ---- FAZ 1 ----
    std::vector<RevFn> pending;
    if (afo >= 0) {
        for (u32 k=0;k<n && k<64;k++) {
            u32 rva; memcpy(&rva, &d[afo+4*k], 4);
            long fnfo = pe.rva2off(rva);
            if (fnfo < 0) continue;
            StubInfo st;
            u32 stub_rva = rva;
            if (d[fnfo] == 0xE9) {
                s32 rel; memcpy(&rel, &d[fnfo+1], 4);
                stub_rva = rva + 5 + rel;
                long sfo = pe.rva2off(stub_rva);
                if (sfo < 0) continue;
                st = parse_xprotect_stub(pe, d, sfo, stub_rva);
            } else if ((d[fnfo] == 0x41 && (d[fnfo+1] == 0x57 || d[fnfo+1] == 0x56 || d[fnfo+1] == 0x55))
                       || d[fnfo] == 0x9C || d[fnfo] == 0x60) {
                st = parse_xprotect_stub(pe, d, fnfo, rva);
            } else continue;
            if (!st.ok) {
                char b2[96]; snprintf(b2, sizeof b2, "0x%X stab yarim", rva);
                fnjson.push_back(std::string("{\"rva\": \"") + hex(rva) + "\", \"note\": \"stab yarim\"}");
                continue;
            }
            u32 ln = st.bc_len;
            long bco = pe.rva2off(st.bc_rva);
            if (bco < 0) continue;
            if (!ln || (size_t)(bco + ln) > d.size()) {
                long end = vmp0->ptr + vmp0->rs;
                long j = bco;
                while (j < std::min(end, (long)d.size() - 4)) {
                    if (d[j]==0xCC && d[j+1]==0xCC && d[j+2]==0xCC && d[j+3]==0xCC) break;
                    j++;
                }
                ln = (u32)(j - bco);
            }
            if (ln < 4) continue;
            std::vector<u8> bc;
            cfb_decrypt(&d[bco], ln, st.key, bc, 1);
            u32 limit_here = fn_limit(rva);
            auto perm = vm_perm_tab(rva);
            UnliftResult U = unlift(bc, pe.is64, rva, pe.imgbase, false, &perm);
            RevFn p;
            p.rva = rva; p.stub_rva = (d[fnfo] == 0xE9) ? stub_rva : rva;
            p.bc_rva = st.bc_rva; p.bc_len = ln; p.key = st.key; p.vm_entry = st.vm_entry;
            p.code = std::move(U.code);
            if (U.notes.size() > 4) U.notes.resize(4);
            p.notes = std::move(U.notes);
            p.jfixups = std::move(U.jfixups);
            p.bc2out = std::move(U.bc2out);
            p.fixes = std::move(U.rip_fixups);
            pending.push_back(std::move(p));
        }
    }
    // ---- FAZ 2: yazim + kuyruk tasiima ----
    std::sort(pending.begin(), pending.end(), [](const RevFn& a, const RevFn& b){ return a.rva < b.rva; });
    u32 pad_rva = text->va + text->vs;
    long pad_off = pe.rva2off(pad_rva);
    long pad_end = text->ptr + text->rs;
    int jcc_total = 0, jcc_ok = 0;
    std::vector<std::pair<u32, u32>> reloc_regions;   // (rva, len) capstone tarama icin
    for (auto& pfn : pending) {
        u32 rva = pfn.rva;
        long raw = pe.rva2off(rva);
        if (raw < 0 || pfn.code.size() < 4) continue;
        u32 limit = fn_limit(rva);
        auto& fx = pfn.fixes;
        if (pfn.code.size() <= limit) {
            memcpy(&d[raw], pfn.code.data(), pfn.code.size());
            pfn.has_head = false; pfn.has_tail = false;
            pfn.code_len = (u32)pfn.code.size();
            for (auto& fp : fx) {
                size_t disp_off = fp.first; u32 tgt_rva = fp.second;
                u32 next_rip = rva + (u32)disp_off + 4;
                if ((size_t)raw + disp_off + 4 <= d.size()) {
                    u32 v = tgt_rva - next_rip;
                    memcpy(&d[raw + disp_off], &v, 4);
                }
            }
            reloc_regions.push_back({rva, pfn.code_len});
        } else {
            bool vmp0_used = false;
            // komut siniri hizala (capstone)
            csh md;
            if (cs_open(CS_ARCH_X86, pe.is64 ? CS_MODE_64 : CS_MODE_32, &md) == CS_ERR_OK) {
                u32 head_len = limit - 5;
                u32 last_end = 0;
                {
                    cs_insn* ins; size_t c = cs_disasm(md, pfn.code.data(), head_len, rva, 0, &ins);
                    if (c > 0) last_end = (u32)(ins[c-1].address - rva + ins[c-1].size);
                    if (c) cs_free(ins, c);
                }
                if (last_end < 8) {
                    memcpy(&d[raw], pfn.code.data(), pfn.code.size());
                    cs_close(&md);
                    continue;
                }
                std::vector<u8> tail(pfn.code.begin() + last_end, pfn.code.end());
                if (!tail.size() || pad_off + (long)tail.size() > pad_end) {
                    if (!tail.size()) {
                        memcpy(&d[raw], pfn.code.data(), pfn.code.size());
                        pfn.has_head = false; pfn.has_tail = false;
                        cs_close(&md);
                        continue;
                    }
                    // kuyrugu .vmp0 sonuna yaz
                    const Sec* vmp0s_c = pe.sec(".vmp0");
                    Sec* vmp0s = const_cast<Sec*>(vmp0s_c);
                    u32 tail_rva = vmp0s->va + vmp0s->vs;
                    u32 add = (u32)((tail.size() + 0xF) & ~(size_t)0xF);
                    long new_off = pe.rva2off(tail_rva);
                    if (new_off < 0 || (size_t)(new_off + tail.size()) > d.size()) {
                        // Python birebir: ekleme = (new_off+len(tail)-len(d)+15)&~15 (new_off varken)
                        // yoksa add; HER DURUMDA len(d) baz alinir
                        size_t grow;
                        if (new_off >= 0)
                            grow = ((size_t)new_off + tail.size() + 0xF - d.size()) & ~(size_t)0xF;
                        else
                            grow = add;
                        d.resize(d.size() + grow, 0xCC);
                    }
                    if (new_off >= 0) memcpy(&d[new_off], tail.data(), tail.size());
                    u32 lfanew; memcpy(&lfanew, &d[0x3C], 4);
                    u16 optsz; memcpy(&optsz, &d[lfanew + 0x14], 2);
                    u32 sh = lfanew + 24 + optsz + 40 * (pe.nsec - 1);
                    char snm[9]; memcpy(snm, &d[sh], 8); snm[8]=0;
                    if (strncmp(snm, ".vmp0", 5) == 0) {
                        u32 vs2 = vmp0s->vs + add, rs2 = vmp0s->rs + add;
                        memcpy(&d[sh+8], &vs2, 4);
                        memcpy(&d[sh+16], &rs2, 4);
                    }
                    vmp0s->vs += add; vmp0s->rs += add;
                    u32 cur_img; memcpy(&cur_img, &d[pe.opt+56], 4);
                    u32 need_img = vmp0s->va + vmp0s->vs;
                    if (need_img > cur_img) {
                        u32 img2 = ((need_img + 0xFFF) & ~0xFFF);
                        memcpy(&d[pe.opt+56], &img2, 4);
                    }
                    pfn.tail_off = new_off;
                    pfn.tail_len = (u32)tail.size();
                    pfn.code_len = (u32)pfn.code.size();
                    memcpy(&d[raw], pfn.code.data(), last_end);           // HEAD
                    pfn.has_head = true; pfn.head_end = last_end;
                    pfn.has_tail = true; pfn.tail_rva = tail_rva;
                    u32 br = tail_rva - (rva + last_end + 5);
                    d[raw+last_end] = 0xE9;
                    memcpy(&d[raw+last_end+1], &br, 4);
                    for (auto& fp : fx) {
                        size_t disp_off = fp.first; u32 tgt_rva = fp.second;
                        if (disp_off + 4 <= last_end) {
                            u32 next_rip = rva + (u32)disp_off + 4;
                            if ((size_t)raw + disp_off + 4 <= d.size()) {
                                u32 v = tgt_rva - next_rip;
                                memcpy(&d[raw + disp_off], &v, 4);
                            }
                        } else {
                            u32 site_rva = tail_rva + (u32)(disp_off - last_end);
                            long so2 = pe.rva2off(site_rva);
                            if (so2 >= 0 && (size_t)so2 + 4 <= d.size()) {
                                u32 v = tgt_rva - (site_rva + 4);
                                memcpy(&d[so2], &v, 4);
                            }
                        }
                    }
                    char b2[96]; snprintf(b2, sizeof b2, "kuyruk vmp0-sonuna tasindi: %zuB @rva 0x%llX", tail.size(), (unsigned long long)tail_rva);
                    pfn.notes.push_back(b2);
                    vmp0_used = true;
                }
                if (!vmp0_used) {
                    memcpy(&d[raw], pfn.code.data(), last_end);
                    pfn.code_len = (u32)pfn.code.size();
                    memcpy(&d[pad_off], tail.data(), tail.size());
                    pfn.has_head = true; pfn.head_end = last_end;
                    pfn.has_tail = true; pfn.tail_rva = pad_rva;
                    pfn.tail_len = (u32)tail.size();
                    u32 br = pad_rva - (rva + last_end + 5);
                    d[raw+last_end] = 0xE9;
                    memcpy(&d[raw+last_end+1], &br, 4);
                    pad_off += (long)tail.size();
                    pad_rva += (u32)tail.size();
                    for (auto& fp : fx) {
                        size_t disp_off = fp.first; u32 tgt_rva = fp.second;
                        if (disp_off + 4 <= last_end) {
                            u32 next_rip = rva + (u32)disp_off + 4;
                            if ((size_t)raw + disp_off + 4 <= d.size()) {
                                u32 v = tgt_rva - next_rip;
                                memcpy(&d[raw + disp_off], &v, 4);
                            }
                        } else {
                            u32 site_rva = pfn.tail_rva + (u32)(disp_off - last_end);
                            long so2 = pe.rva2off(site_rva);
                            if (so2 >= 0 && (size_t)so2 + 4 <= d.size()) {
                                u32 v = tgt_rva - (site_rva + 4);
                                memcpy(&d[so2], &v, 4);
                            }
                        }
                    }
                    char b2[128]; snprintf(b2, sizeof b2, "kuyruk pad'e tasindi: %zuB @rva 0x%llX", tail.size(), (unsigned long long)(pad_rva - tail.size()));
                    pfn.notes.push_back(b2);
                }
                cs_close(&md);
            }
            reloc_regions.push_back({rva, pfn.has_head ? pfn.head_end : pfn.code_len});
            if (pfn.has_tail && pfn.tail_len) reloc_regions.push_back({pfn.tail_rva, pfn.tail_len});
        }
        // --- JMP/JCC fixuplar ---
        if (pfn.jfixups.size()) {
            u32 head_end_out = pfn.has_head ? pfn.head_end : 0xFFFFFFFF;
            u32 tail_rva0 = pfn.has_tail ? pfn.tail_rva : 0;
            std::map<size_t, u32> out2rva;
            for (auto& kv : pfn.bc2out) {
                size_t bc_off = kv.first, out_off = kv.second;
                if (!pfn.has_head || out_off < head_end_out)
                    out2rva[out_off] = rva + (u32)out_off;
                else if (pfn.has_tail)
                    out2rva[out_off] = tail_rva0 + (u32)(out_off - head_end_out);
            }
            for (auto& jp : pfn.jfixups) {
                size_t disp_pos = jp.first; u32 tgt_bc = jp.second;
                u32 t_rva;
                u32 site_rva;
                if (tgt_bc & 0x40000000u) {
                    t_rva = tgt_bc & 0x3FFFFFFFu;
                    site_rva = (!pfn.has_head || disp_pos < head_end_out)
                        ? rva + (u32)disp_pos
                        : (pfn.has_tail ? tail_rva0 + (u32)(disp_pos - head_end_out) : rva + (u32)disp_pos);
                } else {
                    auto it = pfn.bc2out.find(tgt_bc);
                    size_t t_out;
                    if (it != pfn.bc2out.end()) t_out = it->second;
                    else {
                        long best = -1;
                        for (auto& kv : pfn.bc2out) if ((long)kv.first <= (long)tgt_bc) best = (long)kv.first;
                        t_out = best >= 0 ? pfn.bc2out[(size_t)best] : 0;
                    }
                    auto it2 = out2rva.find(t_out);
                    t_rva = (it2 != out2rva.end()) ? it2->second : rva;
                    site_rva = (!pfn.has_head || disp_pos < head_end_out)
                        ? rva + (u32)disp_pos
                        : (pfn.has_tail ? tail_rva0 + (u32)(disp_pos - head_end_out) : rva + (u32)disp_pos);
                }
                u32 rel = t_rva - (site_rva + 4);
                long site_off = pe.rva2off(site_rva);
                if (site_off >= 0 && (size_t)site_off + 4 <= d.size())
                    memcpy(&d[site_off], &rel, 4);
            }
            found++;
            std::ostringstream F;
            F << "{\n      \"rva\": \"" << lc_hex(rva) << "\", \"stub_rva\": \"0x" << hex(pfn.stub_rva)
              << "\", \"bc_rva\": \"0x" << hex(pfn.bc_rva) << "\", \"bc_len\": " << pfn.bc_len
              << ",\n      \"key\": \"0x" << hex(pfn.key) << "\", \"vm_entry\": \"0x" << hex(pfn.vm_entry)
              << "\", \"unlifted_bytes\": " << pfn.code.size() << ", \"notes\": [";
            for (size_t k=0;k<pfn.notes.size();k++)
                F << (k?", \"":"\"") << jstr(pfn.notes[k]) << "\"";
            F << "]}";
            fnjson.push_back(F.str());
        }
    }
    actions.push_back(std::to_string(found) + " fonksiyon stub-cozumlendi, bayt-kod de-sifrelenip .text'e geri yazildi");
    if (found) {
        // vmp0-sonu kuyruk snapshotlari + sifirlama
        std::vector<std::pair<long, std::vector<u8>>> snaps;
        for (auto& pfn : pending) {
            if (pfn.has_tail && pfn.tail_len && pfn.tail_off >= 0
                && vmp0->va <= pfn.tail_rva && pfn.tail_rva < vmp0->va + vmp0->vs) {
                snaps.push_back({pfn.tail_off, std::vector<u8>(d.begin()+pfn.tail_off, d.begin()+pfn.tail_off+pfn.tail_len)});
            }
        }
        long vo = vmp0->ptr;
        if (vo >= 0) {
            // Python birebir: d[vo:vo+rs] = bytearray(rs) — slice-assign dosyayi
            // UZATIR (rs grow sonrasi buyuk) — sonra snapshotlar geri yazilir
            if ((size_t)(vo + vmp0->rs) > d.size()) d.resize((size_t)vo + vmp0->rs, 0);
            memset(&d[vo], 0, vmp0->rs);
        }
        for (auto& sp : snaps) memcpy(&d[sp.first], sp.second.data(), sp.second.size());
        actions.push_back(".vmp0 icerigi sifirlandi (VM kaldirildi; vmp0-sonu kuyruklar snapshot ile korundu)");
    }
    restored = found;
    // --- restore post-pass: jcc_audit + 32-bit mutlak-adres .rloc ---
    std::vector<u32> fields;
    {
        csh md;
        if (cs_open(CS_ARCH_X86, pe.is64 ? CS_MODE_64 : CS_MODE_32, &md) == CS_ERR_OK) {
            cs_option(md, CS_OPT_DETAIL, CS_OPT_ON);
            u64 img_lo = pe.imgbase, img_hi = pe.imgbase + 0x2000000;
            for (auto& pfn : pending) {
                if (!pfn.code_len) continue;
                std::vector<std::pair<u32, u32>> regions;
                regions.push_back({pfn.rva, pfn.has_head ? pfn.head_end : pfn.code_len});
                if (pfn.has_tail && pfn.tail_len) regions.push_back({pfn.tail_rva, pfn.tail_len});
                for (auto& rg : regions) {
                    long o = pe.rva2off(rg.first);
                    if (o < 0) continue;
                    const u8* body = &d[o];
                    size_t cnt = 0;
                    cs_insn* ins;
                    cnt = cs_disasm(md, body, rg.second, rg.first, 0, &ins);
                    for (size_t k=0;k<cnt;k++) {
                        std::string mn = ins[k].mnemonic;
                        bool isj = (mn == "jmp") || (mn[0] == 'j' && mn != "jmp");
                        if (isj) jcc_total++;
                        const u8* ibytes = &d[o + (ins[k].address - rg.first)];
                        size_t isz = ins[k].size;
                        if (isj && ins[k].detail) {
                            auto& ops = ins[k].detail->x86.operands;
                            if (ins[k].detail->x86.op_count == 1 && ops[0].type == X86_OP_IMM) {
                                s64 tgt = ops[0].imm;
                                u32 he = pfn.has_head ? pfn.head_end : pfn.code_len;
                                bool inhead = pfn.rva <= (u32)tgt && (u32)tgt < pfn.rva + std::max(he, 1u);
                                bool inreg = false;
                                if (pfn.has_tail && pfn.tail_len)
                                    inreg = pfn.tail_rva <= (u32)tgt && (u32)tgt < pfn.tail_rva + pfn.tail_len;
                                if (inhead || inreg) jcc_ok++;
                            }
                        }
                        if (ins[k].detail && !pe.is64) {
                            for (int z=0;z<ins[k].detail->x86.op_count;z++) {
                                auto& opx = ins[k].detail->x86.operands[z];
                                if (opx.type == X86_OP_MEM && opx.mem.disp >= (s64)img_lo && opx.mem.disp < (s64)img_hi) {
                                    u32 dv = (u32)(opx.mem.disp & 0xFFFFFFFF);
                                    for (size_t q=0;q+4<=isz;q++)
                                        if (!memcmp(ibytes+q, &dv, 4)) { fields.push_back((u32)ins[k].address + (u32)q); break; }
                                }
                            }
                        }
                    }
                    if (cnt) cs_free(ins, cnt);
                }
            }
            cs_close(&md);
        }
    }
    std::sort(fields.begin(), fields.end());
    fields.erase(std::unique(fields.begin(), fields.end()), fields.end());
    std::vector<u8> blob;
    bool has_reloc = fields.size() && !pe.is64;
    int unorm_count = 0;
    {
        // import adlari tara (dd1 — cikis header'indan)
        u32 _ddoff = pe.opt + (pe.is64 ? 112 : 96);
        u32 dd1_rva; memcpy(&dd1_rva, &d[_ddoff + 8], 4);
        auto out_rva2off = [&](u32 rva) -> long {
            u32 lf; memcpy(&lf, &d[0x3C], 4);
            u16 ns; memcpy(&ns, &d[lf+6], 2);
            u16 osz; memcpy(&osz, &d[lf+0x14], 2);
            u32 sh0 = lf + 24 + osz;
            for (u32 k=0;k<ns;k++) {
                u32 h = sh0 + 40*k;
                u32 vs, va, rs, rp;
                memcpy(&vs, &d[h+8], 4); memcpy(&va, &d[h+12], 4);
                memcpy(&rs, &d[h+16], 4); memcpy(&rp, &d[h+20], 4);
                if (va <= rva && rva < va + std::max(vs, rs)) return rp + (rva - va);
            }
            return -1;
        };
        if (dd1_rva) {
            long io = out_rva2off(dd1_rva);
            if (io >= 0) {
                int idt_e = pe.is64 ? 24 : 20;
                for (int k=0;k<64;k++) {
                    u32 base_i = (u32)io + (u32)k * idt_e;
                    u32 oft, ts2, fwd, nmr, fat;
                    memcpy(&oft, &d[base_i], 4); memcpy(&ts2, &d[base_i+4], 4);
                    memcpy(&fwd, &d[base_i+8], 4); memcpy(&nmr, &d[base_i+12], 4);
                    memcpy(&fat, &d[base_i+16], 4);
                    if (!nmr) break;
                    long no = out_rva2off(nmr);
                    if (no < 0) continue;
                    char nm[40]; memcpy(nm, &d[no], 39); nm[39]=0;
                    if (!strncmp(nm, "api-ms-win-crt", 14)) unorm_count++;
                }
            }
        }
    }
    if (has_reloc) {
        std::map<u32, std::vector<u32>> blocks2;
        for (u32 fr : fields) blocks2[fr & ~0xFFFu].push_back(fr);
        for (auto& kv : blocks2) {
            u32 page = kv.first;
            auto& ents = kv.second;
            std::sort(ents.begin(), ents.end());
            u32 blk_sz = 8 + (u32)(2 * ents.size());
            u32 p2 = page; blob.push_back((u8)p2); blob.push_back((u8)(p2>>8));
            blob.push_back((u8)(p2>>16)); blob.push_back((u8)(p2>>24));
            u32 s2 = blk_sz; blob.push_back((u8)s2); blob.push_back((u8)(s2>>8));
            blob.push_back((u8)(s2>>16)); blob.push_back((u8)(s2>>24));
            for (size_t k=0;k<ents.size();k++) {
                bool last = (k == ents.size()-1) && (ents.size() % 2 == 1);
                u16 e = last ? 0 : (u16)((3 << 12) | (ents[k] & 0xFFF));
                blob.push_back((u8)e); blob.push_back((u8)(e>>8));
            }
        }
    }
    u32 unorm_name_rva = 0;
    if (unorm_count) {
        if (has_reloc) { for (int k=0;k<4;k++) blob.push_back(0); }
        unorm_name_rva = (u32)blob.size();               // string .rloc-ici ofset
        const char* un = "ucrtbase.dll";
        blob.insert(blob.end(), un, un + strlen(un) + 1);
    }
    if (blob.size()) {
        u32 lfanew; memcpy(&lfanew, &d[0x3C], 4);
        u16 nsec; memcpy(&nsec, &d[lfanew+6], 2);
        u16 optsz; memcpy(&optsz, &d[lfanew+0x14], 2);
        u32 table_end = lfanew + 24 + optsz + 40 * (u32)nsec;
        u32 soh; memcpy(&soh, &d[pe.opt+60], 4);
        u32 fa; memcpy(&fa, &d[pe.opt+36], 4);
        if (table_end + 40 <= soh) {
            u32 last_end_rva = 0;
            for (auto& sc : pe.secs) last_end_rva = std::max(last_end_rva, sc.va + sc.vs);
            u32 new_rva = (last_end_rva + 0xFFF) & ~0xFFF;
            u32 body_off, pad;
            if (fa < 0x200) { body_off = new_rva; pad = 0; }
            else {
                body_off = (u32)((d.size() + fa - 1) & ~(u32)(fa - 1));
                pad = (u32)((fa - (blob.size() % fa)) % fa);
            }
            if ((size_t)body_off > d.size()) d.resize(body_off, 0);
            d.insert(d.end(), blob.begin(), blob.end());
            d.insert(d.end(), pad, 0);
            u32 sh = lfanew + 24 + optsz + 40 * (u32)nsec;
            memset(&d[sh], 0, 40);
            const char* rn = ".rloc";
            memcpy(&d[sh], rn, 5);
            u32 vs2 = (u32)blob.size(), va2 = new_rva, rs2 = (u32)blob.size() + pad, rp2 = body_off;
            u32 chars2 = 0x42000040;
            memcpy(&d[sh+8], &vs2, 4); memcpy(&d[sh+12], &va2, 4);
            memcpy(&d[sh+16], &rs2, 4); memcpy(&d[sh+20], &rp2, 4);
            memcpy(&d[sh+36], &chars2, 4);
            u16 ns2 = nsec + 1;
            memcpy(&d[lfanew+6], &ns2, 2);
            u32 cur_img; memcpy(&cur_img, &d[pe.opt+56], 4);
            u32 need_img = new_rva + (u32)blob.size() + pad;
            if (need_img > cur_img) {
                u32 img2 = ((need_img + 0xFFF) & ~0xFFF);
                memcpy(&d[pe.opt+56], &img2, 4);
            }
            if (has_reloc) {
                u32 dd5_va_off = pe.opt + 96 + 8 * 5;
                u32 v2 = new_rva, sz2 = (u32)blob.size();
                memcpy(&d[dd5_va_off], &v2, 4);
                memcpy(&d[dd5_va_off+4], &sz2, 4);
                actions.push_back("32-bit .rloc: " + std::to_string(fields.size()) + " mutlak-adres girdisi eklendi (ASLR guvenligi)");
            }
            if (unorm_count) {
                // IDT Name alanlarini ucrtbase.dll'e yonlendir (Python birebir)
                u32 u_rva = new_rva + unorm_name_rva;
                u32 _ddoff2 = pe.opt + (pe.is64 ? 112 : 96);
                u32 dd1_rva2; memcpy(&dd1_rva2, &d[_ddoff2 + 8], 4);
                auto out_rva2off2 = [&](u32 rva) -> long {
                    u32 lf; memcpy(&lf, &d[0x3C], 4);
                    u16 ns; memcpy(&ns, &d[lf+6], 2);
                    u16 osz; memcpy(&osz, &d[lf+0x14], 2);
                    u32 sh0 = lf + 24 + osz;
                    for (u32 k=0;k<ns;k++) {
                        u32 h = sh0 + 40*k;
                        u32 vs, va, rs, rp;
                        memcpy(&vs, &d[h+8], 4); memcpy(&va, &d[h+12], 4);
                        memcpy(&rs, &d[h+16], 4); memcpy(&rp, &d[h+20], 4);
                        if (va <= rva && rva < va + std::max(vs, rs)) return rp + (rva - va);
                    }
                    return -1;
                };
                long io2 = out_rva2off2(dd1_rva2);
                if (io2 >= 0) {
                    int idt_e = pe.is64 ? 24 : 20;
                    int npatched = 0;
                    for (int k=0;k<64;k++) {
                        u32 base_i = (u32)io2 + (u32)k * idt_e;
                        u32 nmr; memcpy(&nmr, &d[base_i + 12], 4);
                        if (!nmr) break;
                        long no = out_rva2off2(nmr);
                        if (no < 0) continue;
                        char nm[40]; memcpy(nm, &d[no], 39); nm[39]=0;
                        if (!strncmp(nm, "api-ms-win-crt", 14)) {
                            memcpy(&d[base_i + 12], &u_rva, 4);
                            npatched++;
                        }
                    }
                    if (npatched)
                        actions.push_back("Import normalizasyonu: api-ms-win-crt-* -> ucrtbase.dll (" + std::to_string(npatched) + " DLL, CE force-loader uyumu)");
                }
            }
            // b) 32-bit: DYNAMICBASE temizle
            if (!pe.is64) {
                u32 dc_off = pe.opt + 70;
                u16 dc; memcpy(&dc, &d[dc_off], 2);
                if (dc & 0x0040) {
                    dc &= (u16)~0x0040;
                    memcpy(&d[dc_off], &dc, 2);
                    actions.push_back("32-bit: DYNAMICBASE temizlendi (ASLR preferred-base yukleme)");
                }
            }
        }
    }
    // ---- JSON rapor ----
    J << "{\n  \"input\": \"" << jstr(path) << "\",\n  \"output\": \"" << jstr(out_path) << "\"";
    J << ",\n  \"actions\": [";
    for (size_t k=0;k<actions.size();k++) J << (k?",\n    \"":"\n    \"") << jstr(actions[k]) << "\"";
    J << "\n  ]";
    J << ",\n  \"functions\": [";
    for (size_t k=0;k<fnjson.size();k++) J << (k?",":"") << "\n    " << fnjson[k];
    J << "\n  ]";
    J << ",\n  \"success\": " << (found ? "true" : "false");
    J << ",\n  \"restored_functions\": " << restored;
    J << ",\n  \"jcc_audit\": {\n    \"total\": " << jcc_total << ",\n    \"ok\": " << jcc_ok << "\n  }";
    J << "\n}";
    std::ofstream f(out_path, std::ios::binary);
    f.write((char*)d.data(), d.size());
    printf("%s\n", J.str().c_str());
    return J.str();
}

#ifndef NO_MAIN
int main(int argc, char** argv) {
    if (argc < 3) {
        printf("kullanim: mvpreverse3 analyze <dosya> [--json out] | reverse <in> <out>\n");
        return 2;
    }
    std::string mode = argv[1];
    if (mode == "analyze") {
        std::string j;
        for (int i=3;i<argc-1;i++) if (!strcmp(argv[i],"--json")) j=argv[i+1];
        analyze(argv[2], j);
        return 0;
    }
    if (mode == "reverse") {
        reverse(argv[2], argv[3]);
        return 0;
    }
    return 2;
}
#endif
