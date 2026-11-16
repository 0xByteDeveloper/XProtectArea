// ============================================================================
// kozdbg_console.cpp — KozDbg-c (v1.0, console port of ivanpotatoes/KozDbg)
// ----------------------------------------------------------------------------
// KozDbg, x64dbg EKLENTISI olarak calisir (plugin.cpp / x86_plugin.cpp). Bu
// dosya ayni mantigi BAGIMSIZ KONSOL HATA AYIKLAYICISINA tasir: x64dbg SDK'si,
// breakpoint-komut sistemi ve GUI yok. Saf Win32 debug API'si:
//   CreateProcessW(DEBUG_ONLY_THIS_PROCESS) + WaitForDebugEvent/ContinueDebugEvent
//   + Read/WriteProcessMemory + Get/SetThreadContext.
// Kapsanan profil ailesi: 331/340/350 (Engine::Api / legacy) — hedef senaryo
// VMProtect 3.5.1 paritesi. 360+ profilleri syscall enstrümantasyonu ister
// (Engine::ClusteredSyscalls/ScatteredSyscalls) — port KAPSAM DISI.
// Kontroller (KozDbg 1:1, ayni 13-bit maske / 8191):
//  0 PEB/IsDebuggerPresent   1 RemoteDebugger/DebugPort(7)/DebugFlags(0x1f)
//  2 DebugObject(0x1e)       3 ThreadHideFromDebugger(0x11)
//  4 KernelDebugger(0x23)    5 Module list (surucu adi filtresi, 0xb)
//  6 NtClose/CloseHandle(0xDEADC0DE)  7 TrapFlag probe teslimi (9d 0f 31 90)
//  8-12: advanced (syscall enstrümantasyonu) — legacy'de yok, log "n/a".
// Bilincli farklar:
//  - Port, arm aninda PEB.BeingDebugged + NtGlobalFlag'i da temizler (x64
//    pluginda yalniz setupDirect'te vardi) — K1 dogrudan-PEB okumasini kapsar.
//  - Hedef "temiz-ntdll kopyasi" urettiginde (bizim xrt A21 davranisi), arm
//    GIRIS NOKTASINDAN ONCE yapildigi icin int3'ler kopyaya tasinir; kopyadaki
//    kesmeler rva-tabanli eslesme ile ayni mantiktan gecirilir (findCopyHit).
// Derleme (llvm-mingw):
//   x86_64-w64-mingw32-clang++ -O1 -std=c++17 kozdbg_console.cpp -o KozDbgC.exe
//   i686-w64-mingw32-clang++   -O1 -std=c++17 kozdbg_console.cpp -o KozDbgC32.exe
// ============================================================================
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

typedef LONG (WINAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct PBI { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2]; ULONG_PTR UniquePid; PVOID Reserved3; };

static FILE* g_logfile = nullptr;
static bool g_verbose = false;   // --verbose: her olay/dispatch teshis satiri
static void logf(const char* fmt, ...) {
    char text[4096]; va_list a; va_start(a, fmt); _vsnprintf_s(text, sizeof(text), _TRUNCATE, fmt, a); va_end(a);
    printf("%s", text); fflush(stdout);
    if (g_logfile) { fputs(text, g_logfile); fflush(g_logfile); }
}
static void log(const char* s) { logf("[KozDbg-c] %s\n", s); }

static const char* moduleFilterNames[] = { "sice.sys", "siwvid.sys", "ntice.sys", "iceext.sys", "syser.sys" };

enum Kind { K_REMOTE = 1, K_KERNEL = 4, K_MODULES = 5, K_HIDDENQ = 18 };
struct Hook { uintptr_t addr, rva; int action; unsigned char orig; };
struct Pending { uintptr_t addr, buffer, size, stack; DWORD thread; Kind kind; };

static Hook* findExact(uintptr_t a);   // ileri deklarasyon (addHook tarafindan kullanilir)

struct State {
    HANDLE hProc = nullptr;
    DWORD pid = 0;
    uintptr_t mainBase = 0;
    uintptr_t ntdll = 0, kernel32 = 0, kernelbase = 0;
    bool armed = false, enabled = true;
    unsigned controls = 8191;
    int profile = 350;
    std::vector<Hook> hooks;
    std::vector<Pending> pending;
    std::map<DWORD, bool> stepping;        // tid -> bizim TF adimimiz mi
    std::map<DWORD, bool> threadFirstBp;   // tid -> baslangic kesme noktasi goruldumu
    std::map<DWORD, uintptr_t> rearm;      // tid -> adim sonrasi int3 geri konacak adres
    std::map<std::string, unsigned long long> apiSeen;
    unsigned long long hits[13] = {0};
    std::vector<DWORD> hiddenThreads;
#ifdef _WIN64
    static const bool is64 = true;
#else
    static const bool is64 = false;
#endif
    bool on(unsigned n) const { return (controls & (1u << n)) != 0; }
} S;

static void countHit(unsigned n, DWORD tid) { S.hits[n]++; }

// ---- hedef bellek ----------------------------------------------------------
static bool rmem(uintptr_t p, void* out, size_t n) {
    SIZE_T got = 0; return p && ReadProcessMemory(S.hProc, (LPCVOID)p, out, n, &got) && got == n;
}
static bool wmem(uintptr_t p, const void* in, size_t n) {
    SIZE_T w = 0; if (!p || !WriteProcessMemory(S.hProc, (LPVOID)p, in, n, &w) || w != n) return false;
    FlushInstructionCache(S.hProc, (LPCVOID)p, n); return true;
}
template<class T> static bool rd(uintptr_t p, T& v) { return rmem(p, &v, sizeof(T)); }
template<class T> static bool wr(uintptr_t p, const T& v) { return wmem(p, &v, sizeof(T)); }
static bool wrByte(uintptr_t p, unsigned char b) { return wmem(p, &b, 1); }

// ---- kayit erisimi ----------------------------------------------------------
struct Regs {
    CONTEXT c{};
    void get(HANDLE th) { c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL; GetThreadContext(th, &c); }
    void set(HANDLE th) { c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL; SetThreadContext(th, &c); }
#ifdef _WIN64
    uintptr_t ip() const { return c.Rip; }   void ip(uintptr_t v) { c.Rip = v; }
    uintptr_t sp() const { return c.Rsp; }   void sp(uintptr_t v) { c.Rsp = v; }
    uintptr_t ax() const { return c.Rax; }   void ax(uintptr_t v) { c.Rax = v; }
    uintptr_t a0() const { return c.Rcx; }
    uintptr_t a1() const { return c.Rdx; }
    uintptr_t a2() const { return c.R8; }
    uintptr_t a3() const { return c.R9; }
    uintptr_t a4() const { uintptr_t v = 0; rd(c.Rsp + 0x28, v); return v; }   // 5. arg (yigin)
#else
    uintptr_t ip() const { return c.Eip; }   void ip(uintptr_t v) { c.Eip = v; }
    uintptr_t sp() const { return c.Esp; }   void sp(uintptr_t v) { c.Esp = v; }
    uintptr_t ax() const { return c.Eax; }   void ax(uintptr_t v) { c.Eax = v; }
    uintptr_t a0() const { uintptr_t v = 0; rd(c.Esp + 4, v); return v; }
    uintptr_t a1() const { uintptr_t v = 0; rd(c.Esp + 8, v); return v; }
    uintptr_t a2() const { uintptr_t v = 0; rd(c.Esp + 12, v); return v; }
    uintptr_t a3() const { uintptr_t v = 0; rd(c.Esp + 16, v); return v; }
    uintptr_t a4() const { uintptr_t v = 0; rd(c.Esp + 20, v); return v; }
#endif
};

static HANDLE threadOf(DWORD tid) {
    HANDLE th = nullptr, snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == S.pid && te.th32ThreadID == tid) { th = OpenThread(THREAD_ALL_ACCESS, FALSE, tid); break; }
    } while (Thread32Next(snap, &te));
    CloseHandle(snap); return th;
}

static uintptr_t pebBase() {
    static pNtQIP q = nullptr;
    if (!q) { HMODULE n = GetModuleHandleW(L"ntdll.dll"); if (n) q = (pNtQIP)GetProcAddress(n, "NtQueryInformationProcess"); if (!q) return 0; }
    PBI pbi{}; ULONG rl = 0;
    LONG st = q(S.hProc, 0, &pbi, sizeof(pbi), &rl);
    if (st < 0) { logf("[KozDbg-c] NtQueryInformationProcess(PBI) status=0x%08X rl=%lu\n", (unsigned)st, (unsigned long)rl); return 0; }
    return (uintptr_t)pbi.PebBaseAddress;
}

// ---- PE export cozumleme ----------------------------------------------------
static uintptr_t moduleBaseFor(const char* mod) {
    if (!_stricmp(mod, "ntdll")) return S.ntdll;
    if (!_stricmp(mod, "kernelbase")) return S.kernelbase;
    return S.kernel32;
}
static uintptr_t exportOfIn(uintptr_t base, const char* name, int depth) {
    if (!base || depth > 4) return 0;
    unsigned char dosh[64]; if (!rd(base, dosh) || dosh[0] != 'M' || dosh[1] != 'Z') return 0;
    long lfanew; memcpy(&lfanew, dosh + 0x3c, 4);
    unsigned char nth[264]; if (!rmem(base + lfanew, nth, sizeof(nth)) || nth[0] != 'P' || nth[1] != 'E') return 0;
    uint32_t expRva = 0;
    memcpy(&expRva, nth + 24 + (S.is64 ? 112 : 96), 4);
    if (!expRva) return 0;
    uintptr_t exp = base + expRva;
    uint32_t nNames = 0, addrNames = 0, addrFuncs = 0, addrOrds = 0;
    /* IMAGE_EXPORT_DIRECTORY: 0x14 NumberOfFunctions, 0x18 NumberOfNames,
       0x1C AddressOfFunctions, 0x20 AddressOfNames, 0x24 AddressOfNameOrdinals */
    if (!rd(exp + 0x18, nNames) || !rd(exp + 0x20, addrNames) || !rd(exp + 0x1c, addrFuncs) || !rd(exp + 0x24, addrOrds)) return 0;
    for (uint32_t i = 0; i < nNames && i < 65536; i++) {
        uint32_t rva = 0; if (!rd(base + addrNames + 4u * i, rva)) break;
        char nm[80] = {0}; if (!rmem(base + rva, nm, sizeof(nm) - 1)) continue;
        if (_stricmp(nm, name)) continue;
        uint16_t ord = 0; if (!rd(base + addrOrds + 2u * (uint32_t)i, ord)) break;
        uint32_t f = 0; if (!rd(base + addrFuncs + 4u * (uint32_t)ord, f)) break;
        if (f >= expRva && f < expRva + 0x10000) {
            /* forwarder: "Modul.Fonksiyon" stringi — hedef modulde yeniden ara */
            char fwd[96] = {0}; if (!rmem(base + f, fwd, sizeof(fwd) - 1)) return 0;
            char* dot = strchr(fwd, '.');
            if (!dot || dot == fwd) return 0;
            *dot = 0;
            logf("[KozDbg-c] forwarder: %s.%s\n", fwd, dot + 1);
            return exportOfIn(moduleBaseFor(fwd), dot + 1, depth + 1);
        }
        return base + f;
    }
    return 0;
}
static uintptr_t exportOf(uintptr_t base, const char* name) {
    uintptr_t r = exportOfIn(base, name, 0);
    if (!r && base == S.kernel32 && S.kernelbase) r = exportOfIn(S.kernelbase, name, 1);
    return r;
}
static bool followJmp(uintptr_t addr, uintptr_t& target) {
    unsigned char c[6] = {0}; if (!rmem(addr, c, 6)) return false;
    unsigned o = (S.is64 && c[0] == 0x48) ? 1 : 0;
    if (c[o] == 0xff && c[o + 1] == 0x25) {
        int32_t d; memcpy(&d, c + o + 2, 4);
        uintptr_t slot = addr + o + 6 + d, t = 0;
        if (!rd(slot, t) || !t) return false; target = t; return true;
    }
    if (c[0] == 0xe9) { int32_t d; memcpy(&d, c + 1, 4); target = addr + 5 + d; return true; }
    if (c[0] == 0xeb) { target = addr + 2 + (int8_t)c[1]; return true; }
    return false;
}
static uintptr_t leafRet(uintptr_t entry) {
    for (unsigned i = 0; i < 16; i++) {
        unsigned char b = 0; if (!rd(entry + i, b)) return 0;
        if (b == 0xc3) return entry + i;
        if (b == 0xc9 || b == 0xe9 || b == 0xff || b == 0xcc || b == 0xe8) return 0;
    }
    return 0;
}

// ---- arm --------------------------------------------------------------------
static bool addHook(uintptr_t addr, int action) {
    if (!addr) return false;
    if (findExact(addr)) return true;
    unsigned char orig = 0; if (!rd(addr, orig)) return false;
    if (!wrByte(addr, 0xcc)) return false;
    S.hooks.push_back({addr, 0, action, orig});
    return true;
}
static bool resolveApi(const char* mod, const char* fn, bool atRet, uintptr_t& out) {
    uintptr_t base = !_stricmp(mod, "ntdll") ? S.ntdll : (!_stricmp(mod, "kernel32") ? S.kernel32 : (S.kernelbase ? S.kernelbase : S.kernel32));
    if (!base) return false;
    uintptr_t a = exportOf(base, fn);
    if (!a) { logf("[KozDbg-c] %s!%s export bulunamadi (base=%p)\n", mod, fn, (void*)base); return false; }
    for (unsigned hop = 0; hop < 16; hop++) {
        unsigned char c[2] = {0}; rmem(a, c, 2);
        uintptr_t t = 0;
        if ((c[0] == 0xff && c[1] == 0x25) || c[0] == 0xe9 || c[0] == 0xeb) {
            if (!followJmp(a, t) || !t) return false; a = t; continue;
        }
        break;
    }
    if (atRet) { uintptr_t r = leafRet(a); if (!r) { logf("[KozDbg-c] %s!%s RET cozulemedi\n", mod, fn); return false; } a = r; }
    out = a; return true;
}
static void arm() {
    if (!S.enabled || S.armed || !S.ntdll || !S.kernel32) return;
    S.armed = true;
    // K1: dogrudan PEB temizligi
    if (S.on(0)) {
        uintptr_t peb = pebBase();
        if (peb) {
            unsigned char bd = 0;
            if (rd(peb + 2, bd) && bd) { wrByte(peb + 2, 0); log("[KozDbg-c] PEB.BeingDebugged 1 -> 0"); }
            uint32_t ngf = 0; const uint32_t off = S.is64 ? 0xBC : 0x68;
            if (rd(peb + off, ngf) && (ngf & 0x70)) { wr(peb + off, ngf & ~0x70u); log("[KozDbg-c] PEB.NtGlobalFlag FLG_HEAP temizlendi"); }
            S.hits[0]++;
        } else log("[KozDbg-c] PEB tabani cozulemedi (K1 PEB yamasi atlandi)");
    }
    uintptr_t a = 0;
    if (S.on(0)) {
        if (!resolveApi("kernel32", "IsDebuggerPresent", true, a))
            resolveApi("ntdll", "IsDebuggerPresent", true, a);      // wine: gercek uretim ntdll'de
        if (resolveApi("kernel32", "IsDebuggerPresent", true, a) || a) addHook(a, 0);
        if (S.kernelbase && resolveApi("kernelbase", "IsDebuggerPresent", true, a)) addHook(a, 0);
    }
    if (S.on(1)) {
        if (resolveApi("kernel32", "CheckRemoteDebuggerPresent", false, a)) addHook(a, 1);
        if (S.kernelbase && resolveApi("kernelbase", "CheckRemoteDebuggerPresent", false, a)) addHook(a, 1);
    }
    if ((S.on(1) || S.on(2)) && resolveApi("ntdll", "NtQueryInformationProcess", false, a)) addHook(a, 2);
    if (S.on(3) && resolveApi("ntdll", "NtSetInformationThread", false, a)) addHook(a, 3);
    if ((S.on(4) || S.on(5)) && resolveApi("ntdll", "NtQuerySystemInformation", false, a)) addHook(a, 4);
    if (S.on(6)) {
        if (resolveApi("ntdll", "NtClose", false, a)) addHook(a, 5);
        if (resolveApi("kernel32", "CloseHandle", false, a)) addHook(a, 6);   // K9 dogrudan CloseHandle
    }
    for (auto& h : S.hooks) {
        uintptr_t base = (S.ntdll && h.addr >= S.ntdll && h.addr < S.ntdll + 0x400000) ? S.ntdll : S.kernel32;
        h.rva = h.addr - base;
    }
    logf("[KozDbg-c] profil=%d ARM: %u int3 yerlestirildi, PEB=%p | ntdll=%p k32=%p kb=%p\n",
         S.profile, (unsigned)S.hooks.size(), (void*)pebBase(), (void*)S.ntdll, (void*)S.kernel32, (void*)S.kernelbase);
}

// ---- temiz-kopya eslesmesi --------------------------------------------------
static Hook* findExact(uintptr_t a) {
    for (auto& h : S.hooks) if (h.addr == a) return &h;
    return nullptr;
}
static Hook* findCopyHit(uintptr_t a) {
    for (auto& h : S.hooks) {
        if (h.rva && a >= h.rva) {
            uintptr_t base = a - h.rva;
            if (base != h.addr && !(base & 0xfff)) {
                unsigned char mz[2] = {0};
                if (rmem(base, mz, 2) && mz[0] == 'M' && mz[1] == 'Z') return &h;
            }
        }
    }
    return nullptr;
}

// ---- donus izleme -----------------------------------------------------------
static bool watchReturn(uintptr_t ra, Kind kind, uintptr_t buf, uintptr_t sz, Regs& r, DWORD tid) {
    if (S.pending.size() >= 4096) return false;
    for (auto& p : S.pending) if (p.addr == ra && p.thread == tid && p.kind == kind && p.buffer == buf) return true;
    if (!findExact(ra)) {
        unsigned char orig = 0; if (!rd(ra, orig) || !wrByte(ra, 0xcc)) return false;
        S.hooks.push_back({ra, 0, 99, orig});
    }
    S.pending.push_back({ra, buf, sz, r.sp(), tid, kind});
    return true;
}

// ---- modul filtresi ----------------------------------------------------------
static bool filterModules(const Pending& p) {
    const uint32_t rec = S.is64 ? 0x128 : 0x11c, cntOff = S.is64 ? 8u : 4u;
    uint32_t n = 0; if (!rd(p.buffer, n) || p.size < cntOff) return false;
    if (n > (p.size - cntOff) / rec || n > 65536) return false;
    std::vector<unsigned char> d((size_t)n * rec);
    if (!d.empty() && !rmem(p.buffer + cntOff, d.data(), d.size())) return false;
    const uint32_t offAt = S.is64 ? 0x26 : 0x1a, nmAt = S.is64 ? 0x28 : 0x1c;
    uint32_t kept = 0, removed = 0;
    for (uint32_t i = 0; i < n; i++) {
        unsigned char* recp = d.data() + (size_t)i * rec;
        uint16_t o = 0; memcpy(&o, recp + offAt, 2);
        if (o >= 256) return false;
        const char* nm = (const char*)recp + nmAt + o;
        bool block = false;
        for (auto s : moduleFilterNames) if (!_stricmp(nm, s)) block = true;
        if (block) { removed++; continue; }
        if (kept != i) memmove(d.data() + (size_t)kept * rec, recp, rec);
        kept++;
    }
    if (removed) {
        std::fill(d.begin() + (size_t)kept * rec, d.end(), 0);
        if (!wmem(p.buffer + cntOff, d.data(), d.size()) || !wr(p.buffer, kept)) return false;
    }
    logf("[KozDbg-c] modul listesi: %u kayit, %u surucu adi elendi\n", n, removed);
    return true;
}

static bool processReturn(const Pending& p, Regs& r) {
    int32_t st = (int32_t)(int64_t)r.ax();
    switch (p.kind) {
    case K_REMOTE:  if (st) { uint32_t z = 0; if (!wr(p.buffer, z)) return false; countHit(1, p.thread); logf("[KozDbg-c] tid=%u: uzaktan hata ayiklayici sorgusu -> FALSE yazildi (buffer=%p)\n", p.thread, (void*)p.buffer); } return true;
    case K_HIDDENQ: if (st >= 0) { unsigned char one = 1; if (!wr(p.buffer, one)) return false; countHit(3, p.thread); } return true;
    case K_KERNEL:  if (st >= 0) { uint16_t v = 0x0100; if (!wr(p.buffer, v)) return false; countHit(4, p.thread); logf("[KozDbg-c] tid=%u: kernel debugger sorgusu -> 00 01\n", p.thread); } return true;
    case K_MODULES: if (st >= 0) { countHit(5, p.thread); return filterModules(p); } return true;
    }
    return true;
}

// ---- int3 dispatch ----------------------------------------------------------
// donus 0 = DBG_CONTINUE (baglam zaten apply edildi), -1 = hata.
// Passthrough durumlari icinde halledilir (restore + tek-adim + rearm).
static int dispatchHit(Hook* h, Regs& r, HANDLE th, DWORD tid, uintptr_t exip) {
    if (g_verbose) logf("[KozDbg-c] dispatch: action=%d exip=%p hookAddr=%p tid=%u\n", h->action, (void*)exip, (void*)h->addr, tid);
    // passthrough: orijinal bayti restore et, o instruction'u tek adimla calistir,
    // SS'de int3'u geri koy (rearm kaydi).
    auto passthrough = [&]() {
        const uintptr_t site = (uintptr_t)exip;   // kesme adresi (orijinal VEYA temiz kopya)
        wrByte(site, h->orig);                    // kopyada da bayt icin ayni orijinal dogru
        r.ip(site); r.c.EFlags |= 0x100; r.set(th);
        S.stepping[tid] = true; S.rearm[tid] = site;
        return 0;
    };
    if (h->action == 99) {                       // izlenen donus
        auto it = std::find_if(S.pending.begin(), S.pending.end(), [&](const Pending& p) {
            return p.addr == h->addr && p.thread == tid && p.stack == r.sp();
        });
        if (it == S.pending.end()) return passthrough();   // ayni adrese baska cagri
        Pending p = *it; S.pending.erase(it);
        if (!processReturn(p, r)) return -1;
        return passthrough();                    // gercek ret calisir, int3 yeniden kurulur
    }
    if (h->action == 0) {                        // IsDebuggerPresent RET: ax=0
        r.ax(0); countHit(0, tid);
        logf("[KozDbg-c] tid=%u: IsDebuggerPresent -> 0 (RET yamasinda)\n", tid);
        return passthrough();
    }
    uintptr_t ra = 0; if (!rd(r.sp(), ra)) return -1;
    auto selfHandle = [&](uintptr_t hv) -> bool {
        if (hv == (uintptr_t)-1) return true;                 // current process
        if (!hv || hv >= (uintptr_t)-16) return false;
        HANDLE local = nullptr;
        if (!DuplicateHandle(S.hProc, (HANDLE)hv, GetCurrentProcess(), &local, 0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
        DWORD p = GetProcessId(local); CloseHandle(local);
        return p == S.pid;
    };
    auto selfThread = [&](uintptr_t hv) -> bool {
        if (hv == (uintptr_t)-2) return true;                 // current thread
        if (!hv || hv >= (uintptr_t)-16) return false;
        HANDLE local = nullptr;
        if (!DuplicateHandle(S.hProc, (HANDLE)hv, GetCurrentProcess(), &local, 0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
        DWORD p = GetProcessIdOfThread(local); CloseHandle(local);
        return p == S.pid;
    };
    auto finish = [&](unsigned argCount, uintptr_t status) -> bool {   // cagriyi taklit et, don
        uintptr_t ret = 0; if (!rd(r.sp(), ret)) return false;
        r.ip(ret);
        r.sp(r.sp() + (S.is64 ? 8 : 4 * (argCount + 1)));
        r.ax(status);
        return true;
    };
    int action = h->action;
    bool emulated = false;
    if (action == 1) {                                           // CheckRemoteDebuggerPresent(proc, out)
        if (selfHandle(r.a0()) && r.a1()) { if (!watchReturn(ra, K_REMOTE, r.a1(), 4, r, tid)) return -1; }
    } else if (action == 2) {                                    // NtQueryInformationProcess
        uintptr_t cls = r.a1(), buf = r.a2();
        if (selfHandle(r.a0())) {
#ifdef _WIN64
            if (cls == 0x1e && S.on(2) && buf) {
                if (!finish(0, 0xc0000353)) return -1;
                countHit(2, tid); logf("[KozDbg-c] tid=%u: DebugObjectHandle -> STATUS_PORT_NOT_SET\n", tid);
                emulated = true;
            } else return passthrough();
#else
            uintptr_t retlen = r.a4();
            if (cls == 0x1e && S.on(2) && buf && !(buf & 3)) {
                if (buf) wr(buf, (uint32_t)0);
                if (retlen) wr(retlen, (uint32_t)4);
                if (!finish(4, 0xc0000353)) return -1;
                countHit(2, tid); logf("[KozDbg-c] tid=%u: DebugObjectHandle -> PORT_NOT_SET (out=0, retlen=4)\n", tid);
                emulated = true;
            } else if (S.on(1) && (cls == 0x7 || cls == 0x1f) && buf) {
                if (!watchReturn(ra, K_REMOTE, buf, 4, r, tid)) return -1;
            } else return passthrough();
#endif
        } else return passthrough();
    } else if (action == 3) {                                    // NtSetInformationThread(ThreadHide)
        if (selfThread(r.a0()) && r.a1() == 0x11 && !r.a2() && !r.a3()) {
            if (!finish(S.is64 ? 0 : 4, 0)) return -1;
            countHit(3, tid); logf("[KozDbg-c] tid=%u: ThreadHideFromDebugger bastirildi\n", tid);
            emulated = true;
        } else return passthrough();
    } else if (action == 4) {                                    // NtQuerySystemInformation
        uintptr_t cls = r.a0(), buf = r.a1(), sz = r.a2();
        if (cls == 0x23 && S.on(4) && buf && sz >= 2) { if (!watchReturn(ra, K_KERNEL, buf, sz, r, tid)) return -1; }
        else if (cls == 0xb && S.on(5) && buf && sz >= (S.is64 ? 8u : 4u)) { if (!watchReturn(ra, K_MODULES, buf, sz, r, tid)) return -1; }
        else return passthrough();
    } else if (action == 5 || action == 6) {                     // NtClose / CloseHandle
        if (r.a0() == 0xdeadc0de) {
            if (!finish(S.is64 ? 0 : 1, 0xc0000008)) return -1;
            countHit(6, tid); logf("[KozDbg-c] tid=%u: DEADC0DE -> STATUS_INVALID_HANDLE (istisna yok)\n", tid);
            emulated = true;
        } else return passthrough();
    } else return passthrough();

    if (emulated) {
        // kesme sitesindeki byte restore + int3'u HEMEN geri koy (o byte yeniden yurutulmeyecek)
        wrByte((uintptr_t)exip, h->orig); wrByte((uintptr_t)exip, 0xcc);
        r.set(th);
        return 0;
    }
    return passthrough();                                        // watch kurulanlar: giris yeniden calisir
}

// ---- ana dongu ---------------------------------------------------------------
int main(int argc, char** argv) {
    const char* target = nullptr; const char* logPath = "kozdbgc.log";
    std::string prof = "350"; unsigned ctl = 8191;
    std::vector<std::string> targs;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--profile" && i + 1 < argc) prof = argv[++i];
        else if (a == "--controls" && i + 1 < argc) ctl = (unsigned)strtoul(argv[++i], nullptr, 0);
        else if (a == "--log" && i + 1 < argc) logPath = argv[++i];
        else if (a == "--verbose") g_verbose = true;
        else if (!target) target = argv[i];
        else targs.push_back(a);
    }
    if (!target) { printf("Kullanim: kozdbgc [--profile 331|340|350|off] [--controls N] [--log dosya] hedef.exe [args]\n"); return 2; }
    if (prof == "off") S.enabled = false; else S.profile = atoi(prof.c_str());
    S.controls = ctl & 8191;
    if (fopen_s(&g_logfile, logPath, "a") != 0) g_logfile = nullptr;
    if (S.enabled && S.profile != 331 && S.profile != 340 && S.profile != 350) {
        log("Bu port yalniz Engine::Api profillerini (331/340/350) destekler; 360+ syscall enstrümantasyonu kapsam disi.");
        return 2;
    }
#ifdef _WIN64
    log("KozDbg-c x64 hata ayiklayici (KozDbg v1.1.2 konsol portu, Engine::Api/legacy)");
#else
    log("KozDbg-c x86 hata ayiklayici (KozDbg v1.1.2 konsol portu, Engine::Api/legacy)");
#endif
    logf("[KozDbg-c] profil=%s kontroller=0x%X hedef=%s\n", prof.c_str(), S.controls, target);

    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cmd = std::string("\"") + target + "\"";
    for (auto& t : targs) cmd += " \"" + t + "\"";
    if (!CreateProcessA(target, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi)) {
        logf("[KozDbg-c] CreateProcess basarisiz: %lu\n", GetLastError()); return 3;
    }
    S.hProc = pi.hProcess; S.pid = pi.dwProcessId;
    CloseHandle(pi.hThread);

    bool sysBpSeen = false; static bool sysBpSeen2 = false;
    DEBUG_EVENT ev{};
    int exitCode = -1;
    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD cont = DBG_CONTINUE; DWORD tid = ev.dwThreadId;
        if (g_verbose) logf("[KozDbg-c] olay=%lu tid=%u\n", (unsigned long)ev.dwDebugEventCode, tid);
        bool closeTh = false; HANDLE th = nullptr;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            S.mainBase = (uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            if (ev.u.CreateProcessInfo.hFile && ev.u.CreateProcessInfo.hFile != INVALID_HANDLE_VALUE) CloseHandle(ev.u.CreateProcessInfo.hFile);
            logf("[KozDbg-c] surec olustu pid=%u ana modul=%p\n", S.pid, (void*)S.mainBase);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            char nm[MAX_PATH] = {0};
            if (ev.u.LoadDll.hFile && ev.u.LoadDll.hFile != INVALID_HANDLE_VALUE) {
                GetFinalPathNameByHandleA(ev.u.LoadDll.hFile, nm, sizeof(nm), 0);
                CloseHandle(ev.u.LoadDll.hFile);
            }
            std::string low = nm; for (auto& c : low) c = (char)tolower((unsigned char)c);
            if (low.find("ntdll.dll") != std::string::npos) S.ntdll = (uintptr_t)ev.u.LoadDll.lpBaseOfDll;
            else if (low.find("kernelbase.dll") != std::string::npos) S.kernelbase = (uintptr_t)ev.u.LoadDll.lpBaseOfDll;
            else if (low.find("kernel32.dll") != std::string::npos) S.kernel32 = (uintptr_t)ev.u.LoadDll.lpBaseOfDll;
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            const DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
            const bool first = ev.u.Exception.dwFirstChance != 0;
            const uintptr_t ip = (uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            th = threadOf(tid); closeTh = th != nullptr;
            if (code == EXCEPTION_BREAKPOINT) {
                Hook* h = findExact(ip);
                if (!h && S.armed) h = findCopyHit(ip);
                if (h && th) {
                    Regs r; r.get(th);
                    int d = dispatchHit(h, r, th, tid, ip);
                    cont = (d == 0) ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
                } else if (!sysBpSeen) {
                    sysBpSeen = true;
                    log("[KozDbg-c] sistem kesme noktasi");
                    arm();   // KozDbg gibi: giris noktasindan hemen once, prob hizasindan sonra
                    S.threadFirstBp[tid] = true;
                } else if (!S.threadFirstBp[tid] ||
                           (S.ntdll && ip >= S.ntdll && ip < S.ntdll + 0x400000)) {
                    // thread baslangic / break-in kesmesi (ntdll icinde): yut (x64dbg davranisi)
                    S.threadFirstBp[tid] = true;
                    logf("[KozDbg-c] break-in yutuldu tid=%u ip=%p\n", tid, (void*)ip);
                } else cont = DBG_EXCEPTION_NOT_HANDLED;   // hedefin kendi int3/SEH probu
                if (g_verbose && !sysBpSeen2) { logf("[KozDbg-c] istisna iletilmedi-code=0x%08X tid=%u first=%u ip=%p\n", (unsigned)code, tid, (unsigned)first, (void*)ip); }
            } else if (code == EXCEPTION_SINGLE_STEP && th) {
                Regs r; r.get(th);
                auto st = S.stepping.find(tid);
                if (st != S.stepping.end() && st->second) {
                    S.stepping.erase(st);
                    r.c.EFlags &= ~0x100u;
                    auto ra2 = S.rearm.find(tid);
                    if (ra2 != S.rearm.end()) { wrByte(ra2->second, 0xcc); S.rearm.erase(ra2); }
                    r.set(th);
                } else if (first && S.on(7) && ip >= 3 &&
                           ip - 3 >= S.mainBase && ip - 3 < S.mainBase + 0x10000000) {
                    unsigned char b[4] = {0};
                    if (rmem(ip - 3, b, 4) && b[0] == 0x9d && b[1] == 0x0f && b[2] == 0x31 && b[3] == 0x90) {
                        logf("[KozDbg-c] tid=%u: TF probe (%p) hedefe teslim ediliyor\n", tid, (void*)ip);
                        cont = DBG_EXCEPTION_NOT_HANDLED;
                    } else cont = DBG_EXCEPTION_NOT_HANDLED;
                } else cont = DBG_EXCEPTION_NOT_HANDLED;
            } else { cont = DBG_EXCEPTION_NOT_HANDLED; if (code != 0x4000001F) logf("[KozDbg-c] istisna (diger) code=0x%08X tid=%u first=%u\n", (unsigned)code, tid, (unsigned)first); }
            break;
        }
        case EXIT_THREAD_DEBUG_EVENT:
            S.stepping.erase(tid); S.rearm.erase(tid);
            S.hiddenThreads.erase(std::remove(S.hiddenThreads.begin(), S.hiddenThreads.end(), tid), S.hiddenThreads.end());
            S.pending.erase(std::remove_if(S.pending.begin(), S.pending.end(), [&](const Pending& p) { return p.thread == tid; }), S.pending.end());
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            exitCode = (int)ev.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            goto done;
        }
        if (closeTh && th) CloseHandle(th);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
done:
    logf("[KozDbg-c] hedef cikti, kod=%d (0x%X) | ARM=%s profil=%d\n", exitCode, exitCode, S.armed ? "acik" : "kapali", S.enabled ? S.profile : -1);
    static const char* lbl[13] = { "PEB/IsDebuggerPresent", "RemoteDebugger/Port/Flags", "DebugObject", "ThreadHide", "KernelDebugger", "ModuleList", "InvalidHandle", "TFDelivery", "InstrCallback", "DRHide", "RemoteBreakin", "TitanHide", "DecoderHW" };
    unsigned long long total = 0;
    for (unsigned i = 0; i < 13; i++) { total += S.hits[i]; logf("[KozDbg-c]   %-26s %-4s mudahale=%llu\n", lbl[i], i >= 8 ? "n/a" : (S.on(i) ? "on" : "off"), S.hits[i]); }
    logf("[KozDbg-c] toplam mudahale=%llu\n", total);
    if (g_logfile) fclose(g_logfile);
    return exitCode == -1 ? 1 : exitCode;
}
