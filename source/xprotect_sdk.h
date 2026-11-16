// ============================================================
// xprotect_sdk.h — XProtect SDK (0.7.0)
// ============================================================
// A) BOLGE KORUMASI (0.5.0'dan beri):
//    XProtectBeginVirtualization/Mutation/Ultra + XProtectEnd
//    Kaynak koda isaret konur; XProtect ile acildiginda otomatik bulunur.
//
// B) LISANS API'LERI (0.7.0 — VMProtect SDK birebir karsiliklar):
//    XProtectSetSerialNumber(serial)         -> VMProtectSetSerialNumber
//    XProtectGetSerialNumberState()          -> VMProtectGetSerialNumberState
//    XProtectGetSerialNumberData(&d, sizeof) -> VMProtectGetSerialNumberData
//    XProtectGetCurrentHWID(buf, size)       -> VMProtectGetCurrentHWID
//    XProtectIsProtected()                   -> VMProtectIsProtected
//    XProtectIsDebuggerPresent()             -> VMProtectIsDebuggerPresent
//    XProtectIsValidImageCRC()               -> VMProtectIsValidImageCRC
//    XProtectDecryptStringA/W, XProtectFreeString
//    XProtectActivateLicense / DeactivateLicense (0.7.0: MVP — agirlikli
//      islemler Weblm sunucusu ister; 0 ya da "baglanti yok" doner)
//    XProtectIsVirtualMachinePresent (0.7.0: MVP 0)
//
//    Bunlar FONKSIYON kimlikli isaretlerdir: motor, fonksiyon govdesini
//    .vmp0'daki lisans dispatch'ine yamar. KORUNMAMIS derlemede hepsi
//    guvenli "basarisiz" doner (0 / false / 1 kuralina gore).
//
// KURALLAR (bolge korumasi icin gecerli olanlar):
//   1) Isaretleri FONKSIYON BASINA koyun; bolge sonunda donus degeri
//      RAX/EAX'te hazir olmali.
//   2) Isaret makrolari EAX'i bozar; canli EAX tutmayin.
//   3) x86'da V/U bolgesi icinde call KULLANMAYIN (duru RED); M kullanin.
//   4) Bolge icindeki degiskenler volatile olsun.
//   5) Korumasiz calistirma: XPROTECT_NO_SDK tanimlayin (hepsi bos).
//
// SOZLESME (motor tarafinda birebir sabitler):
//   Bolge:  B8 9C37E1B5  B8 <tip 1..3>  ...bolge...  B8 3D7A2C8E
//   API:    B8 58504A4C  B8 <fnid 1..37> (govdesiz)        B8 3D7A2C8E
// ============================================================
#ifndef XPROTECT_SDK_H
#define XPROTECT_SDK_H

#include <stddef.h>   /* wchar_t */

#if defined(_MSC_VER)
  // MSVC: x86 __asm; x64 MSVC satir-ici asm desteklemez — GCC/Clang kullanin.
  #define XProtectBeginVirtualization() do { __asm { mov eax, 0x9C37E1B5h } __asm { mov eax, 1 } } while (0)
  #define XProtectBeginMutation()       do { __asm { mov eax, 0x9C37E1B5h } __asm { mov eax, 2 } } while (0)
  #define XProtectBeginUltra()          do { __asm { mov eax, 0x9C37E1B5h } __asm { mov eax, 3 } } while (0)
  #define XProtectBeginUltraLockByKey()          do { __asm { mov eax, 0x9C37E1B5h } __asm { mov eax, 4 } } while (0)
  #define XProtectBeginVirtualizationLockByKey() do { __asm { mov eax, 0x9C37E1B5h } __asm { mov eax, 5 } } while (0)
  #define XProtectEnd()                 do { __asm { mov eax, 0x3D7A2C8Eh } } while (0)
  #define XP_API_DECL static
#elif defined(XPROTECT_NO_SDK)
  #define XProtectBeginVirtualization() ((void)0)
  #define XProtectBeginMutation()       ((void)0)
  #define XProtectBeginUltra()          ((void)0)
  #define XProtectEnd()                 ((void)0)
  #define XP_API_DECL static
  #define XP_API_STUB 1
  #define XP_API_BEG(id) ((void)0)
  #define XP_API_END() ((void)0)
#else
  // GCC / Clang / zig cc: ham bayt yayini (sozdiziminden bagimsiz).
  #define XP_SDK_BEG(t) \
      __asm__ volatile(".byte 0xB8, 0xB5, 0xE1, 0x37, 0x9C" ::: "eax", "memory"); \
      __asm__ volatile(".byte 0xB8, " #t ", 0x00, 0x00, 0x00" ::: "eax", "memory")
  #define XP_SDK_END() \
      __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")
  #define XP_API_BEG(id) \
      __asm__ volatile(".byte 0xB8, 0x58, 0x50, 0x41, 0x4C" ::: "eax", "memory"); \
      __asm__ volatile(".byte 0xB8, " #id ", 0x00, 0x00, 0x00" ::: "eax", "memory")
  #define XP_API_END() XP_SDK_END()

  #define XProtectBeginVirtualization() XP_SDK_BEG(1)
  #define XProtectBeginMutation()       XP_SDK_BEG(2)
  #define XProtectBeginUltra()          XP_SDK_BEG(3)
  #define XProtectEnd()                 XP_SDK_END()
  /* 1.2.2-A20: UO/VMP birebir LockByKey varyantlari (ty 4/5) —
     bolge U/V olarak derlenir; anahtar baglama proje-lisans LSD ile */
  #define XProtectBeginUltraLockByKey()          XP_SDK_BEG(4)
  #define XProtectBeginVirtualizationLockByKey() XP_SDK_BEG(5)
  #define XP_API_DECL static __attribute__((noinline))
#endif

// ---- lisans tipleri (VMProtect SDK birebir) ----
#pragma pack(push, 1)
typedef struct {
    unsigned short wYear;
    unsigned char  bMonth;
    unsigned char  bDay;
} XProtectDate;

typedef struct {
    int          nState;        // XProtectSerialStateFlags
    wchar_t      wUserName[256];
    wchar_t      wEMail[256];
    XProtectDate dtExpire;
    XProtectDate dtMaxBuild;
    int          bRunningTime;
    unsigned char nUserDataLength;
    unsigned char bUserData[255];
} XProtectSerialNumberData;
#pragma pack(pop)

enum XProtectSerialStateFlags {
    XSERIAL_STATE_SUCCESS              = 0,
    XSERIAL_STATE_FLAG_CORRUPTED       = 0x00000001,
    XSERIAL_STATE_FLAG_INVALID         = 0x00000002,
    XSERIAL_STATE_FLAG_BLACKLISTED     = 0x00000004,
    XSERIAL_STATE_FLAG_DATE_EXPIRED    = 0x00000008,
    XSERIAL_STATE_FLAG_RUNNING_TIME_OVER = 0x00000010,
    XSERIAL_STATE_FLAG_BAD_HWID        = 0x00000020,
    XSERIAL_STATE_FLAG_MAX_BUILD_EXPIRED = 0x00000040
};

// ---- lisans API'leri ----
// 0.7.0 MIMARI NOT: govdeLER xprotect_sdk.c'DE (ayri derleme birimi).
// VMProtect ile birebir isleyis: VMProtectSDK.lib/dll import'u gibi
// ceviri-birimler arasi cagri — yoksa GCC "return 0" sabitini cagri
// noktasina katlar ve motorun yamasi anlamsizlasir (t9_q kaniti:
// xor edx,edx; call; call printf — rax hic okunmadi!).
// KULLANIM: #include "xprotect_sdk.h" + xprotect_sdk.c'yi LINKLE.
#ifdef __cplusplus
extern "C" {
#endif

int  XProtectSetSerialNumber(const char* serial);
int  XProtectGetSerialNumberState(void);
int  XProtectGetSerialNumberData(XProtectSerialNumberData* data, int size);
int  XProtectGetCurrentHWID(char* hwid, int size);
int  XProtectIsProtected(void);
int  XProtectIsDebuggerPresent(void);
int  XProtectIsValidImageCRC(void);
const char*    XProtectDecryptStringA(const char* s);
const wchar_t* XProtectDecryptStringW(const wchar_t* s);
int  XProtectFreeString(void* v);
int  XProtectActivateLicense(const char* code, char* serial, int size);
int  XProtectDeactivateLicense(const char* serial);
int  XProtectGetOfflineActivationString(const char* code, char* buf, int size);
int  XProtectGetOfflineDeactivationString(const char* serial, char* buf, int size);
int  XProtectIsVirtualMachinePresent(void);

/* ---- 0.7.0-final SDK-40: kaynak/buffer/kutu ailesi (fnid 16..37) ----
   core/files.h APIType tam yuzeyi (atBegin/atEnd = bolge isaretleri).
   Kaynak API'leri runtime dispatch'te gercel Windows API'sine yonlenir
   (IAT'siz — PEB hash cozumleme). Korumasiz derlemede guvenli bos doner. */
void* XProtectFindResourceA(void* hModule, const char* name, const char* type);
void* XProtectFindResourceW(void* hModule, const wchar_t* name, const wchar_t* type);
void* XProtectFindResourceExA(void* hModule, const char* type, const char* name, unsigned short lang);
void* XProtectFindResourceExW(void* hModule, const wchar_t* type, const wchar_t* name, unsigned short lang);
void* XProtectLoadResource(void* hModule, void* hResInfo);
int   XProtectLoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax);
int   XProtectLoadStringW(void* hInstance, unsigned int uID, wchar_t* lpBuffer, int cchBufferMax);
int   XProtectEnumResourceNamesA(void* hModule, const char* type, void* cbEnum, long long lParam);
int   XProtectEnumResourceNamesW(void* hModule, const wchar_t* type, void* cbEnum, long long lParam);
int   XProtectEnumResourceLanguagesA(void* hModule, const char* type, const char* name, void* cbEnum, long long lParam);
int   XProtectEnumResourceLanguagesW(void* hModule, const wchar_t* type, const wchar_t* name, void* cbEnum, long long lParam);
int   XProtectEnumResourceTypesA(void* hModule, void* cbEnum, long long lParam);
int   XProtectEnumResourceTypesW(void* hModule, void* cbEnum, long long lParam);
void* XProtectDecryptBuffer(void* buf, unsigned int size, unsigned long long key);
unsigned long long XProtectRandom(void);
void* XProtectBoxPointer(void* p);
void* XProtectUnboxPointer(void* p);
/* ic yuzey (fnid 30..34 — atRuntimeInit/atLoaderData/atSetupImage/
   atFreeImage/atCalcCRC): motor-loader icindir; genel baslikta YOK. */

#ifdef __cplusplus
}
#endif

#ifdef XPROTECT_NO_SDK
/* korunmamis calistirma: yalin uygulama (isaretsiz) */
int  XProtectSetSerialNumber(const char* serial) { (void)serial; return 2; }
int  XProtectGetSerialNumberState(void) { return 0; }
int  XProtectGetSerialNumberData(XProtectSerialNumberData* d, int s) { (void)d; (void)s; return 0; }
int  XProtectGetCurrentHWID(char* h, int s) { (void)h; (void)s; return 0; }
int  XProtectIsProtected(void) { return 0; }
int  XProtectIsDebuggerPresent(void) { return 0; }
int  XProtectIsValidImageCRC(void) { return 0; }
const char*    XProtectDecryptStringA(const char* s) { return s; }
const wchar_t* XProtectDecryptStringW(const wchar_t* s) { return s; }
int  XProtectFreeString(void* v) { (void)v; return 0; }
int  XProtectActivateLicense(const char* c, char* s, int n) { (void)c; (void)s; (void)n; return 5; }
int  XProtectDeactivateLicense(const char* s) { (void)s; return 5; }
int  XProtectGetOfflineActivationString(const char* c, char* b, int n) { (void)c; (void)b; (void)n; return 0; }
int  XProtectGetOfflineDeactivationString(const char* s, char* b, int n) { (void)s; (void)b; (void)n; return 0; }
int  XProtectIsVirtualMachinePresent(void) { return 0; }
/* SDK-40 korunmamis karşiliklar */
void* XProtectFindResourceA(void* h, const char* n, const char* t) { (void)h; (void)n; (void)t; return 0; }
void* XProtectFindResourceW(void* h, const wchar_t* n, const wchar_t* t) { (void)h; (void)n; (void)t; return 0; }
void* XProtectFindResourceExA(void* h, const char* t, const char* n, unsigned short l) { (void)h; (void)t; (void)n; (void)l; return 0; }
void* XProtectFindResourceExW(void* h, const wchar_t* t, const wchar_t* n, unsigned short l) { (void)h; (void)t; (void)n; (void)l; return 0; }
void* XProtectLoadResource(void* h, void* r) { (void)h; (void)r; return 0; }
int   XProtectLoadStringA(void* i, unsigned int u, char* b, int m) { (void)i; (void)u; (void)b; (void)m; return 0; }
int   XProtectLoadStringW(void* i, unsigned int u, wchar_t* b, int m) { (void)i; (void)u; (void)b; (void)m; return 0; }
int   XProtectEnumResourceNamesA(void* h, const char* t, void* c, long long p) { (void)h; (void)t; (void)c; (void)p; return 0; }
int   XProtectEnumResourceNamesW(void* h, const wchar_t* t, void* c, long long p) { (void)h; (void)t; (void)c; (void)p; return 0; }
int   XProtectEnumResourceLanguagesA(void* h, const char* t, const char* n, void* c, long p) { (void)h; (void)t; (void)n; (void)c; (void)p; return 0; }
int   XProtectEnumResourceLanguagesW(void* h, const wchar_t* t, const wchar_t* n, void* c, long p) { (void)h; (void)t; (void)n; (void)c; (void)p; return 0; }
int   XProtectEnumResourceTypesA(void* h, void* c, long p) { (void)h; (void)c; (void)p; return 0; }
int   XProtectEnumResourceTypesW(void* h, void* c, long p) { (void)h; (void)c; (void)p; return 0; }
void* XProtectDecryptBuffer(void* b, unsigned int s, unsigned long long k) { (void)b; (void)s; (void)k; return b; }
unsigned long long XProtectRandom(void) { return 0; }
void* XProtectBoxPointer(void* p) { return p; }
void* XProtectUnboxPointer(void* p) { return p; }
#endif


#endif // XPROTECT_SDK_H
