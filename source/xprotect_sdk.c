// ============================================================
// xprotect_sdk.c — XProtect SDK govdeleri (0.7.0)
// AYRI DERLEME BIRIMI — test/main ile birlikte LINK edilir.
// (VMProtectSDK.lib birebir karsiligi; tek-birim static govdelerde
//  GCC "return 0" sabitini cagri noktasina katladigi icin ayridir.)
// Motor: isaret bloklarini (B8 58 50 41 4C | B8 fnid | ... | B8 8E 2C 7A 3D)
// bulur ve lisans dispatch'ine yamar.
// ============================================================
#include "xprotect_sdk.h"

#ifndef XPROTECT_NO_SDK

#define XP_API_BODY(id) \
    __asm__ volatile(".byte 0xB8, 0x58, 0x50, 0x41, 0x4C" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, " #id ", 0x00, 0x00, 0x00" ::: "eax", "memory"); \
    __asm__ volatile(".byte 0xB8, 0x8E, 0x2C, 0x7A, 0x3D" ::: "eax", "memory")

int XProtectSetSerialNumber(const char* serial) {
    XP_API_BODY(1); (void)serial; return 2; /* korunmamis: INVALID */
}
int XProtectGetSerialNumberState(void) {
    XP_API_BODY(2); return 0;
}
int XProtectGetSerialNumberData(XProtectSerialNumberData* data, int size) {
    XP_API_BODY(3); (void)data; (void)size; return 0;
}
int XProtectGetCurrentHWID(char* hwid, int size) {
    XP_API_BODY(4); (void)hwid; (void)size; return 0;
}
int XProtectIsProtected(void) {
    XP_API_BODY(5); return 0;
}
int XProtectIsDebuggerPresent(void) {
    XP_API_BODY(6); return 0;
}
int XProtectIsValidImageCRC(void) {
    XP_API_BODY(7); return 0;
}
const char* XProtectDecryptStringA(const char* s) {
    XP_API_BODY(8); return s;
}
const wchar_t* XProtectDecryptStringW(const wchar_t* s) {
    XP_API_BODY(9); return s;
}
int XProtectFreeString(void* v) {
    XP_API_BODY(10); (void)v; return 0;
}
int XProtectActivateLicense(const char* code, char* serial, int size) {
    XP_API_BODY(11); (void)code; (void)serial; (void)size; return 5;
}
int XProtectDeactivateLicense(const char* serial) {
    XP_API_BODY(12); (void)serial; return 5;
}
int XProtectGetOfflineActivationString(const char* code, char* buf, int size) {
    XP_API_BODY(13); (void)code; (void)buf; (void)size; return 0;
}
int XProtectGetOfflineDeactivationString(const char* serial, char* buf, int size) {
    XP_API_BODY(14); (void)serial; (void)buf; (void)size; return 0;
}
int XProtectIsVirtualMachinePresent(void) {
    XP_API_BODY(15); return 0;
}

/* ---- 0.7.0-final SDK-40 (fnid 16..37): govdesiz isaret bloklari ---- */
void* XProtectFindResourceA(void* hModule, const char* name, const char* type) {
    XP_API_BODY(17); (void)hModule; (void)name; (void)type; return 0;
}
void* XProtectFindResourceW(void* hModule, const wchar_t* name, const wchar_t* type) {
    XP_API_BODY(19); (void)hModule; (void)name; (void)type; return 0;
}
void* XProtectFindResourceExA(void* hModule, const char* type, const char* name, unsigned short lang) {
    XP_API_BODY(18); (void)hModule; (void)type; (void)name; (void)lang; return 0;
}
void* XProtectFindResourceExW(void* hModule, const wchar_t* type, const wchar_t* name, unsigned short lang) {
    XP_API_BODY(20); (void)hModule; (void)type; (void)name; (void)lang; return 0;
}
void* XProtectLoadResource(void* hModule, void* hResInfo) {
    XP_API_BODY(16); (void)hModule; (void)hResInfo; return 0;
}
int XProtectLoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax) {
    XP_API_BODY(21); (void)hInstance; (void)uID; (void)lpBuffer; (void)cchBufferMax; return 0;
}
int XProtectLoadStringW(void* hInstance, unsigned int uID, wchar_t* lpBuffer, int cchBufferMax) {
    XP_API_BODY(22); (void)hInstance; (void)uID; (void)lpBuffer; (void)cchBufferMax; return 0;
}
int XProtectEnumResourceNamesA(void* hModule, const char* type, void* cbEnum, long long lParam) {
    XP_API_BODY(23); (void)hModule; (void)type; (void)cbEnum; (void)lParam; return 0;
}
int XProtectEnumResourceNamesW(void* hModule, const wchar_t* type, void* cbEnum, long long lParam) {
    XP_API_BODY(24); (void)hModule; (void)type; (void)cbEnum; (void)lParam; return 0;
}
int XProtectEnumResourceLanguagesA(void* hModule, const char* type, const char* name, void* cbEnum, long long lParam) {
    XP_API_BODY(25); (void)hModule; (void)type; (void)name; (void)cbEnum; (void)lParam; return 0;
}
int XProtectEnumResourceLanguagesW(void* hModule, const wchar_t* type, const wchar_t* name, void* cbEnum, long long lParam) {
    XP_API_BODY(26); (void)hModule; (void)type; (void)name; (void)cbEnum; (void)lParam; return 0;
}
int XProtectEnumResourceTypesA(void* hModule, void* cbEnum, long long lParam) {
    XP_API_BODY(27); (void)hModule; (void)cbEnum; (void)lParam; return 0;
}
int XProtectEnumResourceTypesW(void* hModule, void* cbEnum, long long lParam) {
    XP_API_BODY(28); (void)hModule; (void)cbEnum; (void)lParam; return 0;
}
void* XProtectDecryptBuffer(void* buf, unsigned int size, unsigned long long key) {
    XP_API_BODY(29); (void)buf; (void)size; (void)key; return buf;
}
unsigned long long XProtectRandom(void) {
    XP_API_BODY(35); return 0;
}
void* XProtectBoxPointer(void* p) {
    XP_API_BODY(36); (void)p; return p;
}
void* XProtectUnboxPointer(void* p) {
    XP_API_BODY(37); (void)p; return p;
}

#endif // XPROTECT_NO_SDK
