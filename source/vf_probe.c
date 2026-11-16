// vf_probe.c — VF zinciri probe DLL (faRegister yolu)
// DllMain: C:\vf_probe.txt'ye "VFDM\n" yazar
// DllRegisterServer: "VFDRS\n" yazar, S_OK doner
#include <windows.h>
static void app(const char* tag) {
    HANDLE h = CreateFileA("C:\\vf_probe.txt", FILE_APPEND_DATA, 0, NULL,
                           OPEN_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wr = 0;
        WriteFile(h, tag, lstrlenA(tag), &wr, NULL);
        CloseHandle(h);
    }
}
#ifdef __cplusplus
extern "C"
#endif
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) app("VFDM\n");
    return TRUE;
}
#ifdef __cplusplus
extern "C"
#endif
HRESULT __stdcall DllRegisterServer(void) {
    app("VFDRS\n");
    return 0; /* S_OK */
}
