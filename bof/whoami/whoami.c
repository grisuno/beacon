#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS
// ================================
extern FARPROC __imp_GetModuleHandleA;
extern FARPROC __imp_GetProcAddress;
extern FARPROC __imp_LoadLibraryA;
extern FARPROC __imp_GetComputerNameA;

// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 🔍 Iniciando whoami final fixed");

    // 1. Cargar advapi32.dll
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    FARPROC pLoadLibraryA = (FARPROC)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "LoadLibraryA");
    HMODULE hAdvapi32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("advapi32.dll");
    if (!hAdvapi32) { BeaconPrintf(CALLBACK_ERROR, "[WHOAMI] ❌ advapi32.dll no cargada"); return; }

    // 2. Resolver GetUserNameW
    typedef BOOL (WINAPI *GetUserNameW_t)(LPWSTR, LPDWORD);
    GetUserNameW_t GetUserNameW = (GetUserNameW_t)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAdvapi32, "GetUserNameW");
    if (!GetUserNameW) { BeaconPrintf(CALLBACK_ERROR, "[WHOAMI] ❌ GetUserNameW no resuelto"); return; }

    // 3. Obtener usuario
    WCHAR wcUser[256] = {0};
    DWORD dwUser = 256;
    if (GetUserNameW(wcUser, &dwUser)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 👤 Usuario: %ls", wcUser);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ℹ️ Usuario: <no disponible>");
    }

    // 4. Obtener nombre de la máquina con __imp_GetComputerNameA
    char pcName[256] = {0};
    DWORD dwPC = 256;
    if (((BOOL(WINAPI*)(LPSTR, LPDWORD))__imp_GetComputerNameA)(pcName, &dwPC)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 💻 Máquina: %s", pcName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ℹ️ Máquina: <no disponible>");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] ✅ Finalizado");
}
