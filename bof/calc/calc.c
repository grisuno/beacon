#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS
// ================================
extern FARPROC __imp_GetModuleHandleA;
extern FARPROC __imp_GetProcAddress;
extern FARPROC __imp_LoadLibraryA;
extern FARPROC __imp_GetComputerNameA;
extern FARPROC __imp_CloseHandle; 
// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ⚡ Ejecutando calc.exe...\n");

    // 1. Obtener kernel32.dll
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[EXEC] ❌ kernel32.dll no encontrada\n");
        return;
    }

    // 2. Resolver GetProcAddress (con cast correcto)
    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)__imp_GetProcAddress;

    // 3. Obtener CreateProcessA
    FARPROC pCreateProcessA = pGetProcAddress(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) {
        BeaconPrintf(CALLBACK_ERROR, "[EXEC] ❌ CreateProcessA no disponible\n");
        return;
    }

    // 4. Definir tipo de CreateProcessA
    typedef BOOL (WINAPI *CreateProcessA_t)(
        LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    CreateProcessA_t CreateProcessA = (CreateProcessA_t)pCreateProcessA;

    // 5. Configurar STARTUPINFO y PROCESS_INFORMATION
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // 6. Llamar a CreateProcessA
    if (CreateProcessA(NULL, "calc.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ✅ Calculadora lanzada!\n");

        // USAR __imp_CloseHandle
        // Primero: castear __imp_CloseHandle
        typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
        CloseHandle_t pCloseHandle = (CloseHandle_t)__imp_CloseHandle;

        // Luego: llamarlo como una función normal
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);

    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ❌ No se pudo lanzar calc.exe\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ✅ Finalizado\n");
}
