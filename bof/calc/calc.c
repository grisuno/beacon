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
extern FARPROC __imp_GetModuleHandleA;
extern FARPROC __imp_GetProcAddress;
extern FARPROC __imp_LoadLibraryA;
extern FARPROC __imp_GetComputerNameA;
extern FARPROC __imp_CloseHandle; 
// ================================
// MAIN FUNCTION
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] Running calc.exe...\n");

    // 1. Get kernel32.dll
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[EXEC] kernel32.dll not found\n");
        return;
    }

    // 2. Resolve GetProcAddress (with correct cast)
    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)__imp_GetProcAddress;

    // 3. Get CreateProcessA
    FARPROC pCreateProcessA = pGetProcAddress(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) {
        BeaconPrintf(CALLBACK_ERROR, "[EXEC] CreateProcessA not available\n");
        return;
    }

    // 4. Define CreateProcessA type
    typedef BOOL (WINAPI *CreateProcessA_t)(
        LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    CreateProcessA_t CreateProcessA = (CreateProcessA_t)pCreateProcessA;

    // 5. Set up STARTUPINFO and PROCESS_INFORMATION
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // 6. Call CreateProcessA
    if (CreateProcessA(NULL, "calc.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] Calculator launched!\n");

        // Use __imp_CloseHandle
        // First: cast __imp_CloseHandle
        typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
        CloseHandle_t pCloseHandle = (CloseHandle_t)__imp_CloseHandle;

        // Then: call it as a normal function
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);

    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] Failed to launch calc.exe\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] Done\n");
}
