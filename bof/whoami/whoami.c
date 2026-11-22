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

// ================================
// MAIN FUNCTION
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] Starting whoami final fixed");

    // 1. Load advapi32.dll
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    FARPROC pLoadLibraryA = (FARPROC)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "LoadLibraryA");
    HMODULE hAdvapi32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))pLoadLibraryA)("advapi32.dll");
    if (!hAdvapi32) { BeaconPrintf(CALLBACK_ERROR, "[WHOAMI] advapi32.dll not loaded"); return; }

    // 2. Resolve GetUserNameW
    typedef BOOL (WINAPI *GetUserNameW_t)(LPWSTR, LPDWORD);
    GetUserNameW_t GetUserNameW = (GetUserNameW_t)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAdvapi32, "GetUserNameW");
    if (!GetUserNameW) { BeaconPrintf(CALLBACK_ERROR, "[WHOAMI] GetUserNameW not resolved"); return; }

    // 3. Get user
    WCHAR wcUser[256] = {0};
    DWORD dwUser = 256;
    if (GetUserNameW(wcUser, &dwUser)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] User: %ls", wcUser);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] User: <not available>");
    }

    // 4. Get machine name with __imp_GetComputerNameA
    char pcName[256] = {0};
    DWORD dwPC = 256;
    if (((BOOL(WINAPI*)(LPSTR, LPDWORD))__imp_GetComputerNameA)(pcName, &dwPC)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] Machine: %s", pcName);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] Machine: <not available>");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] Done");
}
