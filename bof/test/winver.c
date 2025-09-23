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

extern PVOID __imp_GetVersionExA;

void go(char *args, int alen) {
    OSVERSIONINFOA osvi;
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

    if (!((BOOL(WINAPI*)(LPOSVERSIONINFOA))__imp_GetVersionExA)(&osvi)) {
        BeaconPrintf(CALLBACK_ERROR, "GetVersionExA falló\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Windows Version: %lu.%lu (Build %lu)\n",
                 osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Descripción: %s\n", osvi.szCSDVersion);
}
