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
