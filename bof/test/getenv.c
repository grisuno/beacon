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
