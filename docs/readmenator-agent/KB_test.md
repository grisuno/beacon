# Subsystem: test

## bof/test/Test.c
- Layer: testing
- Doc: include "beacon.h"
- Language: c
- Symbols:
  - `go` (function, line 2) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 4) `BeaconPrintf(CALLBACK_OUTPUT, "[CoffTest] I am alive! . Args=%.*s\n", alen, args);`
- Depends on: `bof/test/beacon.h`

## bof/test/amsibypass.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 34) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 35) `BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] Iniciando bypass AMSI (patch en memoria)...\n");`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_VirtualProtect` (variable, line 28) `extern PVOID __imp_VirtualProtect;`
  - `__imp_RtlCopyMemory` (variable, line 29) `extern PVOID __imp_RtlCopyMemory;`
- Depends on: `bof/test/beacon.h`

## bof/test/beacon.h
- Layer: testing
- Language: h
- Symbols:
  - `datap` (struct, line 25)
  - `BEACON_H` (macro, line 21) `#define BEACON_H`
  - `CALLBACK_OUTPUT` (macro, line 40) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 42) `#define CALLBACK_ERROR`
- Imported by: `bof/test/Test.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c`, `bof/test/disablelog.c`, `bof/test/getenv.c`, `bof/test/loadvnc.c`, `bof/test/persist.c`, `bof/test/persistsvc.c`, `bof/test/scan_shellcode.c`, `bof/test/shellcode.c`, `bof/test/sock5.c`, `bof/test/uacbypass.c`, `bof/test/upload.c`, `bof/test/vncrelay.c`, `bof/test/winver.c`

## bof/test/cmdwhoami.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 42) `void go(char *args, int alen)`
  - `BOOL` (function, line 29) `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD d`
  - `BeaconPrintf` (function, line 46) `BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(kernel32.dll) falló\n");`
  - `__imp_LoadLibraryA` (variable, line 25) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
- Depends on: `bof/test/beacon.h`

## bof/test/disablelog.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `my_wcscmp` (function, line 36) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)`
  - `go` (function, line 68) `void go(char *args, int alen)`
  - `SC_HANDLE` (function, line 46) `typedef SC_HANDLE (WINAPI *pOpenSCManagerA)(LPCSTR, LPCSTR, DWORD);`
  - `BOOL` (function, line 48) `typedef BOOL (WINAPI *pQueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);`
  - `DWORD` (function, line 51) `typedef DWORD (WINAPI *pGetModuleBaseNameW)(HANDLE, HMODULE, LPWSTR, DWORD);`
  - `HANDLE` (function, line 53) `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);`
  - `NTSTATUS` (function, line 61) `typedef NTSTATUS (NTAPI *pNtQueryInformationThread)( HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength );`
  - `BeaconPrintf` (function, line 70) `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Iniciando: Suspensión de hilos en wevtsvc.dll (servicio EventLog)\n");`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 28) `extern PVOID __imp_GetProcAddress;`
  - `__imp_GetModuleHandleA` (variable, line 29) `extern PVOID __imp_GetModuleHandleA;`
  - `__imp_CloseHandle` (variable, line 30) `extern PVOID __imp_CloseHandle;`
  - `__imp_OpenProcess` (variable, line 31) `extern PVOID __imp_OpenProcess;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 20) `#define WIN32_LEAN_AND_MEAN`
  - `NT_SUCCESS` (macro, line 34) `#define NT_SUCCESS(x)`
- Depends on: `bof/test/beacon.h`

## bof/test/getenv.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `go` (function, line 24) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 42) `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] %-15s = [NO DISPONIBLE]\n", vars[i]);`
  - `__imp_GetEnvironmentVariableA` (variable, line 22) `extern PVOID __imp_GetEnvironmentVariableA;`
- Depends on: `bof/test/beacon.h`

## bof/test/loadvnc.c
- Layer: testing
- Language: c
- Symbols:
  - `_PROCESSENTRY32` (struct, line 35)
  - `dwSize` (type_alias, line 34) `typedef struct _PROCESSENTRY32 { DWORD dwSize;`
  - `execute_cmd_hidden` (function, line 51) `void execute_cmd_hidden(char* cmd)`
  - `go` (function, line 81) `void go(char *args, int alen)`
  - `BOOL` (function, line 54) `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);`
  - `DWORD` (function, line 67) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
  - `pWaitForSingleObject` (function, line 70) `pWaitForSingleObject(pi.hProcess, 8000);`
  - `BeaconPrintf` (function, line 82) `BeaconPrintf(CALLBACK_OUTPUT, "[VNC] Iniciando descarga e inyección...");`
  - `int` (function, line 104) `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);`
  - `pwsprintfA` (function, line 111) `pwsprintfA(dll_path, "%s\\winvnc.x64.dll", temp_path);`
  - `HANDLE` (function, line 121) `typedef HANDLE (WINAPI *CREATE_SNAPSHOT)(DWORD, DWORD);`
  - `LPVOID` (function, line 182) `typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);`
  - `HMODULE` (function, line 204) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
  - `TH32CS_SNAPPROCESS` (macro, line 33) `#define TH32CS_SNAPPROCESS`
- Depends on: `bof/test/beacon.h`

## bof/test/make_table.c
- Layer: testing
- Language: c
- Symbols:
  - `Copyright` (function, line 16) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
  - `main` (function, line 33) `void main()`
  - `printf` (function, line 48) `printf("Hash for '%s' = 0x%08X\n", names[i], h);`

## bof/test/persist.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 26) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 38) `BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA falló: %ld\n", result);`
  - `strlen` (function, line 49) `strlen(valueData) + 1 );`
  - `__imp_RegOpenKeyExA` (variable, line 22) `extern PVOID __imp_RegOpenKeyExA;`
  - `__imp_RegSetValueExA` (variable, line 24) `extern PVOID __imp_RegSetValueExA;`
  - `__imp_RegCloseKey` (variable, line 25) `extern PVOID __imp_RegCloseKey;`
- Depends on: `bof/test/beacon.h`

## bof/test/persistsvc.c
- Layer: testing
- Language: c
- Symbols:
  - `my_memcpy` (function, line 33) `static void* my_memcpy(void* dst, const void* src, size_t len)`
  - `my_strlen` (function, line 39) `static int my_strlen(const char* str)`
  - `my_strcat` (function, line 46) `static char* my_strcat(char* dest, const char* src)`
  - `my_strcmp` (function, line 54) `static int my_strcmp(const char* s1, const char* s2)`
  - `ServiceHandler` (function, line 82) `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...`
  - `ServiceMain` (function, line 116) `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)`
  - `go` (function, line 251) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 68) `BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] No se pudo resolver " #name "\n");`
  - `BOOL` (function, line 103) `typedef BOOL (WINAPI *pSetServiceStatus_t)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);`
  - `pSetServiceStatus` (function, line 106) `pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);`
  - `SERVICE_STATUS_HANDLE` (function, line 126) `typedef SERVICE_STATUS_HANDLE (WINAPI *pRegisterServiceCtrlHandlerA_t)(LPCSTR, LPHANDLER_FUNCTION);`
  - `HANDLE` (function, line 128) `typedef HANDLE (WINAPI *pCreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);`
  - `RESOLVE_API` (function, line 132) `RESOLVE_API(Advapi32, RegisterServiceCtrlHandlerA, pRegisterServiceCtrlHandlerA_t);`
  - `void` (function, line 174) `typedef void (WINAPI *pRtlZeroMemory_t)(PVOID, SIZE_T);`
  - `DWORD` (function, line 175) `typedef DWORD (WINAPI *pGetLastError_t)(void);`
  - `HMODULE` (function, line 176) `typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);`
  - `pRtlZeroMemory` (function, line 207) `pRtlZeroMemory(&si, sizeof(si));`
  - `pCloseHandle` (function, line 228) `pCloseHandle(pi.hProcess);`
  - `pWaitForSingleObject` (function, line 236) `pWaitForSingleObject(g_StopEvent, INFINITE);`
  - `pCloseServiceHandle` (function, line 357) `pCloseServiceHandle(hService);`
  - `__imp_LoadLibraryA` (variable, line 27) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 28) `extern PVOID __imp_GetProcAddress;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 19) `#define WIN32_LEAN_AND_MEAN`
  - `RESOLVE_API` (macro, line 65) `#define RESOLVE_API(lib, name, type)`
  - `cleanup` (macro, line 131) `#define cleanup`
  - `cleanup` (macro, line 183) `#define cleanup`
- Depends on: `bof/test/beacon.h`

## bof/test/scan_shellcode.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 84) `void go(char *args, int alen)`
  - `HANDLE` (function, line 75) `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);`
  - `BOOL` (function, line 77) `typedef BOOL (WINAPI *pProcess32First)(HANDLE, LPPROCESSENTRY32);`
  - `BeaconPrintf` (function, line 86) `BeaconPrintf(CALLBACK_OUTPUT, "[*] Iniciando búsqueda de regiones RWX en procesos...\n");`
  - `pCloseHandleFn` (function, line 120) `pCloseHandleFn(snapshot);`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CreateToolhelp32Snapshot` (variable, line 28) `extern PVOID __imp_CreateToolhelp32Snapshot;`
  - `__imp_Process32First` (variable, line 29) `extern PVOID __imp_Process32First;`
  - `__imp_Process32Next` (variable, line 30) `extern PVOID __imp_Process32Next;`
  - `__imp_OpenProcess` (variable, line 31) `extern PVOID __imp_OpenProcess;`
  - `__imp_CloseHandle` (variable, line 32) `extern PVOID __imp_CloseHandle;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 19) `#define WIN32_LEAN_AND_MEAN`
- Depends on: `bof/test/beacon.h`

## bof/test/shellcode.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 25) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 34) `BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc falló\n");`
  - `__imp_VirtualAlloc` (variable, line 22) `extern PVOID __imp_VirtualAlloc;`
  - `__imp_RtlCopyMemory` (variable, line 24) `extern PVOID __imp_RtlCopyMemory;`
- Depends on: `bof/test/beacon.h`

## bof/test/sock5.c
- Layer: testing
- Doc: define WIN32_LEAN_AND_MEAN include <windows.h> include "beacon.h"  ===== DECLARACIONES QUE FALTABAN =====
- Language: c
- Symbols:
  - `WSAData` (struct, line 16)
  - `fd_set` (struct, line 27)
  - `timeval` (struct, line 32)
  - `in_addr` (struct, line 47)
  - `sockaddr_in` (struct, line 49)
  - `sockaddr` (struct, line 56)
  - `hostent` (struct, line 58)
  - `SOCKET` (type_alias, line 6) `typedef unsigned __int64 SOCKET;`
  - `wVersion` (type_alias, line 16) `typedef struct WSAData { WORD wVersion;`
  - `fd_count` (type_alias, line 26) `typedef struct fd_set { unsigned int fd_count;`
  - `tv_sec` (type_alias, line 31) `typedef struct timeval { long tv_sec;`
  - `u_short` (type_alias, line 42) `typedef unsigned short u_short;`
  - `u_int` (type_alias, line 44) `typedef unsigned int u_int;`
  - `u_long` (type_alias, line 45) `typedef unsigned long u_long;`
  - `my_FD_ISSET` (function, line 107) `static int my_FD_ISSET(SOCKET s, fd_set *set)`
  - `HandleSocks5Connection` (function, line 118) `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...`
  - `ProxyThread` (function, line 261) `DWORD WINAPI ProxyThread(LPVOID _)`
  - `go` (function, line 358) `void go(char *args, int alen)`
  - `HMODULE` (function, line 81) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
  - `FARPROC` (function, line 82) `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);`
  - `LPVOID` (function, line 83) `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);`
  - `BOOL` (function, line 84) `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);`
  - `HANDLE` (function, line 85) `typedef HANDLE (WINAPI *CREATE_EVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);`
  - `DWORD` (function, line 86) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
  - `int` (function, line 90) `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);`
  - `SOCKET` (function, line 91) `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);`
  - `ULONG` (function, line 102) `typedef ULONG (WINAPI *HTONL)(ULONG);`
  - `USHORT` (function, line 103) `typedef USHORT (WINAPI *HTONS)(USHORT);`
  - `pSend` (function, line 139) `pSend(client_sock, rep, 10, 0);`
  - `BeaconPrintf` (function, line 194) `BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló conexión al destino. WSAError: %d\n", err);`
  - `pCloseSocket` (function, line 197) `pCloseSocket(tgt);`
  - `FD_ZERO` (function, line 218) `FD_ZERO(&read_fds);`
  - `FD_SET` (function, line 219) `FD_SET(client_sock, &read_fds);`
  - `pWSACleanup` (function, line 347) `cleanup_wsa: pWSACleanup();`
  - `pCloseHandle` (function, line 389) `pCloseHandle(g_hShutdownEvent);`
  - `pWaitForSingleObject` (function, line 395) `pWaitForSingleObject(g_hShutdownEvent, INFINITE);`
  - `__imp_LoadLibraryA` (variable, line 68) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 69) `extern PVOID __imp_GetProcAddress;`
  - `__imp_VirtualAlloc` (variable, line 70) `extern PVOID __imp_VirtualAlloc;`
  - `__imp_VirtualFree` (variable, line 71) `extern PVOID __imp_VirtualFree;`
  - `__imp_CloseHandle` (variable, line 72) `extern PVOID __imp_CloseHandle;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 1) `#define WIN32_LEAN_AND_MEAN`
  - `INVALID_SOCKET` (macro, line 7) `#define INVALID_SOCKET`
  - `SOCKET_ERROR` (macro, line 8) `#define SOCKET_ERROR`
  - `AF_INET` (macro, line 9) `#define AF_INET`
  - `SOCK_STREAM` (macro, line 10) `#define SOCK_STREAM`
  - `IPPROTO_TCP` (macro, line 11) `#define IPPROTO_TCP`
  - `INADDR_ANY` (macro, line 12) `#define INADDR_ANY`
  - `INADDR_LOOPBACK` (macro, line 13) `#define INADDR_LOOPBACK`
  - `FD_SETSIZE` (macro, line 36) `#define FD_SETSIZE`
  - `FD_CLR` (macro, line 38) `#define FD_CLR(fd,set)`
  - `FD_SET` (macro, line 39) `#define FD_SET(fd,set)`
  - `FD_ZERO` (macro, line 40) `#define FD_ZERO(set)`
  - `FD_ISSET` (macro, line 41) `#define FD_ISSET(fd,set)`
  - `h_addr` (macro, line 64) `#define h_addr`
  - `SOCKS5_LISTEN_PORT` (macro, line 75) `#define SOCKS5_LISTEN_PORT`
  - `SOCKS5_CONTROL_PORT` (macro, line 76) `#define SOCKS5_CONTROL_PORT`
  - `MAX_PENDING_CONNECTIONS` (macro, line 77) `#define MAX_PENDING_CONNECTIONS`
  - `BUFFER_SIZE` (macro, line 78) `#define BUFFER_SIZE`
- Depends on: `bof/test/beacon.h`

## bof/test/tel.py
- Layer: testing
- Language: py
- Symbols:
  - `get_machine_id` (function, line 8) `def get_machine_id()`
  - `get_version` (function, line 20) `def get_version()`
  - `to_numbers` (function, line 31) `def to_numbers(hex_str)`
  - `to_hex` (function, line 35) `def to_hex(byte_list)`
  - `decrypt_cookie` (function, line 39) `def decrypt_cookie(encrypted, key, iv)`
  - `main` (function, line 45) `def main()`

## bof/test/uacbypass.c
- Layer: testing
- Language: c
- Symbols:
  - `execute_hidden_cmd` (function, line 33) `void execute_hidden_cmd(char* cmd)`
  - `go` (function, line 61) `void go(char *args, int alen)`
  - `BOOL` (function, line 36) `typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);`
  - `DWORD` (function, line 48) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
  - `pWaitForSingleObject` (function, line 51) `pWaitForSingleObject(pi.hProcess, 10000);`
  - `BeaconPrintf` (function, line 62) `BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Iniciando bypass UAC via SilentCleanup (fodhelper/CMSTP)...\n");`
  - `int` (function, line 79) `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);`
  - `pwsprintfA` (function, line 85) `pwsprintfA(inf_path, "%s\\uac_bypass.inf", temp_path);`
  - `HANDLE` (function, line 89) `typedef HANDLE (WINAPI *CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);`
  - `pWriteFile` (function, line 114) `pWriteFile(hFile, inf_content, strlen(inf_content), &written, NULL);`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
- Depends on: `bof/test/beacon.h`

## bof/test/upload.c
- Layer: testing
- Doc: define WIN32_LEAN_AND_MEAN include <windows.h> include "beacon.h"  ================================ IMPORTS DIRECTOS ===
- Language: c
- Symbols:
  - `AES_ctx` (struct, line 46)
  - `uint8_t` (type_alias, line 14) `typedef unsigned char uint8_t;`
  - `uint32_t` (type_alias, line 15) `typedef unsigned int uint32_t;`
  - `HINTERNET` (type_alias, line 16) `typedef void* HINTERNET;`
  - `INTERNET_PORT` (type_alias, line 17) `typedef WORD INTERNET_PORT;`
  - `HCRYPTPROV` (type_alias, line 18) `typedef ULONG_PTR HCRYPTPROV;`
  - `my_strlen` (function, line 53) `static int my_strlen(const char *s)`
  - `my_memcpy` (function, line 58) `static void* my_memcpy(void* dst, const void* src, size_t len)`
  - `my_memset` (function, line 65) `static void* my_memset(void* dst, int val, size_t len)`
  - `my_contains_dotdot` (function, line 71) `static BOOL my_contains_dotdot(const char* path)`
  - `my_strchr` (function, line 80) `static char* my_strchr(const char *s, int c)`
  - `xtime` (function, line 93) `static uint8_t xtime(uint8_t x)`
  - `AddRoundKey` (function, line 98) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
  - `SubBytes` (function, line 105) `static void SubBytes(state_t* state, const uint8_t* sbox)`
  - `ShiftRows` (function, line 112) `static void ShiftRows(state_t* state)`
  - `MixColumns` (function, line 120) `static void MixColumns(state_t* state)`
  - `Cipher` (function, line 132) `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
  - `KeyExpansion` (function, line 145) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
  - `AES_init_ctx` (function, line 173) `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
  - `AES_CFB_encrypt_buffer` (function, line 177) `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
  - `my_base64_encode` (function, line 205) `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...`
  - `ParseUploadArgs` (function, line 230) `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
  - `go` (function, line 273) `void go(char *args, int alen)`
  - `NEXT_TOKEN` (function, line 252) `NEXT_TOKEN(local_path, 128);`
  - `BeaconPrintf` (function, line 302) `BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de loader\n");`
  - `LPVOID` (function, line 314) `typedef LPVOID (WINAPI *t_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);`
  - `BOOL` (function, line 316) `typedef BOOL (WINAPI *t_VirtualFree)(LPVOID, SIZE_T, DWORD);`
  - `HANDLE` (function, line 354) `typedef HANDLE (WINAPI *t_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);`
  - `int` (function, line 358) `typedef int (WINAPI *t_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);`
  - `HINTERNET` (function, line 376) `typedef HINTERNET (WINAPI *t_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);`
  - `pCloseHandle` (function, line 422) `pCloseHandle(hFile);`
  - `pVirtualFree` (function, line 438) `pVirtualFree(fileBuffer, 0, MEM_RELEASE);`
  - `pMultiByteToWideChar` (function, line 489) `pMultiByteToWideChar(CP_UTF8, 0, host, -1, w_host, host_len);`
  - `pWinHttpCloseHandle` (function, line 516) `pWinHttpCloseHandle(hSession);`
  - `__imp_LoadLibraryA` (variable, line 8) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 9) `extern PVOID __imp_GetProcAddress;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 1) `#define WIN32_LEAN_AND_MEAN`
  - `PROV_RSA_AES` (macro, line 20) `#define PROV_RSA_AES`
  - `CRYPT_VERIFYCONTEXT` (macro, line 21) `#define CRYPT_VERIFYCONTEXT`
  - `AES_BLOCKLEN` (macro, line 22) `#define AES_BLOCKLEN`
  - `AES256_KEYLEN` (macro, line 24) `#define AES256_KEYLEN`
  - `Nr` (macro, line 25) `#define Nr`
  - `Nk` (macro, line 26) `#define Nk`
  - `Nb` (macro, line 27) `#define Nb`
  - `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (macro, line 28) `#define SECURITY_FLAG_IGNORE_UNKNOWN_CA`
  - `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` (macro, line 30) `#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID`
  - `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` (macro, line 31) `#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID`
  - `WINHTTP_OPTION_SECURITY_FLAGS` (macro, line 32) `#define WINHTTP_OPTION_SECURITY_FLAGS`
  - `WINHTTP_ACCESS_TYPE_NO_PROXY` (macro, line 35) `#define WINHTTP_ACCESS_TYPE_NO_PROXY`
  - `WINHTTP_NO_PROXY_NAME` (macro, line 39) `#define WINHTTP_NO_PROXY_NAME`
  - `WINHTTP_NO_PROXY_BYPASS` (macro, line 43) `#define WINHTTP_NO_PROXY_BYPASS`
  - `NEXT_TOKEN` (macro, line 244) `#define NEXT_TOKEN(dst,lim)`
- Depends on: `bof/test/beacon.h`

## bof/test/vncrelay.c
- Layer: testing
- Language: c
- Symbols:
  - `my_FD_ISSET` (function, line 62) `int my_FD_ISSET(SOCKET sock, fd_set *set)`
  - `relay_traffic` (function, line 75) `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)`
  - `go` (function, line 132) `void go(char *args, int alen)`
  - `HMODULE` (function, line 36) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
  - `FARPROC` (function, line 37) `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);`
  - `LPVOID` (function, line 38) `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);`
  - `BOOL` (function, line 39) `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);`
  - `int` (function, line 44) `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);`
  - `SOCKET` (function, line 45) `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);`
  - `ULONG` (function, line 56) `typedef ULONG (WINAPI *HTONL)(ULONG);`
  - `USHORT` (function, line 57) `typedef USHORT (WINAPI *HTONS)(USHORT);`
  - `FD_ZERO` (function, line 96) `FD_ZERO(&read_fds);`
  - `FD_SET` (function, line 97) `FD_SET(client_sock, &read_fds);`
  - `BeaconPrintf` (function, line 133) `BeaconPrintf(CALLBACK_OUTPUT, "[VNC RELAY] Iniciando relay en 0.0.0.0:5901 → 127.0.0.1:5900\n");`
  - `pCloseSocket` (function, line 185) `pCloseSocket(listen_sock);`
  - `__imp_LoadLibraryA` (variable, line 27) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 28) `extern PVOID __imp_GetProcAddress;`
  - `__imp_VirtualAlloc` (variable, line 29) `extern PVOID __imp_VirtualAlloc;`
  - `__imp_VirtualFree` (variable, line 30) `extern PVOID __imp_VirtualFree;`
  - `__imp_CloseHandle` (variable, line 31) `extern PVOID __imp_CloseHandle;`
- Depends on: `bof/test/beacon.h`

## bof/test/winver.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 24) `void go(char *args, int alen)`
  - `BeaconPrintf` (function, line 30) `BeaconPrintf(CALLBACK_ERROR, "GetVersionExA falló\n");`
  - `__imp_GetVersionExA` (variable, line 22) `extern PVOID __imp_GetVersionExA;`
- Depends on: `bof/test/beacon.h`
