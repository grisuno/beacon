# Subsystem: test

## bof/test/Test.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 3) `void go(char *args, int alen)`
- Depends on: `bof/test/beacon.h`

## bof/test/amsibypass.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 34) `void go(char *args, int alen)`
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
  - `CALLBACK_OUTPUT` (macro, line 41) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 42) `#define CALLBACK_ERROR`
- Imported by: `bof/test/Test.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c`, `bof/test/disablelog.c`, `bof/test/getenv.c`, `bof/test/loadvnc.c`, `bof/test/persist.c`, `bof/test/persistsvc.c`, `bof/test/scan_shellcode.c`, `bof/test/shellcode.c`, `bof/test/sock5.c`, `bof/test/uacbypass.c`, `bof/test/upload.c`, `bof/test/vncrelay.c`, `bof/test/winver.c`

## bof/test/cmdwhoami.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 43) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
- Depends on: `bof/test/beacon.h`

## bof/test/disablelog.c
- Layer: testing
- Language: c
- Symbols:
  - `my_wcscmp` (function, line 37) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)`
  - `go` (function, line 69) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 27) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 28) `extern PVOID __imp_GetProcAddress;`
  - `__imp_GetModuleHandleA` (variable, line 29) `extern PVOID __imp_GetModuleHandleA;`
  - `__imp_CloseHandle` (variable, line 30) `extern PVOID __imp_CloseHandle;`
  - `__imp_OpenProcess` (variable, line 31) `extern PVOID __imp_OpenProcess;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 20) `#define WIN32_LEAN_AND_MEAN`
  - `NT_SUCCESS` (macro, line 34) `#define NT_SUCCESS(x)`
- Depends on: `bof/test/beacon.h`

## bof/test/getenv.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 25) `void go(char *args, int alen)`
  - `__imp_GetEnvironmentVariableA` (variable, line 23) `extern PVOID __imp_GetEnvironmentVariableA;`
- Depends on: `bof/test/beacon.h`

## bof/test/loadvnc.c
- Layer: testing
- Language: c
- Symbols:
  - `_PROCESSENTRY32` (struct, line 35)
  - `dwSize` (type_alias, line 34) `typedef struct _PROCESSENTRY32 { DWORD dwSize;`
  - `execute_cmd_hidden` (function, line 51) `void execute_cmd_hidden(char* cmd)`
  - `go` (function, line 81) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
  - `TH32CS_SNAPPROCESS` (macro, line 33) `#define TH32CS_SNAPPROCESS`
- Depends on: `bof/test/beacon.h`

## bof/test/make_table.c
- Layer: testing
- Language: c
- Symbols:
  - `Copyright` (function, line 17) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
  - `main` (function, line 34) `void main()`

## bof/test/persist.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 27) `void go(char *args, int alen)`
  - `__imp_RegOpenKeyExA` (variable, line 23) `extern PVOID __imp_RegOpenKeyExA;`
  - `__imp_RegSetValueExA` (variable, line 24) `extern PVOID __imp_RegSetValueExA;`
  - `__imp_RegCloseKey` (variable, line 25) `extern PVOID __imp_RegCloseKey;`
- Depends on: `bof/test/beacon.h`

## bof/test/persistsvc.c
- Layer: testing
- Language: c
- Symbols:
  - `my_memcpy` (function, line 33) `static void* my_memcpy(void* dst, const void* src, size_t len)`
  - `my_strlen` (function, line 40) `static int my_strlen(const char* str)`
  - `my_strcat` (function, line 47) `static char* my_strcat(char* dest, const char* src)`
  - `my_strcmp` (function, line 55) `static int my_strcmp(const char* s1, const char* s2)`
  - `ServiceHandler` (function, line 82) `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...`
  - `ServiceMain` (function, line 116) `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)`
  - `go` (function, line 251) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 27) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 28) `extern PVOID __imp_GetProcAddress;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 20) `#define WIN32_LEAN_AND_MEAN`
  - `RESOLVE_API` (macro, line 65) `#define RESOLVE_API(lib, name, type)`
  - `cleanup` (macro, line 131) `#define cleanup`
  - `cleanup` (macro, line 183) `#define cleanup`
- Depends on: `bof/test/beacon.h`

## bof/test/scan_shellcode.c
- Doc: __imp_LoadLibraryA: Símbolos
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 85) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CreateToolhelp32Snapshot` (variable, line 28) `extern PVOID __imp_CreateToolhelp32Snapshot;`
  - `__imp_Process32First` (variable, line 29) `extern PVOID __imp_Process32First;`
  - `__imp_Process32Next` (variable, line 30) `extern PVOID __imp_Process32Next;`
  - `__imp_OpenProcess` (variable, line 31) `extern PVOID __imp_OpenProcess;`
  - `__imp_CloseHandle` (variable, line 32) `extern PVOID __imp_CloseHandle;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 20) `#define WIN32_LEAN_AND_MEAN`
- Depends on: `bof/test/beacon.h`

## bof/test/shellcode.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 26) `void go(char *args, int alen)`
  - `__imp_VirtualAlloc` (variable, line 23) `extern PVOID __imp_VirtualAlloc;`
  - `__imp_RtlCopyMemory` (variable, line 24) `extern PVOID __imp_RtlCopyMemory;`
- Depends on: `bof/test/beacon.h`

## bof/test/sock5.c
- Doc: WSAData: pragma pack(push,1)
- Layer: testing
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
  - `FD_SETSIZE` (macro, line 37) `#define FD_SETSIZE`
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
- Doc: to_numbers: Simula la función toNumbers de JavaScript
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
  - `__imp_LoadLibraryA` (variable, line 26) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern PVOID __imp_GetProcAddress;`
  - `__imp_CloseHandle` (variable, line 28) `extern PVOID __imp_CloseHandle;`
- Depends on: `bof/test/beacon.h`

## bof/test/upload.c
- Layer: testing
- Language: c
- Symbols:
  - `AES_ctx` (struct, line 46)
  - `uint8_t` (type_alias, line 14) `typedef unsigned char uint8_t;`
  - `uint32_t` (type_alias, line 15) `typedef unsigned int uint32_t;`
  - `HINTERNET` (type_alias, line 16) `typedef void* HINTERNET;`
  - `INTERNET_PORT` (type_alias, line 17) `typedef WORD INTERNET_PORT;`
  - `HCRYPTPROV` (type_alias, line 18) `typedef ULONG_PTR HCRYPTPROV;`
  - `my_strlen` (function, line 53) `static int my_strlen(const char *s)`
  - `my_memcpy` (function, line 59) `static void* my_memcpy(void* dst, const void* src, size_t len)`
  - `my_memset` (function, line 66) `static void* my_memset(void* dst, int val, size_t len)`
  - `my_contains_dotdot` (function, line 72) `static BOOL my_contains_dotdot(const char* path)`
  - `my_strchr` (function, line 81) `static char* my_strchr(const char *s, int c)`
  - `xtime` (function, line 93) `static uint8_t xtime(uint8_t x)`
  - `AddRoundKey` (function, line 99) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
  - `SubBytes` (function, line 106) `static void SubBytes(state_t* state, const uint8_t* sbox)`
  - `ShiftRows` (function, line 113) `static void ShiftRows(state_t* state)`
  - `MixColumns` (function, line 121) `static void MixColumns(state_t* state)`
  - `Cipher` (function, line 133) `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
  - `KeyExpansion` (function, line 146) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
  - `AES_init_ctx` (function, line 174) `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
  - `AES_CFB_encrypt_buffer` (function, line 178) `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
  - `my_base64_encode` (function, line 205) `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...`
  - `ParseUploadArgs` (function, line 231) `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
  - `go` (function, line 273) `void go(char *args, int alen)`
  - `__imp_LoadLibraryA` (variable, line 8) `extern PVOID __imp_LoadLibraryA;`
  - `__imp_GetProcAddress` (variable, line 9) `extern PVOID __imp_GetProcAddress;`
  - `WIN32_LEAN_AND_MEAN` (macro, line 1) `#define WIN32_LEAN_AND_MEAN`
  - `PROV_RSA_AES` (macro, line 20) `#define PROV_RSA_AES`
  - `CRYPT_VERIFYCONTEXT` (macro, line 21) `#define CRYPT_VERIFYCONTEXT`
  - `AES_BLOCKLEN` (macro, line 23) `#define AES_BLOCKLEN`
  - `AES256_KEYLEN` (macro, line 24) `#define AES256_KEYLEN`
  - `Nr` (macro, line 25) `#define Nr`
  - `Nk` (macro, line 26) `#define Nk`
  - `Nb` (macro, line 27) `#define Nb`
  - `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (macro, line 29) `#define SECURITY_FLAG_IGNORE_UNKNOWN_CA`
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
  - `go` (function, line 25) `void go(char *args, int alen)`
  - `__imp_GetVersionExA` (variable, line 23) `extern PVOID __imp_GetVersionExA;`
- Depends on: `bof/test/beacon.h`
