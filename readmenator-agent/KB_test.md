# Subsystem: test

## bof/test/Test.c
- Layer: testing
- Doc: include "beacon.h"
- Language: c
- Symbols:
  - `go` (function, line 2) `void go(char *args, int alen)`

## bof/test/amsibypass.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 34) `void go(char *args, int alen)`

## bof/test/beacon.h
- Layer: testing
- Language: h
- Symbols:
  - `BEACON_H` (macro, line 21)
  - `CALLBACK_OUTPUT` (macro, line 40)
  - `CALLBACK_ERROR` (macro, line 42)

## bof/test/cmdwhoami.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 42) `void go(char *args, int alen)`

## bof/test/disablelog.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `my_wcscmp` (function, line 36) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)`
  - `go` (function, line 68) `void go(char *args, int alen)`
  - `WIN32_LEAN_AND_MEAN` (macro, line 20)
  - `NT_SUCCESS` (macro, line 34)

## bof/test/getenv.c
- Layer: infrastructure
- Language: c
- Symbols:
  - `go` (function, line 24) `void go(char *args, int alen)`

## bof/test/loadvnc.c
- Layer: testing
- Language: c
- Symbols:
  - `_PROCESSENTRY32` (struct, line 35)
  - `execute_cmd_hidden` (function, line 51) `void execute_cmd_hidden(char* cmd)`
  - `go` (function, line 81) `void go(char *args, int alen)`
  - `TH32CS_SNAPPROCESS` (macro, line 33)

## bof/test/make_table.c
- Layer: testing
- Language: c
- Symbols:
  - `Copyright` (function, line 16) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
  - `main` (function, line 33) `void main()`

## bof/test/persist.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 26) `void go(char *args, int alen)`

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
  - `WIN32_LEAN_AND_MEAN` (macro, line 19)
  - `RESOLVE_API` (macro, line 65)
  - `cleanup` (macro, line 131)
  - `cleanup` (macro, line 183)

## bof/test/scan_shellcode.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 84) `void go(char *args, int alen)`
  - `WIN32_LEAN_AND_MEAN` (macro, line 19)

## bof/test/shellcode.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 25) `void go(char *args, int alen)`

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
  - `my_FD_ISSET` (function, line 107) `static int my_FD_ISSET(SOCKET s, fd_set *set)`
  - `HandleSocks5Connection` (function, line 118) `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...`
  - `ProxyThread` (function, line 261) `DWORD WINAPI ProxyThread(LPVOID _)`
  - `go` (function, line 358) `void go(char *args, int alen)`
  - `WIN32_LEAN_AND_MEAN` (macro, line 1)
  - `INVALID_SOCKET` (macro, line 7)
  - `SOCKET_ERROR` (macro, line 8)
  - `AF_INET` (macro, line 9)
  - `SOCK_STREAM` (macro, line 10)
  - `IPPROTO_TCP` (macro, line 11)
  - `INADDR_ANY` (macro, line 12)
  - `INADDR_LOOPBACK` (macro, line 13)
  - `FD_SETSIZE` (macro, line 36)
  - `FD_CLR` (macro, line 38)
  - `FD_SET` (macro, line 39)
  - `FD_ZERO` (macro, line 40)
  - `FD_ISSET` (macro, line 41)
  - `h_addr` (macro, line 64)
  - `SOCKS5_LISTEN_PORT` (macro, line 75)
  - `SOCKS5_CONTROL_PORT` (macro, line 76)
  - `MAX_PENDING_CONNECTIONS` (macro, line 77)
  - `BUFFER_SIZE` (macro, line 78)

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

## bof/test/upload.c
- Layer: testing
- Doc: define WIN32_LEAN_AND_MEAN include <windows.h> include "beacon.h"  ================================ IMPORTS DIRECTOS ===
- Language: c
- Symbols:
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
  - `WIN32_LEAN_AND_MEAN` (macro, line 1)
  - `PROV_RSA_AES` (macro, line 20)
  - `CRYPT_VERIFYCONTEXT` (macro, line 21)
  - `AES_BLOCKLEN` (macro, line 22)
  - `AES256_KEYLEN` (macro, line 24)
  - `Nr` (macro, line 25)
  - `Nk` (macro, line 26)
  - `Nb` (macro, line 27)
  - `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (macro, line 28)
  - `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` (macro, line 30)
  - `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` (macro, line 31)
  - `WINHTTP_OPTION_SECURITY_FLAGS` (macro, line 32)
  - `WINHTTP_ACCESS_TYPE_NO_PROXY` (macro, line 35)
  - `WINHTTP_NO_PROXY_NAME` (macro, line 39)
  - `WINHTTP_NO_PROXY_BYPASS` (macro, line 43)
  - `NEXT_TOKEN` (macro, line 244)

## bof/test/vncrelay.c
- Layer: testing
- Language: c
- Symbols:
  - `my_FD_ISSET` (function, line 62) `int my_FD_ISSET(SOCKET sock, fd_set *set)`
  - `relay_traffic` (function, line 75) `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)`
  - `go` (function, line 132) `void go(char *args, int alen)`

## bof/test/winver.c
- Layer: testing
- Language: c
- Symbols:
  - `go` (function, line 24) `void go(char *args, int alen)`
