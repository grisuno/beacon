# API

## COFFLoader3.c

### djb2_hash `static uint32_t djb2_hash(const char* str)`
- Defined: `COFFLoader3.c:632`
- Doc: === Función hash DJB2 ===

### create_trampoline `static void* create_trampoline(void* target)`
- Defined: `COFFLoader3.c:912`

### handle_relocation `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...`
- Defined: `COFFLoader3.c:940`

### get_symbol_name `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)`
- Defined: `COFFLoader3.c:1079`

### __attribute__ `__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2)`
- Defined: `COFFLoader3.c:1102`

### RunCOFF `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...`
- Defined: `COFFLoader3.c:1112`
- Doc: === Cargador COFF  ===

## aes.c

### getSBoxValue `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16

### getSBoxInvert `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:34`

### Td0 `static uint8_t Td0(int x)`
- Defined: `aes.c:56`

### Td1 `static uint8_t Td1(int x)`
- Defined: `aes.c:58`

### Td2 `static uint8_t Td2(int x)`
- Defined: `aes.c:59`

### Td3 `static uint8_t Td3(int x)`
- Defined: `aes.c:60`

### Td4 `static uint8_t Td4(int x)`
- Defined: `aes.c:61`

### KeyExpansion `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.

### AES_init_ctx `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `aes.c:238`

### AES_init_ctx_iv `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))

### AES_ctx_set_iv `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `aes.c:249`

### AddRoundKey `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.

### SubBytes `static void SubBytes(state_t* state)`
- Defined: `aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### ShiftRows `static void ShiftRows(state_t* state)`
- Defined: `aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R

### xtime `static uint8_t xtime(uint8_t x)`
- Defined: `aes.c:313`

### MixColumns `static void MixColumns(state_t* state)`
- Defined: `aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix

### Multiply `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 

### InvMixColumns `static void InvMixColumns(state_t* state)`
- Defined: `aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo

### InvSubBytes `static void InvSubBytes(state_t* state)`
- Defined: `aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.

### InvShiftRows `static void InvShiftRows(state_t* state)`
- Defined: `aes.c:402`

### Cipher `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.

### InvCipher `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

### AES_ECB_encrypt `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&

### AES_ECB_decrypt `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:495`

### XorWithIv `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)

### AES_CBC_encrypt_buffer `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:520`

### AES_CBC_decrypt_buffer `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:535`

### AES_CTR_xcrypt_buffer `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)

## beacon.c

### ExceptionFilter `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)`
- Defined: `beacon.c:253`

### get_shell_cmd `const char* get_shell_cmd()`
- Defined: `beacon.c:334`

### __declspec `__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)`
- Defined: `beacon.c:416`
- Doc: === Beacon API: implementaciones exportables para BOFs ===

### __declspec `__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)`
- Defined: `beacon.c:422`

### __declspec `__declspec(dllexport) int BeaconDataInt(datap * parser)`
- Defined: `beacon.c:430`

### __declspec `__declspec(dllexport) short BeaconDataShort(datap * parser)`
- Defined: `beacon.c:435`

### __declspec `__declspec(dllexport) int BeaconDataLength(datap * parser)`
- Defined: `beacon.c:440`

### __declspec `__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)`
- Defined: `beacon.c:445`

### __declspec `__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)`
- Defined: `beacon.c:455`

### __declspec `__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)`
- Defined: `beacon.c:503`

### MapDllNameToModule `HMODULE MapDllNameToModule(char* dllName)`
- Defined: `beacon.c:521`
- Doc: === MAP DLL NAME TO REAL DLL ===

### GetSyscallNumber `DWORD GetSyscallNumber(PVOID func_addr)`
- Defined: `beacon.c:548`

### HellsGate `DWORD HellsGate(DWORD ssn)`
- Defined: `beacon.c:560`

### __attribute__ `__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DW...`
- Defined: `beacon.c:565`

### GetProcessIdByName `DWORD GetProcessIdByName(const char* processName)`
- Defined: `beacon.c:581`

### ExecuteTLSCallbacks `void ExecuteTLSCallbacks(PVOID moduleBase)`
- Defined: `beacon.c:600`
- Doc: === EJECUTAR TLS CALLBACKS ===

### MapModuleToMemory `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)`
- Defined: `beacon.c:617`
- Doc: === Carga un módulo en memoria ===

### ExecuteModule `BOOL ExecuteModule(PVOID moduleBase)`
- Defined: `beacon.c:706`
- Doc: === Ejecuta el módulo (DllMain o EntryPoint) ===

### LoadModuleFromURL `BOOL LoadModuleFromURL(const char* url)`
- Defined: `beacon.c:751`
- Doc: === Carga y ejecuta un módulo desde URL ===

### xor_string `void xor_string(char* data, size_t len, char key)`
- Defined: `beacon.c:915`
- Doc: === XOR ===

### anti_analysis `BOOL anti_analysis()`
- Defined: `beacon.c:922`
- Doc: === ANTI-ANALYSIS ===

### load_lazyconf `BOOL load_lazyconf()`
- Defined: `beacon.c:945`

### GetNtdllBase `HMODULE GetNtdllBase()`
- Defined: `beacon.c:1183`

### isVMByMAC `BOOL isVMByMAC()`
- Defined: `beacon.c:1231`

### extract_shellcode `int extract_shellcode(const char* input, size_t len, unsigned char** out)`
- Defined: `beacon.c:1303`
- Doc: === EXTRAER SHELLCODE ===

### hex_char_to_byte `BYTE hex_char_to_byte(char c)`
- Defined: `beacon.c:1334`
- Doc: Función para convertir hex a bytes

### hex_to_bytes `void hex_to_bytes(const char* hex, BYTE* output, size_t len)`
- Defined: `beacon.c:1340`

### executeLoader `void executeLoader(void *arg)`
- Defined: `beacon.c:1348`
- Doc: === executeLoader ===

### ReverseShell `void __cdecl ReverseShell(void* arg)`
- Defined: `beacon.c:1404`
- Doc: ======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================

### ReadFromProcess `DWORD WINAPI ReadFromProcess(LPVOID lpParam)`
- Defined: `beacon.c:1513`
- Doc: === Hilo para leer salida del proceso (como en el ejemplo que funciona) ===

### GetJitteredSleep `DWORD GetJitteredSleep(DWORD base_ms)`
- Defined: `beacon.c:1586`

### GetUsefulSoftware `char* GetUsefulSoftware()`
- Defined: `beacon.c:1591`

### base64_encode `char* base64_encode(const unsigned char* data, size_t inputLen)`
- Defined: `beacon.c:1626`

### base64_decode `char* base64_decode(const char* input, size_t* out_len)`
- Defined: `beacon.c:1662`

### discoverLocalHosts `void discoverLocalHosts()`
- Defined: `beacon.c:1695`

### initProxy `void initProxy()`
- Defined: `beacon.c:1752`
- Doc: startProxy.c

### relay_thread `void WINAPI relay_thread(void* param)`
- Defined: `beacon.c:1763`
- Doc: Función para reenviar datos entre sockets

### proxy_thread `void WINAPI proxy_thread(void* param)`
- Defined: `beacon.c:1784`
- Doc: Tu función proxy_thread usando tus estructuras exactas

### proxy_accept_thread `void WINAPI proxy_accept_thread(void* param)`
- Defined: `beacon.c:1855`
- Doc: Thread para aceptar conexiones

### startProxy `BOOL startProxy(const char* listenAddr, const char* targetAddr)`
- Defined: `beacon.c:1922`

### stopProxy `BOOL stopProxy(const char* listenAddr)`
- Defined: `beacon.c:2009`

### cleanupProxy `void cleanupProxy()`
- Defined: `beacon.c:2061`

### compressDirectory `BOOL compressDirectory(const char* dirPath)`
- Defined: `beacon.c:2094`
- Doc: Función simplificada para compresión de directorios

### getNetworkConfig `char* getNetworkConfig()`
- Defined: `beacon.c:2104`
- Doc: Para netconfig

### UploadFileToC2 `BOOL UploadFileToC2(const char* url, const char* filePath)`
- Defined: `beacon.c:2107`

### handleUpload `BOOL handleUpload(const char* command)`
- Defined: `beacon.c:2280`
- Doc: === handleUpload: envía del beacon al C2 ===

### FileExistsA `BOOL FileExistsA(const char* filePath)`
- Defined: `beacon.c:2301`
- Doc: Función para verificar si un archivo existe

### selfDestruct `void selfDestruct()`
- Defined: `beacon.c:2306`
- Doc: selfdestruct.c

### stristr `char* stristr(const char* str, const char* pattern)`
- Defined: `beacon.c:2361`

### isSensitiveFile `int isSensitiveFile(const char* filename)`
- Defined: `beacon.c:2378`

### searchCredentials `char* searchCredentials(const char* basePath)`
- Defined: `beacon.c:2424`

### UTF8ToWide `WCHAR* UTF8ToWide(const char* utf8)`
- Defined: `beacon.c:2551`
- Doc: Convierte UTF-8 a wide string

### obfuscateFileTimestamp `BOOL obfuscateFileTimestamp(const char* filepath)`
- Defined: `beacon.c:2562`
- Doc: Ofusca los timestamps de un archivo

### obfuscateFileTimestamps `void obfuscateFileTimestamps(const char* basePath, int depth)`
- Defined: `beacon.c:2592`
- Doc: Recorre directorios buscando archivos sensibles

### simulateLegitimateTraffic `void simulateLegitimateTraffic(void* param)`
- Defined: `beacon.c:2656`
- Doc: traffic.c

### restartClient `void restartClient()`
- Defined: `beacon.c:2734`

### checkDebuggers `BOOL checkDebuggers()`
- Defined: `beacon.c:2776`

### MapPEToMemory `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)`
- Defined: `beacon.c:2837`

### downloadAndExecute `BOOL downloadAndExecute(const char* url, const char* targetProcess)`
- Defined: `beacon.c:2860`

### DecryptPacket `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)`
- Defined: `beacon.c:2910`

### GetIPs `char* GetIPs()`
- Defined: `beacon.c:3006`

### GetHostname `char* GetHostname()`
- Defined: `beacon.c:3039`

### GetUsername `char* GetUsername()`
- Defined: `beacon.c:3056`

### patchAMSI `BOOL patchAMSI(void)`
- Defined: `beacon.c:3072`

### get_nt_headers `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)`
- Defined: `beacon.c:3092`
- Doc: ==================================================================== PE HELPERS (usando winnt.h) =======================

### is_64bit `BOOL is_64bit(BYTE* buffer)`
- Defined: `beacon.c:3100`

### get_image_size `DWORD get_image_size(BYTE* buffer)`
- Defined: `beacon.c:3106`

### get_entry_point_rva `DWORD get_entry_point_rva(BYTE* buffer)`
- Defined: `beacon.c:3112`

### pe_buffer_to_virtual_image `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- Defined: `beacon.c:3117`

### create_suspended_process `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
- Defined: `beacon.c:3148`
- Doc: ==================================================================== PROCESS MANIPULATION ==============================

### get_remote_image_base `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- Defined: `beacon.c:3154`

### update_remote_entry_point `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)`
- Defined: `beacon.c:3249`

### overWrite `void overWrite(const char* targetPath, const char* payloadPath)`
- Defined: `beacon.c:3277`
- Doc: ==================================================================== MAIN FUNCTION: overWrite ==========================

### cleanSystemLogs `void cleanSystemLogs()`
- Defined: `beacon.c:3384`
- Doc: Limpia el historial de comandos de la consola actual

### ensurePersistence `BOOL ensurePersistence()`
- Defined: `beacon.c:3421`
- Doc: ensurePersistence.c

### isSandboxEnvironment `BOOL isSandboxEnvironment()`
- Defined: `beacon.c:3482`
- Doc: isSandboxEnvironment.c

### tryPrivilegeEscalation `void tryPrivilegeEscalation()`
- Defined: `beacon.c:3551`

### executeUACBypass `BOOL executeUACBypass(const char* payloadPath)`
- Defined: `beacon.c:3556`

### scanPort `void scanPort(void* arg)`
- Defined: `beacon.c:3610`

### PortScanner `void PortScanner(char* targetIP, int* ports, int numPorts)`
- Defined: `beacon.c:3661`
- Doc: PortScanner.c

### PortScannerWrapper `void PortScannerWrapper(void* arg)`
- Defined: `beacon.c:3705`

### EarlyBirdInject `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)`
- Defined: `beacon.c:3729`
- Doc: === INYECCIÓN EARLY BIRD + SYSCALL ===

### init_aes_context `PacketEncryptionContext* init_aes_context(const char* key_hex)`
- Defined: `beacon.c:3898`

### retry_http_request `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)`
- Defined: `beacon.c:3918`
- Doc: retry_http_request.c

### exec_cmd `char* exec_cmd(const char* cmd)`
- Defined: `beacon.c:4172`
- Doc: exec_cmd.c

### GetC2Command `char* GetC2Command(const char* host, const char* path)`
- Defined: `beacon.c:4200`
- Doc: c2.c (reemplaza la función actual)

### DownloadToBuffer `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)`
- Defined: `beacon.c:4346`

### DownloadFromURL `BOOL DownloadFromURL(const char* url, const char* filepath)`
- Defined: `beacon.c:4422`

### encrypt_data `char* encrypt_data(const char* data)`
- Defined: `beacon.c:4452`

### isValidUUID `BOOL isValidUUID(const char* uuid)`
- Defined: `beacon.c:4511`

### deleteFilesDelay `void deleteFilesDelay(void* arg)`
- Defined: `beacon.c:4536`

### executeCommand `void executeCommand(void* cmdPtr)`
- Defined: `beacon.c:4550`

### handleAtomic `void handleAtomic(char* command)`
- Defined: `beacon.c:4559`

### handleDownload `BOOL handleDownload(const char* command)`
- Defined: `beacon.c:4683`
- Doc: === handleDownload: descarga del C2 al beacon ===

### SerializeBeaconString `void SerializeBeaconString(char* buffer, int* offset, const char* str)`
- Defined: `beacon.c:4702`

### BeaconDataSerializeString `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)`
- Defined: `beacon.c:4711`

### go `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)`
- Defined: `beacon.c:4719`

### handleAdversary `void handleAdversary(char* command)`
- Defined: `beacon.c:4738`
- Doc: Función principal de manejo de comandos

### main `int main()`
- Defined: `beacon.c:5233`
- Doc: main.c

## bof/calc/calc.c

### go `void go(char *args, int alen)`
- Defined: `bof/calc/calc.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## bof/etw/etw.c

### go `void go(char *a,int l)`
- Defined: `bof/etw/etw.c:26`

## bof/test/Test.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/Test.c:2`
- Doc: include "beacon.h"

## bof/test/amsibypass.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/amsibypass.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## bof/test/cmdwhoami.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/cmdwhoami.c:42`

## bof/test/disablelog.c

### my_wcscmp `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)`
- Defined: `bof/test/disablelog.c:36`
- Doc: ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif

### go `void go(char *args, int alen)`
- Defined: `bof/test/disablelog.c:68`

## bof/test/getenv.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/getenv.c:24`

## bof/test/loadvnc.c

### execute_cmd_hidden `void execute_cmd_hidden(char* cmd)`
- Defined: `bof/test/loadvnc.c:51`
- Doc: ================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================

### go `void go(char *args, int alen)`
- Defined: `bof/test/loadvnc.c:81`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## bof/test/make_table.c

### Copyright `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
- Defined: `bof/test/make_table.c:16`

### main `void main()`
- Defined: `bof/test/make_table.c:33`

## bof/test/persist.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/persist.c:26`

## bof/test/persistsvc.c

### my_memcpy `static void* my_memcpy(void* dst, const void* src, size_t len)`
- Defined: `bof/test/persistsvc.c:33`
- Doc: ================================ FUNCIONES AUXILIARES ================================

### my_strlen `static int my_strlen(const char* str)`
- Defined: `bof/test/persistsvc.c:39`

### my_strcat `static char* my_strcat(char* dest, const char* src)`
- Defined: `bof/test/persistsvc.c:46`

### my_strcmp `static int my_strcmp(const char* s1, const char* s2)`
- Defined: `bof/test/persistsvc.c:54`

### ServiceHandler `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...`
- Defined: `bof/test/persistsvc.c:82`
- Doc: ================================ MANEJADOR DE CONTROL DEL SERVICIO ================================

### ServiceMain `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)`
- Defined: `bof/test/persistsvc.c:116`
- Doc: ================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================

### go `void go(char *args, int alen)`
- Defined: `bof/test/persistsvc.c:251`
- Doc: ================================ FUNCIÓN PRINCIPAL DEL BOF ================================

## bof/test/scan_shellcode.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/scan_shellcode.c:84`

## bof/test/shellcode.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/shellcode.c:25`

## bof/test/sock5.c

### my_FD_ISSET `static int my_FD_ISSET(SOCKET s, fd_set *set)`
- Defined: `bof/test/sock5.c:107`
- Doc: typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typ

### HandleSocks5Connection `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...`
- Defined: `bof/test/sock5.c:118`
- Doc: typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if 

### ProxyThread `DWORD WINAPI ProxyThread(LPVOID _)`
- Defined: `bof/test/sock5.c:261`
- Doc: break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n

### go `void go(char *args, int alen)`
- Defined: `bof/test/sock5.c:358`
- Doc: cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HAND

## bof/test/tel.py

### get_machine_id `def get_machine_id()`
- Defined: `bof/test/tel.py:8`

### get_version `def get_version()`
- Defined: `bof/test/tel.py:20`

### to_numbers `def to_numbers(hex_str)`
- Defined: `bof/test/tel.py:31`
- Doc: Simula la función toNumbers de JavaScript

### to_hex `def to_hex(byte_list)`
- Defined: `bof/test/tel.py:35`
- Doc: Simula la función toHex de JavaScript

### decrypt_cookie `def decrypt_cookie(encrypted, key, iv)`
- Defined: `bof/test/tel.py:39`
- Doc: Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))

### main `def main()`
- Defined: `bof/test/tel.py:45`
- Doc: Sistema de telemetría de uso por instalación no invasiva.

## bof/test/uacbypass.c

### execute_hidden_cmd `void execute_hidden_cmd(char* cmd)`
- Defined: `bof/test/uacbypass.c:33`
- Doc: ================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================

### go `void go(char *args, int alen)`
- Defined: `bof/test/uacbypass.c:61`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## bof/test/upload.c

### my_strlen `static int my_strlen(const char *s)`
- Defined: `bof/test/upload.c:53`
- Doc: ================================ FUNCIONES AUXILIARES ================================

### my_memcpy `static void* my_memcpy(void* dst, const void* src, size_t len)`
- Defined: `bof/test/upload.c:58`

### my_memset `static void* my_memset(void* dst, int val, size_t len)`
- Defined: `bof/test/upload.c:65`

### my_contains_dotdot `static BOOL my_contains_dotdot(const char* path)`
- Defined: `bof/test/upload.c:71`

### my_strchr `static char* my_strchr(const char *s, int c)`
- Defined: `bof/test/upload.c:80`

### xtime `static uint8_t xtime(uint8_t x)`
- Defined: `bof/test/upload.c:93`
- Doc: ================================ AES (sin datos globales) ================================

### AddRoundKey `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `bof/test/upload.c:98`

### SubBytes `static void SubBytes(state_t* state, const uint8_t* sbox)`
- Defined: `bof/test/upload.c:105`

### ShiftRows `static void ShiftRows(state_t* state)`
- Defined: `bof/test/upload.c:112`

### MixColumns `static void MixColumns(state_t* state)`
- Defined: `bof/test/upload.c:120`

### Cipher `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
- Defined: `bof/test/upload.c:132`

### KeyExpansion `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
- Defined: `bof/test/upload.c:145`

### AES_init_ctx `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
- Defined: `bof/test/upload.c:173`

### AES_CFB_encrypt_buffer `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
- Defined: `bof/test/upload.c:177`

### my_base64_encode `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...`
- Defined: `bof/test/upload.c:205`
- Doc: ================================ BASE64 ================================

### ParseUploadArgs `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
- Defined: `bof/test/upload.c:230`

### go `void go(char *args, int alen)`
- Defined: `bof/test/upload.c:273`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## bof/test/vncrelay.c

### my_FD_ISSET `int my_FD_ISSET(SOCKET sock, fd_set *set)`
- Defined: `bof/test/vncrelay.c:62`
- Doc: ================================ FD_ISSET MANUAL ================================

### relay_traffic `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)`
- Defined: `bof/test/vncrelay.c:75`
- Doc: ================================ RELAY TRAFFIC ================================

### go `void go(char *args, int alen)`
- Defined: `bof/test/vncrelay.c:132`
- Doc: ================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================

## bof/test/winver.c

### go `void go(char *args, int alen)`
- Defined: `bof/test/winver.c:24`

## bof/whoami/whoami.c

### go `void go(char *args, int alen)`
- Defined: `bof/whoami/whoami.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================

## cJSON.c

### CJSON_PUBLIC `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:94`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:99`

### CJSON_PUBLIC `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:109`

### CJSON_PUBLIC `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 

### case_insensitive_strcmp `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)

### internal_malloc `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s

### internal_free `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `cJSON.c:170`

### internal_realloc `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `cJSON.c:174`

### cJSON_strdup `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `cJSON.c:188`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:209`

### cJSON_New_Item `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar

### get_decimal_point `static unsigned char get_decimal_point(void)`
- Defined: `cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate

### parse_number `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks

### ensure `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form

### update_offset `static void update_offset(printbuffer * const buffer)`
- Defined: `cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt

### compare_double `static cJSON_bool compare_double(double a, double b)`
- Defined: `cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *

### print_number `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely

### parse_hex4 `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of

### utf16_literal_to_utf8 `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX

### parse_string `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length

### print_string_ptr `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(

### print_string `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b

### buffer_skip_whitespace `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char

### skip_utf8_bom `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `cJSON.c:1133`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1235`

### print `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1315`

### CJSON_PUBLIC `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1351`

### parse_value `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =

### print_value `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input

### parse_array `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 

### print_array `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 

### parse_object `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_

### print_object `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object

### get_array_item `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `cJSON.c:1915`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1934`

### get_object_item `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1944`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1976`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1986`

### suffix_object `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co

### create_reference `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec

### add_item_to_array `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2020`

### cast_away_const `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_

### add_item_to_object `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2111`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2122`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2132`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2142`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2154`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2166`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2178`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2190`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2202`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2214`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2226`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2238`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2250`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2286`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2296`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2301`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2308`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2315`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2320`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2362`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2412`

### replace_item_in_object `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2422`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2445`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2450`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2467`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2478`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2489`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2500`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2525`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2542`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2554`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2566`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2578`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2595`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2606`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2658`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2698`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2738`

### cJSON_Duplicate_rec `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2785`

### skip_oneline_comment `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2872`

### skip_multiline_comment `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2885`

### minify_string `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2899`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2921`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2971`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2981`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2991`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3001`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3011`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3021`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3031`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3041`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3051`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3061`

### CJSON_PUBLIC `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3071`

### cJSON_ArrayForEach `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`

### cJSON_ArrayForEach `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju

### CJSON_PUBLIC `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3193`

### CJSON_PUBLIC `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3198`

## gen_beacon.sh

### show_help
- Defined: `gen_beacon.sh:34`
- Doc: === FUNCIONES ===

### xor_string
- Defined: `gen_beacon.sh:138`
- Doc: === XOR STRING TO BYTES ===

### crc32
- Defined: `gen_beacon.sh:5916`

## gen_dll_rev.sh

### usage
- Defined: `gen_dll_rev.sh:12`
- Doc: === USO ===

## gen_dll_ss.sh

### usage
- Defined: `gen_dll_ss.sh:10`
- Doc: === USO ===

## gen_key.sh

### usage
- Defined: `gen_key.sh:10`
- Doc: === USO ===

## gen_module.sh

### show_help
- Defined: `gen_module.sh:18`
- Doc: === FUNCIONES ===

### xor_obfuscate
- Defined: `gen_module.sh:35`
- Doc: Función para ofuscar binario con XOR y convertir a \x..

## generate_hashs.py

### djb2 `def djb2(s)`
- Defined: `generate_hashs.py:23`

### generate_coff_loader `def generate_coff_loader()`
- Defined: `generate_hashs.py:223`

### generate_bof_test `def generate_bof_test()`
- Defined: `generate_hashs.py:491`

### main `def main()`
- Defined: `generate_hashs.py:553`
