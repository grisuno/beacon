# API

## COFFLoader.h

### Copyright (function) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved. */ #ifndef COFFLOADER_H #define COFFLOADER_H #include <windows.h> int RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, `
- Defined: `COFFLoader.h:16`
- Imported by: `beacon.c`

## COFFLoader3.c

### djb2_hash (function) `static uint32_t djb2_hash(const char* str)`
- Defined: `COFFLoader3.c:632`
- Doc: === Función hash DJB2 ===
- Depends on: `beacon.h`

### create_trampoline (function) `static void* create_trampoline(void* target)`
- Defined: `COFFLoader3.c:912`
- Depends on: `beacon.h`

### handle_relocation (function) `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...`
- Defined: `COFFLoader3.c:940`
- Depends on: `beacon.h`

### get_symbol_name (function) `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)`
- Defined: `COFFLoader3.c:1079`
- Depends on: `beacon.h`

### __attribute__ (function) `__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2)`
- Defined: `COFFLoader3.c:1102`
- Depends on: `beacon.h`

### RunCOFF (function) `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...`
- Defined: `COFFLoader3.c:1112`
- Doc: === Cargador COFF  ===
- Depends on: `beacon.h`

### void (function) `typedef void (__attribute__((ms_abi)) * bof_func_t)(char*, int);`
- Defined: `COFFLoader3.c:906`
- Depends on: `beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "[BOF] create_trampoline nulled target=NULL\n");`
- Defined: `COFFLoader3.c:915`
- Depends on: `beacon.h`

### VirtualProtect (function) `VirtualProtect(patch_addr, sizeof(uint64_t), oldProtect, &oldProtect);`
- Defined: `COFFLoader3.c:959`
- Depends on: `beacon.h`

### memcpy (function) `memcpy(short_name, s->Name, 8);`
- Defined: `COFFLoader3.c:1092`
- Depends on: `beacon.h`

### f (function) `f(arg1, arg2);`
- Defined: `COFFLoader3.c:1107`
- Depends on: `beacon.h`

### VirtualQuery (function) `VirtualQuery(go, &mbi, sizeof(mbi));`
- Defined: `COFFLoader3.c:1357`
- Depends on: `beacon.h`

### call_go_aligned (function) `call_go_aligned(go, (char*)argumentdata, argumentSize);`
- Defined: `COFFLoader3.c:1365`
- Doc: Llamada ALINEADA — ¡CRUCIAL PARA BOFs GRANDES!
- Depends on: `beacon.h`

### free (function) `free(sections);`
- Defined: `COFFLoader3.c:1376`
- Depends on: `beacon.h`

### VirtualFree (function) `VirtualFree(g_trampoline_page, 0, MEM_RELEASE);`
- Defined: `COFFLoader3.c:1379`
- Depends on: `beacon.h`

## aes.c

### getSBoxValue (function) `static uint8_t getSBoxValue(uint8_t num)`
- Defined: `aes.c:12`
- Doc: define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16
- Depends on: `aes.h`

### getSBoxInvert (function) `static uint8_t getSBoxInvert(uint8_t num)`
- Defined: `aes.c:34`
- Depends on: `aes.h`

### Td0 (function) `static uint8_t Td0(int x)`
- Defined: `aes.c:56`
- Depends on: `aes.h`

### Td1 (function) `static uint8_t Td1(int x)`
- Defined: `aes.c:58`
- Depends on: `aes.h`

### Td2 (function) `static uint8_t Td2(int x)`
- Defined: `aes.c:59`
- Depends on: `aes.h`

### Td3 (function) `static uint8_t Td3(int x)`
- Defined: `aes.c:60`
- Depends on: `aes.h`

### Td4 (function) `static uint8_t Td4(int x)`
- Defined: `aes.c:61`
- Depends on: `aes.h`

### KeyExpansion (function) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)`
- Defined: `aes.c:166`
- Doc: This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
- Depends on: `aes.h`

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- Defined: `aes.c:238`
- Depends on: `aes.h`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)`
- Defined: `aes.c:244`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Depends on: `aes.h`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- Defined: `aes.c:249`
- Depends on: `aes.h`

### AddRoundKey (function) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:257`
- Doc: This function adds the round key to state. The round key is added to the state by an XOR function.
- Depends on: `aes.h`

### SubBytes (function) `static void SubBytes(state_t* state)`
- Defined: `aes.c:271`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### ShiftRows (function) `static void ShiftRows(state_t* state)`
- Defined: `aes.c:286`
- Doc: The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = R
- Depends on: `aes.h`

### xtime (function) `static uint8_t xtime(uint8_t x)`
- Defined: `aes.c:313`
- Depends on: `aes.h`

### MixColumns (function) `static void MixColumns(state_t* state)`
- Defined: `aes.c:320`
- Doc: MixColumns function mixes the columns of the state matrix
- Depends on: `aes.h`

### Multiply (function) `static uint8_t Multiply(uint8_t x, uint8_t y)`
- Defined: `aes.c:340`
- Doc: Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up 
- Depends on: `aes.h`

### InvMixColumns (function) `static void InvMixColumns(state_t* state)`
- Defined: `aes.c:370`
- Doc: MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand fo
- Depends on: `aes.h`

### InvSubBytes (function) `static void InvSubBytes(state_t* state)`
- Defined: `aes.c:391`
- Doc: The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- Depends on: `aes.h`

### InvShiftRows (function) `static void InvShiftRows(state_t* state)`
- Defined: `aes.c:402`
- Depends on: `aes.h`

### Cipher (function) `static void Cipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:433`
- Doc: Cipher is the main function that encrypts the PlainText.
- Depends on: `aes.h`

### InvCipher (function) `static void InvCipher(state_t* state, const uint8_t* RoundKey)`
- Defined: `aes.c:459`
- Doc: if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- Depends on: `aes.h`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:488`
- Doc: AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) &&
- Depends on: `aes.h`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- Defined: `aes.c:495`
- Depends on: `aes.h`

### XorWithIv (function) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- Defined: `aes.c:510`
- Doc: if defined(CBC) && (CBC == 1)
- Depends on: `aes.h`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:520`
- Depends on: `aes.h`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:535`
- Depends on: `aes.h`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- Defined: `aes.c:558`
- Doc: XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC)
- Depends on: `aes.h`

### memcpy (function) `memcpy (ctx->Iv, iv, AES_BLOCKLEN);`
- Defined: `aes.c:247`
- Depends on: `aes.h`

## aes.h

### AES_init_ctx (function) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- Defined: `aes.h:40`
- Imported by: `aes.c`, `beacon.c`

### AES_init_ctx_iv (function) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);`
- Defined: `aes.h:43`
- Doc: if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- Imported by: `aes.c`, `beacon.c`

### AES_ctx_set_iv (function) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- Defined: `aes.h:44`
- Imported by: `aes.c`, `beacon.c`

### AES_ECB_encrypt (function) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `aes.h:48`
- Doc: if defined(ECB) && (ECB == 1)
- Imported by: `aes.c`, `beacon.c`

### AES_ECB_decrypt (function) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- Defined: `aes.h:49`
- Imported by: `aes.c`, `beacon.c`

### AES_CBC_encrypt_buffer (function) `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:53`
- Doc: if defined(CBC) && (CBC == 1)
- Imported by: `aes.c`, `beacon.c`

### AES_CBC_decrypt_buffer (function) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:54`
- Imported by: `aes.c`, `beacon.c`

### AES_CTR_xcrypt_buffer (function) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- Defined: `aes.h:58`
- Doc: if defined(CTR) && (CTR == 1)
- Imported by: `aes.c`, `beacon.c`

## beacon.c

### ExceptionFilter (function) `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)`
- Defined: `beacon.c:253`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### get_shell_cmd (function) `const char* get_shell_cmd()`
- Defined: `beacon.c:334`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)`
- Defined: `beacon.c:416`
- Doc: === Beacon API: implementaciones exportables para BOFs ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)`
- Defined: `beacon.c:422`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) int BeaconDataInt(datap * parser)`
- Defined: `beacon.c:430`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) short BeaconDataShort(datap * parser)`
- Defined: `beacon.c:435`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) int BeaconDataLength(datap * parser)`
- Defined: `beacon.c:440`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)`
- Defined: `beacon.c:445`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)`
- Defined: `beacon.c:455`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __declspec (function) `__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)`
- Defined: `beacon.c:503`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### MapDllNameToModule (function) `HMODULE MapDllNameToModule(char* dllName)`
- Defined: `beacon.c:521`
- Doc: === MAP DLL NAME TO REAL DLL ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetSyscallNumber (function) `DWORD GetSyscallNumber(PVOID func_addr)`
- Defined: `beacon.c:548`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### HellsGate (function) `DWORD HellsGate(DWORD ssn)`
- Defined: `beacon.c:560`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### __attribute__ (function) `__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DW...`
- Defined: `beacon.c:565`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetProcessIdByName (function) `DWORD GetProcessIdByName(const char* processName)`
- Defined: `beacon.c:581`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ExecuteTLSCallbacks (function) `void ExecuteTLSCallbacks(PVOID moduleBase)`
- Defined: `beacon.c:600`
- Doc: === EJECUTAR TLS CALLBACKS ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### MapModuleToMemory (function) `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)`
- Defined: `beacon.c:617`
- Doc: === Carga un módulo en memoria ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ExecuteModule (function) `BOOL ExecuteModule(PVOID moduleBase)`
- Defined: `beacon.c:706`
- Doc: === Ejecuta el módulo (DllMain o EntryPoint) ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### LoadModuleFromURL (function) `BOOL LoadModuleFromURL(const char* url)`
- Defined: `beacon.c:751`
- Doc: === Carga y ejecuta un módulo desde URL ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### xor_string (function) `void xor_string(char* data, size_t len, char key)`
- Defined: `beacon.c:915`
- Doc: === XOR ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### anti_analysis (function) `BOOL anti_analysis()`
- Defined: `beacon.c:922`
- Doc: === ANTI-ANALYSIS ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### load_lazyconf (function) `BOOL load_lazyconf()`
- Defined: `beacon.c:945`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetNtdllBase (function) `HMODULE GetNtdllBase()`
- Defined: `beacon.c:1183`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### isVMByMAC (function) `BOOL isVMByMAC()`
- Defined: `beacon.c:1231`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### extract_shellcode (function) `int extract_shellcode(const char* input, size_t len, unsigned char** out)`
- Defined: `beacon.c:1303`
- Doc: === EXTRAER SHELLCODE ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### hex_char_to_byte (function) `BYTE hex_char_to_byte(char c)`
- Defined: `beacon.c:1334`
- Doc: Función para convertir hex a bytes
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### hex_to_bytes (function) `void hex_to_bytes(const char* hex, BYTE* output, size_t len)`
- Defined: `beacon.c:1340`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### executeLoader (function) `void executeLoader(void *arg)`
- Defined: `beacon.c:1348`
- Doc: === executeLoader ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ReverseShell (function) `void __cdecl ReverseShell(void* arg)`
- Defined: `beacon.c:1404`
- Doc: ======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ReadFromProcess (function) `DWORD WINAPI ReadFromProcess(LPVOID lpParam)`
- Defined: `beacon.c:1513`
- Doc: === Hilo para leer salida del proceso (como en el ejemplo que funciona) ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetJitteredSleep (function) `DWORD GetJitteredSleep(DWORD base_ms)`
- Defined: `beacon.c:1586`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetUsefulSoftware (function) `char* GetUsefulSoftware()`
- Defined: `beacon.c:1591`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### base64_encode (function) `char* base64_encode(const unsigned char* data, size_t inputLen)`
- Defined: `beacon.c:1626`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### base64_decode (function) `char* base64_decode(const char* input, size_t* out_len)`
- Defined: `beacon.c:1662`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### discoverLocalHosts (function) `void discoverLocalHosts()`
- Defined: `beacon.c:1695`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### initProxy (function) `void initProxy()`
- Defined: `beacon.c:1752`
- Doc: startProxy.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### relay_thread (function) `void WINAPI relay_thread(void* param)`
- Defined: `beacon.c:1763`
- Doc: Función para reenviar datos entre sockets
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### proxy_thread (function) `void WINAPI proxy_thread(void* param)`
- Defined: `beacon.c:1784`
- Doc: Tu función proxy_thread usando tus estructuras exactas
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### proxy_accept_thread (function) `void WINAPI proxy_accept_thread(void* param)`
- Defined: `beacon.c:1855`
- Doc: Thread para aceptar conexiones
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### startProxy (function) `BOOL startProxy(const char* listenAddr, const char* targetAddr)`
- Defined: `beacon.c:1922`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### stopProxy (function) `BOOL stopProxy(const char* listenAddr)`
- Defined: `beacon.c:2009`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cleanupProxy (function) `void cleanupProxy()`
- Defined: `beacon.c:2061`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### compressDirectory (function) `BOOL compressDirectory(const char* dirPath)`
- Defined: `beacon.c:2094`
- Doc: Función simplificada para compresión de directorios
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### getNetworkConfig (function) `char* getNetworkConfig()`
- Defined: `beacon.c:2104`
- Doc: Para netconfig
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### UploadFileToC2 (function) `BOOL UploadFileToC2(const char* url, const char* filePath)`
- Defined: `beacon.c:2107`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### handleUpload (function) `BOOL handleUpload(const char* command)`
- Defined: `beacon.c:2280`
- Doc: === handleUpload: envía del beacon al C2 ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FileExistsA (function) `BOOL FileExistsA(const char* filePath)`
- Defined: `beacon.c:2301`
- Doc: Función para verificar si un archivo existe
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### selfDestruct (function) `void selfDestruct()`
- Defined: `beacon.c:2306`
- Doc: selfdestruct.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### stristr (function) `char* stristr(const char* str, const char* pattern)`
- Defined: `beacon.c:2361`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### isSensitiveFile (function) `int isSensitiveFile(const char* filename)`
- Defined: `beacon.c:2378`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### searchCredentials (function) `char* searchCredentials(const char* basePath)`
- Defined: `beacon.c:2424`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### UTF8ToWide (function) `WCHAR* UTF8ToWide(const char* utf8)`
- Defined: `beacon.c:2551`
- Doc: Convierte UTF-8 a wide string
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### obfuscateFileTimestamp (function) `BOOL obfuscateFileTimestamp(const char* filepath)`
- Defined: `beacon.c:2562`
- Doc: Ofusca los timestamps de un archivo
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### obfuscateFileTimestamps (function) `void obfuscateFileTimestamps(const char* basePath, int depth)`
- Defined: `beacon.c:2592`
- Doc: Recorre directorios buscando archivos sensibles
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### simulateLegitimateTraffic (function) `void simulateLegitimateTraffic(void* param)`
- Defined: `beacon.c:2656`
- Doc: traffic.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### restartClient (function) `void restartClient()`
- Defined: `beacon.c:2734`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### checkDebuggers (function) `BOOL checkDebuggers()`
- Defined: `beacon.c:2776`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### MapPEToMemory (function) `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)`
- Defined: `beacon.c:2837`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### downloadAndExecute (function) `BOOL downloadAndExecute(const char* url, const char* targetProcess)`
- Defined: `beacon.c:2860`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### DecryptPacket (function) `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)`
- Defined: `beacon.c:2910`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetIPs (function) `char* GetIPs()`
- Defined: `beacon.c:3006`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetHostname (function) `char* GetHostname()`
- Defined: `beacon.c:3039`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetUsername (function) `char* GetUsername()`
- Defined: `beacon.c:3056`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### patchAMSI (function) `BOOL patchAMSI(void)`
- Defined: `beacon.c:3072`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### get_nt_headers (function) `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)`
- Defined: `beacon.c:3092`
- Doc: ==================================================================== PE HELPERS (usando winnt.h) =======================
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### is_64bit (function) `BOOL is_64bit(BYTE* buffer)`
- Defined: `beacon.c:3100`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### get_image_size (function) `DWORD get_image_size(BYTE* buffer)`
- Defined: `beacon.c:3106`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### get_entry_point_rva (function) `DWORD get_entry_point_rva(BYTE* buffer)`
- Defined: `beacon.c:3112`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### pe_buffer_to_virtual_image (function) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- Defined: `beacon.c:3117`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### create_suspended_process (function) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
- Defined: `beacon.c:3148`
- Doc: ==================================================================== PROCESS MANIPULATION ==============================
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### get_remote_image_base (function) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- Defined: `beacon.c:3154`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### update_remote_entry_point (function) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)`
- Defined: `beacon.c:3249`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### overWrite (function) `void overWrite(const char* targetPath, const char* payloadPath)`
- Defined: `beacon.c:3277`
- Doc: ==================================================================== MAIN FUNCTION: overWrite ==========================
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cleanSystemLogs (function) `void cleanSystemLogs()`
- Defined: `beacon.c:3384`
- Doc: Limpia el historial de comandos de la consola actual
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ensurePersistence (function) `BOOL ensurePersistence()`
- Defined: `beacon.c:3421`
- Doc: ensurePersistence.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### isSandboxEnvironment (function) `BOOL isSandboxEnvironment()`
- Defined: `beacon.c:3482`
- Doc: isSandboxEnvironment.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### tryPrivilegeEscalation (function) `void tryPrivilegeEscalation()`
- Defined: `beacon.c:3551`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### executeUACBypass (function) `BOOL executeUACBypass(const char* payloadPath)`
- Defined: `beacon.c:3556`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### scanPort (function) `void scanPort(void* arg)`
- Defined: `beacon.c:3610`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### PortScanner (function) `void PortScanner(char* targetIP, int* ports, int numPorts)`
- Defined: `beacon.c:3661`
- Doc: PortScanner.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### PortScannerWrapper (function) `void PortScannerWrapper(void* arg)`
- Defined: `beacon.c:3705`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### EarlyBirdInject (function) `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)`
- Defined: `beacon.c:3729`
- Doc: === INYECCIÓN EARLY BIRD + SYSCALL ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### init_aes_context (function) `PacketEncryptionContext* init_aes_context(const char* key_hex)`
- Defined: `beacon.c:3898`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### retry_http_request (function) `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)`
- Defined: `beacon.c:3918`
- Doc: retry_http_request.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### exec_cmd (function) `char* exec_cmd(const char* cmd)`
- Defined: `beacon.c:4172`
- Doc: exec_cmd.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetC2Command (function) `char* GetC2Command(const char* host, const char* path)`
- Defined: `beacon.c:4200`
- Doc: c2.c (reemplaza la función actual)
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### DownloadToBuffer (function) `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)`
- Defined: `beacon.c:4346`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### DownloadFromURL (function) `BOOL DownloadFromURL(const char* url, const char* filepath)`
- Defined: `beacon.c:4422`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### encrypt_data (function) `char* encrypt_data(const char* data)`
- Defined: `beacon.c:4452`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### isValidUUID (function) `BOOL isValidUUID(const char* uuid)`
- Defined: `beacon.c:4511`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### deleteFilesDelay (function) `void deleteFilesDelay(void* arg)`
- Defined: `beacon.c:4536`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### executeCommand (function) `void executeCommand(void* cmdPtr)`
- Defined: `beacon.c:4550`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### handleAtomic (function) `void handleAtomic(char* command)`
- Defined: `beacon.c:4559`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### handleDownload (function) `BOOL handleDownload(const char* command)`
- Defined: `beacon.c:4683`
- Doc: === handleDownload: descarga del C2 al beacon ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### SerializeBeaconString (function) `void SerializeBeaconString(char* buffer, int* offset, const char* str)`
- Defined: `beacon.c:4702`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### BeaconDataSerializeString (function) `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)`
- Defined: `beacon.c:4711`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### go (function) `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)`
- Defined: `beacon.c:4719`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### handleAdversary (function) `void handleAdversary(char* command)`
- Defined: `beacon.c:4738`
- Doc: Función principal de manejo de comandos
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### main (function) `int main()`
- Defined: `beacon.c:5233`
- Doc: main.c
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### NTSTATUS (function) `typedef NTSTATUS (NTAPI *SpLsaModeInitialize_t)( ULONG LsaVersion, PULONG PackageVersion, void** ppTables, PULONG pcTables );`
- Defined: `beacon.c:198`
- Doc: === FIRMA DE SpLsaModeInitialize (MinGW compatible) ===
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### longjmp (function) `longjmp(exceptionJump, 1);`
- Defined: `beacon.c:256`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### VOID (function) `typedef VOID (NTAPI *PAPCFUNC)(ULONG_PTR);`
- Defined: `beacon.c:302`
- Doc: ifndef NT_SUCCESS define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0) endif
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### va_start (function) `va_start(args, fmt);`
- Defined: `beacon.c:461`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### va_end (function) `va_end(args);`
- Defined: `beacon.c:464`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fprintf (function) `fprintf(stderr, "[ERROR] vsnprintf failed\n");`
- Defined: `beacon.c:468`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fputs (function) `fputs(buffer, stdout);`
- Defined: `beacon.c:477`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fflush (function) `fflush(stdout);`
- Defined: `beacon.c:479`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### memcpy (function) `memcpy(copy, data, len);`
- Defined: `beacon.c:507`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### free (function) `free(copy);`
- Defined: `beacon.c:515`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetModuleHandleA (function) `return GetModuleHandleA("ucrtbase.dll");`
- Defined: `beacon.c:523`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### LoadLibraryA (function) `return LoadLibraryA(dllName);`
- Defined: `beacon.c:546`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### volatile (function) `__asm__ volatile ( "movq %%rcx, %%r10\n\t" "movl __syscall_ssn(%%rip), %%eax\n\t" "syscall\n\t" "ret\n\t" : : : "rax", "r10", "rcx" );`
- Defined: `beacon.c:571`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### CloseHandle (function) `CloseHandle(hSnapshot);`
- Defined: `beacon.c:591`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### printf (function) `printf("[I] Cargando DLL: %s\n", dllName);`
- Defined: `beacon.c:671`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### VirtualFree (function) `VirtualFree(baseAddress, 0, MEM_RELEASE);`
- Defined: `beacon.c:678`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### BOOL (function) `typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);`
- Defined: `beacon.c:721`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WaitForSingleObject (function) `WaitForSingleObject(hThread, INFINITE);`
- Defined: `beacon.c:740`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetTempPathA (function) `GetTempPathA(MAX_PATH, tempPath);`
- Defined: `beacon.c:780`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### strcat_s (function) `strcat_s(tempPath, MAX_PATH, "mimilib.dll");`
- Defined: `beacon.c:781`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WriteFile (function) `WriteFile(hFile, dllBuffer, fileSize, &written, NULL);`
- Defined: `beacon.c:798`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### VirtualFreeEx (function) `VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);`
- Defined: `beacon.c:824`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### pStartW (function) `pStartW();`
- Defined: `beacon.c:907`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### RegCloseKey (function) `RegCloseKey(hKey);`
- Defined: `beacon.c:937`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### Sleep (function) `Sleep(1000);`
- Defined: `beacon.c:972`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### strncpy (function) `strncpy(host, host_start, host_len);`
- Defined: `beacon.c:994`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### strcpy (function) `strcpy(path, path_start);`
- Defined: `beacon.c:998`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WinHttpCloseHandle (function) `WinHttpCloseHandle(hSession);`
- Defined: `beacon.c:1019`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WinHttpQueryHeaders (function) `WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &size, NULL);`
- Defined: `beacon.c:1092`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(root);`
- Defined: `beacon.c:1173`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### snprintf (function) `snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X", adapter->Address[0], adapter->Address[1], adapter->Address[2]);`
- Defined: `beacon.c:1280`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### _endthread (function) `_endthread();`
- Defined: `beacon.c:1408`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WSACleanup (function) `WSACleanup();`
- Defined: `beacon.c:1432`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### closesocket (function) `closesocket(s);`
- Defined: `beacon.c:1446`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### send (function) `send(s, buffer, n, 0);`
- Defined: `beacon.c:1520`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### memmove (function) `memmove(buffer + r, buffer + r - 1, 1);`
- Defined: `beacon.c:1551`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FlushFileBuffers (function) `FlushFileBuffers(hInWrite);`
- Defined: `beacon.c:1570`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### strcat (function) `strcat(result, binaries[i]);`
- Defined: `beacon.c:1612`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### IcmpCloseHandle (function) `IcmpCloseHandle(hIcmp);`
- Defined: `beacon.c:1741`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### InitializeCriticalSection (function) `InitializeCriticalSection(&proxyMutex);`
- Defined: `beacon.c:1755`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### memset (function) `memset(proxySessions, 0, sizeof(proxySessions));`
- Defined: `beacon.c:1756`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### shutdown (function) `shutdown(from, SD_BOTH);`
- Defined: `beacon.c:1776`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### EnterCriticalSection (function) `EnterCriticalSection(&proxyMutex);`
- Defined: `beacon.c:1806`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### LeaveCriticalSection (function) `LeaveCriticalSection(&proxyMutex);`
- Defined: `beacon.c:1808`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WaitForMultipleObjects (function) `WaitForMultipleObjects(2, threads, FALSE, INFINITE);`
- Defined: `beacon.c:1829`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### _beginthread (function) `_beginthread(proxy_thread, 0, (void*)data);`
- Defined: `beacon.c:1903`
- Doc: Usar tu función proxy_thread original
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### setsockopt (function) `setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));`
- Defined: `beacon.c:1979`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### DeleteCriticalSection (function) `DeleteCriticalSection(&proxyMutex);`
- Defined: `beacon.c:2089`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fseek (function) `fseek(fp, 0, SEEK_END);`
- Defined: `beacon.c:2115`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fclose (function) `fclose(fp);`
- Defined: `beacon.c:2122`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fread (function) `fread(fileData, 1, fileSize, fp);`
- Defined: `beacon.c:2125`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WinHttpSetOption (function) `WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));`
- Defined: `beacon.c:2232`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### MultiByteToWideChar (function) `MultiByteToWideChar(CP_UTF8, 0, contentType, -1, wContentType, 512);`
- Defined: `beacon.c:2239`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### RegDeleteValueA (function) `RegDeleteValueA(hKey, "SystemMaintenance");`
- Defined: `beacon.c:2321`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### system (function) `system("schtasks /delete /tn \"SystemMaintenanceTask\" /f > nul 2>&1");`
- Defined: `beacon.c:2326`
- Doc: Eliminar tarea programada
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ExitProcess (function) `ExitProcess(0);`
- Defined: `beacon.c:2358`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FindClose (function) `FindClose(hFind);`
- Defined: `beacon.c:2454`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetSystemTimeAsFileTime (function) `GetSystemTimeAsFileTime(&ftNow);`
- Defined: `beacon.c:2579`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WinHttpReceiveResponse (function) `WinHttpReceiveResponse(hRequest, NULL);`
- Defined: `beacon.c:2721`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### DeleteFileA (function) `DeleteFileA(filename);`
- Defined: `beacon.c:2895`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### AES_init_ctx (function) `AES_init_ctx(&ctx, aes_key);`
- Defined: `beacon.c:2949`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### AES_ECB_encrypt (function) `AES_ECB_encrypt(&ctx, keystream);`
- Defined: `beacon.c:2960`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetAdaptersInfo (function) `GetAdaptersInfo(adapterInfo, &len);`
- Defined: `beacon.c:3017`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WriteProcessMemory (function) `WriteProcessMemory(GetCurrentProcess(), (LPVOID)scan_buffer_addr, patch, sizeof(patch), NULL);`
- Defined: `beacon.c:3084`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### VirtualProtect (function) `VirtualProtect((LPVOID)scan_buffer_addr, 1, old_protect, &old_protect);`
- Defined: `beacon.c:3085`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FreeLibrary (function) `FreeLibrary(amsi_dll);`
- Defined: `beacon.c:3086`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### CreateProcessA (function) `return CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);`
- Defined: `beacon.c:3152`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### Wow64SetThreadContext (function) `return Wow64SetThreadContext(pi->hThread, &ctx);`
- Defined: `beacon.c:3257`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### SetThreadContext (function) `return SetThreadContext(pi->hThread, &ctx);`
- Defined: `beacon.c:3263`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### fwrite (function) `fwrite(downloaded, 1, fileSize, fp);`
- Defined: `beacon.c:3295`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ReadFile (function) `ReadFile(hFile, rawBuffer, rawSize, &read, NULL);`
- Defined: `beacon.c:3315`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### HeapFree (function) `HeapFree(GetProcessHeap(), 0, rawBuffer);`
- Defined: `beacon.c:3320`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### TerminateProcess (function) `TerminateProcess(pi.hProcess, 1);`
- Defined: `beacon.c:3346`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ResumeThread (function) `ResumeThread(pi.hThread);`
- Defined: `beacon.c:3374`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### WriteConsoleA (function) `WriteConsoleA(hConOut, "\x1b[2J\x1b[H", 7, &written, NULL);`
- Defined: `beacon.c:3398`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### AdjustTokenPrivileges (function) `AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);`
- Defined: `beacon.c:3410`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ExpandEnvironmentStringsA (function) `ExpandEnvironmentStringsA("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.bat", startupPath, sizeof(startupPath));`
- Defined: `beacon.c:3460`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### SetFileAttributesA (function) `SetFileAttributesA(startupPath, FILE_ATTRIBUTE_HIDDEN);`
- Defined: `beacon.c:3471`
- Doc: Hacer archivo oculto
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### GetSystemInfo (function) `GetSystemInfo(&sysInfo);`
- Defined: `beacon.c:3487`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### strlwr (function) `strlwr(vendor);`
- Defined: `beacon.c:3538`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### RegOpenKeyA (function) `RegOpenKeyA(HKEY_CURRENT_USER, regKey, &hKey);`
- Defined: `beacon.c:3603`
- Doc: Limpiar
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### inet_pton (function) `inet_pton(AF_INET, result->ip, &sa.sin_addr);`
- Defined: `beacon.c:3631`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ioctlsocket (function) `ioctlsocket(s, FIONBIO, &blocking_mode);`
- Defined: `beacon.c:3635`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### connect (function) `connect(s, (SOCKADDR*)&sa, sizeof(sa));`
- Defined: `beacon.c:3636`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FD_ZERO (function) `FD_ZERO(&write_set);`
- Defined: `beacon.c:3640`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### FD_SET (function) `FD_SET(s, &write_set);`
- Defined: `beacon.c:3641`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### getsockopt (function) `getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);`
- Defined: `beacon.c:3649`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### _pclose (function) `_pclose(fp);`
- Defined: `beacon.c:4190`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### CryptGenRandom (function) `CryptGenRandom(hProv, 16, iv);`
- Defined: `beacon.c:4473`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### CryptReleaseContext (function) `CryptReleaseContext(hProv, 0);`
- Defined: `beacon.c:4474`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Descargado: %d bytes", bof_size);`
- Defined: `beacon.c:4721`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddStringToObject (function) `cJSON_AddStringToObject(json_obj, "id", "windows" && strlen("windows") > 0 ? "windows" : "windows");`
- Defined: `beacon.c:5172`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_AddNumberToObject (function) `cJSON_AddNumberToObject(json_obj, "pid", (double)GetCurrentProcessId());`
- Defined: `beacon.c:5179`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### cJSON_free (function) `cJSON_free(json_str);`
- Defined: `beacon.c:5224`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### srand (function) `srand(time(NULL));`
- Defined: `beacon.c:5236`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### ShowWindow (function) `ShowWindow(GetConsoleWindow(), SW_HIDE);`
- Defined: `beacon.c:5239`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

### wcstombs (function) `wcstombs(lazyconf.rhost, LC2_HOST, sizeof(lazyconf.rhost) - 1);`
- Defined: `beacon.c:5260`
- Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`

## bof/calc/calc.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/calc/calc.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/calc/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ⚡ Ejecutando calc.exe...\n");`
- Defined: `bof/calc/calc.c:35`
- Depends on: `bof/calc/beacon.h`

### FARPROC (function) `typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);`
- Defined: `bof/calc/calc.c:45`
- Doc: 2. Resolver GetProcAddress (con cast correcto)
- Depends on: `bof/calc/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *CreateProcessA_t)( LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);`
- Defined: `bof/calc/calc.c:56`
- Doc: 4. Definir tipo de CreateProcessA
- Depends on: `bof/calc/beacon.h`

### pCloseHandle (function) `pCloseHandle(pi.hProcess);`
- Defined: `bof/calc/calc.c:76`
- Doc: Luego: llamarlo como una función normal
- Depends on: `bof/calc/beacon.h`

## bof/etw/etw.c

### go (function) `void go(char *a,int l)`
- Defined: `bof/etw/etw.c:26`
- Depends on: `bof/etw/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT,"[ETW] patching...\n");`
- Defined: `bof/etw/etw.c:27`
- Depends on: `bof/etw/beacon.h`

## bof/test/Test.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/Test.c:2`
- Doc: include "beacon.h"
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[CoffTest] I am alive! . Args=%.*s\n", alen, args);`
- Defined: `bof/test/Test.c:4`
- Depends on: `bof/test/beacon.h`

## bof/test/amsibypass.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/amsibypass.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] Iniciando bypass AMSI (patch en memoria)...\n");`
- Defined: `bof/test/amsibypass.c:35`
- Depends on: `bof/test/beacon.h`

## bof/test/cmdwhoami.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/cmdwhoami.c:42`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD d`
- Defined: `bof/test/cmdwhoami.c:29`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(kernel32.dll) falló\n");`
- Defined: `bof/test/cmdwhoami.c:46`
- Depends on: `bof/test/beacon.h`

## bof/test/disablelog.c

### my_wcscmp (function) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)`
- Defined: `bof/test/disablelog.c:36`
- Doc: ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/disablelog.c:68`
- Depends on: `bof/test/beacon.h`

### SC_HANDLE (function) `typedef SC_HANDLE (WINAPI *pOpenSCManagerA)(LPCSTR, LPCSTR, DWORD);`
- Defined: `bof/test/disablelog.c:46`
- Doc: Tipos de funciones que cargaremos dinámicamente
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *pQueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);`
- Defined: `bof/test/disablelog.c:48`
- Depends on: `bof/test/beacon.h`

### DWORD (function) `typedef DWORD (WINAPI *pGetModuleBaseNameW)(HANDLE, HMODULE, LPWSTR, DWORD);`
- Defined: `bof/test/disablelog.c:51`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);`
- Defined: `bof/test/disablelog.c:53`
- Depends on: `bof/test/beacon.h`

### NTSTATUS (function) `typedef NTSTATUS (NTAPI *pNtQueryInformationThread)( HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength );`
- Defined: `bof/test/disablelog.c:61`
- Doc: Prototipo de NtQueryInformationThread
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Iniciando: Suspensión de hilos en wevtsvc.dll (servicio EventLog)\n");`
- Defined: `bof/test/disablelog.c:70`
- Depends on: `bof/test/beacon.h`

## bof/test/getenv.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/getenv.c:24`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] %-15s = [NO DISPONIBLE]\n", vars[i]);`
- Defined: `bof/test/getenv.c:42`
- Depends on: `bof/test/beacon.h`

## bof/test/loadvnc.c

### execute_cmd_hidden (function) `void execute_cmd_hidden(char* cmd)`
- Defined: `bof/test/loadvnc.c:51`
- Doc: ================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/loadvnc.c:81`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);`
- Defined: `bof/test/loadvnc.c:54`
- Depends on: `bof/test/beacon.h`

### DWORD (function) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
- Defined: `bof/test/loadvnc.c:67`
- Depends on: `bof/test/beacon.h`

### pWaitForSingleObject (function) `pWaitForSingleObject(pi.hProcess, 8000);`
- Defined: `bof/test/loadvnc.c:70`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[VNC] Iniciando descarga e inyección...");`
- Defined: `bof/test/loadvnc.c:82`
- Depends on: `bof/test/beacon.h`

### int (function) `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);`
- Defined: `bof/test/loadvnc.c:104`
- Depends on: `bof/test/beacon.h`

### pwsprintfA (function) `pwsprintfA(dll_path, "%s\\winvnc.x64.dll", temp_path);`
- Defined: `bof/test/loadvnc.c:111`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *CREATE_SNAPSHOT)(DWORD, DWORD);`
- Defined: `bof/test/loadvnc.c:121`
- Doc: === Paso 3: Cargar Toolhelp32 dinámicamente ===
- Depends on: `bof/test/beacon.h`

### LPVOID (function) `typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);`
- Defined: `bof/test/loadvnc.c:182`
- Doc: === Paso 6: Reservar memoria para la ruta ===
- Depends on: `bof/test/beacon.h`

### HMODULE (function) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
- Defined: `bof/test/loadvnc.c:204`
- Doc: === Paso 8: Inyectar LoadLibraryA ===
- Depends on: `bof/test/beacon.h`

## bof/test/make_table.c

### Copyright (function) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
- Defined: `bof/test/make_table.c:16`

### main (function) `void main()`
- Defined: `bof/test/make_table.c:33`

### printf (function) `printf("Hash for '%s' = 0x%08X\n", names[i], h);`
- Defined: `bof/test/make_table.c:48`

## bof/test/persist.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/persist.c:26`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA falló: %ld\n", result);`
- Defined: `bof/test/persist.c:38`
- Depends on: `bof/test/beacon.h`

### strlen (function) `strlen(valueData) + 1 );`
- Defined: `bof/test/persist.c:49`
- Depends on: `bof/test/beacon.h`

## bof/test/persistsvc.c

### my_memcpy (function) `static void* my_memcpy(void* dst, const void* src, size_t len)`
- Defined: `bof/test/persistsvc.c:33`
- Doc: ================================ FUNCIONES AUXILIARES ================================
- Depends on: `bof/test/beacon.h`

### my_strlen (function) `static int my_strlen(const char* str)`
- Defined: `bof/test/persistsvc.c:39`
- Depends on: `bof/test/beacon.h`

### my_strcat (function) `static char* my_strcat(char* dest, const char* src)`
- Defined: `bof/test/persistsvc.c:46`
- Depends on: `bof/test/beacon.h`

### my_strcmp (function) `static int my_strcmp(const char* s1, const char* s2)`
- Defined: `bof/test/persistsvc.c:54`
- Depends on: `bof/test/beacon.h`

### ServiceHandler (function) `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...`
- Defined: `bof/test/persistsvc.c:82`
- Doc: ================================ MANEJADOR DE CONTROL DEL SERVICIO ================================
- Depends on: `bof/test/beacon.h`

### ServiceMain (function) `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)`
- Defined: `bof/test/persistsvc.c:116`
- Doc: ================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/persistsvc.c:251`
- Doc: ================================ FUNCIÓN PRINCIPAL DEL BOF ================================
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] No se pudo resolver " #name "\n");`
- Defined: `bof/test/persistsvc.c:68`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *pSetServiceStatus_t)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);`
- Defined: `bof/test/persistsvc.c:103`
- Depends on: `bof/test/beacon.h`

### pSetServiceStatus (function) `pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);`
- Defined: `bof/test/persistsvc.c:106`
- Depends on: `bof/test/beacon.h`

### SERVICE_STATUS_HANDLE (function) `typedef SERVICE_STATUS_HANDLE (WINAPI *pRegisterServiceCtrlHandlerA_t)(LPCSTR, LPHANDLER_FUNCTION);`
- Defined: `bof/test/persistsvc.c:126`
- Doc: ================================ 🔧 RESOLVER APIS con macro ================================
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *pCreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);`
- Defined: `bof/test/persistsvc.c:128`
- Depends on: `bof/test/beacon.h`

### RESOLVE_API (function) `RESOLVE_API(Advapi32, RegisterServiceCtrlHandlerA, pRegisterServiceCtrlHandlerA_t);`
- Defined: `bof/test/persistsvc.c:132`
- Doc: 👇 Define temporalmente "cleanup" como alias de "cleanup_service" define cleanup cleanup_service
- Depends on: `bof/test/beacon.h`

### void (function) `typedef void (WINAPI *pRtlZeroMemory_t)(PVOID, SIZE_T);`
- Defined: `bof/test/persistsvc.c:174`
- Depends on: `bof/test/beacon.h`

### DWORD (function) `typedef DWORD (WINAPI *pGetLastError_t)(void);`
- Defined: `bof/test/persistsvc.c:175`
- Depends on: `bof/test/beacon.h`

### HMODULE (function) `typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);`
- Defined: `bof/test/persistsvc.c:176`
- Depends on: `bof/test/beacon.h`

### pRtlZeroMemory (function) `pRtlZeroMemory(&si, sizeof(si));`
- Defined: `bof/test/persistsvc.c:207`
- Depends on: `bof/test/beacon.h`

### pCloseHandle (function) `pCloseHandle(pi.hProcess);`
- Defined: `bof/test/persistsvc.c:228`
- Depends on: `bof/test/beacon.h`

### pWaitForSingleObject (function) `pWaitForSingleObject(g_StopEvent, INFINITE);`
- Defined: `bof/test/persistsvc.c:236`
- Depends on: `bof/test/beacon.h`

### pCloseServiceHandle (function) `pCloseServiceHandle(hService);`
- Defined: `bof/test/persistsvc.c:357`
- Doc: Cerrar handles
- Depends on: `bof/test/beacon.h`

## bof/test/scan_shellcode.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/scan_shellcode.c:84`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);`
- Defined: `bof/test/scan_shellcode.c:75`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *pProcess32First)(HANDLE, LPPROCESSENTRY32);`
- Defined: `bof/test/scan_shellcode.c:77`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[*] Iniciando búsqueda de regiones RWX en procesos...\n");`
- Defined: `bof/test/scan_shellcode.c:86`
- Depends on: `bof/test/beacon.h`

### pCloseHandleFn (function) `pCloseHandleFn(snapshot);`
- Defined: `bof/test/scan_shellcode.c:120`
- Depends on: `bof/test/beacon.h`

## bof/test/shellcode.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/shellcode.c:25`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc falló\n");`
- Defined: `bof/test/shellcode.c:34`
- Depends on: `bof/test/beacon.h`

## bof/test/sock5.c

### my_FD_ISSET (function) `static int my_FD_ISSET(SOCKET s, fd_set *set)`
- Defined: `bof/test/sock5.c:107`
- Doc: typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typ
- Depends on: `bof/test/beacon.h`

### HandleSocks5Connection (function) `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...`
- Defined: `bof/test/sock5.c:118`
- Doc: typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if 
- Depends on: `bof/test/beacon.h`

### ProxyThread (function) `DWORD WINAPI ProxyThread(LPVOID _)`
- Defined: `bof/test/sock5.c:261`
- Doc: break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/sock5.c:358`
- Doc: cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HAND
- Depends on: `bof/test/beacon.h`

### HMODULE (function) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
- Defined: `bof/test/sock5.c:81`
- Doc: /* ===== DIRECT IMPORTS ===== extern PVOID __imp_LoadLibraryA; extern PVOID __imp_GetProcAddress; extern PVOID __imp_Vir
- Depends on: `bof/test/beacon.h`

### FARPROC (function) `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);`
- Defined: `bof/test/sock5.c:82`
- Depends on: `bof/test/beacon.h`

### LPVOID (function) `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);`
- Defined: `bof/test/sock5.c:83`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);`
- Defined: `bof/test/sock5.c:84`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *CREATE_EVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);`
- Defined: `bof/test/sock5.c:85`
- Depends on: `bof/test/beacon.h`

### DWORD (function) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
- Defined: `bof/test/sock5.c:86`
- Depends on: `bof/test/beacon.h`

### int (function) `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);`
- Defined: `bof/test/sock5.c:90`
- Doc: #define SOCKS5_CONTROL_PORT 9051 #define MAX_PENDING_CONNECTIONS 5 #define BUFFER_SIZE 4096 /* ===== TIPOS DE FUNCIÓN ==
- Depends on: `bof/test/beacon.h`

### SOCKET (function) `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);`
- Defined: `bof/test/sock5.c:91`
- Depends on: `bof/test/beacon.h`

### ULONG (function) `typedef ULONG (WINAPI *HTONL)(ULONG);`
- Defined: `bof/test/sock5.c:102`
- Depends on: `bof/test/beacon.h`

### USHORT (function) `typedef USHORT (WINAPI *HTONS)(USHORT);`
- Defined: `bof/test/sock5.c:103`
- Depends on: `bof/test/beacon.h`

### pSend (function) `pSend(client_sock, rep, 10, 0);`
- Defined: `bof/test/sock5.c:139`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló conexión al destino. WSAError: %d\n", err);`
- Defined: `bof/test/sock5.c:194`
- Depends on: `bof/test/beacon.h`

### pCloseSocket (function) `pCloseSocket(tgt);`
- Defined: `bof/test/sock5.c:197`
- Depends on: `bof/test/beacon.h`

### FD_ZERO (function) `FD_ZERO(&read_fds);`
- Defined: `bof/test/sock5.c:218`
- Depends on: `bof/test/beacon.h`

### FD_SET (function) `FD_SET(client_sock, &read_fds);`
- Defined: `bof/test/sock5.c:219`
- Depends on: `bof/test/beacon.h`

### pWSACleanup (function) `cleanup_wsa: pWSACleanup();`
- Defined: `bof/test/sock5.c:347`
- Depends on: `bof/test/beacon.h`

### pCloseHandle (function) `pCloseHandle(g_hShutdownEvent);`
- Defined: `bof/test/sock5.c:389`
- Depends on: `bof/test/beacon.h`

### pWaitForSingleObject (function) `pWaitForSingleObject(g_hShutdownEvent, INFINITE);`
- Defined: `bof/test/sock5.c:395`
- Depends on: `bof/test/beacon.h`

## bof/test/tel.py

### get_machine_id (function) `def get_machine_id()`
- Defined: `bof/test/tel.py:8`

### get_version (function) `def get_version()`
- Defined: `bof/test/tel.py:20`

### to_numbers (function) `def to_numbers(hex_str)`
- Defined: `bof/test/tel.py:31`
- Doc: Simula la función toNumbers de JavaScript

### to_hex (function) `def to_hex(byte_list)`
- Defined: `bof/test/tel.py:35`
- Doc: Simula la función toHex de JavaScript

### decrypt_cookie (function) `def decrypt_cookie(encrypted, key, iv)`
- Defined: `bof/test/tel.py:39`
- Doc: Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))

### main (function) `def main()`
- Defined: `bof/test/tel.py:45`
- Doc: Sistema de telemetría de uso por instalación no invasiva.

## bof/test/uacbypass.c

### execute_hidden_cmd (function) `void execute_hidden_cmd(char* cmd)`
- Defined: `bof/test/uacbypass.c:33`
- Doc: ================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/uacbypass.c:61`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);`
- Defined: `bof/test/uacbypass.c:36`
- Depends on: `bof/test/beacon.h`

### DWORD (function) `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);`
- Defined: `bof/test/uacbypass.c:48`
- Depends on: `bof/test/beacon.h`

### pWaitForSingleObject (function) `pWaitForSingleObject(pi.hProcess, 10000);`
- Defined: `bof/test/uacbypass.c:51`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Iniciando bypass UAC via SilentCleanup (fodhelper/CMSTP)...\n");`
- Defined: `bof/test/uacbypass.c:62`
- Depends on: `bof/test/beacon.h`

### int (function) `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);`
- Defined: `bof/test/uacbypass.c:79`
- Depends on: `bof/test/beacon.h`

### pwsprintfA (function) `pwsprintfA(inf_path, "%s\\uac_bypass.inf", temp_path);`
- Defined: `bof/test/uacbypass.c:85`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);`
- Defined: `bof/test/uacbypass.c:89`
- Doc: === Paso 3: Crear archivo .inf malicioso ===
- Depends on: `bof/test/beacon.h`

### pWriteFile (function) `pWriteFile(hFile, inf_content, strlen(inf_content), &written, NULL);`
- Defined: `bof/test/uacbypass.c:114`
- Depends on: `bof/test/beacon.h`

## bof/test/upload.c

### my_strlen (function) `static int my_strlen(const char *s)`
- Defined: `bof/test/upload.c:53`
- Doc: ================================ FUNCIONES AUXILIARES ================================
- Depends on: `bof/test/beacon.h`

### my_memcpy (function) `static void* my_memcpy(void* dst, const void* src, size_t len)`
- Defined: `bof/test/upload.c:58`
- Depends on: `bof/test/beacon.h`

### my_memset (function) `static void* my_memset(void* dst, int val, size_t len)`
- Defined: `bof/test/upload.c:65`
- Depends on: `bof/test/beacon.h`

### my_contains_dotdot (function) `static BOOL my_contains_dotdot(const char* path)`
- Defined: `bof/test/upload.c:71`
- Depends on: `bof/test/beacon.h`

### my_strchr (function) `static char* my_strchr(const char *s, int c)`
- Defined: `bof/test/upload.c:80`
- Depends on: `bof/test/beacon.h`

### xtime (function) `static uint8_t xtime(uint8_t x)`
- Defined: `bof/test/upload.c:93`
- Doc: ================================ AES (sin datos globales) ================================
- Depends on: `bof/test/beacon.h`

### AddRoundKey (function) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- Defined: `bof/test/upload.c:98`
- Depends on: `bof/test/beacon.h`

### SubBytes (function) `static void SubBytes(state_t* state, const uint8_t* sbox)`
- Defined: `bof/test/upload.c:105`
- Depends on: `bof/test/beacon.h`

### ShiftRows (function) `static void ShiftRows(state_t* state)`
- Defined: `bof/test/upload.c:112`
- Depends on: `bof/test/beacon.h`

### MixColumns (function) `static void MixColumns(state_t* state)`
- Defined: `bof/test/upload.c:120`
- Depends on: `bof/test/beacon.h`

### Cipher (function) `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
- Defined: `bof/test/upload.c:132`
- Depends on: `bof/test/beacon.h`

### KeyExpansion (function) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
- Defined: `bof/test/upload.c:145`
- Depends on: `bof/test/beacon.h`

### AES_init_ctx (function) `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
- Defined: `bof/test/upload.c:173`
- Depends on: `bof/test/beacon.h`

### AES_CFB_encrypt_buffer (function) `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
- Defined: `bof/test/upload.c:177`
- Depends on: `bof/test/beacon.h`

### my_base64_encode (function) `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...`
- Defined: `bof/test/upload.c:205`
- Doc: ================================ BASE64 ================================
- Depends on: `bof/test/beacon.h`

### ParseUploadArgs (function) `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
- Defined: `bof/test/upload.c:230`
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/upload.c:273`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/test/beacon.h`

### NEXT_TOKEN (function) `NEXT_TOKEN(local_path, 128);`
- Defined: `bof/test/upload.c:252`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de loader\n");`
- Defined: `bof/test/upload.c:302`
- Depends on: `bof/test/beacon.h`

### LPVOID (function) `typedef LPVOID (WINAPI *t_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);`
- Defined: `bof/test/upload.c:314`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *t_VirtualFree)(LPVOID, SIZE_T, DWORD);`
- Defined: `bof/test/upload.c:316`
- Depends on: `bof/test/beacon.h`

### HANDLE (function) `typedef HANDLE (WINAPI *t_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);`
- Defined: `bof/test/upload.c:354`
- Doc: Resolución de APIs
- Depends on: `bof/test/beacon.h`

### int (function) `typedef int (WINAPI *t_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);`
- Defined: `bof/test/upload.c:358`
- Depends on: `bof/test/beacon.h`

### HINTERNET (function) `typedef HINTERNET (WINAPI *t_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);`
- Defined: `bof/test/upload.c:376`
- Depends on: `bof/test/beacon.h`

### pCloseHandle (function) `pCloseHandle(hFile);`
- Defined: `bof/test/upload.c:422`
- Depends on: `bof/test/beacon.h`

### pVirtualFree (function) `pVirtualFree(fileBuffer, 0, MEM_RELEASE);`
- Defined: `bof/test/upload.c:438`
- Depends on: `bof/test/beacon.h`

### pMultiByteToWideChar (function) `pMultiByteToWideChar(CP_UTF8, 0, host, -1, w_host, host_len);`
- Defined: `bof/test/upload.c:489`
- Depends on: `bof/test/beacon.h`

### pWinHttpCloseHandle (function) `pWinHttpCloseHandle(hSession);`
- Defined: `bof/test/upload.c:516`
- Depends on: `bof/test/beacon.h`

## bof/test/vncrelay.c

### my_FD_ISSET (function) `int my_FD_ISSET(SOCKET sock, fd_set *set)`
- Defined: `bof/test/vncrelay.c:62`
- Doc: ================================ FD_ISSET MANUAL ================================
- Depends on: `bof/test/beacon.h`

### relay_traffic (function) `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)`
- Defined: `bof/test/vncrelay.c:75`
- Doc: ================================ RELAY TRAFFIC ================================
- Depends on: `bof/test/beacon.h`

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/vncrelay.c:132`
- Doc: ================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================
- Depends on: `bof/test/beacon.h`

### HMODULE (function) `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);`
- Defined: `bof/test/vncrelay.c:36`
- Doc: ================================ TIPOS ================================
- Depends on: `bof/test/beacon.h`

### FARPROC (function) `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);`
- Defined: `bof/test/vncrelay.c:37`
- Depends on: `bof/test/beacon.h`

### LPVOID (function) `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);`
- Defined: `bof/test/vncrelay.c:38`
- Depends on: `bof/test/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);`
- Defined: `bof/test/vncrelay.c:39`
- Depends on: `bof/test/beacon.h`

### int (function) `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);`
- Defined: `bof/test/vncrelay.c:44`
- Doc: ================================ FUNCIONES DE RED ================================
- Depends on: `bof/test/beacon.h`

### SOCKET (function) `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);`
- Defined: `bof/test/vncrelay.c:45`
- Depends on: `bof/test/beacon.h`

### ULONG (function) `typedef ULONG (WINAPI *HTONL)(ULONG);`
- Defined: `bof/test/vncrelay.c:56`
- Depends on: `bof/test/beacon.h`

### USHORT (function) `typedef USHORT (WINAPI *HTONS)(USHORT);`
- Defined: `bof/test/vncrelay.c:57`
- Depends on: `bof/test/beacon.h`

### FD_ZERO (function) `FD_ZERO(&read_fds);`
- Defined: `bof/test/vncrelay.c:96`
- Depends on: `bof/test/beacon.h`

### FD_SET (function) `FD_SET(client_sock, &read_fds);`
- Defined: `bof/test/vncrelay.c:97`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[VNC RELAY] Iniciando relay en 0.0.0.0:5901 → 127.0.0.1:5900\n");`
- Defined: `bof/test/vncrelay.c:133`
- Depends on: `bof/test/beacon.h`

### pCloseSocket (function) `pCloseSocket(listen_sock);`
- Defined: `bof/test/vncrelay.c:185`
- Depends on: `bof/test/beacon.h`

## bof/test/winver.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/test/winver.c:24`
- Depends on: `bof/test/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_ERROR, "GetVersionExA falló\n");`
- Defined: `bof/test/winver.c:30`
- Depends on: `bof/test/beacon.h`

## bof/whoami/whoami.c

### go (function) `void go(char *args, int alen)`
- Defined: `bof/whoami/whoami.c:34`
- Doc: ================================ FUNCIÓN PRINCIPAL ================================
- Depends on: `bof/whoami/beacon.h`

### BeaconPrintf (function) `BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 🔍 Iniciando whoami final fixed");`
- Defined: `bof/whoami/whoami.c:35`
- Depends on: `bof/whoami/beacon.h`

### BOOL (function) `typedef BOOL (WINAPI *GetUserNameW_t)(LPWSTR, LPDWORD);`
- Defined: `bof/whoami/whoami.c:44`
- Doc: 2. Resolver GetUserNameW
- Depends on: `bof/whoami/beacon.h`

## cJSON.c

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- Defined: `cJSON.c:94`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- Defined: `cJSON.c:99`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- Defined: `cJSON.c:109`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- Defined: `cJSON.c:124`
- Doc: CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; 
- Depends on: `cJSON.h`

### case_insensitive_strcmp (function) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)`
- Defined: `cJSON.c:134`
- Doc: /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1)
- Depends on: `cJSON.h`

### internal_malloc (function) `static void * CJSON_CDECL internal_malloc(size_t size)`
- Defined: `cJSON.c:166`
- Doc: } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t s
- Depends on: `cJSON.h`

### internal_free (function) `static void CJSON_CDECL internal_free(void *pointer)`
- Defined: `cJSON.c:170`
- Depends on: `cJSON.h`

### internal_realloc (function) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- Defined: `cJSON.c:174`
- Depends on: `cJSON.h`

### cJSON_strdup (function) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- Defined: `cJSON.c:188`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- Defined: `cJSON.c:209`
- Depends on: `cJSON.h`

### cJSON_New_Item (function) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)`
- Defined: `cJSON.c:242`
- Doc: if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc ar
- Depends on: `cJSON.h`

### get_decimal_point (function) `static unsigned char get_decimal_point(void)`
- Defined: `cJSON.c:281`
- Doc: item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate
- Depends on: `cJSON.h`

### parse_number (function) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:309`
- Doc: size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks
- Depends on: `cJSON.h`

### ensure (function) `static unsigned char* ensure(printbuffer * const p, size_t needed)`
- Defined: `cJSON.c:494`
- Doc: } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for form
- Depends on: `cJSON.h`

### update_offset (function) `static void update_offset(printbuffer * const buffer)`
- Defined: `cJSON.c:579`
- Doc: p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->lengt
- Depends on: `cJSON.h`

### compare_double (function) `static cJSON_bool compare_double(double a, double b)`
- Defined: `cJSON.c:592`
- Doc: /* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer *
- Depends on: `cJSON.h`

### print_number (function) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:599`
- Doc: } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely
- Depends on: `cJSON.h`

### parse_hex4 (function) `static unsigned parse_hex4(const unsigned char * const input)`
- Defined: `cJSON.c:669`
- Doc: output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->of
- Depends on: `cJSON.h`

### utf16_literal_to_utf8 (function) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...`
- Defined: `cJSON.c:706`
- Doc: converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- Depends on: `cJSON.h`

### parse_string (function) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:827`
- Doc: else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length
- Depends on: `cJSON.h`

### print_string_ptr (function) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...`
- Defined: `cJSON.c:957`
- Doc: { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(
- Depends on: `cJSON.h`

### print_string (function) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)`
- Defined: `cJSON.c:1079`
- Doc: /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; b
- Depends on: `cJSON.h`

### buffer_skip_whitespace (function) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)`
- Defined: `cJSON.c:1093`
- Doc: static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char
- Depends on: `cJSON.h`

### skip_utf8_bom (function) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)`
- Defined: `cJSON.c:1119`
- Doc: while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset =
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- Defined: `cJSON.c:1133`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- Defined: `cJSON.c:1235`
- Depends on: `cJSON.h`

### print (function) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- Defined: `cJSON.c:1242`
- Doc: define cjson_min(a, b) (((a) < (b)) ? (a) : (b))
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- Defined: `cJSON.c:1315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- Defined: `cJSON.c:1320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- Defined: `cJSON.c:1351`
- Depends on: `cJSON.h`

### parse_value (function) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1372`
- Doc: return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format =
- Depends on: `cJSON.h`

### print_value (function) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1427`
- Doc: if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input
- Depends on: `cJSON.h`

### parse_array (function) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1501`
- Doc: return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: 
- Depends on: `cJSON.h`

### print_array (function) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1599`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array 
- Depends on: `cJSON.h`

### parse_object (function) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)`
- Defined: `cJSON.c:1661`
- Doc: output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_
- Depends on: `cJSON.h`

### print_object (function) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)`
- Defined: `cJSON.c:1780`
- Doc: input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object
- Depends on: `cJSON.h`

### get_array_item (function) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- Defined: `cJSON.c:1915`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- Defined: `cJSON.c:1934`
- Depends on: `cJSON.h`

### get_object_item (function) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- Defined: `cJSON.c:1944`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- Defined: `cJSON.c:1976`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- Defined: `cJSON.c:1981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- Defined: `cJSON.c:1986`
- Depends on: `cJSON.h`

### suffix_object (function) `static void suffix_object(cJSON *prev, cJSON *item)`
- Defined: `cJSON.c:1993`
- Doc: return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * co
- Depends on: `cJSON.h`

### create_reference (function) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)`
- Defined: `cJSON.c:2000`
- Doc: CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(objec
- Depends on: `cJSON.h`

### add_item_to_array (function) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2020`
- Depends on: `cJSON.h`

### cast_away_const (function) `static void* cast_away_const(const void* string)`
- Defined: `cJSON.c:2066`
- Doc: /* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_
- Depends on: `cJSON.h`

### add_item_to_object (function) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- Defined: `cJSON.c:2073`
- Doc: if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma G
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- Defined: `cJSON.c:2111`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- Defined: `cJSON.c:2122`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- Defined: `cJSON.c:2132`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2142`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2154`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2166`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- Defined: `cJSON.c:2178`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2190`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- Defined: `cJSON.c:2202`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- Defined: `cJSON.c:2214`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2226`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- Defined: `cJSON.c:2238`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- Defined: `cJSON.c:2250`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2286`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- Defined: `cJSON.c:2296`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2301`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2308`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- Defined: `cJSON.c:2315`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- Defined: `cJSON.c:2320`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- Defined: `cJSON.c:2362`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- Defined: `cJSON.c:2412`
- Depends on: `cJSON.h`

### replace_item_in_object (function) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- Defined: `cJSON.c:2422`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- Defined: `cJSON.c:2445`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- Defined: `cJSON.c:2450`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- Defined: `cJSON.c:2467`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- Defined: `cJSON.c:2478`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- Defined: `cJSON.c:2489`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- Defined: `cJSON.c:2500`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- Defined: `cJSON.c:2525`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- Defined: `cJSON.c:2542`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- Defined: `cJSON.c:2554`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- Defined: `cJSON.c:2566`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- Defined: `cJSON.c:2578`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- Defined: `cJSON.c:2595`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- Defined: `cJSON.c:2606`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- Defined: `cJSON.c:2658`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- Defined: `cJSON.c:2698`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- Defined: `cJSON.c:2738`
- Depends on: `cJSON.h`

### cJSON_Duplicate_rec (function) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- Defined: `cJSON.c:2785`
- Depends on: `cJSON.h`

### skip_oneline_comment (function) `static void skip_oneline_comment(char **input)`
- Defined: `cJSON.c:2872`
- Depends on: `cJSON.h`

### skip_multiline_comment (function) `static void skip_multiline_comment(char **input)`
- Defined: `cJSON.c:2885`
- Depends on: `cJSON.h`

### minify_string (function) `static void minify_string(char **input, char **output)`
- Defined: `cJSON.c:2899`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- Defined: `cJSON.c:2921`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- Defined: `cJSON.c:2971`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- Defined: `cJSON.c:2981`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- Defined: `cJSON.c:2991`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- Defined: `cJSON.c:3001`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- Defined: `cJSON.c:3011`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- Defined: `cJSON.c:3021`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- Defined: `cJSON.c:3031`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- Defined: `cJSON.c:3041`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- Defined: `cJSON.c:3051`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- Defined: `cJSON.c:3061`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- Defined: `cJSON.c:3071`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(a_element, a)`
- Defined: `cJSON.c:3157`
- Depends on: `cJSON.h`

### cJSON_ArrayForEach (function) `cJSON_ArrayForEach(b_element, b)`
- Defined: `cJSON.c:3173`
- Doc: doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is ju
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- Defined: `cJSON.c:3193`
- Depends on: `cJSON.h`

### CJSON_PUBLIC (function) `CJSON_PUBLIC(void) cJSON_free(void *object)`
- Defined: `cJSON.c:3198`
- Depends on: `cJSON.h`

### sprintf (function) `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);`
- Defined: `cJSON.c:128`
- Depends on: `cJSON.h`

### tolower (function) `return tolower(*string1) - tolower(*string2);`
- Defined: `cJSON.c:153`
- Depends on: `cJSON.h`

### void (function) `void (CJSON_CDECL *deallocate)(void *pointer);`
- Defined: `cJSON.c:160`
- Depends on: `cJSON.h`

### malloc (function) `return malloc(size);`
- Defined: `cJSON.c:168`
- Depends on: `cJSON.h`

### free (function) `free(pointer);`
- Defined: `cJSON.c:172`
- Depends on: `cJSON.h`

### realloc (function) `return realloc(pointer, size);`
- Defined: `cJSON.c:176`
- Depends on: `cJSON.h`

### memcpy (function) `memcpy(copy, string, length);`
- Defined: `cJSON.c:205`
- Depends on: `cJSON.h`

### memset (function) `memset(node, '\0', sizeof(cJSON));`
- Defined: `cJSON.c:247`
- Depends on: `cJSON.h`

### cJSON_Delete (function) `cJSON_Delete(item->child);`
- Defined: `cJSON.c:262`
- Depends on: `cJSON.h`

### strcpy (function) `strcpy(object->valuestring, valuestring);`
- Defined: `cJSON.c:464`
- Depends on: `cJSON.h`

### cJSON_free (function) `cJSON_free(object->valuestring);`
- Defined: `cJSON.c:475`
- Depends on: `cJSON.h`

### cJSON_ParseWithLengthOpts (function) `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);`
- Defined: `cJSON.c:1145`
- Depends on: `cJSON.h`

### cJSON_ParseWithOpts (function) `return cJSON_ParseWithOpts(value, 0, 0);`
- Defined: `cJSON.c:1233`
- Depends on: `cJSON.h`

### cJSON_DetachItemViaPointer (function) `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));`
- Defined: `cJSON.c:2293`
- Depends on: `cJSON.h`

### cJSON_ReplaceItemViaPointer (function) `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);`
- Defined: `cJSON.c:2419`
- Depends on: `cJSON.h`

## cJSON.h

### void (function) `void (CJSON_CDECL *free_fn)(void *ptr);`
- Defined: `cJSON.h:118`
- Imported by: `beacon.c`, `cJSON.c`

### sensitive (function) `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bo`
- Defined: `cJSON.h:249`
- Imported by: `beacon.c`, `cJSON.c`

## gen_beacon.sh

### show_help (function)
- Defined: `gen_beacon.sh:34`
- Doc: === FUNCIONES ===

### xor_string (function)
- Defined: `gen_beacon.sh:138`
- Doc: === XOR STRING TO BYTES ===

### crc32 (function)
- Defined: `gen_beacon.sh:5916`

## gen_dll_rev.sh

### usage (function)
- Defined: `gen_dll_rev.sh:12`
- Doc: === USO ===

## gen_dll_ss.sh

### usage (function)
- Defined: `gen_dll_ss.sh:10`
- Doc: === USO ===

## gen_key.sh

### usage (function)
- Defined: `gen_key.sh:10`
- Doc: === USO ===

## gen_module.sh

### show_help (function)
- Defined: `gen_module.sh:18`
- Doc: === FUNCIONES ===

### xor_obfuscate (function)
- Defined: `gen_module.sh:35`
- Doc: Función para ofuscar binario con XOR y convertir a \x..

## generate_hashs.py

### djb2 (function) `def djb2(s)`
- Defined: `generate_hashs.py:23`

### generate_coff_loader (function) `def generate_coff_loader()`
- Defined: `generate_hashs.py:223`

### generate_bof_test (function) `def generate_bof_test()`
- Defined: `generate_hashs.py:491`

### main (function) `def main()`
- Defined: `generate_hashs.py:553`
