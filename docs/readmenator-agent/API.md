# API

## COFFLoader3.c
Depends on: `beacon.h`
- `djb2_hash` (function) `COFFLoader3.c:632` `static uint32_t djb2_hash(const char* str)` -- === Función hash DJB2 ===
- `create_trampoline` (function) `COFFLoader3.c:913` `static void* create_trampoline(void* target)`
- `handle_relocation` (function) `COFFLoader3.c:940` `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...`
- `get_symbol_name` (function) `COFFLoader3.c:1080` `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)`
- `RunCOFF` (function) `COFFLoader3.c:1112` `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...` -- === Cargador COFF  ===

## aes.c
Depends on: `aes.h`
- `getSBoxValue` (function) `aes.c:13` `static uint8_t getSBoxValue(uint8_t num)`
- `getSBoxInvert` (function) `aes.c:35` `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (function) `aes.c:57` `static uint8_t Td0(int x)`
- `Td1` (function) `aes.c:58` `static uint8_t Td1(int x)`
- `Td2` (function) `aes.c:59` `static uint8_t Td2(int x)`
- `Td3` (function) `aes.c:60` `static uint8_t Td3(int x)`
- `Td4` (function) `aes.c:61` `static uint8_t Td4(int x)`
- `KeyExpansion` (function) `aes.c:166` `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` -- This function produces Nb(Nr+1) round keys.
- `AES_init_ctx` (function) `aes.c:239` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (function) `aes.c:244` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.c:249` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (function) `aes.c:257` `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` -- This function adds the round key to state.
- `SubBytes` (function) `aes.c:271` `static void SubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `ShiftRows` (function) `aes.c:286` `static void ShiftRows(state_t* state)` -- The ShiftRows() function shifts the rows in the state to the left.
- `xtime` (function) `aes.c:314` `static uint8_t xtime(uint8_t x)`
- `MixColumns` (function) `aes.c:320` `static void MixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix
- `Multiply` (function) `aes.c:340` `static uint8_t Multiply(uint8_t x, uint8_t y)` -- Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends...
- `InvMixColumns` (function) `aes.c:370` `static void InvMixColumns(state_t* state)` -- MixColumns function mixes the columns of the state matrix.
- `InvSubBytes` (function) `aes.c:391` `static void InvSubBytes(state_t* state)` -- The SubBytes Function Substitutes the values in the state matrix with values in an S-box.
- `InvShiftRows` (function) `aes.c:403` `static void InvShiftRows(state_t* state)`
- `Cipher` (function) `aes.c:433` `static void Cipher(state_t* state, const uint8_t* RoundKey)` -- Cipher is the main function that encrypts the PlainText.
- `InvCipher` (function) `aes.c:459` `static void InvCipher(state_t* state, const uint8_t* RoundKey)` -- if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
- `AES_ECB_encrypt` (function) `aes.c:490` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `AES_ECB_decrypt` (function) `aes.c:496` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (function) `aes.c:512` `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)`
- `AES_CBC_encrypt_buffer` (function) `aes.c:521` `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (function) `aes.c:536` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (function) `aes.c:558` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` -- XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if...

## aes.h
Imported by: `aes.c`, `beacon.c`
- `AES_init_ctx` (function) `aes.h:41` `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);`
- `AES_init_ctx_iv` (function) `aes.h:43` `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` -- if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
- `AES_ctx_set_iv` (function) `aes.h:44` `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);`
- `AES_ECB_encrypt` (function) `aes.h:48` `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` -- if defined(ECB) && (ECB == 1)
- `AES_ECB_decrypt` (function) `aes.h:49` `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);`
- `AES_CBC_encrypt_buffer` (function) `aes.h:53` `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CBC) && (CBC == 1)
- `AES_CBC_decrypt_buffer` (function) `aes.h:54` `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);`
- `AES_CTR_xcrypt_buffer` (function) `aes.h:58` `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` -- if defined(CTR) && (CTR == 1)

## beacon.c
Depends on: `COFFLoader.h`, `aes.h`, `beacon.h`, `cJSON.h`
- `ExceptionFilter` (function) `beacon.c:253` `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)`
- `get_shell_cmd` (function) `beacon.c:335` `const char* get_shell_cmd()`
- `MapDllNameToModule` (function) `beacon.c:521` `HMODULE MapDllNameToModule(char* dllName)` -- === MAP DLL NAME TO REAL DLL ===
- `GetSyscallNumber` (function) `beacon.c:549` `DWORD GetSyscallNumber(PVOID func_addr)`
- `HellsGate` (function) `beacon.c:561` `DWORD HellsGate(DWORD ssn)`
- `GetProcessIdByName` (function) `beacon.c:582` `DWORD GetProcessIdByName(const char* processName)`
- `ExecuteTLSCallbacks` (function) `beacon.c:600` `void ExecuteTLSCallbacks(PVOID moduleBase)` -- === EJECUTAR TLS CALLBACKS ===
- `MapModuleToMemory` (function) `beacon.c:617` `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)` -- === Carga un módulo en memoria ===
- `ExecuteModule` (function) `beacon.c:706` `BOOL ExecuteModule(PVOID moduleBase)` -- === Ejecuta el módulo (DllMain o EntryPoint) ===
- `LoadModuleFromURL` (function) `beacon.c:751` `BOOL LoadModuleFromURL(const char* url)` -- === Carga y ejecuta un módulo desde URL ===
- `xor_string` (function) `beacon.c:915` `void xor_string(char* data, size_t len, char key)` -- === XOR ===
- `anti_analysis` (function) `beacon.c:922` `BOOL anti_analysis()` -- === ANTI-ANALYSIS ===
- `load_lazyconf` (function) `beacon.c:946` `BOOL load_lazyconf()`
- `GetNtdllBase` (function) `beacon.c:1184` `HMODULE GetNtdllBase()`
- `isVMByMAC` (function) `beacon.c:1232` `BOOL isVMByMAC()`
- `extract_shellcode` (function) `beacon.c:1303` `int extract_shellcode(const char* input, size_t len, unsigned char** out)` -- === EXTRAER SHELLCODE ===
- `hex_char_to_byte` (function) `beacon.c:1334` `BYTE hex_char_to_byte(char c)` -- Función para convertir hex a bytes
- `hex_to_bytes` (function) `beacon.c:1341` `void hex_to_bytes(const char* hex, BYTE* output, size_t len)`
- `executeLoader` (function) `beacon.c:1348` `void executeLoader(void *arg)` -- === executeLoader ===
- `ReverseShell` (function) `beacon.c:1404` `void __cdecl ReverseShell(void* arg)`
- `ReadFromProcess` (function) `beacon.c:1513` `DWORD WINAPI ReadFromProcess(LPVOID lpParam)` -- === Hilo para leer salida del proceso (como en el ejemplo que funciona) ===
- `GetJitteredSleep` (function) `beacon.c:1587` `DWORD GetJitteredSleep(DWORD base_ms)`
- `GetUsefulSoftware` (function) `beacon.c:1592` `char* GetUsefulSoftware()`
- `base64_encode` (function) `beacon.c:1627` `char* base64_encode(const unsigned char* data, size_t inputLen)`
- `base64_decode` (function) `beacon.c:1663` `char* base64_decode(const char* input, size_t* out_len)`
- `discoverLocalHosts` (function) `beacon.c:1696` `void discoverLocalHosts()`
- `initProxy` (function) `beacon.c:1753` `void initProxy()`
- `relay_thread` (function) `beacon.c:1763` `void WINAPI relay_thread(void* param)` -- Función para reenviar datos entre sockets
- `proxy_thread` (function) `beacon.c:1784` `void WINAPI proxy_thread(void* param)` -- Tu función proxy_thread usando tus estructuras exactas
- `proxy_accept_thread` (function) `beacon.c:1855` `void WINAPI proxy_accept_thread(void* param)` -- Thread para aceptar conexiones
- `startProxy` (function) `beacon.c:1923` `BOOL startProxy(const char* listenAddr, const char* targetAddr)`
- `stopProxy` (function) `beacon.c:2010` `BOOL stopProxy(const char* listenAddr)`
- `cleanupProxy` (function) `beacon.c:2062` `void cleanupProxy()`
- `compressDirectory` (function) `beacon.c:2094` `BOOL compressDirectory(const char* dirPath)` -- Función simplificada para compresión de directorios
- `getNetworkConfig` (function) `beacon.c:2104` `char* getNetworkConfig()` -- Para netconfig
- `UploadFileToC2` (function) `beacon.c:2108` `BOOL UploadFileToC2(const char* url, const char* filePath)`
- `handleUpload` (function) `beacon.c:2280` `BOOL handleUpload(const char* command)` -- === handleUpload: envía del beacon al C2 ===
- `FileExistsA` (function) `beacon.c:2301` `BOOL FileExistsA(const char* filePath)` -- Función para verificar si un archivo existe
- `selfDestruct` (function) `beacon.c:2306` `void selfDestruct()`
- `stristr` (function) `beacon.c:2362` `char* stristr(const char* str, const char* pattern)`
- `isSensitiveFile` (function) `beacon.c:2378` `int isSensitiveFile(const char* filename)`
- `searchCredentials` (function) `beacon.c:2425` `char* searchCredentials(const char* basePath)`
- `UTF8ToWide` (function) `beacon.c:2551` `WCHAR* UTF8ToWide(const char* utf8)` -- Convierte UTF-8 a wide string
- `obfuscateFileTimestamp` (function) `beacon.c:2562` `BOOL obfuscateFileTimestamp(const char* filepath)` -- Ofusca los timestamps de un archivo
- `obfuscateFileTimestamps` (function) `beacon.c:2592` `void obfuscateFileTimestamps(const char* basePath, int depth)` -- Recorre directorios buscando archivos sensibles
- `simulateLegitimateTraffic` (function) `beacon.c:2656` `void simulateLegitimateTraffic(void* param)`
- `restartClient` (function) `beacon.c:2735` `void restartClient()`
- `checkDebuggers` (function) `beacon.c:2776` `BOOL checkDebuggers()`
- `MapPEToMemory` (function) `beacon.c:2838` `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)`
- `downloadAndExecute` (function) `beacon.c:2861` `BOOL downloadAndExecute(const char* url, const char* targetProcess)`
- `DecryptPacket` (function) `beacon.c:2911` `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)`
- `GetIPs` (function) `beacon.c:3007` `char* GetIPs()`
- `GetHostname` (function) `beacon.c:3041` `char* GetHostname()`
- `GetUsername` (function) `beacon.c:3057` `char* GetUsername()`
- `patchAMSI` (function) `beacon.c:3074` `BOOL patchAMSI(void)`
- `get_nt_headers` (function) `beacon.c:3092` `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)`
- `is_64bit` (function) `beacon.c:3101` `BOOL is_64bit(BYTE* buffer)`
- `get_image_size` (function) `beacon.c:3107` `DWORD get_image_size(BYTE* buffer)`
- `get_entry_point_rva` (function) `beacon.c:3113` `DWORD get_entry_point_rva(BYTE* buffer)`
- `pe_buffer_to_virtual_image` (function) `beacon.c:3119` `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- `create_suspended_process` (function) `beacon.c:3149` `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)`
- `get_remote_image_base` (function) `beacon.c:3156` `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- `update_remote_entry_point` (function) `beacon.c:3250` `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)`
- `overWrite` (function) `beacon.c:3277` `void overWrite(const char* targetPath, const char* payloadPath)`
- `cleanSystemLogs` (function) `beacon.c:3384` `void cleanSystemLogs()` -- Limpia el historial de comandos de la consola actual
- `ensurePersistence` (function) `beacon.c:3421` `BOOL ensurePersistence()`
- `isSandboxEnvironment` (function) `beacon.c:3482` `BOOL isSandboxEnvironment()`
- `tryPrivilegeEscalation` (function) `beacon.c:3552` `void tryPrivilegeEscalation()`
- `executeUACBypass` (function) `beacon.c:3557` `BOOL executeUACBypass(const char* payloadPath)`
- `scanPort` (function) `beacon.c:3610` `void scanPort(void* arg)`
- `PortScanner` (function) `beacon.c:3661` `void PortScanner(char* targetIP, int* ports, int numPorts)`
- `PortScannerWrapper` (function) `beacon.c:3706` `void PortScannerWrapper(void* arg)`
- `EarlyBirdInject` (function) `beacon.c:3729` `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)` -- === INYECCIÓN EARLY BIRD + SYSCALL ===
- `init_aes_context` (function) `beacon.c:3900` `PacketEncryptionContext* init_aes_context(const char* key_hex)`
- `retry_http_request` (function) `beacon.c:3918` `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)`
- `exec_cmd` (function) `beacon.c:4172` `char* exec_cmd(const char* cmd)`
- `GetC2Command` (function) `beacon.c:4200` `char* GetC2Command(const char* host, const char* path)`
- `DownloadToBuffer` (function) `beacon.c:4347` `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)`
- `DownloadFromURL` (function) `beacon.c:4423` `BOOL DownloadFromURL(const char* url, const char* filepath)`
- `encrypt_data` (function) `beacon.c:4454` `char* encrypt_data(const char* data)`
- `isValidUUID` (function) `beacon.c:4512` `BOOL isValidUUID(const char* uuid)`
- `deleteFilesDelay` (function) `beacon.c:4537` `void deleteFilesDelay(void* arg)`
- `executeCommand` (function) `beacon.c:4551` `void executeCommand(void* cmdPtr)`
- `handleAtomic` (function) `beacon.c:4560` `void handleAtomic(char* command)`
- `handleDownload` (function) `beacon.c:4683` `BOOL handleDownload(const char* command)` -- === handleDownload: descarga del C2 al beacon ===
- `SerializeBeaconString` (function) `beacon.c:4703` `void SerializeBeaconString(char* buffer, int* offset, const char* str)`
- `BeaconDataSerializeString` (function) `beacon.c:4712` `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)`
- `go` (function) `beacon.c:4720` `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)`
- `handleAdversary` (function) `beacon.c:4738` `void handleAdversary(char* command)` -- Función principal de manejo de comandos
- `main` (function) `beacon.c:5233` `int main()`

## bof/calc/calc.c
Depends on: `bof/calc/beacon.h`
- `go` (function) `bof/calc/calc.c:34` `void go(char *args, int alen)`

## bof/etw/etw.c
Depends on: `bof/etw/beacon.h`
- `go` (function) `bof/etw/etw.c:26` `void go(char *a,int l)`

## bof/whoami/whoami.c
Depends on: `bof/whoami/beacon.h`
- `go` (function) `bof/whoami/whoami.c:34` `void go(char *args, int alen)`

## cJSON.c
Depends on: `cJSON.h`
- `CJSON_PUBLIC` (function) `cJSON.c:95` `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:100` `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:110` `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:125` `CJSON_PUBLIC(const char*) cJSON_Version(void)`
- `case_insensitive_strcmp` (function) `cJSON.c:134` `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` -- /* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR...
- `internal_malloc` (function) `cJSON.c:166` `static void * CJSON_CDECL internal_malloc(size_t size)` -- } return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL...
- `internal_free` (function) `cJSON.c:170` `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (function) `cJSON.c:174` `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (function) `cJSON.c:189` `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (function) `cJSON.c:210` `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (function) `cJSON.c:242` `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` -- if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and...
- `get_decimal_point` (function) `cJSON.c:281` `static unsigned char get_decimal_point(void)` -- item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {...
- `parse_number` (function) `cJSON.c:309` `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` -- size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset....
- `ensure` (function) `cJSON.c:494` `static unsigned char* ensure(printbuffer * const p, size_t needed)` -- } typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for...
- `update_offset` (function) `cJSON.c:579` `static void update_offset(printbuffer * const buffer)` -- p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); }...
- `compare_double` (function) `cJSON.c:592` `static cJSON_bool compare_double(double a, double b)` -- /* calculate the new length of the string in a printbuffer and update the offset static void...
- `print_number` (function) `cJSON.c:599` `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` -- } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /*...
- `parse_hex4` (function) `cJSON.c:669` `static unsigned parse_hex4(const unsigned char * const input)` -- output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'...
- `utf16_literal_to_utf8` (function) `cJSON.c:706` `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` -- converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX
- `parse_string` (function) `cJSON.c:827` `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` -- else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return...
- `print_string_ptr` (function) `cJSON.c:957` `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` -- { input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset =...
- `print_string` (function) `cJSON.c:1079` `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` -- /* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer +=...
- `buffer_skip_whitespace` (function) `cJSON.c:1093` `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` -- static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned...
- `skip_utf8_bom` (function) `cJSON.c:1119` `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` -- while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if...
- `CJSON_PUBLIC` (function) `cJSON.c:1134` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (function) `cJSON.c:1236` `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (function) `cJSON.c:1243` `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...`
- `CJSON_PUBLIC` (function) `cJSON.c:1316` `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:1321` `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (function) `cJSON.c:1352` `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (function) `cJSON.c:1372` `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` -- return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true...
- `print_value` (function) `cJSON.c:1427` `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` -- if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item...
- `parse_array` (function) `cJSON.c:1501` `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` -- return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case...
- `print_array` (function) `cJSON.c:1599` `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `parse_object` (function) `cJSON.c:1661` `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` -- output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'...
- `print_object` (function) `cJSON.c:1780` `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` -- input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an...
- `get_array_item` (function) `cJSON.c:1916` `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (function) `cJSON.c:1935` `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (function) `cJSON.c:1945` `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (function) `cJSON.c:1977` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (function) `cJSON.c:1982` `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (function) `cJSON.c:1987` `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (function) `cJSON.c:1993` `static void suffix_object(cJSON *prev, cJSON *item)` -- return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON...
- `create_reference` (function) `cJSON.c:2000` `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` -- CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return...
- `add_item_to_array` (function) `cJSON.c:2021` `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (function) `cJSON.c:2066` `static void* cast_away_const(const void* string)` -- /* Add item to array/object.
- `add_item_to_object` (function) `cJSON.c:2075` `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...`
- `CJSON_PUBLIC` (function) `cJSON.c:2112` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2123` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2133` `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2143` `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2155` `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2167` `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2179` `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (function) `cJSON.c:2191` `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `cJSON.c:2203` `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (function) `cJSON.c:2215` `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (function) `cJSON.c:2227` `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2239` `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (function) `cJSON.c:2251` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2287` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2297` `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (function) `cJSON.c:2302` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2309` `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2316` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2321` `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2363` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (function) `cJSON.c:2413` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (function) `cJSON.c:2423` `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (function) `cJSON.c:2446` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (function) `cJSON.c:2451` `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (function) `cJSON.c:2468` `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2479` `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2490` `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (function) `cJSON.c:2501` `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (function) `cJSON.c:2526` `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2543` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (function) `cJSON.c:2555` `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2567` `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (function) `cJSON.c:2579` `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (function) `cJSON.c:2596` `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2607` `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (function) `cJSON.c:2659` `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2699` `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (function) `cJSON.c:2739` `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (function) `cJSON.c:2786` `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (function) `cJSON.c:2873` `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (function) `cJSON.c:2886` `static void skip_multiline_comment(char **input)`
- `minify_string` (function) `cJSON.c:2900` `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (function) `cJSON.c:2922` `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (function) `cJSON.c:2972` `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2982` `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:2992` `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3002` `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3012` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3022` `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3032` `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3042` `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3052` `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3062` `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (function) `cJSON.c:3072` `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (function) `cJSON.c:3157` `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (function) `cJSON.c:3173` `cJSON_ArrayForEach(b_element, b)` -- doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this...
- `CJSON_PUBLIC` (function) `cJSON.c:3194` `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (function) `cJSON.c:3199` `CJSON_PUBLIC(void) cJSON_free(void *object)`

## cJSON.h
Imported by: `beacon.c`, `cJSON.c`
- `sensitive` (function) `cJSON.h:249` `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */...`

## gen_beacon.sh
- `show_help` (function) `gen_beacon.sh:34` -- === FUNCIONES ===
- `xor_string` (function) `gen_beacon.sh:138` -- === XOR STRING TO BYTES ===
- `crc32` (function) `gen_beacon.sh:5916`

## gen_dll_rev.sh
- `usage` (function) `gen_dll_rev.sh:12` -- === USO ===

## gen_dll_ss.sh
- `usage` (function) `gen_dll_ss.sh:10` -- === USO ===

## gen_key.sh
- `usage` (function) `gen_key.sh:10` -- === USO ===

## gen_module.sh
- `show_help` (function) `gen_module.sh:18` -- === FUNCIONES ===
- `xor_obfuscate` (function) `gen_module.sh:35` -- Función para ofuscar binario con XOR y convertir a \x..

## generate_hashs.py
- `djb2` (function) `generate_hashs.py:23` `def djb2(s)`
- `generate_coff_loader` (function) `generate_hashs.py:223` `def generate_coff_loader()`
- `generate_bof_test` (function) `generate_hashs.py:491` `def generate_bof_test()`
- `main` (function) `generate_hashs.py:553` `def main()`
