# Documentation Coverage

Overall: **23.0%** (96 of 417 public modules, types, and callables). Data members are excluded from the ratio.

[Back to index](index.md)

## By kind

| Kind | Documented | Total | Coverage |
|---|---|---|---|
| function | 62 | 207 | 30.0% |
| macro | 17 | 145 | 11.7% |
| module | 10 | 23 | 43.5% |
| struct | 2 | 30 | 6.7% |
| type_alias | 5 | 12 | 41.7% |

## By module (lowest first)

| Module | Documented | Total | Coverage |
|---|---|---|---|
| [`COFFLoader.h`](modules/COFFLoader.h.md) | 0 | 1 | 0.0% |
| [`beacon.h`](modules/beacon.h.md) | 0 | 4 | 0.0% |
| [`bof/calc/beacon.h`](modules/bof.calc.beacon.h.md) | 0 | 4 | 0.0% |
| [`bof/etw/beacon.h`](modules/bof.etw.beacon.h.md) | 0 | 4 | 0.0% |
| [`bof/etw/etw.c`](modules/bof.etw.etw.c.md) | 0 | 2 | 0.0% |
| [`bof/whoami/beacon.h`](modules/bof.whoami.beacon.h.md) | 0 | 4 | 0.0% |
| [`install.sh`](modules/install.sh.md) | 0 | 1 | 0.0% |
| [`cJSON.c`](modules/cJSON.c.md) | 6 | 89 | 6.7% |
| [`COFFLoader3.c`](modules/COFFLoader3.c.md) | 3 | 25 | 12.0% |
| [`generate_hashs`](modules/generate_hashs.py.md) | 1 | 5 | 20.0% |
| [`cJSON.h`](modules/cJSON.h.md) | 8 | 37 | 21.6% |
| [`aes.h`](modules/aes.h.md) | 5 | 21 | 23.8% |
| [`beacon.c`](modules/beacon.c.md) | 49 | 177 | 27.7% |
| [`aes.c`](modules/aes.c.md) | 8 | 24 | 33.3% |
| [`bof/calc/calc.c`](modules/bof.calc.calc.c.md) | 1 | 2 | 50.0% |
| [`bof/whoami/whoami.c`](modules/bof.whoami.whoami.c.md) | 1 | 2 | 50.0% |
| [`gen_beacon.sh`](modules/gen_beacon.sh.md) | 3 | 4 | 75.0% |
| [`app`](modules/app.py.md) | 1 | 1 | 100.0% |
| [`gen_dll.sh`](modules/gen_dll.sh.md) | 1 | 1 | 100.0% |
| [`gen_dll_rev.sh`](modules/gen_dll_rev.sh.md) | 2 | 2 | 100.0% |
| [`gen_dll_ss.sh`](modules/gen_dll_ss.sh.md) | 2 | 2 | 100.0% |
| [`gen_key.sh`](modules/gen_key.sh.md) | 2 | 2 | 100.0% |
| [`gen_module.sh`](modules/gen_module.sh.md) | 3 | 3 | 100.0% |

## Warnings

DOC001 undocumented public item, DOC002 parameter not documented, DOC003 documented parameter missing from the signature (stale doc), DOC004 return value not documented, DOC005 raised exception not documented.

DOC001: 321

- DOC001 `COFFLoader.h:1` module COFFLoader.h is not documented
- DOC001 `COFFLoader3.c:1` module COFFLoader3.c is not documented
- DOC001 `COFFLoader3.c:569` macro IMAGE_REL_AMD64_ADDR64 is not documented
- DOC001 `COFFLoader3.c:570` macro IMAGE_REL_AMD64_ADDR32 is not documented
- DOC001 `COFFLoader3.c:571` macro IMAGE_REL_AMD64_ADDR32NB is not documented
- DOC001 `COFFLoader3.c:572` macro IMAGE_REL_AMD64_REL32 is not documented
- DOC001 `COFFLoader3.c:573` macro IMAGE_REL_AMD64_REL32_1 is not documented
- DOC001 `COFFLoader3.c:574` macro IMAGE_REL_AMD64_REL32_2 is not documented
- DOC001 `COFFLoader3.c:575` macro IMAGE_REL_AMD64_REL32_3 is not documented
- DOC001 `COFFLoader3.c:576` macro IMAGE_REL_AMD64_REL32_4 is not documented
- DOC001 `COFFLoader3.c:577` macro IMAGE_REL_AMD64_REL32_5 is not documented
- DOC001 `COFFLoader3.c:578` macro IMAGE_REL_AMD64_SECTION is not documented
- DOC001 `COFFLoader3.c:579` macro IMAGE_REL_AMD64_SECREL is not documented
- DOC001 `COFFLoader3.c:580` macro IMAGE_REL_AMD64_SECREL7 is not documented
- DOC001 `COFFLoader3.c:581` macro IMAGE_REL_AMD64_TOKEN is not documented
- DOC001 `COFFLoader3.c:582` macro IMAGE_REL_AMD64_SREL32 is not documented
- DOC001 `COFFLoader3.c:583` macro IMAGE_REL_AMD64_PAIR is not documented
- DOC001 `COFFLoader3.c:584` macro IMAGE_REL_AMD64_SSPAN32 is not documented
- DOC001 `COFFLoader3.c:586` struct COFFSection is not documented
- DOC001 `COFFLoader3.c:599` struct COFFRelocation is not documented
- DOC001 `COFFLoader3.c:620` struct COFFHeader is not documented
- DOC001 `COFFLoader3.c:940` function handle_relocation is not documented
- DOC001 `COFFLoader3.c:1103` function __attribute__ is not documented
- DOC001 `aes.c:5` macro Nb is not documented
- DOC001 `aes.c:9` macro KEYLEN_256 is not documented
- DOC001 `aes.c:10` macro RKLENGTH is not documented
- DOC001 `aes.c:11` macro BLOCKLEN is not documented
- DOC001 `aes.c:70` macro Nk is not documented
- DOC001 `aes.c:71` macro Nr is not documented
- DOC001 `aes.c:73` macro Nk is not documented
- DOC001 `aes.c:74` macro Nr is not documented
- DOC001 `aes.c:76` macro Nk is not documented
- DOC001 `aes.c:77` macro Nr is not documented
- DOC001 `aes.c:84` macro MULTIPLY_AS_A_FUNCTION is not documented
- DOC001 `aes.c:239` function AES_init_ctx is not documented
- DOC001 `aes.c:249` function AES_ctx_set_iv is not documented
- DOC001 `aes.c:349` macro Multiply is not documented
- DOC001 `aes.c:496` function AES_ECB_decrypt is not documented
- DOC001 `aes.c:536` function AES_CBC_decrypt_buffer is not documented
- DOC001 `aes.h:9` macro CBC is not documented
- DOC001 `aes.h:12` macro ECB is not documented
- DOC001 `aes.h:15` macro CTR is not documented
- DOC001 `aes.h:18` macro AES256 is not documented
- DOC001 `aes.h:20` macro AES_BLOCKLEN is not documented
- DOC001 `aes.h:23` macro AES_KEYLEN is not documented
- DOC001 `aes.h:24` macro AES_keyExpSize is not documented
- DOC001 `aes.h:26` macro AES_KEYLEN is not documented
- DOC001 `aes.h:27` macro AES_keyExpSize is not documented
- DOC001 `aes.h:29` macro AES_KEYLEN is not documented
- DOC001 `aes.h:30` macro AES_keyExpSize is not documented
- DOC001 `aes.h:33` struct AES_ctx is not documented
- DOC001 `aes.h:41` function AES_init_ctx is not documented
- DOC001 `aes.h:44` function AES_ctx_set_iv is not documented
- DOC001 `aes.h:49` function AES_ECB_decrypt is not documented
- DOC001 `aes.h:54` function AES_CBC_decrypt_buffer is not documented
- DOC001 `beacon.c:1` macro PSAPI_VERSION is not documented
- DOC001 `beacon.c:1` module beacon.c is not documented
- DOC001 `beacon.c:2` macro WIN32_LEAN_AND_MEAN is not documented
- DOC001 `beacon.c:46` macro NT_SUCCESS is not documented
- DOC001 `beacon.c:53` type_alias Length is not documented
- DOC001 `beacon.c:54` struct _UNICODE_STRING is not documented
- DOC001 `beacon.c:59` type_alias Length is not documented
- DOC001 `beacon.c:60` struct _OBJECT_ATTRIBUTES is not documented
- DOC001 `beacon.c:68` type_alias Status is not documented
- DOC001 `beacon.c:69` struct _IO_STATUS_BLOCK is not documented
- DOC001 `beacon.c:77` macro OBJ_CASE_INSENSITIVE is not documented
- DOC001 `beacon.c:79` macro FILE_SYNCHRONOUS_IO_NONALERT is not documented
- DOC001 `beacon.c:81` macro FILE_NON_DIRECTORY_FILE is not documented
- DOC001 `beacon.c:82` macro FILE_DIRECTORY_FILE is not documented
- DOC001 `beacon.c:126` macro DEBUG is not documented
- DOC001 `beacon.c:127` macro TIMEOUT is not documented
- DOC001 `beacon.c:128` macro MAX_RESPONSE_SIZE is not documented
- DOC001 `beacon.c:129` macro C2_URL is not documented
- DOC001 `beacon.c:130` macro MALEABLE is not documented
- DOC001 `beacon.c:131` macro CLIENT_ID is not documented
- DOC001 `beacon.c:132` macro SLEEP_BASE is not documented
- DOC001 `beacon.c:133` macro MIN_JITTER is not documented
- DOC001 `beacon.c:134` macro MAX_JITTER is not documented
- DOC001 `beacon.c:135` macro MAX_RETRIES is not documented
- DOC001 `beacon.c:136` macro C2_HOST is not documented
- DOC001 `beacon.c:137` macro LC2_HOST is not documented
- DOC001 `beacon.c:138` macro C2_USER is not documented
- DOC001 `beacon.c:139` macro C2_PASS is not documented
- DOC001 `beacon.c:140` macro C2_PORT is not documented
- DOC001 `beacon.c:141` macro CONFIG_PATH is not documented
- DOC001 `beacon.c:142` macro C2_PATH is not documented
- DOC001 `beacon.c:143` macro LC2_PATH is not documented
- DOC001 `beacon.c:145` macro min is not documented
- DOC001 `beacon.c:148` macro SECURITY_FLAG_IGNORE_REVOCATION is not documented
- DOC001 `beacon.c:151` macro INVALID_SOCKET is not documented
- DOC001 `beacon.c:153` macro USER_AGENT is not documented
- DOC001 `beacon.c:154` macro USER_AGENT_A is not documented
- DOC001 `beacon.c:155` macro IMAGE_DOS_SIGNATURE is not documented
- DOC001 `beacon.c:156` macro IMAGE_NT_SIGNATURE is not documented
- DOC001 `beacon.c:157` macro IMAGE_NT_OPTIONAL_HDR32_MAGIC is not documented
- DOC001 `beacon.c:158` macro IMAGE_NT_OPTIONAL_HDR64_MAGIC is not documented
- DOC001 `beacon.c:160` macro SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE is not documented
- DOC001 `beacon.c:163` macro SECURITY_FLAG_IGNORE_INVALID_POLICY is not documented
- DOC001 `beacon.c:166` macro _SECURITY_PACKAGE_DEFINITION_ is not documented
- DOC001 `beacon.c:169` macro _PROCESS_BASIC_INFORMATION_ is not documented
- DOC001 `beacon.c:177` macro ProcessBasicInformation is not documented
- DOC001 `beacon.c:180` macro CHECK_ERROR is not documented
- DOC001 `beacon.c:183` struct _PROCESS_BASIC_INFORMATION is not documented
- DOC001 `beacon.c:193` struct ProxySession is not documented
- DOC001 `beacon.c:201` struct ProxyThreadData is not documented
- DOC001 `beacon.c:210` struct ReverseArgs is not documented
- DOC001 `beacon.c:215` struct PortScannerArgs is not documented
- DOC001 `beacon.c:222` struct LazyDataType is not documented
- DOC001 `beacon.c:230` struct ProxyListener is not documented
- DOC001 `beacon.c:643` macro NUM_USER_AGENTS is not documented
- DOC001 `beacon.c:652` macro NUM_URLS is not documented
- DOC001 `beacon.c:659` macro NUM_UAS is not documented
- DOC001 `beacon.c:676` struct _LDR_DATA_TABLE_ENTRY is not documented
- DOC001 `beacon.c:685` type_alias Length is not documented
- DOC001 `beacon.c:686` struct _PEB_LDR_DATA is not documented
- DOC001 `beacon.c:694` type_alias Reserved1 is not documented
- DOC001 `beacon.c:695` struct _PEB is not documented
- DOC001 `beacon.c:708` macro NT_SUCCESS is not documented
- DOC001 `beacon.c:712` type_alias NTSTATUS is not documented
- DOC001 `beacon.c:737` struct PacketEncryptionContext is not documented
- DOC001 `beacon.c:743` function get_shell_cmd is not documented
- DOC001 `beacon.c:751` struct PortResult is not documented
- DOC001 `beacon.c:824` function __declspec is not documented
- DOC001 `beacon.c:841` function __declspec is not documented
- DOC001 `beacon.c:849` function __declspec is not documented
- DOC001 `beacon.c:854` function __declspec is not documented
- DOC001 `beacon.c:859` function __declspec is not documented
- DOC001 `beacon.c:864` function __declspec is not documented
- DOC001 `beacon.c:874` function __declspec is not documented
- DOC001 `beacon.c:922` function __declspec is not documented
- DOC001 `beacon.c:967` function GetSyscallNumber is not documented
- DOC001 `beacon.c:979` function HellsGate is not documented
- DOC001 `beacon.c:984` function __attribute__ is not documented
- DOC001 `beacon.c:1000` function GetProcessIdByName is not documented
- DOC001 `beacon.c:1244` function load_lazyconf is not documented
- DOC001 `beacon.c:1482` function GetNtdllBase is not documented
- DOC001 `beacon.c:1530` function isVMByMAC is not documented
- DOC001 `beacon.c:1639` function hex_to_bytes is not documented
- DOC001 `beacon.c:1885` function GetJitteredSleep is not documented
- DOC001 `beacon.c:1890` function GetUsefulSoftware is not documented
- DOC001 `beacon.c:1925` function base64_encode is not documented
- DOC001 `beacon.c:1961` function base64_decode is not documented
- DOC001 `beacon.c:1994` function discoverLocalHosts is not documented
- DOC001 `beacon.c:2051` function initProxy is not documented
- DOC001 `beacon.c:2221` function startProxy is not documented
- DOC001 `beacon.c:2308` function stopProxy is not documented
- DOC001 `beacon.c:2360` function cleanupProxy is not documented
- DOC001 `beacon.c:2406` function UploadFileToC2 is not documented
- DOC001 `beacon.c:2660` function stristr is not documented
- DOC001 `beacon.c:2676` function isSensitiveFile is not documented
- DOC001 `beacon.c:2723` function searchCredentials is not documented
- DOC001 `beacon.c:3025` function restartClient is not documented
- DOC001 `beacon.c:3066` function checkDebuggers is not documented
- DOC001 `beacon.c:3128` function MapPEToMemory is not documented
- DOC001 `beacon.c:3151` function downloadAndExecute is not documented
- DOC001 `beacon.c:3201` function DecryptPacket is not documented
- DOC001 `beacon.c:3297` function GetIPs is not documented
- DOC001 `beacon.c:3331` function GetHostname is not documented
- DOC001 `beacon.c:3347` function GetUsername is not documented
- DOC001 `beacon.c:3364` function patchAMSI is not documented
- DOC001 `beacon.c:3391` function is_64bit is not documented
- DOC001 `beacon.c:3397` function get_image_size is not documented
- DOC001 `beacon.c:3403` function get_entry_point_rva is not documented
- DOC001 `beacon.c:3409` function pe_buffer_to_virtual_image is not documented
- DOC001 `beacon.c:3439` function create_suspended_process is not documented
- DOC001 `beacon.c:3446` function get_remote_image_base is not documented
- DOC001 `beacon.c:3540` function update_remote_entry_point is not documented
- DOC001 `beacon.c:3842` function tryPrivilegeEscalation is not documented
- DOC001 `beacon.c:3847` function executeUACBypass is not documented
- DOC001 `beacon.c:3900` function scanPort is not documented
- DOC001 `beacon.c:3996` function PortScannerWrapper is not documented
- DOC001 `beacon.c:4228` function init_aes_context is not documented
- DOC001 `beacon.c:4675` function DownloadToBuffer is not documented
- DOC001 `beacon.c:4751` function DownloadFromURL is not documented
- DOC001 `beacon.c:4782` function encrypt_data is not documented
- DOC001 `beacon.c:4840` function isValidUUID is not documented
- DOC001 `beacon.c:4865` function deleteFilesDelay is not documented
- DOC001 `beacon.c:4879` function executeCommand is not documented
- DOC001 `beacon.c:4888` function handleAtomic is not documented
- DOC001 `beacon.c:5031` function SerializeBeaconString is not documented
- DOC001 `beacon.c:5040` function BeaconDataSerializeString is not documented
- DOC001 `beacon.c:5048` function go is not documented
- DOC001 `beacon.c:5065` function hooked is not documented
- DOC001 `beacon.h:1` module beacon.h is not documented
- DOC001 `beacon.h:25` struct datap is not documented
- DOC001 `beacon.h:41` macro CALLBACK_OUTPUT is not documented
- DOC001 `beacon.h:42` macro CALLBACK_ERROR is not documented
- DOC001 `bof/calc/beacon.h:1` module bof/calc/beacon.h is not documented
- DOC001 `bof/calc/beacon.h:25` struct datap is not documented
- DOC001 `bof/calc/beacon.h:41` macro CALLBACK_OUTPUT is not documented
- DOC001 `bof/calc/beacon.h:42` macro CALLBACK_ERROR is not documented
- DOC001 `bof/calc/calc.c:1` module bof/calc/calc.c is not documented
- DOC001 `bof/etw/beacon.h:1` module bof/etw/beacon.h is not documented
- DOC001 `bof/etw/beacon.h:25` struct datap is not documented
- DOC001 `bof/etw/beacon.h:41` macro CALLBACK_OUTPUT is not documented
- DOC001 `bof/etw/beacon.h:42` macro CALLBACK_ERROR is not documented
- DOC001 `bof/etw/etw.c:1` module bof/etw/etw.c is not documented
- DOC001 `bof/etw/etw.c:26` function go is not documented
- DOC001 `bof/whoami/beacon.h:1` module bof/whoami/beacon.h is not documented
- DOC001 `bof/whoami/beacon.h:25` struct datap is not documented
- DOC001 `bof/whoami/beacon.h:41` macro CALLBACK_OUTPUT is not documented
- DOC001 `bof/whoami/beacon.h:42` macro CALLBACK_ERROR is not documented
- DOC001 `bof/whoami/whoami.c:1` module bof/whoami/whoami.c is not documented
- DOC001 `cJSON.c:1` module cJSON.c is not documented
- DOC001 `cJSON.c:28` macro _CRT_SECURE_NO_DEPRECATE is not documented
- DOC001 `cJSON.c:65` macro true is not documented
- DOC001 `cJSON.c:70` macro false is not documented
- DOC001 `cJSON.c:74` macro isinf is not documented
- DOC001 `cJSON.c:77` macro isnan is not documented
- DOC001 `cJSON.c:82` macro NAN is not documented
- DOC001 `cJSON.c:84` macro NAN is not documented
- DOC001 `cJSON.c:88` struct error is not documented
- DOC001 `cJSON.c:95` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:100` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:110` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:125` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:157` struct internal_hooks is not documented
- DOC001 `cJSON.c:179` macro internal_malloc is not documented
- DOC001 `cJSON.c:180` macro internal_free is not documented
- DOC001 `cJSON.c:181` macro internal_realloc is not documented
- DOC001 `cJSON.c:210` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:291` struct parse_buffer is not documented
- DOC001 `cJSON.c:304` macro cannot_access_at_index is not documented
- DOC001 `cJSON.c:482` struct printbuffer is not documented
- DOC001 `cJSON.c:1134` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1236` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1241` macro cjson_min is not documented
- DOC001 `cJSON.c:1316` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1321` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1352` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1935` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1977` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1982` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:1987` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2112` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2123` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2133` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2143` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2155` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2167` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2179` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2191` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2203` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2215` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2227` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2239` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2251` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2287` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2297` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2302` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2309` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2316` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2321` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2363` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2413` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2446` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2451` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2468` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2479` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2490` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2501` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2526` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2543` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2555` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2567` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2579` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2596` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2607` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2659` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2699` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2739` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2786` function cJSON_Duplicate_rec is not documented
- DOC001 `cJSON.c:2922` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2972` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2982` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:2992` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3002` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3012` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3022` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3032` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3042` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3052` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3062` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3072` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3194` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.c:3199` function CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:1` module cJSON.h is not documented
- DOC001 `cJSON.h:24` macro cJSON__h is not documented
- DOC001 `cJSON.h:32` macro __WINDOWS__ is not documented
- DOC001 `cJSON.h:45` macro CJSON_STDCALL is not documented
- DOC001 `cJSON.h:49` macro CJSON_EXPORT_SYMBOLS is not documented
- DOC001 `cJSON.h:53` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:55` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:57` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:61` macro CJSON_STDCALL is not documented
- DOC001 `cJSON.h:64` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:66` macro CJSON_PUBLIC is not documented
- DOC001 `cJSON.h:72` macro CJSON_VERSION_MINOR is not documented
- DOC001 `cJSON.h:73` macro CJSON_VERSION_PATCH is not documented
- DOC001 `cJSON.h:79` macro cJSON_False is not documented
- DOC001 `cJSON.h:80` macro cJSON_True is not documented
- DOC001 `cJSON.h:81` macro cJSON_NULL is not documented
- DOC001 `cJSON.h:82` macro cJSON_Number is not documented
- DOC001 `cJSON.h:83` macro cJSON_String is not documented
- DOC001 `cJSON.h:84` macro cJSON_Array is not documented
- DOC001 `cJSON.h:85` macro cJSON_Object is not documented
- DOC001 `cJSON.h:86` macro cJSON_Raw is not documented
- DOC001 `cJSON.h:88` macro cJSON_IsReference is not documented
- DOC001 `cJSON.h:89` macro cJSON_StringIsConst is not documented
- DOC001 `cJSON.h:114` struct cJSON_Hooks is not documented
- DOC001 `cJSON.h:120` type_alias cJSON_bool is not documented
- DOC001 `cJSON.h:126` macro CJSON_NESTING_LIMIT is not documented
- DOC001 `cJSON.h:132` macro CJSON_CIRCULAR_LIMIT is not documented
- DOC001 `cJSON.h:249` function sensitive is not documented
- DOC001 `cJSON.h:273` macro cJSON_SetNumberValue is not documented
- DOC001 `gen_beacon.sh:5979` function crc32 is not documented
- DOC001 `generate_hashs.py:23` function djb2 is not documented
- DOC001 `generate_hashs.py:223` function generate_coff_loader is not documented
- DOC001 `generate_hashs.py:491` function generate_bof_test is not documented
- DOC001 `generate_hashs.py:553` function main is not documented
- DOC001 `install.sh:1` module install.sh is not documented
