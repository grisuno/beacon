# Symbols

| Symbol | Kind | File:Line | Signature |
|--------|------|-----------|-----------|
| `COFFLOADER_H` | macro | `COFFLoader.h:21` | `#define COFFLOADER_H` |
| `Copyright` | function | `COFFLoader.h:16` | `Copyright (c) LazyOwn RedTeam 2025. All rights reserved. */ #ifndef COFFLOADER_H #define COFFLOADER_H #include <windows.` |
| `BeaconPrintf` | function | `COFFLoader3.c:915` | `BeaconPrintf(CALLBACK_ERROR, "[BOF] create_trampoline nulled target=NULL\n");` |
| `COFFHeader` | struct | `COFFLoader3.c:620` | `` |
| `COFFRelocation` | struct | `COFFLoader3.c:599` | `` |
| `COFFSection` | struct | `COFFLoader3.c:586` | `` |
| `IMAGE_REL_AMD64_ABSOLUTE` | macro | `COFFLoader3.c:568` | `#define IMAGE_REL_AMD64_ABSOLUTE` |
| `IMAGE_REL_AMD64_ADDR32` | macro | `COFFLoader3.c:570` | `#define IMAGE_REL_AMD64_ADDR32` |
| `IMAGE_REL_AMD64_ADDR32NB` | macro | `COFFLoader3.c:571` | `#define IMAGE_REL_AMD64_ADDR32NB` |
| `IMAGE_REL_AMD64_ADDR64` | macro | `COFFLoader3.c:569` | `#define IMAGE_REL_AMD64_ADDR64` |
| `IMAGE_REL_AMD64_PAIR` | macro | `COFFLoader3.c:583` | `#define IMAGE_REL_AMD64_PAIR` |
| `IMAGE_REL_AMD64_REL32` | macro | `COFFLoader3.c:572` | `#define IMAGE_REL_AMD64_REL32` |
| `IMAGE_REL_AMD64_REL32_1` | macro | `COFFLoader3.c:573` | `#define IMAGE_REL_AMD64_REL32_1` |
| `IMAGE_REL_AMD64_REL32_2` | macro | `COFFLoader3.c:574` | `#define IMAGE_REL_AMD64_REL32_2` |
| `IMAGE_REL_AMD64_REL32_3` | macro | `COFFLoader3.c:575` | `#define IMAGE_REL_AMD64_REL32_3` |
| `IMAGE_REL_AMD64_REL32_4` | macro | `COFFLoader3.c:576` | `#define IMAGE_REL_AMD64_REL32_4` |
| `IMAGE_REL_AMD64_REL32_5` | macro | `COFFLoader3.c:577` | `#define IMAGE_REL_AMD64_REL32_5` |
| `IMAGE_REL_AMD64_SECREL` | macro | `COFFLoader3.c:579` | `#define IMAGE_REL_AMD64_SECREL` |
| `IMAGE_REL_AMD64_SECREL7` | macro | `COFFLoader3.c:580` | `#define IMAGE_REL_AMD64_SECREL7` |
| `IMAGE_REL_AMD64_SECTION` | macro | `COFFLoader3.c:578` | `#define IMAGE_REL_AMD64_SECTION` |
| `IMAGE_REL_AMD64_SREL32` | macro | `COFFLoader3.c:582` | `#define IMAGE_REL_AMD64_SREL32` |
| `IMAGE_REL_AMD64_SSPAN32` | macro | `COFFLoader3.c:584` | `#define IMAGE_REL_AMD64_SSPAN32` |
| `IMAGE_REL_AMD64_TOKEN` | macro | `COFFLoader3.c:581` | `#define IMAGE_REL_AMD64_TOKEN` |
| `RunCOFF` | function | `COFFLoader3.c:1112` | `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...` |
| `SymbolHash` | struct | `COFFLoader3.c:642` | `` |
| `VirtualFree` | function | `COFFLoader3.c:1379` | `VirtualFree(g_trampoline_page, 0, MEM_RELEASE);` |
| `VirtualProtect` | function | `COFFLoader3.c:959` | `VirtualProtect(patch_addr, sizeof(uint64_t), oldProtect, &oldProtect);` |
| `VirtualQuery` | function | `COFFLoader3.c:1357` | `VirtualQuery(go, &mbi, sizeof(mbi));` |
| `__attribute__` | function | `COFFLoader3.c:1102` | `__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2)` |
| `__imp_AdjustTokenPrivileges` | variable | `COFFLoader3.c:450` | `extern PVOID __imp_AdjustTokenPrivileges;` |
| `__imp_AllocConsole` | variable | `COFFLoader3.c:436` | `extern PVOID __imp_AllocConsole;` |
| `__imp_AttachConsole` | variable | `COFFLoader3.c:438` | `extern PVOID __imp_AttachConsole;` |
| `__imp_BeaconDataExtract` | variable | `COFFLoader3.c:337` | `extern PVOID __imp_BeaconDataExtract;` |
| `__imp_BeaconDataInt` | variable | `COFFLoader3.c:335` | `extern PVOID __imp_BeaconDataInt;` |
| `__imp_BeaconDataParse` | variable | `COFFLoader3.c:334` | `extern PVOID __imp_BeaconDataParse;` |
| `__imp_BeaconDataShort` | variable | `COFFLoader3.c:336` | `extern PVOID __imp_BeaconDataShort;` |
| `__imp_BeaconOutput` | variable | `COFFLoader3.c:333` | `extern PVOID __imp_BeaconOutput;` |
| `__imp_BeaconPrintf` | variable | `COFFLoader3.c:328` | `extern PVOID __imp_BeaconPrintf;` |
| `__imp_CheckRemoteDebuggerPresent` | variable | `COFFLoader3.c:440` | `extern PVOID __imp_CheckRemoteDebuggerPresent;` |
| `__imp_CloseHandle` | variable | `COFFLoader3.c:344` | `extern PVOID __imp_CloseHandle;` |
| `__imp_CoCreateInstance` | variable | `COFFLoader3.c:481` | `extern PVOID __imp_CoCreateInstance;` |
| `__imp_CoInitializeEx` | variable | `COFFLoader3.c:479` | `extern PVOID __imp_CoInitializeEx;` |
| `__imp_CoTaskMemFree` | variable | `COFFLoader3.c:482` | `extern PVOID __imp_CoTaskMemFree;` |
| `__imp_CoUninitialize` | variable | `COFFLoader3.c:480` | `extern PVOID __imp_CoUninitialize;` |
| `__imp_CopyFileA` | variable | `COFFLoader3.c:364` | `extern PVOID __imp_CopyFileA;` |
| `__imp_CopyFileW` | variable | `COFFLoader3.c:365` | `extern PVOID __imp_CopyFileW;` |
| `__imp_CreateDirectoryA` | variable | `COFFLoader3.c:368` | `extern PVOID __imp_CreateDirectoryA;` |
| `__imp_CreateDirectoryW` | variable | `COFFLoader3.c:369` | `extern PVOID __imp_CreateDirectoryW;` |
| `__imp_CreateFileA` | variable | `COFFLoader3.c:354` | `extern PVOID __imp_CreateFileA;` |
| `__imp_CreateFileW` | variable | `COFFLoader3.c:355` | `extern PVOID __imp_CreateFileW;` |
| `__imp_CreateProcessA` | variable | `COFFLoader3.c:551` | `extern PVOID __imp_CreateProcessA;` |
| `__imp_CreateProcessAsUserA` | variable | `COFFLoader3.c:451` | `extern PVOID __imp_CreateProcessAsUserA;` |
| `__imp_CreateProcessAsUserW` | variable | `COFFLoader3.c:452` | `extern PVOID __imp_CreateProcessAsUserW;` |
| `__imp_CreateProcessW` | variable | `COFFLoader3.c:552` | `extern PVOID __imp_CreateProcessW;` |
| `__imp_CreateThread` | variable | `COFFLoader3.c:348` | `extern PVOID __imp_CreateThread;` |
| `__imp_CreateToolhelp32Snapshot` | variable | `COFFLoader3.c:549` | `extern PVOID __imp_CreateToolhelp32Snapshot;` |
| `__imp_CryptAcquireContextA` | variable | `COFFLoader3.c:468` | `extern PVOID __imp_CryptAcquireContextA;` |
| `__imp_CryptAcquireContextW` | variable | `COFFLoader3.c:469` | `extern PVOID __imp_CryptAcquireContextW;` |
| `__imp_CryptCreateHash` | variable | `COFFLoader3.c:470` | `extern PVOID __imp_CryptCreateHash;` |
| `__imp_CryptDecrypt` | variable | `COFFLoader3.c:474` | `extern PVOID __imp_CryptDecrypt;` |
| `__imp_CryptDeriveKey` | variable | `COFFLoader3.c:472` | `extern PVOID __imp_CryptDeriveKey;` |
| `__imp_CryptDestroyHash` | variable | `COFFLoader3.c:476` | `extern PVOID __imp_CryptDestroyHash;` |
| `__imp_CryptDestroyKey` | variable | `COFFLoader3.c:477` | `extern PVOID __imp_CryptDestroyKey;` |
| `__imp_CryptEncrypt` | variable | `COFFLoader3.c:473` | `extern PVOID __imp_CryptEncrypt;` |
| `__imp_CryptGenRandom` | variable | `COFFLoader3.c:478` | `extern PVOID __imp_CryptGenRandom;` |
| `__imp_CryptHashData` | variable | `COFFLoader3.c:471` | `extern PVOID __imp_CryptHashData;` |
| `__imp_CryptReleaseContext` | variable | `COFFLoader3.c:475` | `extern PVOID __imp_CryptReleaseContext;` |
| `__imp_DeleteFileA` | variable | `COFFLoader3.c:360` | `extern PVOID __imp_DeleteFileA;` |
| `__imp_DeleteFileW` | variable | `COFFLoader3.c:361` | `extern PVOID __imp_DeleteFileW;` |
| `__imp_DuplicateTokenEx` | variable | `COFFLoader3.c:445` | `extern PVOID __imp_DuplicateTokenEx;` |
| `__imp_EnumProcessModules` | variable | `COFFLoader3.c:510` | `extern PVOID __imp_EnumProcessModules;` |
| `__imp_EnumProcesses` | variable | `COFFLoader3.c:509` | `extern PVOID __imp_EnumProcesses;` |
| `__imp_EnumWindows` | variable | `COFFLoader3.c:502` | `extern PVOID __imp_EnumWindows;` |
| `__imp_ExitProcess` | variable | `COFFLoader3.c:345` | `extern PVOID __imp_ExitProcess;` |
| `__imp_ExitThread` | variable | `COFFLoader3.c:346` | `extern PVOID __imp_ExitThread;` |
| `__imp_ExpandEnvironmentStringsA` | variable | `COFFLoader3.c:426` | `extern PVOID __imp_ExpandEnvironmentStringsA;` |
| `__imp_ExpandEnvironmentStringsW` | variable | `COFFLoader3.c:427` | `extern PVOID __imp_ExpandEnvironmentStringsW;` |
| `__imp_FindClose` | variable | `COFFLoader3.c:376` | `extern PVOID __imp_FindClose;` |
| `__imp_FindFirstFileA` | variable | `COFFLoader3.c:372` | `extern PVOID __imp_FindFirstFileA;` |
| `__imp_FindFirstFileW` | variable | `COFFLoader3.c:373` | `extern PVOID __imp_FindFirstFileW;` |
| `__imp_FindNextFileA` | variable | `COFFLoader3.c:374` | `extern PVOID __imp_FindNextFileA;` |
| `__imp_FindNextFileW` | variable | `COFFLoader3.c:375` | `extern PVOID __imp_FindNextFileW;` |
| `__imp_FindWindowA` | variable | `COFFLoader3.c:500` | `extern PVOID __imp_FindWindowA;` |
| `__imp_FindWindowW` | variable | `COFFLoader3.c:501` | `extern PVOID __imp_FindWindowW;` |
| `__imp_FormatMessageA` | variable | `COFFLoader3.c:420` | `extern PVOID __imp_FormatMessageA;` |
| `__imp_FormatMessageW` | variable | `COFFLoader3.c:421` | `extern PVOID __imp_FormatMessageW;` |
| `__imp_FreeConsole` | variable | `COFFLoader3.c:437` | `extern PVOID __imp_FreeConsole;` |
| `__imp_FreeLibrary` | variable | `COFFLoader3.c:434` | `extern PVOID __imp_FreeLibrary;` |
| `__imp_GetClassNameA` | variable | `COFFLoader3.c:505` | `extern PVOID __imp_GetClassNameA;` |
| `__imp_GetClassNameW` | variable | `COFFLoader3.c:506` | `extern PVOID __imp_GetClassNameW;` |
| `__imp_GetCommandLineA` | variable | `COFFLoader3.c:428` | `extern PVOID __imp_GetCommandLineA;` |
| `__imp_GetCommandLineW` | variable | `COFFLoader3.c:429` | `extern PVOID __imp_GetCommandLineW;` |
| `__imp_GetComputerNameA` | variable | `COFFLoader3.c:387` | `extern PVOID __imp_GetComputerNameA;` |
| `__imp_GetComputerNameW` | variable | `COFFLoader3.c:388` | `extern PVOID __imp_GetComputerNameW;` |
| `__imp_GetConsoleWindow` | variable | `COFFLoader3.c:435` | `extern PVOID __imp_GetConsoleWindow;` |
| `__imp_GetCurrentProcess` | variable | `COFFLoader3.c:349` | `extern PVOID __imp_GetCurrentProcess;` |
| `__imp_GetCurrentProcessId` | variable | `COFFLoader3.c:350` | `extern PVOID __imp_GetCurrentProcessId;` |
| `__imp_GetCurrentThreadId` | variable | `COFFLoader3.c:351` | `extern PVOID __imp_GetCurrentThreadId;` |
| `__imp_GetDesktopWindow` | variable | `COFFLoader3.c:498` | `extern PVOID __imp_GetDesktopWindow;` |
| `__imp_GetEnvironmentVariableA` | variable | `COFFLoader3.c:422` | `extern PVOID __imp_GetEnvironmentVariableA;` |
| `__imp_GetEnvironmentVariableW` | variable | `COFFLoader3.c:423` | `extern PVOID __imp_GetEnvironmentVariableW;` |
| `__imp_GetFileAttributesA` | variable | `COFFLoader3.c:377` | `extern PVOID __imp_GetFileAttributesA;` |
| `__imp_GetFileAttributesW` | variable | `COFFLoader3.c:378` | `extern PVOID __imp_GetFileAttributesW;` |
| `__imp_GetFileSize` | variable | `COFFLoader3.c:366` | `extern PVOID __imp_GetFileSize;` |
| `__imp_GetFileSizeEx` | variable | `COFFLoader3.c:367` | `extern PVOID __imp_GetFileSizeEx;` |
| `__imp_GetLastError` | variable | `COFFLoader3.c:343` | `extern PVOID __imp_GetLastError;` |
| `__imp_GetModuleBaseNameA` | variable | `COFFLoader3.c:511` | `extern PVOID __imp_GetModuleBaseNameA;` |
| `__imp_GetModuleBaseNameW` | variable | `COFFLoader3.c:512` | `extern PVOID __imp_GetModuleBaseNameW;` |
| `__imp_GetModuleFileNameA` | variable | `COFFLoader3.c:430` | `extern PVOID __imp_GetModuleFileNameA;` |
| `__imp_GetModuleFileNameW` | variable | `COFFLoader3.c:431` | `extern PVOID __imp_GetModuleFileNameW;` |
| `__imp_GetModuleHandleA` | variable | `COFFLoader3.c:340` | `extern PVOID __imp_GetModuleHandleA;` |
| `__imp_GetModuleHandleW` | variable | `COFFLoader3.c:341` | `extern PVOID __imp_GetModuleHandleW;` |
| `__imp_GetModuleInformation` | variable | `COFFLoader3.c:513` | `extern PVOID __imp_GetModuleInformation;` |
| `__imp_GetNativeSystemInfo` | variable | `COFFLoader3.c:393` | `extern PVOID __imp_GetNativeSystemInfo;` |
| `__imp_GetProcAddress` | variable | `COFFLoader3.c:342` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_GetShellWindow` | variable | `COFFLoader3.c:499` | `extern PVOID __imp_GetShellWindow;` |
| `__imp_GetStartupInfoA` | variable | `COFFLoader3.c:432` | `extern PVOID __imp_GetStartupInfoA;` |
| `__imp_GetStartupInfoW` | variable | `COFFLoader3.c:433` | `extern PVOID __imp_GetStartupInfoW;` |
| `__imp_GetSystemDirectoryA` | variable | `COFFLoader3.c:381` | `extern PVOID __imp_GetSystemDirectoryA;` |
| `__imp_GetSystemDirectoryW` | variable | `COFFLoader3.c:382` | `extern PVOID __imp_GetSystemDirectoryW;` |
| `__imp_GetTempPathA` | variable | `COFFLoader3.c:385` | `extern PVOID __imp_GetTempPathA;` |
| `__imp_GetTempPathW` | variable | `COFFLoader3.c:386` | `extern PVOID __imp_GetTempPathW;` |
| `__imp_GetTickCount` | variable | `COFFLoader3.c:352` | `extern PVOID __imp_GetTickCount;` |
| `__imp_GetTickCount64` | variable | `COFFLoader3.c:353` | `extern PVOID __imp_GetTickCount64;` |
| `__imp_GetUserNameA` | variable | `COFFLoader3.c:389` | `extern PVOID __imp_GetUserNameA;` |
| `__imp_GetUserNameW` | variable | `COFFLoader3.c:390` | `extern PVOID __imp_GetUserNameW;` |
| `__imp_GetVersionExA` | variable | `COFFLoader3.c:391` | `extern PVOID __imp_GetVersionExA;` |
| `__imp_GetVersionExW` | variable | `COFFLoader3.c:392` | `extern PVOID __imp_GetVersionExW;` |
| `__imp_GetWindowTextA` | variable | `COFFLoader3.c:503` | `extern PVOID __imp_GetWindowTextA;` |
| `__imp_GetWindowTextW` | variable | `COFFLoader3.c:504` | `extern PVOID __imp_GetWindowTextW;` |
| `__imp_GetWindowsDirectoryA` | variable | `COFFLoader3.c:383` | `extern PVOID __imp_GetWindowsDirectoryA;` |
| `__imp_GetWindowsDirectoryW` | variable | `COFFLoader3.c:384` | `extern PVOID __imp_GetWindowsDirectoryW;` |
| `__imp_GlobalAlloc` | variable | `COFFLoader3.c:402` | `extern PVOID __imp_GlobalAlloc;` |
| `__imp_GlobalFree` | variable | `COFFLoader3.c:403` | `extern PVOID __imp_GlobalFree;` |
| `__imp_HeapAlloc` | variable | `COFFLoader3.c:398` | `extern PVOID __imp_HeapAlloc;` |
| `__imp_HeapFree` | variable | `COFFLoader3.c:399` | `extern PVOID __imp_HeapFree;` |
| `__imp_IIDFromString` | variable | `COFFLoader3.c:483` | `extern PVOID __imp_IIDFromString;` |
| `__imp_ImpersonateLoggedOnUser` | variable | `COFFLoader3.c:446` | `extern PVOID __imp_ImpersonateLoggedOnUser;` |
| `__imp_IsDebuggerPresent` | variable | `COFFLoader3.c:439` | `extern PVOID __imp_IsDebuggerPresent;` |
| `__imp_IsWow64Process` | variable | `COFFLoader3.c:547` | `extern PVOID __imp_IsWow64Process;` |
| `__imp_LoadLibraryA` | variable | `COFFLoader3.c:338` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_LoadLibraryW` | variable | `COFFLoader3.c:339` | `extern PVOID __imp_LoadLibraryW;` |
| `__imp_LocalAlloc` | variable | `COFFLoader3.c:400` | `extern PVOID __imp_LocalAlloc;` |
| `__imp_LocalFree` | variable | `COFFLoader3.c:401` | `extern PVOID __imp_LocalFree;` |
| `__imp_LookupPrivilegeValueA` | variable | `COFFLoader3.c:448` | `extern PVOID __imp_LookupPrivilegeValueA;` |
| `__imp_LookupPrivilegeValueW` | variable | `COFFLoader3.c:449` | `extern PVOID __imp_LookupPrivilegeValueW;` |
| `__imp_MoveFileA` | variable | `COFFLoader3.c:362` | `extern PVOID __imp_MoveFileA;` |
| `__imp_MoveFileW` | variable | `COFFLoader3.c:363` | `extern PVOID __imp_MoveFileW;` |
| `__imp_MultiByteToWideChar` | variable | `COFFLoader3.c:418` | `extern PVOID __imp_MultiByteToWideChar;` |
| `__imp_NetApiBufferFree` | variable | `COFFLoader3.c:539` | `extern PVOID __imp_NetApiBufferFree;` |
| `__imp_NetLocalGroupEnum` | variable | `COFFLoader3.c:535` | `extern PVOID __imp_NetLocalGroupEnum;` |
| `__imp_NetSessionEnum` | variable | `COFFLoader3.c:538` | `extern PVOID __imp_NetSessionEnum;` |
| `__imp_NetShareEnum` | variable | `COFFLoader3.c:536` | `extern PVOID __imp_NetShareEnum;` |
| `__imp_NetUserEnum` | variable | `COFFLoader3.c:534` | `extern PVOID __imp_NetUserEnum;` |
| `__imp_NetWkstaUserEnum` | variable | `COFFLoader3.c:537` | `extern PVOID __imp_NetWkstaUserEnum;` |
| `__imp_NtQueryInformationThread` | variable | `COFFLoader3.c:557` | `extern PVOID __imp_NtQueryInformationThread;` |
| `__imp_OpenProcess` | variable | `COFFLoader3.c:443` | `extern PVOID __imp_OpenProcess;` |
| `__imp_OpenProcessToken` | variable | `COFFLoader3.c:444` | `extern PVOID __imp_OpenProcessToken;` |
| `__imp_OpenThread` | variable | `COFFLoader3.c:554` | `extern PVOID __imp_OpenThread;` |
| `__imp_OutputDebugStringA` | variable | `COFFLoader3.c:441` | `extern PVOID __imp_OutputDebugStringA;` |
| `__imp_OutputDebugStringW` | variable | `COFFLoader3.c:442` | `extern PVOID __imp_OutputDebugStringW;` |
| `__imp_PathCombineA` | variable | `COFFLoader3.c:496` | `extern PVOID __imp_PathCombineA;` |
| `__imp_PathCombineW` | variable | `COFFLoader3.c:497` | `extern PVOID __imp_PathCombineW;` |
| `__imp_PathFileExistsA` | variable | `COFFLoader3.c:494` | `extern PVOID __imp_PathFileExistsA;` |
| `__imp_PathFileExistsW` | variable | `COFFLoader3.c:495` | `extern PVOID __imp_PathFileExistsW;` |
| `__imp_Process32First` | variable | `COFFLoader3.c:548` | `extern PVOID __imp_Process32First;` |
| `__imp_Process32Next` | variable | `COFFLoader3.c:546` | `extern PVOID __imp_Process32Next;` |
| `__imp_ReadFile` | variable | `COFFLoader3.c:356` | `extern PVOID __imp_ReadFile;` |
| `__imp_RegCloseKey` | variable | `COFFLoader3.c:463` | `extern PVOID __imp_RegCloseKey;` |
| `__imp_RegCreateKeyExA` | variable | `COFFLoader3.c:455` | `extern PVOID __imp_RegCreateKeyExA;` |
| `__imp_RegCreateKeyExW` | variable | `COFFLoader3.c:456` | `extern PVOID __imp_RegCreateKeyExW;` |
| `__imp_RegDeleteValueA` | variable | `COFFLoader3.c:461` | `extern PVOID __imp_RegDeleteValueA;` |
| `__imp_RegDeleteValueW` | variable | `COFFLoader3.c:462` | `extern PVOID __imp_RegDeleteValueW;` |
| `__imp_RegEnumKeyExA` | variable | `COFFLoader3.c:464` | `extern PVOID __imp_RegEnumKeyExA;` |
| `__imp_RegEnumKeyExW` | variable | `COFFLoader3.c:465` | `extern PVOID __imp_RegEnumKeyExW;` |
| `__imp_RegEnumValueA` | variable | `COFFLoader3.c:466` | `extern PVOID __imp_RegEnumValueA;` |
| `__imp_RegEnumValueW` | variable | `COFFLoader3.c:467` | `extern PVOID __imp_RegEnumValueW;` |
| `__imp_RegOpenKeyExA` | variable | `COFFLoader3.c:453` | `extern PVOID __imp_RegOpenKeyExA;` |
| `__imp_RegOpenKeyExW` | variable | `COFFLoader3.c:454` | `extern PVOID __imp_RegOpenKeyExW;` |
| `__imp_RegQueryValueExA` | variable | `COFFLoader3.c:459` | `extern PVOID __imp_RegQueryValueExA;` |
| `__imp_RegQueryValueExW` | variable | `COFFLoader3.c:460` | `extern PVOID __imp_RegQueryValueExW;` |
| `__imp_RegSetValueExA` | variable | `COFFLoader3.c:457` | `extern PVOID __imp_RegSetValueExA;` |
| `__imp_RegSetValueExW` | variable | `COFFLoader3.c:458` | `extern PVOID __imp_RegSetValueExW;` |
| `__imp_RemoveDirectoryA` | variable | `COFFLoader3.c:370` | `extern PVOID __imp_RemoveDirectoryA;` |
| `__imp_RemoveDirectoryW` | variable | `COFFLoader3.c:371` | `extern PVOID __imp_RemoveDirectoryW;` |
| `__imp_RevertToSelf` | variable | `COFFLoader3.c:447` | `extern PVOID __imp_RevertToSelf;` |
| `__imp_RtlCopyMemory` | variable | `COFFLoader3.c:405` | `extern PVOID __imp_RtlCopyMemory;` |
| `__imp_RtlFillMemory` | variable | `COFFLoader3.c:406` | `extern PVOID __imp_RtlFillMemory;` |
| `__imp_RtlMoveMemory` | variable | `COFFLoader3.c:404` | `extern PVOID __imp_RtlMoveMemory;` |
| `__imp_RtlZeroMemory` | variable | `COFFLoader3.c:407` | `extern PVOID __imp_RtlZeroMemory;` |
| `__imp_SHGetFolderPathA` | variable | `COFFLoader3.c:491` | `extern PVOID __imp_SHGetFolderPathA;` |
| `__imp_SHGetFolderPathW` | variable | `COFFLoader3.c:492` | `extern PVOID __imp_SHGetFolderPathW;` |
| `__imp_SHGetKnownFolderPath` | variable | `COFFLoader3.c:493` | `extern PVOID __imp_SHGetKnownFolderPath;` |
| `__imp_SendMessageA` | variable | `COFFLoader3.c:507` | `extern PVOID __imp_SendMessageA;` |
| `__imp_SendMessageW` | variable | `COFFLoader3.c:508` | `extern PVOID __imp_SendMessageW;` |
| `__imp_SetEndOfFile` | variable | `COFFLoader3.c:359` | `extern PVOID __imp_SetEndOfFile;` |
| `__imp_SetEnvironmentVariableA` | variable | `COFFLoader3.c:424` | `extern PVOID __imp_SetEnvironmentVariableA;` |
| `__imp_SetEnvironmentVariableW` | variable | `COFFLoader3.c:425` | `extern PVOID __imp_SetEnvironmentVariableW;` |
| `__imp_SetFileAttributesA` | variable | `COFFLoader3.c:379` | `extern PVOID __imp_SetFileAttributesA;` |
| `__imp_SetFileAttributesW` | variable | `COFFLoader3.c:380` | `extern PVOID __imp_SetFileAttributesW;` |
| `__imp_SetFilePointer` | variable | `COFFLoader3.c:358` | `extern PVOID __imp_SetFilePointer;` |
| `__imp_Sleep` | variable | `COFFLoader3.c:347` | `extern PVOID __imp_Sleep;` |
| `__imp_StringFromGUID2` | variable | `COFFLoader3.c:484` | `extern PVOID __imp_StringFromGUID2;` |
| `__imp_SuspendThread` | variable | `COFFLoader3.c:553` | `extern PVOID __imp_SuspendThread;` |
| `__imp_SysAllocString` | variable | `COFFLoader3.c:488` | `extern PVOID __imp_SysAllocString;` |
| `__imp_SysFreeString` | variable | `COFFLoader3.c:489` | `extern PVOID __imp_SysFreeString;` |
| `__imp_SysStringLen` | variable | `COFFLoader3.c:490` | `extern PVOID __imp_SysStringLen;` |
| `__imp_Thread32First` | variable | `COFFLoader3.c:555` | `extern PVOID __imp_Thread32First;` |
| `__imp_Thread32Next` | variable | `COFFLoader3.c:556` | `extern PVOID __imp_Thread32Next;` |
| `__imp_VariantChangeType` | variable | `COFFLoader3.c:487` | `extern PVOID __imp_VariantChangeType;` |
| `__imp_VariantClear` | variable | `COFFLoader3.c:486` | `extern PVOID __imp_VariantClear;` |
| `__imp_VariantInit` | variable | `COFFLoader3.c:485` | `extern PVOID __imp_VariantInit;` |
| `__imp_VirtualAlloc` | variable | `COFFLoader3.c:394` | `extern PVOID __imp_VirtualAlloc;` |
| `__imp_VirtualFree` | variable | `COFFLoader3.c:395` | `extern PVOID __imp_VirtualFree;` |
| `__imp_VirtualProtect` | variable | `COFFLoader3.c:396` | `extern PVOID __imp_VirtualProtect;` |
| `__imp_VirtualQuery` | variable | `COFFLoader3.c:397` | `extern PVOID __imp_VirtualQuery;` |
| `__imp_WNetCloseEnum` | variable | `COFFLoader3.c:544` | `extern PVOID __imp_WNetCloseEnum;` |
| `__imp_WNetEnumResourceA` | variable | `COFFLoader3.c:542` | `extern PVOID __imp_WNetEnumResourceA;` |
| `__imp_WNetEnumResourceW` | variable | `COFFLoader3.c:543` | `extern PVOID __imp_WNetEnumResourceW;` |
| `__imp_WNetOpenEnumA` | variable | `COFFLoader3.c:540` | `extern PVOID __imp_WNetOpenEnumA;` |
| `__imp_WNetOpenEnumW` | variable | `COFFLoader3.c:541` | `extern PVOID __imp_WNetOpenEnumW;` |
| `__imp_WSACleanup` | variable | `COFFLoader3.c:517` | `extern PVOID __imp_WSACleanup;` |
| `__imp_WSASocketA` | variable | `COFFLoader3.c:514` | `extern PVOID __imp_WSASocketA;` |
| `__imp_WSASocketW` | variable | `COFFLoader3.c:515` | `extern PVOID __imp_WSASocketW;` |
| `__imp_WSAStartup` | variable | `COFFLoader3.c:516` | `extern PVOID __imp_WSAStartup;` |
| `__imp_WideCharToMultiByte` | variable | `COFFLoader3.c:419` | `extern PVOID __imp_WideCharToMultiByte;` |
| `__imp_WriteFile` | variable | `COFFLoader3.c:357` | `extern PVOID __imp_WriteFile;` |
| `__imp__stricmp` | variable | `COFFLoader3.c:545` | `extern PVOID __imp__stricmp;` |
| `__imp_accept` | variable | `COFFLoader3.c:520` | `extern PVOID __imp_accept;` |
| `__imp_bind` | variable | `COFFLoader3.c:518` | `extern PVOID __imp_bind;` |
| `__imp_closesocket` | variable | `COFFLoader3.c:524` | `extern PVOID __imp_closesocket;` |
| `__imp_connect` | variable | `COFFLoader3.c:521` | `extern PVOID __imp_connect;` |
| `__imp_freeaddrinfo` | variable | `COFFLoader3.c:529` | `extern PVOID __imp_freeaddrinfo;` |
| `__imp_getaddrinfo` | variable | `COFFLoader3.c:528` | `extern PVOID __imp_getaddrinfo;` |
| `__imp_gethostbyname` | variable | `COFFLoader3.c:527` | `extern PVOID __imp_gethostbyname;` |
| `__imp_gethostname` | variable | `COFFLoader3.c:526` | `extern PVOID __imp_gethostname;` |
| `__imp_htonl` | variable | `COFFLoader3.c:532` | `extern PVOID __imp_htonl;` |
| `__imp_htons` | variable | `COFFLoader3.c:530` | `extern PVOID __imp_htons;` |
| `__imp_ioctlsocket` | variable | `COFFLoader3.c:525` | `extern PVOID __imp_ioctlsocket;` |
| `__imp_listen` | variable | `COFFLoader3.c:519` | `extern PVOID __imp_listen;` |
| `__imp_lstrcatA` | variable | `COFFLoader3.c:412` | `extern PVOID __imp_lstrcatA;` |
| `__imp_lstrcatW` | variable | `COFFLoader3.c:413` | `extern PVOID __imp_lstrcatW;` |
| `__imp_lstrcmpA` | variable | `COFFLoader3.c:414` | `extern PVOID __imp_lstrcmpA;` |
| `__imp_lstrcmpW` | variable | `COFFLoader3.c:415` | `extern PVOID __imp_lstrcmpW;` |
| `__imp_lstrcmpiA` | variable | `COFFLoader3.c:416` | `extern PVOID __imp_lstrcmpiA;` |
| `__imp_lstrcmpiW` | variable | `COFFLoader3.c:417` | `extern PVOID __imp_lstrcmpiW;` |
| `__imp_lstrcpyA` | variable | `COFFLoader3.c:410` | `extern PVOID __imp_lstrcpyA;` |
| `__imp_lstrcpyW` | variable | `COFFLoader3.c:411` | `extern PVOID __imp_lstrcpyW;` |
| `__imp_lstrlenA` | variable | `COFFLoader3.c:408` | `extern PVOID __imp_lstrlenA;` |
| `__imp_lstrlenW` | variable | `COFFLoader3.c:409` | `extern PVOID __imp_lstrlenW;` |
| `__imp_ntohl` | variable | `COFFLoader3.c:533` | `extern PVOID __imp_ntohl;` |
| `__imp_ntohs` | variable | `COFFLoader3.c:531` | `extern PVOID __imp_ntohs;` |
| `__imp_recv` | variable | `COFFLoader3.c:523` | `extern PVOID __imp_recv;` |
| `__imp_select` | variable | `COFFLoader3.c:550` | `extern PVOID __imp_select;` |
| `__imp_send` | variable | `COFFLoader3.c:522` | `extern PVOID __imp_send;` |
| `call_go_aligned` | function | `COFFLoader3.c:1365` | `call_go_aligned(go, (char*)argumentdata, argumentSize);` |
| `create_trampoline` | function | `COFFLoader3.c:912` | `static void* create_trampoline(void* target)` |
| `djb2_hash` | function | `COFFLoader3.c:632` | `static uint32_t djb2_hash(const char* str)` |
| `f` | function | `COFFLoader3.c:1107` | `f(arg1, arg2);` |
| `free` | function | `COFFLoader3.c:1376` | `free(sections);` |
| `g_pNtCreateFileUnhooked` | variable | `COFFLoader3.c:558` | `extern PVOID g_pNtCreateFileUnhooked;` |
| `g_pNtCreateThreadExUnhooked` | variable | `COFFLoader3.c:565` | `extern PVOID g_pNtCreateThreadExUnhooked;` |
| `g_pNtProtectVirtualMemoryUnhooked` | variable | `COFFLoader3.c:563` | `extern PVOID g_pNtProtectVirtualMemoryUnhooked;` |
| `g_pNtResumeThreadUnhooked` | variable | `COFFLoader3.c:564` | `extern PVOID g_pNtResumeThreadUnhooked;` |
| `g_pNtWriteVirtualMemoryUnhooked` | variable | `COFFLoader3.c:562` | `extern PVOID g_pNtWriteVirtualMemoryUnhooked;` |
| `get_symbol_name` | function | `COFFLoader3.c:1079` | `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)` |
| `handle_relocation` | function | `COFFLoader3.c:940` | `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...` |
| `memcpy` | function | `COFFLoader3.c:1092` | `memcpy(short_name, s->Name, 8);` |
| `void` | function | `COFFLoader3.c:906` | `typedef void (__attribute__((ms_abi)) * bof_func_t)(char*, int);` |
| `AES_CBC_decrypt_buffer` | function | `aes.c:535` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_CBC_encrypt_buffer` | function | `aes.c:520` | `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)` |
| `AES_CTR_xcrypt_buffer` | function | `aes.c:558` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` |
| `AES_ECB_decrypt` | function | `aes.c:495` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ECB_encrypt` | function | `aes.c:488` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` |
| `AES_ctx_set_iv` | function | `aes.c:249` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)` |
| `AES_init_ctx` | function | `aes.c:238` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)` |
| `AES_init_ctx_iv` | function | `aes.c:244` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` |
| `AddRoundKey` | function | `aes.c:257` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BLOCKLEN` | macro | `aes.c:11` | `#define BLOCKLEN` |
| `Cipher` | function | `aes.c:433` | `static void Cipher(state_t* state, const uint8_t* RoundKey)` |
| `InvCipher` | function | `aes.c:459` | `static void InvCipher(state_t* state, const uint8_t* RoundKey)` |
| `InvMixColumns` | function | `aes.c:370` | `static void InvMixColumns(state_t* state)` |
| `InvShiftRows` | function | `aes.c:402` | `static void InvShiftRows(state_t* state)` |
| `InvSubBytes` | function | `aes.c:391` | `static void InvSubBytes(state_t* state)` |
| `KEYLEN_256` | macro | `aes.c:6` | `#define KEYLEN_256` |
| `KeyExpansion` | function | `aes.c:166` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` |
| `MULTIPLY_AS_A_FUNCTION` | macro | `aes.c:84` | `#define MULTIPLY_AS_A_FUNCTION` |
| `MixColumns` | function | `aes.c:320` | `static void MixColumns(state_t* state)` |
| `Multiply` | function | `aes.c:340` | `static uint8_t Multiply(uint8_t x, uint8_t y)` |
| `Multiply` | macro | `aes.c:349` | `#define Multiply(x, y)` |
| `Nb` | macro | `aes.c:4` | `#define Nb` |
| `Nb` | macro | `aes.c:67` | `#define Nb` |
| `Nk` | macro | `aes.c:70` | `#define Nk` |
| `Nk` | macro | `aes.c:73` | `#define Nk` |
| `Nk` | macro | `aes.c:76` | `#define Nk` |
| `Nr` | macro | `aes.c:71` | `#define Nr` |
| `Nr` | macro | `aes.c:74` | `#define Nr` |
| `Nr` | macro | `aes.c:77` | `#define Nr` |
| `RKLENGTH` | macro | `aes.c:10` | `#define RKLENGTH` |
| `ShiftRows` | function | `aes.c:286` | `static void ShiftRows(state_t* state)` |
| `SubBytes` | function | `aes.c:271` | `static void SubBytes(state_t* state)` |
| `Td0` | function | `aes.c:56` | `static uint8_t Td0(int x)` |
| `Td1` | function | `aes.c:58` | `static uint8_t Td1(int x)` |
| `Td2` | function | `aes.c:59` | `static uint8_t Td2(int x)` |
| `Td3` | function | `aes.c:60` | `static uint8_t Td3(int x)` |
| `Td4` | function | `aes.c:61` | `static uint8_t Td4(int x)` |
| `XorWithIv` | function | `aes.c:510` | `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` |
| `getSBoxInvert` | function | `aes.c:34` | `static uint8_t getSBoxInvert(uint8_t num)` |
| `getSBoxInvert` | macro | `aes.c:365` | `#define getSBoxInvert(num)` |
| `getSBoxValue` | function | `aes.c:12` | `static uint8_t getSBoxValue(uint8_t num)` |
| `getSBoxValue` | macro | `aes.c:163` | `#define getSBoxValue(num)` |
| `memcpy` | function | `aes.c:247` | `memcpy (ctx->Iv, iv, AES_BLOCKLEN);` |
| `xtime` | function | `aes.c:313` | `static uint8_t xtime(uint8_t x)` |
| `AES256` | macro | `aes.h:17` | `#define AES256` |
| `AES_BLOCKLEN` | macro | `aes.h:19` | `#define AES_BLOCKLEN` |
| `AES_CBC_decrypt_buffer` | function | `aes.h:54` | `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CBC_encrypt_buffer` | function | `aes.h:53` | `void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_CTR_xcrypt_buffer` | function | `aes.h:58` | `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);` |
| `AES_ECB_decrypt` | function | `aes.h:49` | `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_ECB_encrypt` | function | `aes.h:48` | `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);` |
| `AES_KEYLEN` | macro | `aes.h:23` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:26` | `#define AES_KEYLEN` |
| `AES_KEYLEN` | macro | `aes.h:29` | `#define AES_KEYLEN` |
| `AES_ctx` | struct | `aes.h:33` | `` |
| `AES_ctx_set_iv` | function | `aes.h:44` | `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);` |
| `AES_init_ctx` | function | `aes.h:40` | `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);` |
| `AES_init_ctx_iv` | function | `aes.h:43` | `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);` |
| `AES_keyExpSize` | macro | `aes.h:24` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:27` | `#define AES_keyExpSize` |
| `AES_keyExpSize` | macro | `aes.h:30` | `#define AES_keyExpSize` |
| `CBC` | macro | `aes.h:9` | `#define CBC` |
| `CTR` | macro | `aes.h:15` | `#define CTR` |
| `ECB` | macro | `aes.h:12` | `#define ECB` |
| `_AES_H_` | macro | `aes.h:2` | `#define _AES_H_` |
| `AES_ECB_encrypt` | function | `beacon.c:2960` | `AES_ECB_encrypt(&ctx, keystream);` |
| `AES_init_ctx` | function | `beacon.c:2949` | `AES_init_ctx(&ctx, aes_key);` |
| `AdjustTokenPrivileges` | function | `beacon.c:3410` | `AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);` |
| `BOOL` | function | `beacon.c:721` | `typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);` |
| `BeaconDataSerializeString` | function | `beacon.c:4711` | `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)` |
| `BeaconPrintf` | function | `beacon.c:4721` | `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Descargado: %d bytes", bof_size);` |
| `C2_HOST` | macro | `beacon.c:82` | `#define C2_HOST` |
| `C2_PASS` | macro | `beacon.c:85` | `#define C2_PASS` |
| `C2_PATH` | macro | `beacon.c:88` | `#define C2_PATH` |
| `C2_PORT` | macro | `beacon.c:86` | `#define C2_PORT` |
| `C2_URL` | macro | `beacon.c:75` | `#define C2_URL` |
| `C2_USER` | macro | `beacon.c:84` | `#define C2_USER` |
| `CHECK_ERROR` | macro | `beacon.c:125` | `#define CHECK_ERROR(cond, msg)` |
| `CLIENT_ID` | macro | `beacon.c:77` | `#define CLIENT_ID` |
| `CONFIG_PATH` | macro | `beacon.c:87` | `#define CONFIG_PATH` |
| `CloseHandle` | function | `beacon.c:591` | `CloseHandle(hSnapshot);` |
| `CreateProcessA` | function | `beacon.c:3152` | `return CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);` |
| `CryptGenRandom` | function | `beacon.c:4473` | `CryptGenRandom(hProv, 16, iv);` |
| `CryptReleaseContext` | function | `beacon.c:4474` | `CryptReleaseContext(hProv, 0);` |
| `DEBUG` | macro | `beacon.c:72` | `#define DEBUG` |
| `DecryptPacket` | function | `beacon.c:2910` | `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)` |
| `DeleteCriticalSection` | function | `beacon.c:2089` | `DeleteCriticalSection(&proxyMutex);` |
| `DeleteFileA` | function | `beacon.c:2895` | `DeleteFileA(filename);` |
| `DownloadFromURL` | function | `beacon.c:4422` | `BOOL DownloadFromURL(const char* url, const char* filepath)` |
| `DownloadToBuffer` | function | `beacon.c:4346` | `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)` |
| `EarlyBirdInject` | function | `beacon.c:3729` | `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)` |
| `EnterCriticalSection` | function | `beacon.c:1806` | `EnterCriticalSection(&proxyMutex);` |
| `ExceptionFilter` | function | `beacon.c:253` | `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)` |
| `ExecuteModule` | function | `beacon.c:706` | `BOOL ExecuteModule(PVOID moduleBase)` |
| `ExecuteTLSCallbacks` | function | `beacon.c:600` | `void ExecuteTLSCallbacks(PVOID moduleBase)` |
| `ExitProcess` | function | `beacon.c:2358` | `ExitProcess(0);` |
| `ExitStatus` | type_alias | `beacon.c:127` | `typedef struct _PROCESS_BASIC_INFORMATION { LONG ExitStatus;` |
| `ExpandEnvironmentStringsA` | function | `beacon.c:3460` | `ExpandEnvironmentStringsA("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.bat", startupPath, size` |
| `FD_SET` | function | `beacon.c:3641` | `FD_SET(s, &write_set);` |
| `FD_ZERO` | function | `beacon.c:3640` | `FD_ZERO(&write_set);` |
| `FileExistsA` | function | `beacon.c:2301` | `BOOL FileExistsA(const char* filePath)` |
| `FindClose` | function | `beacon.c:2454` | `FindClose(hFind);` |
| `FlushFileBuffers` | function | `beacon.c:1570` | `FlushFileBuffers(hInWrite);` |
| `FreeLibrary` | function | `beacon.c:3086` | `FreeLibrary(amsi_dll);` |
| `GetAdaptersInfo` | function | `beacon.c:3017` | `GetAdaptersInfo(adapterInfo, &len);` |
| `GetC2Command` | function | `beacon.c:4200` | `char* GetC2Command(const char* host, const char* path)` |
| `GetHostname` | function | `beacon.c:3039` | `char* GetHostname()` |
| `GetIPs` | function | `beacon.c:3006` | `char* GetIPs()` |
| `GetJitteredSleep` | function | `beacon.c:1586` | `DWORD GetJitteredSleep(DWORD base_ms)` |
| `GetModuleHandleA` | function | `beacon.c:523` | `return GetModuleHandleA("ucrtbase.dll");` |
| `GetNtdllBase` | function | `beacon.c:1183` | `HMODULE GetNtdllBase()` |
| `GetProcessIdByName` | function | `beacon.c:581` | `DWORD GetProcessIdByName(const char* processName)` |
| `GetSyscallNumber` | function | `beacon.c:548` | `DWORD GetSyscallNumber(PVOID func_addr)` |
| `GetSystemInfo` | function | `beacon.c:3487` | `GetSystemInfo(&sysInfo);` |
| `GetSystemTimeAsFileTime` | function | `beacon.c:2579` | `GetSystemTimeAsFileTime(&ftNow);` |
| `GetTempPathA` | function | `beacon.c:780` | `GetTempPathA(MAX_PATH, tempPath);` |
| `GetUsefulSoftware` | function | `beacon.c:1591` | `char* GetUsefulSoftware()` |
| `GetUsername` | function | `beacon.c:3056` | `char* GetUsername()` |
| `HeapFree` | function | `beacon.c:3320` | `HeapFree(GetProcessHeap(), 0, rawBuffer);` |
| `HellsGate` | function | `beacon.c:560` | `DWORD HellsGate(DWORD ssn)` |
| `IMAGE_DOS_SIGNATURE` | macro | `beacon.c:101` | `#define IMAGE_DOS_SIGNATURE` |
| `IMAGE_NT_OPTIONAL_HDR32_MAGIC` | macro | `beacon.c:103` | `#define IMAGE_NT_OPTIONAL_HDR32_MAGIC` |
| `IMAGE_NT_OPTIONAL_HDR64_MAGIC` | macro | `beacon.c:104` | `#define IMAGE_NT_OPTIONAL_HDR64_MAGIC` |
| `IMAGE_NT_SIGNATURE` | macro | `beacon.c:102` | `#define IMAGE_NT_SIGNATURE` |
| `INVALID_SOCKET` | macro | `beacon.c:97` | `#define INVALID_SOCKET` |
| `IcmpCloseHandle` | function | `beacon.c:1741` | `IcmpCloseHandle(hIcmp);` |
| `InMemoryOrderLinks` | type_alias | `beacon.c:267` | `typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InMemoryOrderLinks;` |
| `InitializeCriticalSection` | function | `beacon.c:1755` | `InitializeCriticalSection(&proxyMutex);` |
| `LC2_HOST` | macro | `beacon.c:83` | `#define LC2_HOST` |
| `LC2_PATH` | macro | `beacon.c:89` | `#define LC2_PATH` |
| `LazyDataType` | struct | `beacon.c:168` | `` |
| `LeaveCriticalSection` | function | `beacon.c:1808` | `LeaveCriticalSection(&proxyMutex);` |
| `Length` | type_alias | `beacon.c:262` | `typedef struct _UNICODE_STRING { USHORT Length;` |
| `Length` | type_alias | `beacon.c:277` | `typedef struct _PEB_LDR_DATA { DWORD Length;` |
| `LoadLibraryA` | function | `beacon.c:546` | `return LoadLibraryA(dllName);` |
| `LoadModuleFromURL` | function | `beacon.c:751` | `BOOL LoadModuleFromURL(const char* url)` |
| `MALEABLE` | macro | `beacon.c:76` | `#define MALEABLE` |
| `MAX_JITTER` | macro | `beacon.c:80` | `#define MAX_JITTER` |
| `MAX_RESPONSE_SIZE` | macro | `beacon.c:74` | `#define MAX_RESPONSE_SIZE` |
| `MAX_RETRIES` | macro | `beacon.c:81` | `#define MAX_RETRIES` |
| `MIN_JITTER` | macro | `beacon.c:79` | `#define MIN_JITTER` |
| `MapDllNameToModule` | function | `beacon.c:521` | `HMODULE MapDllNameToModule(char* dllName)` |
| `MapModuleToMemory` | function | `beacon.c:617` | `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)` |
| `MapPEToMemory` | function | `beacon.c:2837` | `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)` |
| `MultiByteToWideChar` | function | `beacon.c:2239` | `MultiByteToWideChar(CP_UTF8, 0, contentType, -1, wContentType, 512);` |
| `NTSTATUS` | function | `beacon.c:198` | `typedef NTSTATUS (NTAPI *SpLsaModeInitialize_t)( ULONG LsaVersion, PULONG PackageVersion, void** ppTables, PULONG pcTabl` |
| `NTSTATUS` | type_alias | `beacon.c:296` | `typedef LONG NTSTATUS;` |
| `NTSTATUS` | type_alias | `beacon.c:304` | `typedef LONG NTSTATUS;` |
| `NT_SUCCESS` | macro | `beacon.c:300` | `#define NT_SUCCESS(Status)` |
| `NUM_UAS` | macro | `beacon.c:247` | `#define NUM_UAS` |
| `NUM_URLS` | macro | `beacon.c:240` | `#define NUM_URLS` |
| `NUM_USER_AGENTS` | macro | `beacon.c:231` | `#define NUM_USER_AGENTS` |
| `PSAPI_VERSION` | macro | `beacon.c:19` | `#define PSAPI_VERSION` |
| `PacketEncryptionContext` | struct | `beacon.c:329` | `` |
| `PortResult` | struct | `beacon.c:343` | `` |
| `PortScanner` | function | `beacon.c:3661` | `void PortScanner(char* targetIP, int* ports, int numPorts)` |
| `PortScannerArgs` | struct | `beacon.c:161` | `` |
| `PortScannerWrapper` | function | `beacon.c:3705` | `void PortScannerWrapper(void* arg)` |
| `ProcessBasicInformation` | macro | `beacon.c:123` | `#define ProcessBasicInformation` |
| `ProxyListener` | struct | `beacon.c:176` | `` |
| `ProxySession` | struct | `beacon.c:139` | `` |
| `ProxyThreadData` | struct | `beacon.c:147` | `` |
| `ReadFile` | function | `beacon.c:3315` | `ReadFile(hFile, rawBuffer, rawSize, &read, NULL);` |
| `ReadFromProcess` | function | `beacon.c:1513` | `DWORD WINAPI ReadFromProcess(LPVOID lpParam)` |
| `RegCloseKey` | function | `beacon.c:937` | `RegCloseKey(hKey);` |
| `RegDeleteValueA` | function | `beacon.c:2321` | `RegDeleteValueA(hKey, "SystemMaintenance");` |
| `RegOpenKeyA` | function | `beacon.c:3603` | `RegOpenKeyA(HKEY_CURRENT_USER, regKey, &hKey);` |
| `Reserved1` | type_alias | `beacon.c:286` | `typedef struct _PEB { BYTE Reserved1[2];` |
| `ResumeThread` | function | `beacon.c:3374` | `ResumeThread(pi.hThread);` |
| `ReverseArgs` | struct | `beacon.c:156` | `` |
| `ReverseShell` | function | `beacon.c:1404` | `void __cdecl ReverseShell(void* arg)` |
| `SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE` | macro | `beacon.c:106` | `#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE` |
| `SECURITY_FLAG_IGNORE_INVALID_POLICY` | macro | `beacon.c:109` | `#define SECURITY_FLAG_IGNORE_INVALID_POLICY` |
| `SECURITY_FLAG_IGNORE_REVOCATION` | macro | `beacon.c:94` | `#define SECURITY_FLAG_IGNORE_REVOCATION` |
| `SLEEP_BASE` | macro | `beacon.c:78` | `#define SLEEP_BASE` |
| `SerializeBeaconString` | function | `beacon.c:4702` | `void SerializeBeaconString(char* buffer, int* offset, const char* str)` |
| `SetFileAttributesA` | function | `beacon.c:3471` | `SetFileAttributesA(startupPath, FILE_ATTRIBUTE_HIDDEN);` |
| `SetThreadContext` | function | `beacon.c:3263` | `return SetThreadContext(pi->hThread, &ctx);` |
| `ShowWindow` | function | `beacon.c:5239` | `ShowWindow(GetConsoleWindow(), SW_HIDE);` |
| `Sleep` | function | `beacon.c:972` | `Sleep(1000);` |
| `TIMEOUT` | macro | `beacon.c:73` | `#define TIMEOUT` |
| `TerminateProcess` | function | `beacon.c:3346` | `TerminateProcess(pi.hProcess, 1);` |
| `USER_AGENT` | macro | `beacon.c:99` | `#define USER_AGENT` |
| `USER_AGENT_A` | macro | `beacon.c:100` | `#define USER_AGENT_A` |
| `UTF8ToWide` | function | `beacon.c:2551` | `WCHAR* UTF8ToWide(const char* utf8)` |
| `UploadFileToC2` | function | `beacon.c:2107` | `BOOL UploadFileToC2(const char* url, const char* filePath)` |
| `VOID` | function | `beacon.c:302` | `typedef VOID (NTAPI *PAPCFUNC)(ULONG_PTR);` |
| `VirtualFree` | function | `beacon.c:678` | `VirtualFree(baseAddress, 0, MEM_RELEASE);` |
| `VirtualFreeEx` | function | `beacon.c:824` | `VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);` |
| `VirtualProtect` | function | `beacon.c:3085` | `VirtualProtect((LPVOID)scan_buffer_addr, 1, old_protect, &old_protect);` |
| `WIN32_LEAN_AND_MEAN` | macro | `beacon.c:21` | `#define WIN32_LEAN_AND_MEAN` |
| `WSACleanup` | function | `beacon.c:1432` | `WSACleanup();` |
| `WaitForMultipleObjects` | function | `beacon.c:1829` | `WaitForMultipleObjects(2, threads, FALSE, INFINITE);` |
| `WaitForSingleObject` | function | `beacon.c:740` | `WaitForSingleObject(hThread, INFINITE);` |
| `WinHttpCloseHandle` | function | `beacon.c:1019` | `WinHttpCloseHandle(hSession);` |
| `WinHttpQueryHeaders` | function | `beacon.c:1092` | `WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE \| WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &size, NULL);` |
| `WinHttpReceiveResponse` | function | `beacon.c:2721` | `WinHttpReceiveResponse(hRequest, NULL);` |
| `WinHttpSetOption` | function | `beacon.c:2232` | `WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));` |
| `Wow64SetThreadContext` | function | `beacon.c:3257` | `return Wow64SetThreadContext(pi->hThread, &ctx);` |
| `WriteConsoleA` | function | `beacon.c:3398` | `WriteConsoleA(hConOut, "\x1b[2J\x1b[H", 7, &written, NULL);` |
| `WriteFile` | function | `beacon.c:798` | `WriteFile(hFile, dllBuffer, fileSize, &written, NULL);` |
| `WriteProcessMemory` | function | `beacon.c:3084` | `WriteProcessMemory(GetCurrentProcess(), (LPVOID)scan_buffer_addr, patch, sizeof(patch), NULL);` |
| `XOR_KEY` | macro | `beacon.c:71` | `#define XOR_KEY` |
| `_LDR_DATA_TABLE_ENTRY` | struct | `beacon.c:268` | `` |
| `_PEB` | struct | `beacon.c:287` | `` |
| `_PEB_LDR_DATA` | struct | `beacon.c:278` | `` |
| `_PROCESS_BASIC_INFORMATION` | struct | `beacon.c:129` | `` |
| `_PROCESS_BASIC_INFORMATION_` | macro | `beacon.c:115` | `#define _PROCESS_BASIC_INFORMATION_` |
| `_SECURITY_PACKAGE_DEFINITION_` | macro | `beacon.c:112` | `#define _SECURITY_PACKAGE_DEFINITION_` |
| `_SP_LSA_MODE_INITIALIZE_DEFINED_` | macro | `beacon.c:117` | `#define _SP_LSA_MODE_INITIALIZE_DEFINED_` |
| `_UNICODE_STRING` | struct | `beacon.c:262` | `` |
| `__attribute__` | function | `beacon.c:565` | `__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DW...` |
| `__declspec` | function | `beacon.c:416` | `__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)` |
| `__declspec` | function | `beacon.c:422` | `__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)` |
| `__declspec` | function | `beacon.c:430` | `__declspec(dllexport) int BeaconDataInt(datap * parser)` |
| `__declspec` | function | `beacon.c:435` | `__declspec(dllexport) short BeaconDataShort(datap * parser)` |
| `__declspec` | function | `beacon.c:440` | `__declspec(dllexport) int BeaconDataLength(datap * parser)` |
| `__declspec` | function | `beacon.c:445` | `__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)` |
| `__declspec` | function | `beacon.c:455` | `__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)` |
| `__declspec` | function | `beacon.c:503` | `__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)` |
| `_beginthread` | function | `beacon.c:1903` | `_beginthread(proxy_thread, 0, (void*)data);` |
| `_endthread` | function | `beacon.c:1408` | `_endthread();` |
| `_pclose` | function | `beacon.c:4190` | `_pclose(fp);` |
| `anti_analysis` | function | `beacon.c:922` | `BOOL anti_analysis()` |
| `base64_decode` | function | `beacon.c:1662` | `char* base64_decode(const char* input, size_t* out_len)` |
| `base64_encode` | function | `beacon.c:1626` | `char* base64_encode(const unsigned char* data, size_t inputLen)` |
| `cJSON_AddNumberToObject` | function | `beacon.c:5179` | `cJSON_AddNumberToObject(json_obj, "pid", (double)GetCurrentProcessId());` |
| `cJSON_AddStringToObject` | function | `beacon.c:5172` | `cJSON_AddStringToObject(json_obj, "id", "windows" && strlen("windows") > 0 ? "windows" : "windows");` |
| `cJSON_Delete` | function | `beacon.c:1173` | `cJSON_Delete(root);` |
| `cJSON_free` | function | `beacon.c:5224` | `cJSON_free(json_str);` |
| `checkDebuggers` | function | `beacon.c:2776` | `BOOL checkDebuggers()` |
| `cleanSystemLogs` | function | `beacon.c:3384` | `void cleanSystemLogs()` |
| `cleanupProxy` | function | `beacon.c:2061` | `void cleanupProxy()` |
| `closesocket` | function | `beacon.c:1446` | `closesocket(s);` |
| `compressDirectory` | function | `beacon.c:2094` | `BOOL compressDirectory(const char* dirPath)` |
| `connect` | function | `beacon.c:3636` | `connect(s, (SOCKADDR*)&sa, sizeof(sa));` |
| `create_suspended_process` | function | `beacon.c:3148` | `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` |
| `deleteFilesDelay` | function | `beacon.c:4536` | `void deleteFilesDelay(void* arg)` |
| `discoverLocalHosts` | function | `beacon.c:1695` | `void discoverLocalHosts()` |
| `downloadAndExecute` | function | `beacon.c:2860` | `BOOL downloadAndExecute(const char* url, const char* targetProcess)` |
| `encrypt_data` | function | `beacon.c:4452` | `char* encrypt_data(const char* data)` |
| `ensurePersistence` | function | `beacon.c:3421` | `BOOL ensurePersistence()` |
| `exec_cmd` | function | `beacon.c:4172` | `char* exec_cmd(const char* cmd)` |
| `executeCommand` | function | `beacon.c:4550` | `void executeCommand(void* cmdPtr)` |
| `executeLoader` | function | `beacon.c:1348` | `void executeLoader(void *arg)` |
| `executeUACBypass` | function | `beacon.c:3556` | `BOOL executeUACBypass(const char* payloadPath)` |
| `extract_shellcode` | function | `beacon.c:1303` | `int extract_shellcode(const char* input, size_t len, unsigned char** out)` |
| `fclose` | function | `beacon.c:2122` | `fclose(fp);` |
| `fflush` | function | `beacon.c:479` | `fflush(stdout);` |
| `fprintf` | function | `beacon.c:468` | `fprintf(stderr, "[ERROR] vsnprintf failed\n");` |
| `fputs` | function | `beacon.c:477` | `fputs(buffer, stdout);` |
| `fread` | function | `beacon.c:2125` | `fread(fileData, 1, fileSize, fp);` |
| `free` | function | `beacon.c:515` | `free(copy);` |
| `fseek` | function | `beacon.c:2115` | `fseek(fp, 0, SEEK_END);` |
| `fwrite` | function | `beacon.c:3295` | `fwrite(downloaded, 1, fileSize, fp);` |
| `getNetworkConfig` | function | `beacon.c:2104` | `char* getNetworkConfig()` |
| `get_entry_point_rva` | function | `beacon.c:3112` | `DWORD get_entry_point_rva(BYTE* buffer)` |
| `get_image_size` | function | `beacon.c:3106` | `DWORD get_image_size(BYTE* buffer)` |
| `get_nt_headers` | function | `beacon.c:3092` | `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)` |
| `get_remote_image_base` | function | `beacon.c:3154` | `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)` |
| `get_shell_cmd` | function | `beacon.c:334` | `const char* get_shell_cmd()` |
| `getsockopt` | function | `beacon.c:3649` | `getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);` |
| `go` | function | `beacon.c:4719` | `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)` |
| `handleAdversary` | function | `beacon.c:4738` | `void handleAdversary(char* command)` |
| `handleAtomic` | function | `beacon.c:4559` | `void handleAtomic(char* command)` |
| `handleDownload` | function | `beacon.c:4683` | `BOOL handleDownload(const char* command)` |
| `handleUpload` | function | `beacon.c:2280` | `BOOL handleUpload(const char* command)` |
| `hex_char_to_byte` | function | `beacon.c:1334` | `BYTE hex_char_to_byte(char c)` |
| `hex_to_bytes` | function | `beacon.c:1340` | `void hex_to_bytes(const char* hex, BYTE* output, size_t len)` |
| `inet_pton` | function | `beacon.c:3631` | `inet_pton(AF_INET, result->ip, &sa.sin_addr);` |
| `initProxy` | function | `beacon.c:1752` | `void initProxy()` |
| `init_aes_context` | function | `beacon.c:3898` | `PacketEncryptionContext* init_aes_context(const char* key_hex)` |
| `ioctlsocket` | function | `beacon.c:3635` | `ioctlsocket(s, FIONBIO, &blocking_mode);` |
| `isSandboxEnvironment` | function | `beacon.c:3482` | `BOOL isSandboxEnvironment()` |
| `isSensitiveFile` | function | `beacon.c:2378` | `int isSensitiveFile(const char* filename)` |
| `isVMByMAC` | function | `beacon.c:1231` | `BOOL isVMByMAC()` |
| `isValidUUID` | function | `beacon.c:4511` | `BOOL isValidUUID(const char* uuid)` |
| `is_64bit` | function | `beacon.c:3100` | `BOOL is_64bit(BYTE* buffer)` |
| `load_lazyconf` | function | `beacon.c:945` | `BOOL load_lazyconf()` |
| `longjmp` | function | `beacon.c:256` | `longjmp(exceptionJump, 1);` |
| `main` | function | `beacon.c:5233` | `int main()` |
| `memcpy` | function | `beacon.c:507` | `memcpy(copy, data, len);` |
| `memmove` | function | `beacon.c:1551` | `memmove(buffer + r, buffer + r - 1, 1);` |
| `memset` | function | `beacon.c:1756` | `memset(proxySessions, 0, sizeof(proxySessions));` |
| `min` | macro | `beacon.c:91` | `#define min(a,b)` |
| `obfuscateFileTimestamp` | function | `beacon.c:2562` | `BOOL obfuscateFileTimestamp(const char* filepath)` |
| `obfuscateFileTimestamps` | function | `beacon.c:2592` | `void obfuscateFileTimestamps(const char* basePath, int depth)` |
| `overWrite` | function | `beacon.c:3277` | `void overWrite(const char* targetPath, const char* payloadPath)` |
| `pStartW` | function | `beacon.c:907` | `pStartW();` |
| `patchAMSI` | function | `beacon.c:3072` | `BOOL patchAMSI(void)` |
| `pe_buffer_to_virtual_image` | function | `beacon.c:3117` | `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)` |
| `printf` | function | `beacon.c:671` | `printf("[I] Cargando DLL: %s\n", dllName);` |
| `proxy_accept_thread` | function | `beacon.c:1855` | `void WINAPI proxy_accept_thread(void* param)` |
| `proxy_thread` | function | `beacon.c:1784` | `void WINAPI proxy_thread(void* param)` |
| `relay_thread` | function | `beacon.c:1763` | `void WINAPI relay_thread(void* param)` |
| `restartClient` | function | `beacon.c:2734` | `void restartClient()` |
| `retry_http_request` | function | `beacon.c:3918` | `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)` |
| `scanPort` | function | `beacon.c:3610` | `void scanPort(void* arg)` |
| `searchCredentials` | function | `beacon.c:2424` | `char* searchCredentials(const char* basePath)` |
| `selfDestruct` | function | `beacon.c:2306` | `void selfDestruct()` |
| `send` | function | `beacon.c:1520` | `send(s, buffer, n, 0);` |
| `setsockopt` | function | `beacon.c:1979` | `setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));` |
| `shutdown` | function | `beacon.c:1776` | `shutdown(from, SD_BOTH);` |
| `simulateLegitimateTraffic` | function | `beacon.c:2656` | `void simulateLegitimateTraffic(void* param)` |
| `snprintf` | function | `beacon.c:1280` | `snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X", adapter->Address[0], adapter->Address[1], adapter->Address[2]);` |
| `srand` | function | `beacon.c:5236` | `srand(time(NULL));` |
| `startProxy` | function | `beacon.c:1922` | `BOOL startProxy(const char* listenAddr, const char* targetAddr)` |
| `stopProxy` | function | `beacon.c:2009` | `BOOL stopProxy(const char* listenAddr)` |
| `strcat` | function | `beacon.c:1612` | `strcat(result, binaries[i]);` |
| `strcat_s` | function | `beacon.c:781` | `strcat_s(tempPath, MAX_PATH, "mimilib.dll");` |
| `strcpy` | function | `beacon.c:998` | `strcpy(path, path_start);` |
| `stristr` | function | `beacon.c:2361` | `char* stristr(const char* str, const char* pattern)` |
| `strlwr` | function | `beacon.c:3538` | `strlwr(vendor);` |
| `strncpy` | function | `beacon.c:994` | `strncpy(host, host_start, host_len);` |
| `system` | function | `beacon.c:2326` | `system("schtasks /delete /tn \"SystemMaintenanceTask\" /f > nul 2>&1");` |
| `tryPrivilegeEscalation` | function | `beacon.c:3551` | `void tryPrivilegeEscalation()` |
| `update_remote_entry_point` | function | `beacon.c:3249` | `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)` |
| `va_end` | function | `beacon.c:464` | `va_end(args);` |
| `va_start` | function | `beacon.c:461` | `va_start(args, fmt);` |
| `volatile` | function | `beacon.c:571` | `__asm__ volatile ( "movq %%rcx, %%r10\n\t" "movl __syscall_ssn(%%rip), %%eax\n\t" "syscall\n\t" "ret\n\t" : : : "rax", "` |
| `wcstombs` | function | `beacon.c:5260` | `wcstombs(lazyconf.rhost, LC2_HOST, sizeof(lazyconf.rhost) - 1);` |
| `xor_string` | function | `beacon.c:915` | `void xor_string(char* data, size_t len, char key)` |
| `BEACON_H` | macro | `beacon.h:21` | `#define BEACON_H` |
| `CALLBACK_ERROR` | macro | `beacon.h:42` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `beacon.h:40` | `#define CALLBACK_OUTPUT` |
| `datap` | struct | `beacon.h:25` | `` |
| `BEACON_H` | macro | `bof/calc/beacon.h:21` | `#define BEACON_H` |
| `CALLBACK_ERROR` | macro | `bof/calc/beacon.h:42` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/calc/beacon.h:40` | `#define CALLBACK_OUTPUT` |
| `datap` | struct | `bof/calc/beacon.h:25` | `` |
| `BOOL` | function | `bof/calc/calc.c:56` | `typedef BOOL (WINAPI *CreateProcessA_t)( LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPP` |
| `BeaconPrintf` | function | `bof/calc/calc.c:35` | `BeaconPrintf(CALLBACK_OUTPUT, "[EXEC] ⚡ Ejecutando calc.exe...\n");` |
| `FARPROC` | function | `bof/calc/calc.c:45` | `typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);` |
| `__imp_CloseHandle` | variable | `bof/calc/calc.c:30` | `extern FARPROC __imp_CloseHandle;` |
| `__imp_GetComputerNameA` | variable | `bof/calc/calc.c:29` | `extern FARPROC __imp_GetComputerNameA;` |
| `__imp_GetModuleHandleA` | variable | `bof/calc/calc.c:26` | `extern FARPROC __imp_GetModuleHandleA;` |
| `__imp_GetProcAddress` | variable | `bof/calc/calc.c:27` | `extern FARPROC __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/calc/calc.c:28` | `extern FARPROC __imp_LoadLibraryA;` |
| `go` | function | `bof/calc/calc.c:34` | `void go(char *args, int alen)` |
| `pCloseHandle` | function | `bof/calc/calc.c:76` | `pCloseHandle(pi.hProcess);` |
| `BEACON_H` | macro | `bof/etw/beacon.h:21` | `#define BEACON_H` |
| `CALLBACK_ERROR` | macro | `bof/etw/beacon.h:42` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/etw/beacon.h:40` | `#define CALLBACK_OUTPUT` |
| `datap` | struct | `bof/etw/beacon.h:25` | `` |
| `BeaconPrintf` | function | `bof/etw/etw.c:27` | `BeaconPrintf(CALLBACK_OUTPUT,"[ETW] patching...\n");` |
| `__imp_GetModuleHandleA` | variable | `bof/etw/etw.c:22` | `extern PVOID __imp_GetModuleHandleA;` |
| `__imp_GetProcAddress` | variable | `bof/etw/etw.c:23` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_RtlCopyMemory` | variable | `bof/etw/etw.c:25` | `extern PVOID __imp_RtlCopyMemory;` |
| `__imp_VirtualProtect` | variable | `bof/etw/etw.c:24` | `extern PVOID __imp_VirtualProtect;` |
| `go` | function | `bof/etw/etw.c:26` | `void go(char *a,int l)` |
| `BeaconPrintf` | function | `bof/test/Test.c:4` | `BeaconPrintf(CALLBACK_OUTPUT, "[CoffTest] I am alive! . Args=%.*s\n", alen, args);` |
| `go` | function | `bof/test/Test.c:2` | `void go(char *args, int alen)` |
| `BeaconPrintf` | function | `bof/test/amsibypass.c:35` | `BeaconPrintf(CALLBACK_OUTPUT, "[AMSI] Iniciando bypass AMSI (patch en memoria)...\n");` |
| `__imp_GetProcAddress` | variable | `bof/test/amsibypass.c:27` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/amsibypass.c:26` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_RtlCopyMemory` | variable | `bof/test/amsibypass.c:29` | `extern PVOID __imp_RtlCopyMemory;` |
| `__imp_VirtualProtect` | variable | `bof/test/amsibypass.c:28` | `extern PVOID __imp_VirtualProtect;` |
| `go` | function | `bof/test/amsibypass.c:34` | `void go(char *args, int alen)` |
| `BEACON_H` | macro | `bof/test/beacon.h:21` | `#define BEACON_H` |
| `CALLBACK_ERROR` | macro | `bof/test/beacon.h:42` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/test/beacon.h:40` | `#define CALLBACK_OUTPUT` |
| `datap` | struct | `bof/test/beacon.h:25` | `` |
| `BOOL` | function | `bof/test/cmdwhoami.c:29` | `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAtt` |
| `BeaconPrintf` | function | `bof/test/cmdwhoami.c:46` | `BeaconPrintf(CALLBACK_ERROR, "LoadLibraryA(kernel32.dll) falló\n");` |
| `__imp_CloseHandle` | variable | `bof/test/cmdwhoami.c:28` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetProcAddress` | variable | `bof/test/cmdwhoami.c:27` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/cmdwhoami.c:25` | `extern PVOID __imp_LoadLibraryA;` |
| `go` | function | `bof/test/cmdwhoami.c:42` | `void go(char *args, int alen)` |
| `BOOL` | function | `bof/test/disablelog.c:48` | `typedef BOOL (WINAPI *pQueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);` |
| `BeaconPrintf` | function | `bof/test/disablelog.c:70` | `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] Iniciando: Suspensión de hilos en wevtsvc.dll (servicio EventLog)\n");` |
| `DWORD` | function | `bof/test/disablelog.c:51` | `typedef DWORD (WINAPI *pGetModuleBaseNameW)(HANDLE, HMODULE, LPWSTR, DWORD);` |
| `HANDLE` | function | `bof/test/disablelog.c:53` | `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);` |
| `NTSTATUS` | function | `bof/test/disablelog.c:61` | `typedef NTSTATUS (NTAPI *pNtQueryInformationThread)( HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInfo` |
| `NT_SUCCESS` | macro | `bof/test/disablelog.c:34` | `#define NT_SUCCESS(x)` |
| `SC_HANDLE` | function | `bof/test/disablelog.c:46` | `typedef SC_HANDLE (WINAPI *pOpenSCManagerA)(LPCSTR, LPCSTR, DWORD);` |
| `WIN32_LEAN_AND_MEAN` | macro | `bof/test/disablelog.c:20` | `#define WIN32_LEAN_AND_MEAN` |
| `__imp_CloseHandle` | variable | `bof/test/disablelog.c:30` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetModuleHandleA` | variable | `bof/test/disablelog.c:29` | `extern PVOID __imp_GetModuleHandleA;` |
| `__imp_GetProcAddress` | variable | `bof/test/disablelog.c:28` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/disablelog.c:26` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_OpenProcess` | variable | `bof/test/disablelog.c:31` | `extern PVOID __imp_OpenProcess;` |
| `go` | function | `bof/test/disablelog.c:68` | `void go(char *args, int alen)` |
| `my_wcscmp` | function | `bof/test/disablelog.c:36` | `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)` |
| `BeaconPrintf` | function | `bof/test/getenv.c:42` | `BeaconPrintf(CALLBACK_OUTPUT, "[BOF] %-15s = [NO DISPONIBLE]\n", vars[i]);` |
| `__imp_GetEnvironmentVariableA` | variable | `bof/test/getenv.c:22` | `extern PVOID __imp_GetEnvironmentVariableA;` |
| `go` | function | `bof/test/getenv.c:24` | `void go(char *args, int alen)` |
| `BOOL` | function | `bof/test/loadvnc.c:54` | `typedef BOOL (WINAPI *CREATEPROCESSA)( LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPRO` |
| `BeaconPrintf` | function | `bof/test/loadvnc.c:82` | `BeaconPrintf(CALLBACK_OUTPUT, "[VNC] Iniciando descarga e inyección...");` |
| `DWORD` | function | `bof/test/loadvnc.c:67` | `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);` |
| `HANDLE` | function | `bof/test/loadvnc.c:121` | `typedef HANDLE (WINAPI *CREATE_SNAPSHOT)(DWORD, DWORD);` |
| `HMODULE` | function | `bof/test/loadvnc.c:204` | `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);` |
| `LPVOID` | function | `bof/test/loadvnc.c:182` | `typedef LPVOID (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);` |
| `TH32CS_SNAPPROCESS` | macro | `bof/test/loadvnc.c:33` | `#define TH32CS_SNAPPROCESS` |
| `_PROCESSENTRY32` | struct | `bof/test/loadvnc.c:35` | `` |
| `__imp_CloseHandle` | variable | `bof/test/loadvnc.c:28` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetProcAddress` | variable | `bof/test/loadvnc.c:27` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/loadvnc.c:26` | `extern PVOID __imp_LoadLibraryA;` |
| `dwSize` | type_alias | `bof/test/loadvnc.c:34` | `typedef struct _PROCESSENTRY32 { DWORD dwSize;` |
| `execute_cmd_hidden` | function | `bof/test/loadvnc.c:51` | `void execute_cmd_hidden(char* cmd)` |
| `go` | function | `bof/test/loadvnc.c:81` | `void go(char *args, int alen)` |
| `int` | function | `bof/test/loadvnc.c:104` | `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);` |
| `pWaitForSingleObject` | function | `bof/test/loadvnc.c:70` | `pWaitForSingleObject(pi.hProcess, 8000);` |
| `pwsprintfA` | function | `bof/test/loadvnc.c:111` | `pwsprintfA(dll_path, "%s\\winvnc.x64.dll", temp_path);` |
| `Copyright` | function | `bof/test/make_table.c:16` | `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....` |
| `main` | function | `bof/test/make_table.c:33` | `void main()` |
| `printf` | function | `bof/test/make_table.c:48` | `printf("Hash for '%s' = 0x%08X\n", names[i], h);` |
| `BeaconPrintf` | function | `bof/test/persist.c:38` | `BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA falló: %ld\n", result);` |
| `__imp_RegCloseKey` | variable | `bof/test/persist.c:25` | `extern PVOID __imp_RegCloseKey;` |
| `__imp_RegOpenKeyExA` | variable | `bof/test/persist.c:22` | `extern PVOID __imp_RegOpenKeyExA;` |
| `__imp_RegSetValueExA` | variable | `bof/test/persist.c:24` | `extern PVOID __imp_RegSetValueExA;` |
| `go` | function | `bof/test/persist.c:26` | `void go(char *args, int alen)` |
| `strlen` | function | `bof/test/persist.c:49` | `strlen(valueData) + 1 );` |
| `BOOL` | function | `bof/test/persistsvc.c:103` | `typedef BOOL (WINAPI *pSetServiceStatus_t)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);` |
| `BeaconPrintf` | function | `bof/test/persistsvc.c:68` | `BeaconPrintf(CALLBACK_ERROR, "[LAZYOWN-SVC][x] No se pudo resolver " #name "\n");` |
| `DWORD` | function | `bof/test/persistsvc.c:175` | `typedef DWORD (WINAPI *pGetLastError_t)(void);` |
| `HANDLE` | function | `bof/test/persistsvc.c:128` | `typedef HANDLE (WINAPI *pCreateEventA_t)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);` |
| `HMODULE` | function | `bof/test/persistsvc.c:176` | `typedef HMODULE (WINAPI *pGetModuleHandleA_t)(LPCSTR);` |
| `RESOLVE_API` | macro | `bof/test/persistsvc.c:65` | `#define RESOLVE_API(lib, name, type)` |
| `RESOLVE_API` | function | `bof/test/persistsvc.c:132` | `RESOLVE_API(Advapi32, RegisterServiceCtrlHandlerA, pRegisterServiceCtrlHandlerA_t);` |
| `SERVICE_STATUS_HANDLE` | function | `bof/test/persistsvc.c:126` | `typedef SERVICE_STATUS_HANDLE (WINAPI *pRegisterServiceCtrlHandlerA_t)(LPCSTR, LPHANDLER_FUNCTION);` |
| `ServiceHandler` | function | `bof/test/persistsvc.c:82` | `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...` |
| `ServiceMain` | function | `bof/test/persistsvc.c:116` | `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)` |
| `WIN32_LEAN_AND_MEAN` | macro | `bof/test/persistsvc.c:19` | `#define WIN32_LEAN_AND_MEAN` |
| `__imp_GetProcAddress` | variable | `bof/test/persistsvc.c:28` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/persistsvc.c:27` | `extern PVOID __imp_LoadLibraryA;` |
| `cleanup` | macro | `bof/test/persistsvc.c:131` | `#define cleanup` |
| `cleanup` | macro | `bof/test/persistsvc.c:183` | `#define cleanup` |
| `go` | function | `bof/test/persistsvc.c:251` | `void go(char *args, int alen)` |
| `my_memcpy` | function | `bof/test/persistsvc.c:33` | `static void* my_memcpy(void* dst, const void* src, size_t len)` |
| `my_strcat` | function | `bof/test/persistsvc.c:46` | `static char* my_strcat(char* dest, const char* src)` |
| `my_strcmp` | function | `bof/test/persistsvc.c:54` | `static int my_strcmp(const char* s1, const char* s2)` |
| `my_strlen` | function | `bof/test/persistsvc.c:39` | `static int my_strlen(const char* str)` |
| `pCloseHandle` | function | `bof/test/persistsvc.c:228` | `pCloseHandle(pi.hProcess);` |
| `pCloseServiceHandle` | function | `bof/test/persistsvc.c:357` | `pCloseServiceHandle(hService);` |
| `pRtlZeroMemory` | function | `bof/test/persistsvc.c:207` | `pRtlZeroMemory(&si, sizeof(si));` |
| `pSetServiceStatus` | function | `bof/test/persistsvc.c:106` | `pSetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);` |
| `pWaitForSingleObject` | function | `bof/test/persistsvc.c:236` | `pWaitForSingleObject(g_StopEvent, INFINITE);` |
| `void` | function | `bof/test/persistsvc.c:174` | `typedef void (WINAPI *pRtlZeroMemory_t)(PVOID, SIZE_T);` |
| `BOOL` | function | `bof/test/scan_shellcode.c:77` | `typedef BOOL (WINAPI *pProcess32First)(HANDLE, LPPROCESSENTRY32);` |
| `BeaconPrintf` | function | `bof/test/scan_shellcode.c:86` | `BeaconPrintf(CALLBACK_OUTPUT, "[*] Iniciando búsqueda de regiones RWX en procesos...\n");` |
| `HANDLE` | function | `bof/test/scan_shellcode.c:75` | `typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);` |
| `WIN32_LEAN_AND_MEAN` | macro | `bof/test/scan_shellcode.c:19` | `#define WIN32_LEAN_AND_MEAN` |
| `__imp_CloseHandle` | variable | `bof/test/scan_shellcode.c:32` | `extern PVOID __imp_CloseHandle;` |
| `__imp_CreateToolhelp32Snapshot` | variable | `bof/test/scan_shellcode.c:28` | `extern PVOID __imp_CreateToolhelp32Snapshot;` |
| `__imp_GetProcAddress` | variable | `bof/test/scan_shellcode.c:27` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/scan_shellcode.c:26` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_OpenProcess` | variable | `bof/test/scan_shellcode.c:31` | `extern PVOID __imp_OpenProcess;` |
| `__imp_Process32First` | variable | `bof/test/scan_shellcode.c:29` | `extern PVOID __imp_Process32First;` |
| `__imp_Process32Next` | variable | `bof/test/scan_shellcode.c:30` | `extern PVOID __imp_Process32Next;` |
| `go` | function | `bof/test/scan_shellcode.c:84` | `void go(char *args, int alen)` |
| `pCloseHandleFn` | function | `bof/test/scan_shellcode.c:120` | `pCloseHandleFn(snapshot);` |
| `BeaconPrintf` | function | `bof/test/shellcode.c:34` | `BeaconPrintf(CALLBACK_ERROR, "VirtualAlloc falló\n");` |
| `__imp_RtlCopyMemory` | variable | `bof/test/shellcode.c:24` | `extern PVOID __imp_RtlCopyMemory;` |
| `__imp_VirtualAlloc` | variable | `bof/test/shellcode.c:22` | `extern PVOID __imp_VirtualAlloc;` |
| `go` | function | `bof/test/shellcode.c:25` | `void go(char *args, int alen)` |
| `AF_INET` | macro | `bof/test/sock5.c:9` | `#define AF_INET` |
| `BOOL` | function | `bof/test/sock5.c:84` | `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);` |
| `BUFFER_SIZE` | macro | `bof/test/sock5.c:78` | `#define BUFFER_SIZE` |
| `BeaconPrintf` | function | `bof/test/sock5.c:194` | `BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló conexión al destino. WSAError: %d\n", err);` |
| `DWORD` | function | `bof/test/sock5.c:86` | `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);` |
| `FARPROC` | function | `bof/test/sock5.c:82` | `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);` |
| `FD_CLR` | macro | `bof/test/sock5.c:38` | `#define FD_CLR(fd,set)` |
| `FD_ISSET` | macro | `bof/test/sock5.c:41` | `#define FD_ISSET(fd,set)` |
| `FD_SET` | macro | `bof/test/sock5.c:39` | `#define FD_SET(fd,set)` |
| `FD_SET` | function | `bof/test/sock5.c:219` | `FD_SET(client_sock, &read_fds);` |
| `FD_SETSIZE` | macro | `bof/test/sock5.c:36` | `#define FD_SETSIZE` |
| `FD_ZERO` | macro | `bof/test/sock5.c:40` | `#define FD_ZERO(set)` |
| `FD_ZERO` | function | `bof/test/sock5.c:218` | `FD_ZERO(&read_fds);` |
| `HANDLE` | function | `bof/test/sock5.c:85` | `typedef HANDLE (WINAPI *CREATE_EVENTA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);` |
| `HMODULE` | function | `bof/test/sock5.c:81` | `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);` |
| `HandleSocks5Connection` | function | `bof/test/sock5.c:118` | `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...` |
| `INADDR_ANY` | macro | `bof/test/sock5.c:12` | `#define INADDR_ANY` |
| `INADDR_LOOPBACK` | macro | `bof/test/sock5.c:13` | `#define INADDR_LOOPBACK` |
| `INVALID_SOCKET` | macro | `bof/test/sock5.c:7` | `#define INVALID_SOCKET` |
| `IPPROTO_TCP` | macro | `bof/test/sock5.c:11` | `#define IPPROTO_TCP` |
| `LPVOID` | function | `bof/test/sock5.c:83` | `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);` |
| `MAX_PENDING_CONNECTIONS` | macro | `bof/test/sock5.c:77` | `#define MAX_PENDING_CONNECTIONS` |
| `ProxyThread` | function | `bof/test/sock5.c:261` | `DWORD WINAPI ProxyThread(LPVOID _)` |
| `SOCKET` | type_alias | `bof/test/sock5.c:6` | `typedef unsigned __int64 SOCKET;` |
| `SOCKET` | function | `bof/test/sock5.c:91` | `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);` |
| `SOCKET_ERROR` | macro | `bof/test/sock5.c:8` | `#define SOCKET_ERROR` |
| `SOCKS5_CONTROL_PORT` | macro | `bof/test/sock5.c:76` | `#define SOCKS5_CONTROL_PORT` |
| `SOCKS5_LISTEN_PORT` | macro | `bof/test/sock5.c:75` | `#define SOCKS5_LISTEN_PORT` |
| `SOCK_STREAM` | macro | `bof/test/sock5.c:10` | `#define SOCK_STREAM` |
| `ULONG` | function | `bof/test/sock5.c:102` | `typedef ULONG (WINAPI *HTONL)(ULONG);` |
| `USHORT` | function | `bof/test/sock5.c:103` | `typedef USHORT (WINAPI *HTONS)(USHORT);` |
| `WIN32_LEAN_AND_MEAN` | macro | `bof/test/sock5.c:1` | `#define WIN32_LEAN_AND_MEAN` |
| `WSAData` | struct | `bof/test/sock5.c:16` | `` |
| `__imp_CloseHandle` | variable | `bof/test/sock5.c:72` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetProcAddress` | variable | `bof/test/sock5.c:69` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/sock5.c:68` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_VirtualAlloc` | variable | `bof/test/sock5.c:70` | `extern PVOID __imp_VirtualAlloc;` |
| `__imp_VirtualFree` | variable | `bof/test/sock5.c:71` | `extern PVOID __imp_VirtualFree;` |
| `fd_count` | type_alias | `bof/test/sock5.c:26` | `typedef struct fd_set { unsigned int fd_count;` |
| `fd_set` | struct | `bof/test/sock5.c:27` | `` |
| `go` | function | `bof/test/sock5.c:358` | `void go(char *args, int alen)` |
| `h_addr` | macro | `bof/test/sock5.c:64` | `#define h_addr` |
| `hostent` | struct | `bof/test/sock5.c:58` | `` |
| `in_addr` | struct | `bof/test/sock5.c:47` | `` |
| `int` | function | `bof/test/sock5.c:90` | `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);` |
| `my_FD_ISSET` | function | `bof/test/sock5.c:107` | `static int my_FD_ISSET(SOCKET s, fd_set *set)` |
| `pCloseHandle` | function | `bof/test/sock5.c:389` | `pCloseHandle(g_hShutdownEvent);` |
| `pCloseSocket` | function | `bof/test/sock5.c:197` | `pCloseSocket(tgt);` |
| `pSend` | function | `bof/test/sock5.c:139` | `pSend(client_sock, rep, 10, 0);` |
| `pWSACleanup` | function | `bof/test/sock5.c:347` | `cleanup_wsa: pWSACleanup();` |
| `pWaitForSingleObject` | function | `bof/test/sock5.c:395` | `pWaitForSingleObject(g_hShutdownEvent, INFINITE);` |
| `sockaddr` | struct | `bof/test/sock5.c:56` | `` |
| `sockaddr_in` | struct | `bof/test/sock5.c:49` | `` |
| `timeval` | struct | `bof/test/sock5.c:32` | `` |
| `tv_sec` | type_alias | `bof/test/sock5.c:31` | `typedef struct timeval { long tv_sec;` |
| `u_int` | type_alias | `bof/test/sock5.c:44` | `typedef unsigned int u_int;` |
| `u_long` | type_alias | `bof/test/sock5.c:45` | `typedef unsigned long u_long;` |
| `u_short` | type_alias | `bof/test/sock5.c:42` | `typedef unsigned short u_short;` |
| `wVersion` | type_alias | `bof/test/sock5.c:16` | `typedef struct WSAData { WORD wVersion;` |
| `decrypt_cookie` | function | `bof/test/tel.py:39` | `def decrypt_cookie(encrypted, key, iv)` |
| `get_machine_id` | function | `bof/test/tel.py:8` | `def get_machine_id()` |
| `get_version` | function | `bof/test/tel.py:20` | `def get_version()` |
| `main` | function | `bof/test/tel.py:45` | `def main()` |
| `to_hex` | function | `bof/test/tel.py:35` | `def to_hex(byte_list)` |
| `to_numbers` | function | `bof/test/tel.py:31` | `def to_numbers(hex_str)` |
| `BOOL` | function | `bof/test/uacbypass.c:36` | `typedef BOOL (WINAPI *CREATEPROCESSA)(LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROC` |
| `BeaconPrintf` | function | `bof/test/uacbypass.c:62` | `BeaconPrintf(CALLBACK_OUTPUT, "[UAC] Iniciando bypass UAC via SilentCleanup (fodhelper/CMSTP)...\n");` |
| `DWORD` | function | `bof/test/uacbypass.c:48` | `typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(HANDLE, DWORD);` |
| `HANDLE` | function | `bof/test/uacbypass.c:89` | `typedef HANDLE (WINAPI *CREATEFILEA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);` |
| `__imp_CloseHandle` | variable | `bof/test/uacbypass.c:28` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetProcAddress` | variable | `bof/test/uacbypass.c:27` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/uacbypass.c:26` | `extern PVOID __imp_LoadLibraryA;` |
| `execute_hidden_cmd` | function | `bof/test/uacbypass.c:33` | `void execute_hidden_cmd(char* cmd)` |
| `go` | function | `bof/test/uacbypass.c:61` | `void go(char *args, int alen)` |
| `int` | function | `bof/test/uacbypass.c:79` | `typedef int (WINAPI *WSPRINTFA)(LPSTR, LPCSTR, ...);` |
| `pWaitForSingleObject` | function | `bof/test/uacbypass.c:51` | `pWaitForSingleObject(pi.hProcess, 10000);` |
| `pWriteFile` | function | `bof/test/uacbypass.c:114` | `pWriteFile(hFile, inf_content, strlen(inf_content), &written, NULL);` |
| `pwsprintfA` | function | `bof/test/uacbypass.c:85` | `pwsprintfA(inf_path, "%s\\uac_bypass.inf", temp_path);` |
| `AES256_KEYLEN` | macro | `bof/test/upload.c:24` | `#define AES256_KEYLEN` |
| `AES_BLOCKLEN` | macro | `bof/test/upload.c:22` | `#define AES_BLOCKLEN` |
| `AES_CFB_encrypt_buffer` | function | `bof/test/upload.c:177` | `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...` |
| `AES_ctx` | struct | `bof/test/upload.c:46` | `` |
| `AES_init_ctx` | function | `bof/test/upload.c:173` | `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)` |
| `AddRoundKey` | function | `bof/test/upload.c:98` | `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` |
| `BOOL` | function | `bof/test/upload.c:316` | `typedef BOOL (WINAPI *t_VirtualFree)(LPVOID, SIZE_T, DWORD);` |
| `BeaconPrintf` | function | `bof/test/upload.c:302` | `BeaconPrintf(CALLBACK_OUTPUT, "[UPLOAD][-] Falló resolución de loader\n");` |
| `CRYPT_VERIFYCONTEXT` | macro | `bof/test/upload.c:21` | `#define CRYPT_VERIFYCONTEXT` |
| `Cipher` | function | `bof/test/upload.c:132` | `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)` |
| `HANDLE` | function | `bof/test/upload.c:354` | `typedef HANDLE (WINAPI *t_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);` |
| `HCRYPTPROV` | type_alias | `bof/test/upload.c:18` | `typedef ULONG_PTR HCRYPTPROV;` |
| `HINTERNET` | type_alias | `bof/test/upload.c:16` | `typedef void* HINTERNET;` |
| `HINTERNET` | function | `bof/test/upload.c:376` | `typedef HINTERNET (WINAPI *t_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);` |
| `INTERNET_PORT` | type_alias | `bof/test/upload.c:17` | `typedef WORD INTERNET_PORT;` |
| `KeyExpansion` | function | `bof/test/upload.c:145` | `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...` |
| `LPVOID` | function | `bof/test/upload.c:314` | `typedef LPVOID (WINAPI *t_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);` |
| `MixColumns` | function | `bof/test/upload.c:120` | `static void MixColumns(state_t* state)` |
| `NEXT_TOKEN` | macro | `bof/test/upload.c:244` | `#define NEXT_TOKEN(dst,lim)` |
| `NEXT_TOKEN` | function | `bof/test/upload.c:252` | `NEXT_TOKEN(local_path, 128);` |
| `Nb` | macro | `bof/test/upload.c:27` | `#define Nb` |
| `Nk` | macro | `bof/test/upload.c:26` | `#define Nk` |
| `Nr` | macro | `bof/test/upload.c:25` | `#define Nr` |
| `PROV_RSA_AES` | macro | `bof/test/upload.c:20` | `#define PROV_RSA_AES` |
| `ParseUploadArgs` | function | `bof/test/upload.c:230` | `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...` |
| `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` | macro | `bof/test/upload.c:30` | `#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID` |
| `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` | macro | `bof/test/upload.c:31` | `#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` |
| `SECURITY_FLAG_IGNORE_UNKNOWN_CA` | macro | `bof/test/upload.c:28` | `#define SECURITY_FLAG_IGNORE_UNKNOWN_CA` |
| `ShiftRows` | function | `bof/test/upload.c:112` | `static void ShiftRows(state_t* state)` |
| `SubBytes` | function | `bof/test/upload.c:105` | `static void SubBytes(state_t* state, const uint8_t* sbox)` |
| `WIN32_LEAN_AND_MEAN` | macro | `bof/test/upload.c:1` | `#define WIN32_LEAN_AND_MEAN` |
| `WINHTTP_ACCESS_TYPE_NO_PROXY` | macro | `bof/test/upload.c:35` | `#define WINHTTP_ACCESS_TYPE_NO_PROXY` |
| `WINHTTP_NO_PROXY_BYPASS` | macro | `bof/test/upload.c:43` | `#define WINHTTP_NO_PROXY_BYPASS` |
| `WINHTTP_NO_PROXY_NAME` | macro | `bof/test/upload.c:39` | `#define WINHTTP_NO_PROXY_NAME` |
| `WINHTTP_OPTION_SECURITY_FLAGS` | macro | `bof/test/upload.c:32` | `#define WINHTTP_OPTION_SECURITY_FLAGS` |
| `__imp_GetProcAddress` | variable | `bof/test/upload.c:9` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/upload.c:8` | `extern PVOID __imp_LoadLibraryA;` |
| `go` | function | `bof/test/upload.c:273` | `void go(char *args, int alen)` |
| `int` | function | `bof/test/upload.c:358` | `typedef int (WINAPI *t_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);` |
| `my_base64_encode` | function | `bof/test/upload.c:205` | `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...` |
| `my_contains_dotdot` | function | `bof/test/upload.c:71` | `static BOOL my_contains_dotdot(const char* path)` |
| `my_memcpy` | function | `bof/test/upload.c:58` | `static void* my_memcpy(void* dst, const void* src, size_t len)` |
| `my_memset` | function | `bof/test/upload.c:65` | `static void* my_memset(void* dst, int val, size_t len)` |
| `my_strchr` | function | `bof/test/upload.c:80` | `static char* my_strchr(const char *s, int c)` |
| `my_strlen` | function | `bof/test/upload.c:53` | `static int my_strlen(const char *s)` |
| `pCloseHandle` | function | `bof/test/upload.c:422` | `pCloseHandle(hFile);` |
| `pMultiByteToWideChar` | function | `bof/test/upload.c:489` | `pMultiByteToWideChar(CP_UTF8, 0, host, -1, w_host, host_len);` |
| `pVirtualFree` | function | `bof/test/upload.c:438` | `pVirtualFree(fileBuffer, 0, MEM_RELEASE);` |
| `pWinHttpCloseHandle` | function | `bof/test/upload.c:516` | `pWinHttpCloseHandle(hSession);` |
| `uint32_t` | type_alias | `bof/test/upload.c:15` | `typedef unsigned int uint32_t;` |
| `uint8_t` | type_alias | `bof/test/upload.c:14` | `typedef unsigned char uint8_t;` |
| `xtime` | function | `bof/test/upload.c:93` | `static uint8_t xtime(uint8_t x)` |
| `BOOL` | function | `bof/test/vncrelay.c:39` | `typedef BOOL (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);` |
| `BeaconPrintf` | function | `bof/test/vncrelay.c:133` | `BeaconPrintf(CALLBACK_OUTPUT, "[VNC RELAY] Iniciando relay en 0.0.0.0:5901 → 127.0.0.1:5900\n");` |
| `FARPROC` | function | `bof/test/vncrelay.c:37` | `typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);` |
| `FD_SET` | function | `bof/test/vncrelay.c:97` | `FD_SET(client_sock, &read_fds);` |
| `FD_ZERO` | function | `bof/test/vncrelay.c:96` | `FD_ZERO(&read_fds);` |
| `HMODULE` | function | `bof/test/vncrelay.c:36` | `typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);` |
| `LPVOID` | function | `bof/test/vncrelay.c:38` | `typedef LPVOID (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);` |
| `SOCKET` | function | `bof/test/vncrelay.c:45` | `typedef SOCKET (WINAPI *SOCKETFN)(int, int, int);` |
| `ULONG` | function | `bof/test/vncrelay.c:56` | `typedef ULONG (WINAPI *HTONL)(ULONG);` |
| `USHORT` | function | `bof/test/vncrelay.c:57` | `typedef USHORT (WINAPI *HTONS)(USHORT);` |
| `__imp_CloseHandle` | variable | `bof/test/vncrelay.c:31` | `extern PVOID __imp_CloseHandle;` |
| `__imp_GetProcAddress` | variable | `bof/test/vncrelay.c:28` | `extern PVOID __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/test/vncrelay.c:27` | `extern PVOID __imp_LoadLibraryA;` |
| `__imp_VirtualAlloc` | variable | `bof/test/vncrelay.c:29` | `extern PVOID __imp_VirtualAlloc;` |
| `__imp_VirtualFree` | variable | `bof/test/vncrelay.c:30` | `extern PVOID __imp_VirtualFree;` |
| `go` | function | `bof/test/vncrelay.c:132` | `void go(char *args, int alen)` |
| `int` | function | `bof/test/vncrelay.c:44` | `typedef int (WINAPI *WSASTARTUP)(WORD, LPWSADATA);` |
| `my_FD_ISSET` | function | `bof/test/vncrelay.c:62` | `int my_FD_ISSET(SOCKET sock, fd_set *set)` |
| `pCloseSocket` | function | `bof/test/vncrelay.c:185` | `pCloseSocket(listen_sock);` |
| `relay_traffic` | function | `bof/test/vncrelay.c:75` | `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)` |
| `BeaconPrintf` | function | `bof/test/winver.c:30` | `BeaconPrintf(CALLBACK_ERROR, "GetVersionExA falló\n");` |
| `__imp_GetVersionExA` | variable | `bof/test/winver.c:22` | `extern PVOID __imp_GetVersionExA;` |
| `go` | function | `bof/test/winver.c:24` | `void go(char *args, int alen)` |
| `BEACON_H` | macro | `bof/whoami/beacon.h:21` | `#define BEACON_H` |
| `CALLBACK_ERROR` | macro | `bof/whoami/beacon.h:42` | `#define CALLBACK_ERROR` |
| `CALLBACK_OUTPUT` | macro | `bof/whoami/beacon.h:40` | `#define CALLBACK_OUTPUT` |
| `datap` | struct | `bof/whoami/beacon.h:25` | `` |
| `BOOL` | function | `bof/whoami/whoami.c:44` | `typedef BOOL (WINAPI *GetUserNameW_t)(LPWSTR, LPDWORD);` |
| `BeaconPrintf` | function | `bof/whoami/whoami.c:35` | `BeaconPrintf(CALLBACK_OUTPUT, "[WHOAMI] 🔍 Iniciando whoami final fixed");` |
| `__imp_GetComputerNameA` | variable | `bof/whoami/whoami.c:29` | `extern FARPROC __imp_GetComputerNameA;` |
| `__imp_GetModuleHandleA` | variable | `bof/whoami/whoami.c:26` | `extern FARPROC __imp_GetModuleHandleA;` |
| `__imp_GetProcAddress` | variable | `bof/whoami/whoami.c:27` | `extern FARPROC __imp_GetProcAddress;` |
| `__imp_LoadLibraryA` | variable | `bof/whoami/whoami.c:28` | `extern FARPROC __imp_LoadLibraryA;` |
| `go` | function | `bof/whoami/whoami.c:34` | `void go(char *args, int alen)` |
| `CJSON_PUBLIC` | function | `cJSON.c:94` | `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:99` | `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:109` | `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:124` | `CJSON_PUBLIC(const char*) cJSON_Version(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:209` | `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1133` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1235` | `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1315` | `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1320` | `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1351` | `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1934` | `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1976` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:1981` | `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:1986` | `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2111` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2122` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2132` | `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2142` | `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2154` | `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2166` | `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2178` | `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2190` | `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2202` | `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2214` | `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2226` | `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2238` | `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2250` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2286` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2296` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2301` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2308` | `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2315` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2320` | `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2362` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2412` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2445` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2450` | `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...` |
| `CJSON_PUBLIC` | function | `cJSON.c:2467` | `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2478` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2489` | `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2500` | `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2525` | `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2542` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2554` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2566` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2578` | `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2595` | `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2606` | `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2658` | `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2698` | `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2738` | `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2921` | `CJSON_PUBLIC(void) cJSON_Minify(char *json)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2971` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2981` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:2991` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3001` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3011` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3021` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3031` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3041` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3051` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3061` | `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3071` | `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...` |
| `CJSON_PUBLIC` | function | `cJSON.c:3193` | `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)` |
| `CJSON_PUBLIC` | function | `cJSON.c:3198` | `CJSON_PUBLIC(void) cJSON_free(void *object)` |
| `NAN` | macro | `cJSON.c:82` | `#define NAN` |
| `NAN` | macro | `cJSON.c:84` | `#define NAN` |
| `_CRT_SECURE_NO_DEPRECATE` | macro | `cJSON.c:28` | `#define _CRT_SECURE_NO_DEPRECATE` |
| `add_item_to_array` | function | `cJSON.c:2020` | `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)` |
| `add_item_to_object` | function | `cJSON.c:2073` | `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` |
| `buffer_at_offset` | macro | `cJSON.c:306` | `#define buffer_at_offset(buffer)` |
| `buffer_skip_whitespace` | function | `cJSON.c:1093` | `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3157` | `cJSON_ArrayForEach(a_element, a)` |
| `cJSON_ArrayForEach` | function | `cJSON.c:3173` | `cJSON_ArrayForEach(b_element, b)` |
| `cJSON_Delete` | function | `cJSON.c:262` | `cJSON_Delete(item->child);` |
| `cJSON_DetachItemViaPointer` | function | `cJSON.c:2293` | `return cJSON_DetachItemViaPointer(array, get_array_item(array, (size_t)which));` |
| `cJSON_Duplicate_rec` | function | `cJSON.c:2785` | `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)` |
| `cJSON_New_Item` | function | `cJSON.c:242` | `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` |
| `cJSON_ParseWithLengthOpts` | function | `cJSON.c:1145` | `return cJSON_ParseWithLengthOpts(value, buffer_length, return_parse_end, require_null_terminated);` |
| `cJSON_ParseWithOpts` | function | `cJSON.c:1233` | `return cJSON_ParseWithOpts(value, 0, 0);` |
| `cJSON_ReplaceItemViaPointer` | function | `cJSON.c:2419` | `return cJSON_ReplaceItemViaPointer(array, get_array_item(array, (size_t)which), newitem);` |
| `cJSON_free` | function | `cJSON.c:475` | `cJSON_free(object->valuestring);` |
| `cJSON_strdup` | function | `cJSON.c:188` | `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)` |
| `can_access_at_index` | macro | `cJSON.c:303` | `#define can_access_at_index(buffer, index)` |
| `can_read` | macro | `cJSON.c:301` | `#define can_read(buffer, size)` |
| `cannot_access_at_index` | macro | `cJSON.c:304` | `#define cannot_access_at_index(buffer, index)` |
| `case_insensitive_strcmp` | function | `cJSON.c:134` | `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` |
| `cast_away_const` | function | `cJSON.c:2066` | `static void* cast_away_const(const void* string)` |
| `cjson_min` | macro | `cJSON.c:1240` | `#define cjson_min(a, b)` |
| `compare_double` | function | `cJSON.c:592` | `static cJSON_bool compare_double(double a, double b)` |
| `create_reference` | function | `cJSON.c:2000` | `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` |
| `ensure` | function | `cJSON.c:494` | `static unsigned char* ensure(printbuffer * const p, size_t needed)` |
| `error` | struct | `cJSON.c:88` | `` |
| `false` | macro | `cJSON.c:70` | `#define false` |
| `free` | function | `cJSON.c:172` | `free(pointer);` |
| `get_array_item` | function | `cJSON.c:1915` | `static cJSON* get_array_item(const cJSON *array, size_t index)` |
| `get_decimal_point` | function | `cJSON.c:281` | `static unsigned char get_decimal_point(void)` |
| `get_object_item` | function | `cJSON.c:1944` | `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...` |
| `internal_free` | function | `cJSON.c:170` | `static void CJSON_CDECL internal_free(void *pointer)` |
| `internal_free` | macro | `cJSON.c:180` | `#define internal_free` |
| `internal_hooks` | struct | `cJSON.c:157` | `` |
| `internal_malloc` | function | `cJSON.c:166` | `static void * CJSON_CDECL internal_malloc(size_t size)` |
| `internal_malloc` | macro | `cJSON.c:179` | `#define internal_malloc` |
| `internal_realloc` | function | `cJSON.c:174` | `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)` |
| `internal_realloc` | macro | `cJSON.c:181` | `#define internal_realloc` |
| `isinf` | macro | `cJSON.c:74` | `#define isinf(d)` |
| `isnan` | macro | `cJSON.c:77` | `#define isnan(d)` |
| `malloc` | function | `cJSON.c:168` | `return malloc(size);` |
| `memcpy` | function | `cJSON.c:205` | `memcpy(copy, string, length);` |
| `memset` | function | `cJSON.c:247` | `memset(node, '\0', sizeof(cJSON));` |
| `minify_string` | function | `cJSON.c:2899` | `static void minify_string(char **input, char **output)` |
| `parse_array` | function | `cJSON.c:1501` | `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_buffer` | struct | `cJSON.c:291` | `` |
| `parse_hex4` | function | `cJSON.c:669` | `static unsigned parse_hex4(const unsigned char * const input)` |
| `parse_number` | function | `cJSON.c:309` | `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_object` | function | `cJSON.c:1661` | `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_string` | function | `cJSON.c:827` | `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` |
| `parse_value` | function | `cJSON.c:1372` | `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` |
| `print` | function | `cJSON.c:1242` | `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` |
| `print_array` | function | `cJSON.c:1599` | `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_number` | function | `cJSON.c:599` | `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_object` | function | `cJSON.c:1780` | `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` |
| `print_string` | function | `cJSON.c:1079` | `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` |
| `print_string_ptr` | function | `cJSON.c:957` | `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` |
| `print_value` | function | `cJSON.c:1427` | `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` |
| `printbuffer` | struct | `cJSON.c:482` | `` |
| `realloc` | function | `cJSON.c:176` | `return realloc(pointer, size);` |
| `replace_item_in_object` | function | `cJSON.c:2422` | `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...` |
| `skip_multiline_comment` | function | `cJSON.c:2885` | `static void skip_multiline_comment(char **input)` |
| `skip_oneline_comment` | function | `cJSON.c:2872` | `static void skip_oneline_comment(char **input)` |
| `skip_utf8_bom` | function | `cJSON.c:1119` | `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` |
| `sprintf` | function | `cJSON.c:128` | `sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH);` |
| `static_strlen` | macro | `cJSON.c:185` | `#define static_strlen(string_literal)` |
| `strcpy` | function | `cJSON.c:464` | `strcpy(object->valuestring, valuestring);` |
| `suffix_object` | function | `cJSON.c:1993` | `static void suffix_object(cJSON *prev, cJSON *item)` |
| `tolower` | function | `cJSON.c:153` | `return tolower(*string1) - tolower(*string2);` |
| `true` | macro | `cJSON.c:65` | `#define true` |
| `update_offset` | function | `cJSON.c:579` | `static void update_offset(printbuffer * const buffer)` |
| `utf16_literal_to_utf8` | function | `cJSON.c:706` | `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` |
| `void` | function | `cJSON.c:160` | `void (CJSON_CDECL *deallocate)(void *pointer);` |
| `CJSON_CDECL` | macro | `cJSON.h:43` | `#define CJSON_CDECL` |
| `CJSON_CDECL` | macro | `cJSON.h:60` | `#define CJSON_CDECL` |
| `CJSON_CIRCULAR_LIMIT` | macro | `cJSON.h:132` | `#define CJSON_CIRCULAR_LIMIT` |
| `CJSON_EXPORT_SYMBOLS` | macro | `cJSON.h:49` | `#define CJSON_EXPORT_SYMBOLS` |
| `CJSON_NESTING_LIMIT` | macro | `cJSON.h:126` | `#define CJSON_NESTING_LIMIT` |
| `CJSON_PUBLIC` | macro | `cJSON.h:53` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:55` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:57` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:64` | `#define CJSON_PUBLIC(type)` |
| `CJSON_PUBLIC` | macro | `cJSON.h:66` | `#define CJSON_PUBLIC(type)` |
| `CJSON_STDCALL` | macro | `cJSON.h:45` | `#define CJSON_STDCALL` |
| `CJSON_STDCALL` | macro | `cJSON.h:61` | `#define CJSON_STDCALL` |
| `CJSON_VERSION_MAJOR` | macro | `cJSON.h:71` | `#define CJSON_VERSION_MAJOR` |
| `CJSON_VERSION_MINOR` | macro | `cJSON.h:72` | `#define CJSON_VERSION_MINOR` |
| `CJSON_VERSION_PATCH` | macro | `cJSON.h:73` | `#define CJSON_VERSION_PATCH` |
| `__WINDOWS__` | macro | `cJSON.h:32` | `#define __WINDOWS__` |
| `cJSON` | struct | `cJSON.h:92` | `` |
| `cJSON_Array` | macro | `cJSON.h:84` | `#define cJSON_Array` |
| `cJSON_ArrayForEach` | macro | `cJSON.h:285` | `#define cJSON_ArrayForEach(element, array)` |
| `cJSON_False` | macro | `cJSON.h:79` | `#define cJSON_False` |
| `cJSON_Hooks` | struct | `cJSON.h:114` | `` |
| `cJSON_Invalid` | macro | `cJSON.h:78` | `#define cJSON_Invalid` |
| `cJSON_IsReference` | macro | `cJSON.h:87` | `#define cJSON_IsReference` |
| `cJSON_NULL` | macro | `cJSON.h:81` | `#define cJSON_NULL` |
| `cJSON_Number` | macro | `cJSON.h:82` | `#define cJSON_Number` |
| `cJSON_Object` | macro | `cJSON.h:85` | `#define cJSON_Object` |
| `cJSON_Raw` | macro | `cJSON.h:86` | `#define cJSON_Raw` |
| `cJSON_SetBoolValue` | macro | `cJSON.h:278` | `#define cJSON_SetBoolValue(object, boolValue)` |
| `cJSON_SetIntValue` | macro | `cJSON.h:270` | `#define cJSON_SetIntValue(object, number)` |
| `cJSON_SetNumberValue` | macro | `cJSON.h:273` | `#define cJSON_SetNumberValue(object, number)` |
| `cJSON_String` | macro | `cJSON.h:83` | `#define cJSON_String` |
| `cJSON_StringIsConst` | macro | `cJSON.h:89` | `#define cJSON_StringIsConst` |
| `cJSON_True` | macro | `cJSON.h:80` | `#define cJSON_True` |
| `cJSON__h` | macro | `cJSON.h:24` | `#define cJSON__h` |
| `cJSON_bool` | type_alias | `cJSON.h:120` | `typedef int cJSON_bool;` |
| `next` | variable | `cJSON.h:27` | `extern "C" { #endif #if !defined(__WINDOWS__) && (defined(WIN32) \|\| defined(WIN64) \|\| defined(_MSC_VER) \|\| defined` |
| `sensitive` | function | `cJSON.h:249` | `* case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */ CJSON_PUBLIC(cJSON_` |
| `void` | function | `cJSON.h:118` | `void (CJSON_CDECL *free_fn)(void *ptr);` |
| `crc32` | function | `gen_beacon.sh:5916` | `` |
| `show_help` | function | `gen_beacon.sh:34` | `` |
| `xor_string` | function | `gen_beacon.sh:138` | `` |
| `usage` | function | `gen_dll_rev.sh:12` | `` |
| `usage` | function | `gen_dll_ss.sh:10` | `` |
| `usage` | function | `gen_key.sh:10` | `` |
| `show_help` | function | `gen_module.sh:18` | `` |
| `xor_obfuscate` | function | `gen_module.sh:35` | `` |
| `djb2` | function | `generate_hashs.py:23` | `def djb2(s)` |
| `generate_bof_test` | function | `generate_hashs.py:491` | `def generate_bof_test()` |
| `generate_coff_loader` | function | `generate_hashs.py:223` | `def generate_coff_loader()` |
| `main` | function | `generate_hashs.py:553` | `def main()` |
