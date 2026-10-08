# bof/test

*Community 0 | 24 files | cohesion 0.97*

## Definition

This community groups 24 file(s) rooted at `bof/test` with dominant language c (cohesion 0.97). Central symbols: `AES256_KEYLEN`, `AES_BLOCKLEN`, `AES_CFB_encrypt_buffer`, `AES_ctx`, `AES_init_ctx`, `AF_INET`, `AddRoundKey`, `BEACON_H`. Core file: `COFFLoader3.c` (258 symbols).

## Files

### `bof/test` (16 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/test/Test.c` | c | testing | 1 | no |
| `bof/test/amsibypass.c` | c | testing | 5 | no |
| `bof/test/beacon.h` | h | testing | 4 | no |
| `bof/test/cmdwhoami.c` | c | testing | 4 | no |
| `bof/test/disablelog.c` | c | testing | 9 | no |
| `bof/test/getenv.c` | c | testing | 2 | no |
| `bof/test/loadvnc.c` | c | testing | 8 | no |
| `bof/test/persist.c` | c | testing | 4 | no |
| `bof/test/persistsvc.c` | c | testing | 13 | no |
| `bof/test/scan_shellcode.c` | c | testing | 9 | no |
| `bof/test/shellcode.c` | c | testing | 3 | no |
| `bof/test/sock5.c` | c | testing | 41 | yes |

### `.` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `COFFLoader3.c` | c | utility | 258 | no |
| `beacon.h` | h | utility | 4 | no |

### `bof/calc` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/calc/beacon.h` | h | utility | 4 | no |
| `bof/calc/calc.c` | c | utility | 6 | no |

### `bof/etw` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/etw/beacon.h` | h | utility | 4 | no |
| `bof/etw/etw.c` | c | utility | 5 | no |

### `bof/whoami` (2 files)

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `bof/whoami/beacon.h` | h | utility | 4 | no |
| `bof/whoami/whoami.c` | c | utility | 5 | no |

*... and 4 more files in this community.*


## Key Symbols

- `__imp_BeaconPrintf` (variable, `COFFLoader3.c:332`) `extern PVOID __imp_BeaconPrintf;`
- `__imp_BeaconOutput` (variable, `COFFLoader3.c:333`) `extern PVOID __imp_BeaconOutput;`
- `__imp_BeaconDataParse` (variable, `COFFLoader3.c:334`) `extern PVOID __imp_BeaconDataParse;`
- `__imp_BeaconDataInt` (variable, `COFFLoader3.c:335`) `extern PVOID __imp_BeaconDataInt;`
- `__imp_BeaconDataShort` (variable, `COFFLoader3.c:336`) `extern PVOID __imp_BeaconDataShort;`
- `__imp_BeaconDataExtract` (variable, `COFFLoader3.c:337`) `extern PVOID __imp_BeaconDataExtract;`
- `__imp_LoadLibraryA` (variable, `COFFLoader3.c:338`) `extern PVOID __imp_LoadLibraryA;`
- `__imp_LoadLibraryW` (variable, `COFFLoader3.c:339`) `extern PVOID __imp_LoadLibraryW;`
- `__imp_GetModuleHandleA` (variable, `COFFLoader3.c:340`) `extern PVOID __imp_GetModuleHandleA;`
- `__imp_GetModuleHandleW` (variable, `COFFLoader3.c:341`) `extern PVOID __imp_GetModuleHandleW;`
- `__imp_GetProcAddress` (variable, `COFFLoader3.c:342`) `extern PVOID __imp_GetProcAddress;`
- `__imp_GetLastError` (variable, `COFFLoader3.c:343`) `extern PVOID __imp_GetLastError;`
- `__imp_CloseHandle` (variable, `COFFLoader3.c:344`) `extern PVOID __imp_CloseHandle;`
- `__imp_ExitProcess` (variable, `COFFLoader3.c:345`) `extern PVOID __imp_ExitProcess;`
- `__imp_ExitThread` (variable, `COFFLoader3.c:346`) `extern PVOID __imp_ExitThread;`
- `__imp_Sleep` (variable, `COFFLoader3.c:347`) `extern PVOID __imp_Sleep;`
- `__imp_CreateThread` (variable, `COFFLoader3.c:348`) `extern PVOID __imp_CreateThread;`
- `__imp_GetCurrentProcess` (variable, `COFFLoader3.c:349`) `extern PVOID __imp_GetCurrentProcess;`
- `__imp_GetCurrentProcessId` (variable, `COFFLoader3.c:350`) `extern PVOID __imp_GetCurrentProcessId;`
- `__imp_GetCurrentThreadId` (variable, `COFFLoader3.c:351`) `extern PVOID __imp_GetCurrentThreadId;`
- `__imp_GetTickCount` (variable, `COFFLoader3.c:352`) `extern PVOID __imp_GetTickCount;`
- `__imp_GetTickCount64` (variable, `COFFLoader3.c:353`) `extern PVOID __imp_GetTickCount64;`
- `__imp_CreateFileA` (variable, `COFFLoader3.c:354`) `extern PVOID __imp_CreateFileA;`
- `__imp_CreateFileW` (variable, `COFFLoader3.c:355`) `extern PVOID __imp_CreateFileW;`
- `__imp_ReadFile` (variable, `COFFLoader3.c:356`) `extern PVOID __imp_ReadFile;`
- `__imp_WriteFile` (variable, `COFFLoader3.c:357`) `extern PVOID __imp_WriteFile;`
- `__imp_SetFilePointer` (variable, `COFFLoader3.c:358`) `extern PVOID __imp_SetFilePointer;`
- `__imp_SetEndOfFile` (variable, `COFFLoader3.c:359`) `extern PVOID __imp_SetEndOfFile;`
- `__imp_DeleteFileA` (variable, `COFFLoader3.c:360`) `extern PVOID __imp_DeleteFileA;`
- `__imp_DeleteFileW` (variable, `COFFLoader3.c:361`) `extern PVOID __imp_DeleteFileW;`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 19
- Cross-boundary resolved imports (EXTRACTED): 1

## Connections

- [EXTRACTED] depends_on community 1 <-> 0 (strength 0.9): Extracted import edge crosses communities: beacon.c imports beacon.h.
- [INFERRED] bridges community 1 <-> 0 (strength 0.5): Inferred cross-community bridge: aes.c reaches bof/calc/beacon.h in 5 hops.
- [INFERRED] bridges community 1 <-> 0 (strength 0.5): Inferred cross-community bridge: aes.c reaches bof/etw/beacon.h in 5 hops.
- [INFERRED] bridges community 1 <-> 0 (strength 0.5): Inferred cross-community bridge: aes.c reaches bof/test/beacon.h in 5 hops.
- [INFERRED] bridges community 1 <-> 0 (strength 0.5): Inferred cross-community bridge: aes.c reaches bof/whoami/beacon.h in 5 hops.
- [INFERRED] bridges community 0 <-> 1 (strength 0.5): Inferred cross-community bridge: bof/calc/beacon.h reaches cJSON.c in 5 hops.

## Risks

- No scoped security, taint, cycle, or layer risks.

## Open Questions

- Why do 22 file(s) lack file-level docs (e.g. `COFFLoader3.c`)? What purpose do they serve?
- What would break if the most connected file in bof/test changed?
- Should bof/test be split, given cohesion 0.97?

## Sources

- `COFFLoader3.c`
- `beacon.h`
- `bof/calc/beacon.h`
- `bof/calc/calc.c`
- `bof/etw/beacon.h`
- `bof/etw/etw.c`
- `bof/test/Test.c`
- `bof/test/amsibypass.c`
- `bof/test/beacon.h`
- `bof/test/cmdwhoami.c`
- `bof/test/disablelog.c`
- `bof/test/getenv.c`
- `bof/test/loadvnc.c`
- `bof/test/persist.c`
- `bof/test/persistsvc.c`
- `bof/test/scan_shellcode.c`
- `bof/test/shellcode.c`
- `bof/test/sock5.c`
- `bof/test/uacbypass.c`
- `bof/test/upload.c`
- *... and 4 more*
