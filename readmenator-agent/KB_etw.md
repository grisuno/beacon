# Subsystem: etw

## bof/etw/beacon.h
- Layer: utility
- Language: h
- Symbols:
  - `datap` (struct, line 25)
  - `BEACON_H` (macro, line 21) `#define BEACON_H`
  - `CALLBACK_OUTPUT` (macro, line 41) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 42) `#define CALLBACK_ERROR`
- Imported by: `bof/etw/etw.c`

## bof/etw/etw.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 26) `void go(char *a,int l)`
  - `__imp_GetModuleHandleA` (variable, line 22) `extern PVOID __imp_GetModuleHandleA;`
  - `__imp_GetProcAddress` (variable, line 23) `extern PVOID __imp_GetProcAddress;`
  - `__imp_VirtualProtect` (variable, line 24) `extern PVOID __imp_VirtualProtect;`
  - `__imp_RtlCopyMemory` (variable, line 25) `extern PVOID __imp_RtlCopyMemory;`
- Depends on: `bof/etw/beacon.h`
