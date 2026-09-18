# Subsystem: calc

## bof/calc/beacon.h
- Layer: utility
- Language: h
- Symbols:
  - `datap` (struct, line 25)
  - `BEACON_H` (macro, line 21) `#define BEACON_H`
  - `CALLBACK_OUTPUT` (macro, line 41) `#define CALLBACK_OUTPUT`
  - `CALLBACK_ERROR` (macro, line 42) `#define CALLBACK_ERROR`
- Imported by: `bof/calc/calc.c`

## bof/calc/calc.c
- Layer: utility
- Language: c
- Symbols:
  - `go` (function, line 34) `void go(char *args, int alen)`
  - `__imp_GetModuleHandleA` (variable, line 26) `extern FARPROC __imp_GetModuleHandleA;`
  - `__imp_GetProcAddress` (variable, line 27) `extern FARPROC __imp_GetProcAddress;`
  - `__imp_LoadLibraryA` (variable, line 28) `extern FARPROC __imp_LoadLibraryA;`
  - `__imp_GetComputerNameA` (variable, line 29) `extern FARPROC __imp_GetComputerNameA;`
  - `__imp_CloseHandle` (variable, line 30) `extern FARPROC __imp_CloseHandle;`
- Depends on: `bof/calc/beacon.h`
