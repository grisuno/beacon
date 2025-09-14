#!/usr/bin/env python3
"""
BOF Bindings Generator for Cobalt Strike
Author: Gris Iscomeback
Email: grisiscomeback@gmail.com
Creation Date: 13/08/2024
License: GPL v3

Generates:
  - COFFLoader3.c: full COFF loader with DJB2 hash table
  - bof_test.c: ready-to-compile BOF with all imports and example
"""

import argparse
import sys
import re

from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import Terminal256Formatter

# ---------- DJB2 HASH ----------
def djb2(s: str) -> int:
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

# ---------- LISTA DE FUNCIONES ----------
imp_functions = [
    "__imp_BeaconPrintf",
    "__imp_BeaconOutput",
    "__imp_BeaconDataParse",
    "__imp_BeaconDataInt",
    "__imp_BeaconDataShort",
    "__imp_BeaconDataExtract",
    "__imp_LoadLibraryA",
    "__imp_GetModuleHandleA",
    "__imp_GetProcAddress",
    "__imp_CoInitializeEx",
    "__imp_CoUninitialize",
    "__imp_IIDFromString",
    "__imp_VariantInit",
    "__imp_VariantClear",
    "__imp_VariantChangeType",
    "__imp_wsprintfW",
    "__imp_FreeLibrary",
    "__imp_GetLastError",
    "__imp_MultiByteToWideChar",
    "__imp_FileTimeToLocalFileTime",
    "__imp_FileTimeToSystemTime",
    "__imp_SystemTimeToVariantTime",
    "__imp_GetComputerNameA",
    "__imp_OpenProcess",
    "__imp_OpenProcessToken",
    "__imp_DuplicateTokenEx",
    "__imp_ImpersonateLoggedOnUser",
    "__imp_RevertToSelf",
    "__imp_GetCurrentProcessId",
    "__imp_CloseHandle",
    "wcscpy",
    "wcsncpy",
    "mbstowcs",
    "wcscat",
    "wcslen",
    "memset",
    "memcpy",
    "strcpy",
    "strcat",
    "strlen",
    "printf",
    "sprintf",
    "ExitThread",
    "GetLastError",
    "__imp_wsprintfA",
]

# ---------- FIRMAS (solo para BOF) ----------
function_signatures = {
    "__imp_BeaconPrintf": {
        "type": "void(WINAPI*)(int, const char*, ...)",
        "example": 'BeaconPrintf(CALLBACK_OUTPUT, "Hello from BOF\\n");'
    },
    "__imp_LoadLibraryA": {
        "type": "HMODULE(WINAPI*)(LPCSTR)",
        "example": 'HMODULE hKernel32 = LoadLibraryA("kernel32.dll");'
    },
    "__imp_GetModuleHandleA": {
        "type": "HMODULE(WINAPI*)(LPCSTR)",
        "example": 'HMODULE hMod = GetModuleHandleA("ntdll.dll");'
    },
    "__imp_GetProcAddress": {
        "type": "FARPROC(WINAPI*)(HMODULE, LPCSTR)",
        "example": 'FARPROC pFunc = GetProcAddress(hMod, "NtQueryInformationProcess");'
    },
    "__imp_CloseHandle": {
        "type": "BOOL (WINAPI *CloseHandle_t)(HANDLE)",
        "example": "pCloseHandle(pi.hProcess);"
    },
    "__imp_CoInitializeEx": {
        "type": "HRESULT(WINAPI*)(LPVOID, DWORD)",
        "example": 'CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);'
    },
    "__imp_CoUninitialize": {
        "type": "void(WINAPI*)()",
        "example": 'CoUninitialize();'
    },
    "__imp_IIDFromString": {
        "type": "HRESULT(WINAPI*)(LPOLESTR, LPIID)",
        "example": 'IID iid; IIDFromString(L"CLSID_WbemLocator", &iid);'
    },
    "__imp_VariantInit": {
        "type": "void(WINAPI*)(VARIANT*)",
        "example": 'VARIANT var; VariantInit(&var);'
    },
    "__imp_VariantClear": {
        "type": "HRESULT(WINAPI*)(VARIANT*)",
        "example": 'VariantClear(&var);'
    },
    "__imp_VariantChangeType": {
        "type": "HRESULT(WINAPI*)(VARIANT*, VARIANT*, USHORT, VARTYPE)",
        "example": 'VariantChangeType(&destVar, &srcVar, 0, VT_BSTR);'
    },
    "__imp_wsprintfW": {
        "type": "int(WINAPI*)(LPWSTR, LPCWSTR, ...)",
        "example": 'wsprintfW(wbuffer, L"Value: %d", value);'
    },
    "__imp_FreeLibrary": {
        "type": "BOOL(WINAPI*)(HMODULE)",
        "example": 'FreeLibrary(hKernel32);'
    },
    "__imp_GetLastError": {
        "type": "DWORD(WINAPI*)()",
        "example": 'DWORD err = GetLastError();'
    },
    "__imp_MultiByteToWideChar": {
        "type": "int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int)",
        "example": 'MultiByteToWideChar(CP_UTF8, 0, "text", -1, wbuf, 256);'
    },
    "__imp_FileTimeToLocalFileTime": {
        "type": "BOOL(WINAPI*)(CONST FILETIME*, LPFILETIME)",
        "example": 'FILETIME localft; FileTimeToLocalFileTime(&ft, &localft);'
    },
    "__imp_FileTimeToSystemTime": {
        "type": "BOOL(WINAPI*)(CONST FILETIME*, LPSYSTEMTIME)",
        "example": 'SYSTEMTIME st; FileTimeToSystemTime(&ft, &st);'
    },
    "__imp_SystemTimeToVariantTime": {
        "type": "BOOL(WINAPI*)(LPSYSTEMTIME, double*)",
        "example": 'double vt; SystemTimeToVariantTime(&st, &vt);'
    },
    "__imp_GetComputerNameA": {
        "type": "BOOL(WINAPI*)(LPSTR, LPDWORD)",
        "example": 'char pcName[256]; DWORD dwPC = 256; GetComputerNameA(pcName, &dwPC);'
    },
    "wcscpy": {
        "type": "wchar_t*(__cdecl*)(wchar_t*, const wchar_t*)",
        "example": 'wcscpy(dest, L"Hello Wide String");'
    },
    "wcsncpy": {
        "type": "wchar_t*(__cdecl*)(wchar_t*, const wchar_t*, size_t)",
        "example": 'wcsncpy(dest, src, 100);'
    },
    "mbstowcs": {
        "type": "size_t(__cdecl*)(wchar_t*, const char*, size_t)",
        "example": 'mbstowcs(wbuf, "ansi", 256);'
    },
    "wcscat": {
        "type": "wchar_t*(__cdecl*)(wchar_t*, const wchar_t*)",
        "example": 'wcscat(buffer, L" more text");'
    },
    "wcslen": {
        "type": "size_t(__cdecl*)(const wchar_t*)",
        "example": 'size_t len = wcslen(L"test");'
    },
    "memset": {
        "type": "void*(__cdecl*)(void*, int, size_t)",
        "example": 'memset(buffer, 0, sizeof(buffer));'
    },
    "memcpy": {
        "type": "void*(__cdecl*)(void*, const void*, size_t)",
        "example": 'memcpy(dst, src, size);'
    },
    "strcpy": {
        "type": "char*(__cdecl*)(char*, const char*)",
        "example": 'strcpy(buf, "copied string");'
    },
    "strcat": {
        "type": "char*(__cdecl*)(char*, const char*)",
        "example": 'strcat(buf, "appended");'
    },
    "strlen": {
        "type": "size_t(__cdecl*)(const char*)",
        "example": 'size_t l = strlen("hello");'
    },
    "printf": {
        "type": "int(__cdecl*)(const char*, ...)",
        "example": 'printf("Debug: %d\\n", value);'
    },
    "sprintf": {
        "type": "int(__cdecl*)(char*, const char*, ...)",
        "example": 'sprintf(buffer, "Value: %d", val);'
    },
    "ExitThread": {
        "type": "void(WINAPI*)(DWORD)",
        "example": 'ExitThread(0);'
    },
    "GetLastError": {
        "type": "DWORD(WINAPI*)()",
        "example": 'DWORD error = GetLastError();'
    },
    "__imp_wsprintfA": {
        "type": "int(WINAPI*)(LPSTR, LPCSTR, ...)",
        "example": 'wsprintfA(buffer, "Number: %d", num);'
    },
    "__imp_BeaconOutput": {
        "type": "void(WINAPI*)(int, void*, int)",
        "example": 'BeaconOutput(CALLBACK_OUTPUT, data, size);'
    },
}

# ---------- GENERADOR DE COFFLoader3.c ----------
def generate_coff_loader():
    lines = []
    lines.append("""#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "beacon.h"

// === Estructuras COFF mínimas ===
#pragma pack(push, 1)
""")

    # Pragmas e imp_*
    for f in imp_functions:
        if f.startswith("__imp_"):
            lines.append(f'#pragma comment(linker, "/INCLUDE:{f}")')
    lines.append("")

    for f in imp_functions:
        if f.startswith("__imp_"):
            lines.append(f"extern PVOID {f};")
    lines.append("")

    # Definiciones de relocaciones x64
    lines.append("""
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

static uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

typedef struct {
    uint32_t hash;
    void* ptr;
} SymbolHash;

// === TABLA DE SÍMBOLOS (AUTO-GENERADA) ===
static SymbolHash g_symbol_table[] = {
""")

    # Agregar símbolos Beacon
    beacon_syms = [
        ("BeaconDataParse", "BeaconDataParse"),
        ("BeaconDataInt", "BeaconDataInt"),
        ("BeaconDataShort", "BeaconDataShort"),
        ("BeaconDataExtract", "BeaconDataExtract"),
        ("BeaconPrintf", "BeaconPrintf"),
        ("BeaconOutput", "BeaconOutput"),
    ]
    for name, sym in beacon_syms:
        h = djb2(name)
        lines.append(f'    {{ 0x{h:08X}, {sym} }},')

    # Agregar __imp_*
    for f in imp_functions:
        h = djb2(f)
        lines.append(f'    {{ 0x{h:08X}, (void*)&{f} }},')

    # Agregar alias sin __imp_
    for f in imp_functions:
        if f.startswith("__imp_"):
            alias = f.replace("__imp_", "")
            h = djb2(alias)
            lines.append(f'    {{ 0x{h:08X}, (void*)&{f} }},')

    lines.append("    {0, NULL}")
    lines.append("};")

    # Resto del loader (truncado por brevedad, pero incluye handle_relocation, RunCOFF, etc.)
    lines.append("""
// === TRAMPOLINES ===
static void* create_trampoline(void* target) {
    void* tramp = VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return NULL;
    unsigned char* c = (unsigned char*)tramp;
    c[0] = 0x48; c[1] = 0xB8;
    *(uint64_t*)(c+2) = (uint64_t)target;
    c[10] = 0xFF; c[11] = 0xE0;
    return tramp;
}

static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size) {
    if (s->Zeroes == 0 && s->Offset != 0) {
        if (s->Offset >= strtab_size) return NULL;
        return strtab + s->Offset;
    } else {
        static char short_name[9];
        memcpy(short_name, s->Name, 8);
        short_name[8] = '\\0';
        return short_name;
    }
}

typedef void (__attribute__((ms_abi)) * bof_func_t)(char*, int);

__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2) {
    typedef void (__attribute__((ms_abi)) *f_t)(char*, int);
    f_t f = (f_t)func;
    f(arg1, arg2);
}

// === RUNCOFF ===
int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize) {
    if (!coff_data || filesize < sizeof(COFFHeader)) return 1;
    COFFHeader* hdr = (COFFHeader*)coff_data;
    COFFSection* sect = (COFFSection*)(coff_data + sizeof(COFFHeader));
    COFFSymbol* sym = (COFFSymbol*)(coff_data + hdr->PointerToSymbolTable);
    uint32_t strtab_offset = hdr->PointerToSymbolTable + hdr->NumberOfSymbols * sizeof(COFFSymbol);
    char* strtab = (strtab_offset < filesize) ? (char*)(coff_data + strtab_offset) : NULL;
    uint32_t strtab_size = strtab ? (filesize - strtab_offset) : 0;

    void** sections = calloc(hdr->NumberOfSections, sizeof(void*));
    if (!sections) return 1;

    for (int i = 0; i < hdr->NumberOfSections; i++) {
        size_t size = sect[i].SizeOfRawData ? sect[i].SizeOfRawData : 1;
        sections[i] = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!sections[i]) goto cleanup;
        if (sect[i].PointerToRawData && sect[i].SizeOfRawData)
            memcpy(sections[i], coff_data + sect[i].PointerToRawData, sect[i].SizeOfRawData);
    }

    for (int i = 0; i < hdr->NumberOfSections; i++) {
        if (!sect[i].PointerToRelocations || !sect[i].NumberOfRelocations) continue;
        COFFRelocation* rel_start = (COFFRelocation*)(coff_data + sect[i].PointerToRelocations);
        for (int j = 0; j < sect[i].NumberOfRelocations; j++) {
            COFFRelocation* rel = &rel_start[j];
            if (rel->SymbolTableIndex >= hdr->NumberOfSymbols) continue;
            COFFSymbol* s = &sym[rel->SymbolTableIndex];
            char* sym_name = get_symbol_name(s, strtab, strtab_size);
            if (!sym_name) continue;

            char* search_name = sym_name;
            if (strncmp(sym_name, "KERNEL32$", 9) == 0) search_name += 9;
            else if (strncmp(sym_name, "OLE32$", 6) == 0) search_name += 6;
            else if (strncmp(sym_name, "OLEAUT32$", 9) == 0) search_name += 9;

            uint32_t name_hash = djb2_hash(search_name);
            void* target = NULL;
            char* patch_addr = (char*)sections[i] + rel->VirtualAddress;

            if (s->SectionNumber > 0) {
                int32_t addend = *(int32_t*)patch_addr;
                target = (char*)sections[s->SectionNumber - 1] + s->Value + addend;
            } else {
                for (int k = 0; g_symbol_table[k].ptr; k++) {
                    if (g_symbol_table[k].hash == name_hash) {
                        target = g_symbol_table[k].ptr;
                        break;
                    }
                }
            }

            if (!target) continue;

            switch (rel->Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(uint64_t*)patch_addr = (uint64_t)target;
                    break;
                case IMAGE_REL_AMD64_REL32: {
                    int64_t offset = (int64_t)target - ((int64_t)patch_addr + 4);
                    if (offset < INT32_MIN || offset > INT32_MAX) {
                        void* tramp = create_trampoline(target);
                        if (!tramp) continue;
                        offset = (int64_t)tramp - ((int64_t)patch_addr + 4);
                    }
                    *(int32_t*)patch_addr = (int32_t)offset;
                    break;
                }
                default:
                    break;
            }
        }
    }

    bof_func_t go = NULL;
    for (int i = 0; i < hdr->NumberOfSymbols; i++) {
        char* sym_name = get_symbol_name(&sym[i], strtab, strtab_size);
        if (!sym_name) continue;
        if (strcmp(sym_name, functionname) == 0) {
            go = (bof_func_t)((char*)sections[sym[i].SectionNumber - 1] + sym[i].Value);
            break;
        }
    }

    if (go) {
        DWORD old;
        VirtualProtect(go, 0x1000, PAGE_EXECUTE_READWRITE, &old);
        call_go_aligned(go, (char*)argumentdata, argumentSize);
    }

cleanup:
    for (int i = 0; i < hdr->NumberOfSections; i++)
        if (sections[i]) VirtualFree(sections[i], 0, MEM_RELEASE);
    free(sections);
    return go ? 0 : 1;
}
""")
    return "\n".join(lines)

# ---------- GENERADOR DE bof_test.c ----------
def generate_bof_test():
    lines = []
    lines.append("""#include <windows.h>
#include "beacon.h"

// ================================
// IMPORTS DIRECTOS (AUTO-GENERADO)
// ================================
""")
    for f in imp_functions:
        if f.startswith("__imp_"):
            lines.append(f"extern FARPROC {f};")

    lines.append("""
// ================================
// FUNCIÓN PRINCIPAL
// ================================
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] ⚡ Ejecutando BOF de prueba...\\n");

    // Ejemplo: lanzar calc.exe
    HMODULE hKernel32 = (HMODULE)((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ kernel32.dll no encontrada\\n");
        return;
    }

    typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
    GetProcAddress_t pGetProcAddress = (GetProcAddress_t)__imp_GetProcAddress;

    FARPROC pCreateProcessA = pGetProcAddress(hKernel32, "CreateProcessA");
    if (!pCreateProcessA) {
        BeaconPrintf(CALLBACK_ERROR, "[BOF] ❌ CreateProcessA no disponible\\n");
        return;
    }

    typedef BOOL (WINAPI *CreateProcessA_t)(
        LPCSTR, LPSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    CreateProcessA_t CreateProcessA = (CreateProcessA_t)pCreateProcessA;

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (CreateProcessA(NULL, "calc.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[BOF] ✅ Calculadora lanzada!\\n");

        typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
        CloseHandle_t pCloseHandle = (CloseHandle_t)__imp_CloseHandle;
        pCloseHandle(pi.hProcess);
        pCloseHandle(pi.hThread);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[BOF] ❌ No se pudo lanzar calc.exe\\n");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[BOF] ✅ Finalizado\\n");
}
""")
    return "\n".join(lines)

# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-o", "--output", help="Base name for output files (e.g., '-o test' → test_COFFLoader3.c, test_bof_test.c)")
    parser.add_argument("--loader-includes", action="store_true", help="Genera symbols_loader.inc")
    parser.add_argument("--bof-template", action="store_true", help="Genera template_bof.inc")
    parser.add_argument("--check-orphans", action="store_true", help="Revisa símbolos huérfanos en COFFLoader.c")

    args = parser.parse_args()

    if args.loader_includes:
        print(generate_loader_includes())
    elif args.bof_template:
        print(generate_bof_template())
    elif args.check_orphans:
        check_orphan_symbols()
    else:
        coff_code = generate_coff_loader()
        bof_code = generate_bof_test()

        if args.output:
            coff_file = f"{args.output}_COFFLoader3.c"
            bof_file = f"{args.output}_bof_test.c"
            with open(coff_file, "w", encoding="utf-8") as f:
                f.write(coff_code)
            with open(bof_file, "w", encoding="utf-8") as f:
                f.write(bof_code)
            print(f"[+] Generated:")
            print(f"  - {coff_file}")
            print(f"  - {bof_file}")
        else:
            print("=== COFFLoader3.c ===")
            try:
                print(highlight(coff_code, CLexer(), Terminal256Formatter(style='monokai')))
            except ImportError:
                print(coff_code)
            print("\n=== bof_test.c ===")
            try:
                print(highlight(bof_code, CLexer(), Terminal256Formatter(style='monokai')))
            except ImportError:
                print(bof_code)


if __name__ == "__main__":
    main()
