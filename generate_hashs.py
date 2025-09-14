#!/usr/bin/env python3
"""
BOF Bindings Generator for Cobalt Strike
Author: Gris Iscomeback
Email: grisiscomeback@gmail.com
Creation Date: 13/08/2024
License: GPL v3

This script generates C code bindings for BOF (Beacon Object Files) used in Cobalt Strike.
It creates function pointer mappings from imported functions with DJB2 hashing and includes
usage examples for each function using proper casting syntax.

Usage:
    python generate_bof_bindings.py                     # prints colored C code to stdout
    python generate_bof_bindings.py -o bindings.c       # saves to file
    python generate_bof_bindings.py --loader-includes   # genera symbols_loader.inc
    python generate_bof_bindings.py --bof-template      # genera template_bof.inc
    python generate_bof_bindings.py --check-orphans     # revisa símbolos huérfanos en COFFLoader.c
"""

import argparse
import sys
import re

from pygments import highlight
from pygments.lexers import CLexer
from pygments.formatters import Terminal256Formatter


def djb2(s: str) -> int:
    """Compute DJB2 hash of a string."""
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF


# List of required import functions (with or without __imp_ prefix)
imp_functions = [
    "__imp_BeaconPrintf",
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
    "BeaconOutput",
]


# Mapping of function names to their full type signatures and example calls
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
    "__imp_CoInitializeEx": {
        "type": "HRESULT(WINAPI*)(LPVOID, DWORD)",
        "example": 'CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);'
    },
    "__imp_CloseHandle": {
        "type": "BOOL (WINAPI *CloseHandle_t)(HANDLE)",
        "example": "pCloseHandle(pi.hProcess);"
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
    "BeaconOutput": {
        "type": "void(WINAPI*)(int, void*, int)",
        "example": 'BeaconOutput(CALLBACK_OUTPUT, data, size);'
    },
}


# ---------- GENERADORES NUEVOS ----------
def generate_loader_includes():
    """Genera #pragma, externs y tabla de hashes para __imp_*"""
    lines = []
    imp_only = [f for f in imp_functions if f.startswith("__imp_")]

    lines.append("// === AUTO-GENERADO DESDE imp_functions ===")
    lines.append("// 1. Pragmas para linker")
    for func in imp_only:
        lines.append(f'#pragma comment(linker, "/INCLUDE:{func}")')

    lines.append("\n// 2. Referencias externas")
    for func in imp_only:
        lines.append(f"extern PVOID {func};")

    lines.append("\n// 3. Tabla de hashes (__imp_ + alias sin prefijo)")
    lines.append("static SymbolHash g_symbol_table[] = {")
    for func in imp_only:
        alias = func.replace("__imp_", "")
        hash_val = djb2(func)
        hash_alias = djb2(alias)
        lines.append(f'    {{ 0x{hash_val:08X}, (void*)&{func} }}, // "{func}"')
        lines.append(f'    {{ 0x{hash_alias:08X}, (void*)&{func} }}, // "{alias}"')
    lines.append("    {0, NULL} // terminador")
    lines.append("};")

    return "\n".join(lines)


def generate_bof_template():
    """Genera extern FARPROC __imp_* y ejemplos de uso para BOFs"""
    lines = []
    imp_only = [f for f in imp_functions if f.startswith("__imp_")]

    lines.append("// ================================")
    lines.append("// IMPORTS DIRECTOS (AUTO-GENERADO)")
    lines.append("// ================================")
    for func in imp_only:
        lines.append(f"extern FARPROC {func};")

    lines.append("\n// ================================")
    lines.append("// EJEMPLO DE USO")
    lines.append("// ================================")
    for func in imp_only:
        sig = function_signatures.get(func)
        if not sig:
            continue
        func_type = sig["type"]
        clean = func.replace("__imp_", "")
        lines.append(f"// {clean}:")
        lines.append(f'(({func_type}){func})("example");')
    return "\n".join(lines)


def check_orphan_symbols():
    """Revisa si hay símbolos huérfanos en COFFLoader.c"""
    try:
        with open("COFFLoader.c") as f:
            content = f.read()
    except FileNotFoundError:
        print("⚠️  COFFLoader.c no encontrado.")
        return

    orphans = []
    for line in content.splitlines():
        line = line.strip()
        if "__imp_" in line and ("extern" in line or "#pragma" in line):
            match = re.search(r"__imp_\w+", line)
            if match:
                symbol = match.group(0)
                if symbol not in imp_functions:
                    orphans.append(symbol)

    if orphans:
        print("⚠️  Símbolos huérfanos detectados en COFFLoader.c:")
        for sym in orphans:
            print(f"   - {sym}")
    else:
        print("✅ No hay símbolos huérfanos.")


# ---------- GENERADOR ORIGINAL ----------
def generate_c_code():
    """Generate full C binding code with hashes and usage examples."""
    output_lines = []
    output_lines.append("// === AUTO-GENERATED BOF FUNCTION BINDINGS ===\n")
    output_lines.append("#include <windows.h>\n")
    output_lines.append("#include \"beacon.h\"\n\n")

    # Typedefs for clarity
    output_lines.append("// Function pointer typedefs\n")
    seen_types = set()
    for func in imp_functions:
        clean_name = func.replace("__imp_", "")
        sig = function_signatures.get(func)
        if not sig:
            continue
        func_type = sig["type"]
        if func_type not in seen_types:
            alias = f"t_{clean_name}"
            output_lines.append(f"typedef {func_type} {alias};")
            seen_types.add(func_type)
    output_lines.append("\n")

    # Hash table definition
    output_lines.append("// Function hash table\n")
    output_lines.append("struct {\n    uint32_t hash;\n    void* addr;\n} fn_table[] = {")
    for func in imp_functions:
        clean_name = func.replace("__imp_", "")
        hash_val = djb2(func)
        output_lines.append(f'    {{ 0x{hash_val:08X}, (void*)&{clean_name} }}, // "{func}"')
    output_lines.append("};\n\n")

    # Example usage section — DIRECT CASTING WITH __imp_ SYMBOLS
    output_lines.append("// === EXAMPLE USAGE OF FUNCTIONS ===\n")
    output_lines.append("/*\n")
    for func in imp_functions:
        clean_name = func.replace("__imp_", "")
        sig = function_signatures.get(func)
        if not sig:
            continue
        func_type = sig["type"]
        example = sig["example"]

        example_clean = example.rstrip(';')
        output_lines.append(f"// Example call to {clean_name}:")
        output_lines.append(f"(({func_type}){func}){example_clean};")
        output_lines.append(f"// --> {example}")
        output_lines.append("")
    output_lines.append("*/\n")

    # Generate #pragma and extern declarations for __imp_ functions
    imp_only = [f for f in imp_functions if f.startswith("__imp_")]
    if imp_only:
        output_lines.append("// === LINKER DIRECTIVES FOR LOADER ===\n")
        for func in imp_only:
            output_lines.append(f'#pragma comment(linker, "/INCLUDE:{func}")')
        output_lines.append("\n")

        output_lines.append("// === EXTERN DECLARATIONS (PVOID) ===\n")
        for func in imp_only:
            output_lines.append(f"extern PVOID {func};")
        output_lines.append("\n")

        output_lines.append("// === EXTERN DECLARATIONS (FARPROC) ===\n")
        for func in imp_only:
            output_lines.append(f"extern FARPROC {func};")
        output_lines.append("\n")

    # === ESTRUCTURAS COFF MÍNIMAS CON PRAGMA Y EXTERN DENTRO ===
    output_lines.append("// === Estructuras COFF mínimas ===\n")
    output_lines.append("#pragma pack(push, 1)\n")

    output_lines.append('#pragma comment(linker, "/INCLUDE:__imp_GetModuleHandleA")')
    output_lines.append('#pragma comment(linker, "/INCLUDE:__imp_GetProcAddress")')
    output_lines.append('#pragma comment(linker, "/INCLUDE:__imp_LoadLibraryA")')
    output_lines.append('#pragma comment(linker, "/INCLUDE:__imp_GetComputerNameA")')
    output_lines.append("// Declarar las referencias externas")
    output_lines.append("extern PVOID __imp_GetModuleHandleA;")
    output_lines.append("extern PVOID __imp_GetProcAddress;")
    output_lines.append("extern PVOID __imp_LoadLibraryA;")
    output_lines.append("extern PVOID __imp_GetComputerNameA;\n")

    output_lines.append("typedef struct {\n")
    output_lines.append("    char Name[8];\n")
    output_lines.append("    DWORD VirtualSize;\n")
    output_lines.append("    DWORD VirtualAddress;\n")
    output_lines.append("    DWORD SizeOfRawData;\n")
    output_lines.append("    DWORD PointerToRawData;\n")
    output_lines.append("    DWORD PointerToRelocations;\n")
    output_lines.append("    DWORD PointerToLinenumbers;\n")
    output_lines.append("    WORD NumberOfRelocations;\n")
    output_lines.append("    WORD NumberOfLinenumbers;\n")
    output_lines.append("    DWORD Characteristics;\n")
    output_lines.append("} COFFSection;\n\n")

    output_lines.append("typedef struct {\n")
    output_lines.append("    DWORD VirtualAddress;\n")
    output_lines.append("    DWORD SymbolTableIndex;\n")
    output_lines.append("    WORD Type;\n")
    output_lines.append("} COFFRelocation;\n\n")

    output_lines.append("typedef struct {\n")
    output_lines.append("    union {\n")
    output_lines.append("        char Name[8];\n")
    output_lines.append("        struct {\n")
    output_lines.append("            DWORD Zeroes;\n")
    output_lines.append("            DWORD Offset;\n")
    output_lines.append("        };\n")
    output_lines.append("    };\n")
    output_lines.append("    DWORD Value;\n")
    output_lines.append("    SHORT SectionNumber;\n")
    output_lines.append("    WORD Type;\n")
    output_lines.append("    BYTE StorageClass;\n")
    output_lines.append("    BYTE NumberOfAuxSymbols;\n")
    output_lines.append("} COFFSymbol;\n\n")

    output_lines.append("typedef struct {\n")
    output_lines.append("    USHORT Machine;\n")
    output_lines.append("    USHORT NumberOfSections;\n")
    output_lines.append("    DWORD TimeDateStamp;\n")
    output_lines.append("    DWORD PointerToSymbolTable;\n")
    output_lines.append("    DWORD NumberOfSymbols;\n")
    output_lines.append("    USHORT SizeOfOptionalHeader;\n")
    output_lines.append("    USHORT Characteristics;\n")
    output_lines.append("} COFFHeader;\n")
    output_lines.append("#pragma pack(pop)\n")

    return "\n".join(output_lines)


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-o", "--output", help="Output .c file (if not specified, prints to stdout)")
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
        code = generate_c_code()
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(code)
            print(f"[+] Generated bindings saved to: {args.output}")
        else:
            try:
                highlighted = highlight(code, CLexer(), Terminal256Formatter(style='monokai'))
                print(highlighted, end="")
            except ImportError:
                print(code)


if __name__ == "__main__":
    main()
