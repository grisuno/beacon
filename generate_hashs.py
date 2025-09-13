# generate_hashes.py
def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

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

for func in imp_functions:
    print(f'    {{ 0x{djb2(func):08x}, (void*){func.replace("__imp_", "")} }}, // "{func}"')
