#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "beacon.h"

// === Estructuras COFF mínimas ===
#pragma pack(push, 1)
#pragma comment(linker, "/INCLUDE:__imp_GetModuleHandleA")
#pragma comment(linker, "/INCLUDE:__imp_GetProcAddress")
#pragma comment(linker, "/INCLUDE:__imp_LoadLibraryA")
#pragma comment(linker, "/INCLUDE:__imp_GetComputerNameA")
#pragma comment(linker, "/INCLUDE:__imp_CloseHandle")
// Declarar las referencias externas
extern PVOID __imp_GetModuleHandleA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_LoadLibraryA;
extern PVOID __imp_GetComputerNameA;
extern PVOID __imp_CloseHandle;
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
    { 0x9e9a9b9c, BeaconDataParse },                  // "BeaconDataParse"
    { 0x1a2b3c4d, BeaconDataInt },                    // "BeaconDataInt"
    { 0x5e6f7a8b, BeaconDataShort },                  // "BeaconDataShort"
    { 0x2c3d4e5f, BeaconDataExtract },                // "BeaconDataExtract"
    { 0x700d8660, BeaconPrintf },                     // "BeaconPrintf"
    { 0x36b7a083, (void*)BeaconPrintf },
    { 0x6df4b81e, (void*)BeaconOutput },                     // "BeaconOutput"

    // === Funciones del sistema ===
    { 0x1d1a2b3c, (void*)FileTimeToLocalFileTime },   // "KERNEL32$FileTimeToLocalFileTime"
    { 0x3eb5b2fb, (void*)&__imp_GetModuleHandleA },          // "KERNEL32$GetModuleHandleA"
    { 0xe8caea02, (void*)&__imp_GetProcAddress },            // "KERNEL32$GetProcAddress"
    { 0x266a0b1e, (void*)&__imp_LoadLibraryA },              // "__imp_LoadLibraryA"
    { 0x8f043359, (void*)&__imp_GetComputerNameA }, // "__imp_GetComputerNameA"
    { 0xE15EABCA, (void*)&__imp_CloseHandle }, // "__imp_CloseHandle"

    { 0xdb66bdc9, (void*)CoInitializeEx },            // "OLE32$CoInitializeEx"
    { 0x087cf3a9, (void*)IIDFromString },             // "OLE32$IIDFromString"
    { 0x1adf272f, (void*)CoUninitialize },            // "OLE32$CoUninitialize"
    { 0x36dd7e55, (void*)VariantChangeType },         // "OLEAUT32$VariantChangeType"
    { 0x58f56f64, (void*)VariantClear },              // "OLEAUT32$VariantClear"
    { 0xe3adac11, (void*)VariantInit },
    { 0xd9dcafff, (void*)FreeLibrary },
    { 0xe72d0506, (void*)GetLastError },
    { 0x4306cf51, (void*)MultiByteToWideChar },
    { 0xaa7cfc34, (void*)FileTimeToLocalFileTime },
    { 0x80df1fae, (void*)FileTimeToSystemTime },
    { 0x7a954a63, (void*)SystemTimeToVariantTime },
    { 0x635db985, (void*)VariantChangeType },
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
