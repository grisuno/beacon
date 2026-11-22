# orphans

*Community 2 | 11 files | cohesion 0.00*

## Definition

This community groups 11 file(s) rooted at `root` with dominant language sh (cohesion 0.00). Central symbols: `C2_URL`, `Copyright`, `CryptStringToBinaryA`, `GetNtdllBase`, `InMemoryOrderLinks`, `Length`, `MAX_PAYLOAD_SIZE`, `Reserved1`. Core file: `stub.c` (19 symbols). Documented purpose: This file is part of Black Basalt Beacon.  Black Basalt Beacon is free software: you can redistribute it and/or modify it under the terms of the GNU General Pub.

## Files

| File | Language | Layer | Symbols | Doc |
|------|----------|-------|---------|-----|
| `app.py` | py | utility | 0 | yes |
| `bof/test/make_table.c` | c | testing | 2 | no |
| `gen_beacon.sh` | sh | utility | 3 | yes |
| `gen_dll.sh` | sh | utility | 0 | yes |
| `gen_dll_rev.sh` | sh | utility | 1 | yes |
| `gen_dll_ss.sh` | sh | utility | 1 | yes |
| `gen_key.sh` | sh | utility | 1 | yes |
| `gen_module.sh` | sh | utility | 2 | yes |
| `generate_hashs.py` | py | utility | 4 | yes |
| `install.sh` | sh | utility | 0 | no |
| `stub.c` | c | testing | 19 | yes |

## Key Symbols

- `Copyright` (function, `bof/test/make_table.c:17`) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved. */  #include <stdint.h>`
- `main` (function, `bof/test/make_table.c:34`) `void main()`
- `show_help` (function, `gen_beacon.sh:46`) - === FUNCIONES ===
- `xor_string` (function, `gen_beacon.sh:194`) - === XOR STRING TO BYTES ===
- `crc32` (function, `gen_beacon.sh:5977`)
- `usage` (function, `gen_dll_rev.sh:12`) - === USAGE ===
- `usage` (function, `gen_dll_ss.sh:10`) - === USAGE ===
- `usage` (function, `gen_key.sh:10`) - === USAGE ===
- `show_help` (function, `gen_module.sh:18`) - === FUNCTIONS ===
- `xor_obfuscate` (function, `gen_module.sh:35`) - Function to obfuscate binary with XOR and convert to \x..
- `djb2` (function, `generate_hashs.py:23`) `def djb2(s)`
- `generate_coff_loader` (function, `generate_hashs.py:223`) `def generate_coff_loader()`
- `generate_bof_test` (function, `generate_hashs.py:491`) `def generate_bof_test()`
- `main` (function, `generate_hashs.py:553`) `def main()`
- `C2_URL` (macro, `stub.c:11`) `#define C2_URL`
- `XOR_KEY` (macro, `stub.c:12`) `#define XOR_KEY`
- `MAX_PAYLOAD_SIZE` (macro, `stub.c:13`) `#define MAX_PAYLOAD_SIZE`
- `_UNICODE_STRING` (struct, `stub.c:16`) - === STRUCTURES AND HELLGATE (for analysis evasion only) ===
- `Length` (type_alias, `stub.c:16`) `typedef struct _UNICODE_STRING { USHORT Length;` - === STRUCTURES AND HELLGATE (for analysis evasion only) ===
- `InMemoryOrderLinks` (type_alias, `stub.c:21`) `typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InMemoryOrderLinks;`
- `_LDR_DATA_TABLE_ENTRY` (struct, `stub.c:22`)
- `Length` (type_alias, `stub.c:31`) `typedef struct _PEB_LDR_DATA { DWORD Length;`
- `_PEB_LDR_DATA` (struct, `stub.c:32`)
- `Reserved1` (type_alias, `stub.c:40`) `typedef struct _PEB { BYTE Reserved1[2];`
- `_PEB` (struct, `stub.c:41`)
- `selfDestruct` (function, `stub.c:51`) `void selfDestruct()`
- `GetNtdllBase` (function, `stub.c:107`) `HMODULE GetNtdllBase()`
- `anti_analysis` (function, `stub.c:142`) `BOOL anti_analysis()` - === ANTI-ANALYSIS ===
- `xor_data` (function, `stub.c:168`) `void xor_data(unsigned char* data, size_t len)` - === XOR + BASE64 ===
- `base64_decode` (function, `stub.c:174`) `BOOL base64_decode(LPCSTR input, DWORD input_len, BYTE** output, DWORD* output_l`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 1 <-> 2 (strength 0.5): Inferred shared context (layer utility) with no import path between community 1 (root) and community 2 (orphans).

## Risks

- [dataflow DEAD_STORE] `gen_beacon.sh:4116` `xor_string` `maliciousCmd`: `maliciousCmd` assigned at line 4116 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:1859` `xor_string` `sc`: Result of allocator stored in `sc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:4167` `xor_string` `s`: Result of allocator stored in `s` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2284` `xor_string` `reply`: Result of allocator stored in `reply` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2342` `xor_string` `server`: Result of allocator stored in `server` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2522` `xor_string` `listenSock`: Result of allocator stored in `listenSock` is never checked against NULL.

## Open Questions

- Why do 2 file(s) lack file-level docs (e.g. `bof/test/make_table.c`)? What purpose do they serve?
- What would break if the most connected file in orphans changed?
- Should orphans be split, given cohesion 0.00?

## Sources

- `app.py`
- `bof/test/make_table.c`
- `gen_beacon.sh`
- `gen_dll.sh`
- `gen_dll_rev.sh`
- `gen_dll_ss.sh`
- `gen_key.sh`
- `gen_module.sh`
- `generate_hashs.py`
- `install.sh`
- `stub.c`
