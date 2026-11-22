# orphans

*Community 2 | 11 files | cohesion 0.00*

## Definition

This community groups 11 file(s) rooted at `root` with dominant language sh (cohesion 0.00). Central symbols: `Copyright`, `crc32`, `decrypt_cookie`, `djb2`, `generate_bof_test`, `generate_coff_loader`, `get_machine_id`, `get_version`. Core file: (6 symbols). Documented purpose: This file is part of Black Basalt Beacon.  Black Basalt Beacon is free software: you can redistribute it and/or modify it under the terms of the GNU General Pub.

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

## Key Symbols

- `Copyright` (function, `bof/test/make_table.c:17`) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved. */  #include <stdint.h>`
- `main` (function, `bof/test/make_table.c:34`) `void main()`
- `show_help` (function, `gen_beacon.sh:34`) - === FUNCTIONS ===
- `xor_string` (function, `gen_beacon.sh:138`) - === XOR STRING TO BYTES ===
- `crc32` (function, `gen_beacon.sh:5916`)
- `usage` (function, `gen_dll_rev.sh:12`) - === USAGE ===
- `usage` (function, `gen_dll_ss.sh:10`) - === USAGE ===
- `usage` (function, `gen_key.sh:10`) - === USAGE ===
- `show_help` (function, `gen_module.sh:18`) - === FUNCTIONS ===
- `xor_obfuscate` (function, `gen_module.sh:35`) - Function to obfuscate binary with XOR and convert to \x..
- `djb2` (function, `generate_hashs.py:23`) `def djb2(s)`
- `generate_coff_loader` (function, `generate_hashs.py:223`) `def generate_coff_loader()`
- `generate_bof_test` (function, `generate_hashs.py:491`) `def generate_bof_test()`
- `main` (function, `generate_hashs.py:553`) `def main()`

## Internal vs External Edges

- Internal resolved imports (EXTRACTED): 0
- Cross-boundary resolved imports (EXTRACTED): 0

## Connections

- [INFERRED] shares_context community 1 <-> 2 (strength 0.5): Inferred shared context (layer utility) with no import path between community 1 (root) and community 2 (orphans).

## Risks

- [dataflow DEAD_STORE] `gen_beacon.sh:4053` `xor_string` `maliciousCmd`: `maliciousCmd` assigned at line 4053 but never read afterwards.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:1796` `xor_string` `sc`: Result of allocator stored in `sc` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:4104` `xor_string` `s`: Result of allocator stored in `s` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2221` `xor_string` `reply`: Result of allocator stored in `reply` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2279` `xor_string` `server`: Result of allocator stored in `server` is never checked against NULL.
- [dataflow UNCHECKED_ALLOC] `gen_beacon.sh:2459` `xor_string` `listenSock`: Result of allocator stored in `listenSock` is never checked against NULL.

## Open Questions

- Why do 3 file(s) lack file-level docs (e.g. `bof/test/make_table.c`)? What purpose do they serve?
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
