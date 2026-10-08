# Gotchas

## God Nodes (high connectivity)

These files have the most connections. Changes here have high blast radius.

- `beacon.h` (score: 40.40, imported by 2 files)
- `COFFLoader3.c` (score: 27.80)
- `beacon.c` (score: 24.00)
- `cJSON.c` (score: 14.50)
- `cJSON.h` (score: 7.70, imported by 2 files)
- `aes.c` (score: 6.30)
- `aes.h` (score: 6.10, imported by 2 files)

## Blast Radius (change impact)

Editing these files can break the listed number of dependents. Run their tests after any change.

- `aes.h` -- 2 direct, 2 total dependents
- `beacon.h` -- 2 direct, 2 total dependents
- `cJSON.h` -- 2 direct, 2 total dependents
- `COFFLoader.h` -- 1 direct, 1 total dependents
- `bof/calc/beacon.h` -- 1 direct, 1 total dependents
- `bof/etw/beacon.h` -- 1 direct, 1 total dependents
- `bof/whoami/beacon.h` -- 1 direct, 1 total dependents

## Hotspots (complexity + centrality)

- `beacon.c` -- complexity: 0.6, centrality: 1.0, combined: 0.8
- `COFFLoader3.c` -- complexity: 1.0, centrality: 0.2, combined: 0.5
- `beacon.h` -- complexity: 0.0, centrality: 0.8, combined: 0.5
- `cJSON.c` -- complexity: 0.5, centrality: 0.3, combined: 0.4
- `cJSON.h` -- complexity: 0.1, centrality: 0.2, combined: 0.2
- `aes.h` -- complexity: 0.1, centrality: 0.2, combined: 0.2
- `aes.c` -- complexity: 0.2, centrality: 0.1, combined: 0.1
- `generate_hashs.py` -- complexity: 0.0, centrality: 0.2, combined: 0.1
- `bof/calc/calc.c` -- complexity: 0.0, centrality: 0.1, combined: 0.1
- `bof/etw/etw.c` -- complexity: 0.0, centrality: 0.1, combined: 0.1

## Dataflow Issues (INFERRED, review each lead)

- `beacon.c:1305` `extract_shellcode` [UNCHECKED_ALLOC] `sc`: Result of allocator stored in `sc` is never checked against NULL.
- `beacon.c:1429` `ReverseShell` [UNCHECKED_ALLOC] `s`: Result of allocator stored in `s` is never checked against NULL.
- `beacon.c:1730` `discoverLocalHosts` [UNCHECKED_ALLOC] `reply`: Result of allocator stored in `reply` is never checked against NULL.
- `beacon.c:1788` `proxy_thread` [UNCHECKED_ALLOC] `server`: Result of allocator stored in `server` is never checked against NULL.
- `beacon.c:1968` `startProxy` [UNCHECKED_ALLOC] `listenSock`: Result of allocator stored in `listenSock` is never checked against NULL.
- `beacon.c:3570` `executeUACBypass` [DEAD_STORE] `maliciousCmd`: `maliciousCmd` assigned at line 3570 but never read afterwards.
- `beacon.c:3621` `scanPort` [UNCHECKED_ALLOC] `s`: Result of allocator stored in `s` is never checked against NULL.
- `cJSON.c:1654` `print_array` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1654 but never read afterwards.
- `cJSON.c:1887` `print_object` [DEAD_STORE] `output_pointer`: `output_pointer` assigned at line 1887 but never read afterwards.
- `gen_beacon.sh:4053` `xor_string` [DEAD_STORE] `maliciousCmd`: `maliciousCmd` assigned at line 4053 but never read afterwards.
