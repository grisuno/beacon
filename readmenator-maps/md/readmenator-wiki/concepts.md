# Concepts

Second-brain semantic layer: nouns map atomically to file sets (EXTRACTED); verbs aggregate structural edges (INFERRED).

| Concept | Files | Mentions | Top Files |
|---------|-------|----------|-----------|
| `bof` | 24 | 29 | `bof/calc/beacon.h`, `bof/calc/calc.c`, `bof/etw/beacon.h`, `bof/etw/etw.c`, `bof/test/Test.c` |
| `get` | 20 | 98 | `COFFLoader3.c`, `aes.c`, `beacon.c`, `bof/calc/calc.c`, `bof/etw/etw.c` |
| `imp` | 18 | 286 | `COFFLoader3.c`, `bof/calc/calc.c`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c` |
| `address` | 15 | 15 | `COFFLoader3.c`, `bof/calc/calc.c`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c` |
| `load` | 14 | 18 | `COFFLoader3.c`, `beacon.c`, `bof/calc/calc.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c` |
| `proc` | 14 | 14 | `COFFLoader3.c`, `bof/calc/calc.c`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c` |
| `function` | 13 | 35 | `COFFLoader3.c`, `aes.c`, `beacon.c`, `bof/calc/calc.c`, `bof/test/amsibypass.c` |
| `library` | 13 | 15 | `COFFLoader3.c`, `bof/calc/calc.c`, `bof/test/amsibypass.c`, `bof/test/cmdwhoami.c`, `bof/test/disablelog.c` |
| `handle` | 12 | 26 | `COFFLoader3.c`, `beacon.c`, `bof/calc/calc.c`, `bof/etw/etw.c`, `bof/test/cmdwhoami.c` |
| `beacon` | 11 | 39 | `COFFLoader3.c`, `app.py`, `beacon.c`, `beacon.h`, `bof/calc/beacon.h` |
| `output` | 10 | 38 | `COFFLoader3.c`, `beacon.c`, `beacon.h`, `bof/calc/beacon.h`, `bof/etw/beacon.h` |
| `close` | 10 | 16 | `COFFLoader3.c`, `bof/calc/calc.c`, `bof/test/cmdwhoami.c`, `bof/test/disablelog.c`, `bof/test/loadvnc.c` |
| `imports` | 10 | 11 | `bof/calc/calc.c`, `bof/test/amsibypass.c`, `bof/test/loadvnc.c`, `bof/test/persistsvc.c`, `bof/test/sock5.c` |
| `key` | 9 | 26 | `COFFLoader3.c`, `aes.c`, `aes.h`, `beacon.c`, `bof/test/persist.c` |
| `error` | 9 | 14 | `COFFLoader3.c`, `beacon.c`, `beacon.h`, `bof/calc/beacon.h`, `bof/etw/beacon.h` |
| `direct` | 9 | 10 | `bof/calc/calc.c`, `bof/test/amsibypass.c`, `bof/test/loadvnc.c`, `bof/test/persistsvc.c`, `bof/test/sock5.c` |
| `buffer` | 7 | 94 | `COFFLoader3.c`, `aes.c`, `aes.h`, `beacon.c`, `bof/test/sock5.c` |
| `size` | 7 | 26 | `COFFLoader3.c`, `aes.h`, `beacon.c`, `bof/test/loadvnc.c`, `bof/test/sock5.c` |
| `version` | 7 | 21 | `COFFLoader3.c`, `app.py`, `beacon.c`, `bof/test/sock5.c`, `bof/test/winver.c` |
| `module` | 7 | 20 | `COFFLoader3.c`, `beacon.c`, `bof/calc/calc.c`, `bof/etw/etw.c`, `bof/test/disablelog.c` |
| `gen` | 7 | 16 | `COFFLoader3.c`, `gen_beacon.sh`, `gen_dll.sh`, `gen_dll_rev.sh`, `gen_dll_ss.sh` |
| `virtual` | 7 | 15 | `COFFLoader3.c`, `beacon.c`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/shellcode.c` |
| `string` | 6 | 43 | `COFFLoader3.c`, `beacon.c`, `cJSON.c`, `cJSON.h`, `gen_beacon.sh` |
| `set` | 6 | 42 | `COFFLoader3.c`, `aes.c`, `aes.h`, `bof/test/persist.c`, `bof/test/sock5.c` |
| `define` | 6 | 26 | `aes.h`, `beacon.c`, `bof/test/loadvnc.c`, `bof/test/sock5.c`, `cJSON.c` |
| `name` | 6 | 18 | `COFFLoader3.c`, `beacon.c`, `bof/calc/calc.c`, `bof/test/sock5.c`, `bof/test/upload.c` |
| `memory` | 6 | 17 | `COFFLoader3.c`, `beacon.c`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/shellcode.c` |
| `callback` | 6 | 13 | `beacon.h`, `bof/calc/beacon.h`, `bof/etw/beacon.h`, `bof/test/beacon.h`, `bof/test/sock5.c` |
| `bytes` | 6 | 10 | `aes.c`, `beacon.c`, `bof/test/sock5.c`, `bof/test/upload.c`, `cJSON.c` |
| `next` | 6 | 10 | `COFFLoader3.c`, `aes.c`, `bof/test/scan_shellcode.c`, `bof/test/upload.c`, `cJSON.c` |
| `copy` | 6 | 8 | `COFFLoader3.c`, `app.py`, `bof/etw/etw.c`, `bof/test/amsibypass.c`, `bof/test/shellcode.c` |
| `lean` | 6 | 7 | `beacon.c`, `bof/test/disablelog.c`, `bof/test/persistsvc.c`, `bof/test/scan_shellcode.c`, `bof/test/sock5.c` |
| `mean` | 6 | 7 | `beacon.c`, `bof/test/disablelog.c`, `bof/test/persistsvc.c`, `bof/test/scan_shellcode.c`, `bof/test/sock5.c` |
| `table` | 6 | 7 | `COFFLoader3.c`, `beacon.c`, `bof/test/make_table.c`, `bof/test/uacbypass.c`, `generate_hashs.py` |
| `win32` | 6 | 7 | `beacon.c`, `bof/test/disablelog.c`, `bof/test/persistsvc.c`, `bof/test/scan_shellcode.c`, `bof/test/sock5.c` |
| `process` | 5 | 23 | `COFFLoader3.c`, `beacon.c`, `bof/test/disablelog.c`, `bof/test/scan_shellcode.c`, `cJSON.c` |
| `value` | 5 | 22 | `COFFLoader3.c`, `aes.c`, `bof/test/persist.c`, `cJSON.c`, `cJSON.h` |
| `free` | 5 | 19 | `COFFLoader3.c`, `app.py`, `bof/test/sock5.c`, `bof/test/vncrelay.c`, `cJSON.c` |
| `data` | 5 | 17 | `COFFLoader3.c`, `beacon.c`, `bof/test/sock5.c`, `bof/test/upload.c`, `stub.c` |
| `dll` | 5 | 14 | `beacon.c`, `gen_dll.sh`, `gen_dll_rev.sh`, `gen_dll_ss.sh`, `gen_module.sh` |
| `xor` | 5 | 13 | `aes.c`, `beacon.c`, `gen_beacon.sh`, `gen_module.sh`, `stub.c` |
| `command` | 5 | 9 | `COFFLoader3.c`, `beacon.c`, `bof/test/loadvnc.c`, `bof/test/uacbypass.c`, `gen_module.sh` |
| `usage` | 5 | 8 | `beacon.c`, `gen_dll_rev.sh`, `gen_dll_ss.sh`, `gen_key.sh`, `gen_module.sh` |
| `encrypt` | 5 | 7 | `COFFLoader3.c`, `aes.c`, `aes.h`, `beacon.c`, `bof/test/upload.c` |
| `datap` | 5 | 5 | `beacon.h`, `bof/calc/beacon.h`, `bof/etw/beacon.h`, `bof/test/beacon.h`, `bof/whoami/beacon.h` |
| `helper` | 5 | 5 | `bof/test/loadvnc.c`, `bof/test/persistsvc.c`, `bof/test/uacbypass.c`, `bof/test/upload.c`, `cJSON.c` |
| `run` | 5 | 5 | `COFFLoader3.c`, `beacon.c`, `bof/test/loadvnc.c`, `bof/test/uacbypass.c`, `gen_module.sh` |
| `aes` | 4 | 42 | `aes.c`, `aes.h`, `beacon.c`, `bof/test/upload.c` |
| `create` | 4 | 24 | `COFFLoader3.c`, `beacon.c`, `bof/test/scan_shellcode.c`, `cJSON.c` |
| `char` | 4 | 22 | `COFFLoader3.c`, `beacon.c`, `bof/test/sock5.c`, `cJSON.c` |

## Verb Edges

| Source | Verb | Target | Strength |
|--------|------|--------|----------|
| `bof` | `consumes` | `beacon` | 1.00 |
| `bof` | `depends_on` | `beacon` | 1.00 |
| `bof` | `consumes` | `callback` | 1.00 |
| `bof` | `depends_on` | `callback` | 1.00 |
| `bof` | `consumes` | `datap` | 1.00 |
| `bof` | `depends_on` | `datap` | 1.00 |
| `bof` | `consumes` | `error` | 1.00 |
| `bof` | `depends_on` | `error` | 1.00 |
| `bof` | `consumes` | `output` | 1.00 |
| `bof` | `depends_on` | `output` | 1.00 |
| `imp` | `consumes` | `beacon` | 1.00 |
| `imp` | `depends_on` | `beacon` | 1.00 |
| `imp` | `consumes` | `callback` | 1.00 |
| `imp` | `depends_on` | `callback` | 1.00 |
| `imp` | `consumes` | `datap` | 1.00 |
| `imp` | `depends_on` | `datap` | 1.00 |
| `imp` | `consumes` | `error` | 1.00 |
| `imp` | `depends_on` | `error` | 1.00 |
| `imp` | `consumes` | `output` | 1.00 |
| `imp` | `depends_on` | `output` | 1.00 |
| `get` | `consumes` | `beacon` | 0.94 |
| `get` | `depends_on` | `beacon` | 0.94 |
| `get` | `consumes` | `callback` | 0.94 |
| `get` | `depends_on` | `callback` | 0.94 |
| `get` | `consumes` | `datap` | 0.94 |
| `get` | `depends_on` | `datap` | 0.94 |
| `get` | `consumes` | `error` | 0.94 |
| `get` | `depends_on` | `error` | 0.94 |
| `get` | `consumes` | `output` | 0.94 |
| `get` | `depends_on` | `output` | 0.94 |
| `imp` | `depends_on` | `bof` | 0.94 |
| `get` | `depends_on` | `bof` | 0.83 |
| `address` | `consumes` | `beacon` | 0.78 |
| `address` | `depends_on` | `beacon` | 0.78 |
| `address` | `consumes` | `callback` | 0.78 |
| `address` | `depends_on` | `callback` | 0.78 |
| `address` | `consumes` | `datap` | 0.78 |
| `address` | `depends_on` | `datap` | 0.78 |
| `address` | `consumes` | `error` | 0.78 |
| `address` | `depends_on` | `error` | 0.78 |
| `address` | `consumes` | `output` | 0.78 |
| `address` | `depends_on` | `output` | 0.78 |
| `load` | `consumes` | `beacon` | 0.78 |
| `load` | `depends_on` | `beacon` | 0.78 |
| `load` | `consumes` | `callback` | 0.78 |
| `load` | `depends_on` | `callback` | 0.78 |
| `load` | `consumes` | `datap` | 0.78 |
| `load` | `depends_on` | `datap` | 0.78 |
| `load` | `consumes` | `error` | 0.78 |
| `load` | `depends_on` | `error` | 0.78 |

## Dialectic Prompts

- Thesis: `address` centralizes 15 files; Antithesis: `bof` pulls 24 files with 13 shared (Jaccard 0.50); Synthesis: should they merge, split by layer, or keep `depends_on` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `close` pulls 10 files with 9 shared (Jaccard 0.56); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `direct` pulls 9 files with 9 shared (Jaccard 0.60); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `function` pulls 13 files with 10 shared (Jaccard 0.56); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `get` pulls 20 files with 15 shared (Jaccard 0.75); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `handle` pulls 12 files with 11 shared (Jaccard 0.69); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `helper` pulls 5 files with 5 shared (Jaccard 0.33); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `imp` pulls 18 files with 14 shared (Jaccard 0.74); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `imports` pulls 10 files with 9 shared (Jaccard 0.56); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
- Thesis: `address` centralizes 15 files; Antithesis: `lean` pulls 6 files with 5 shared (Jaccard 0.31); Synthesis: should they merge, split by layer, or keep `bridges` explicit?
