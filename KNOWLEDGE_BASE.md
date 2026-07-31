# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM, Ruby, Swift, Kotlin, Scala, Lua, Elixir.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Total Files Parsed:** 41 | **Total Symbols Extracted:** 514 | **Total Imports:** 107

<!-- ranking_model: v1.0 | weights: {ppr:0.45,auth:0.2,test:0.15,doc:0.1,fresh:0.1} | alpha:0.85 | commit:e63a2e6 | date:2026-07-18 -->


## Table of Contents

1. [Statistics Dashboard](#statistics-dashboard)
2. [Architectural Layers](#architectural-layers)
3. [Ranked Context](#ranked-context)
4. [God Nodes](#god-nodes)
5. [Community Analysis](#community-analysis)
6. [Surprising Connections](#surprising-connections)
7. [Suggested Questions](#suggested-questions)
8. [Taint Propagation Map](#taint-propagation-map)
9. [Hotspot Analysis](#hotspot-analysis)
10. [Change Impact Analysis](#change-impact-analysis)
11. [Suggested Linting Rules](#suggested-linting-rules)
12. [Orphans](#orphans)
13. [Query Recipes](#query-recipes)
14. [Structural Knowledge Map](#structural-knowledge-map)
15. [Code Property Graph](#code-property-graph)
16. [Architecture Reference](#architecture-reference)
    - [C (23 files)](#c-23-files)
    - [H (8 files)](#h-8-files)
    - [PY (3 files)](#py-3-files)
    - [SH (7 files)](#sh-7-files)

---

## Statistics Dashboard

| Metric | Value |
|--------|-------|
| Total Files | 41 |
| Total Symbols | 514 |
| Total Imports | 107 |
| Call Edges | 96 |
| Inheritance Edges | 0 |
| Languages | 4 |
| Avg Symbols/File | 12.5 |
| Avg Imports/File | 2.6 |

### Top Files by Import Count (Fan-Out)

| File | Imports | Symbols | Language |
|------|---------|---------|----------|
| `beacon.c` | 26 | 145 | c |
| `cJSON.c` | 9 | 122 | c |
| `COFFLoader3.c` | 6 | 23 | c |
| `tel.py` | 6 | 6 | py |
| `generate_hashs.py` | 6 | 4 | py |
| `disablelog.c` | 5 | 4 | c |
| `scan_shellcode.c` | 3 | 2 | c |
| `vncrelay.c` | 3 | 3 | c |
| `aes.c` | 2 | 43 | c |
| `aes.h` | 2 | 13 | h |

### Top Files by Imported-By Count (Fan-In)

| File | Imported By | Symbols | Language |
|------|-------------|---------|----------|
| `beacon.h` | 20 | 3 | h |
| `aes.h` | 2 | 13 | h |
| `cJSON.h` | 2 | 34 | h |
| `COFFLoader.h` | 1 | 1 | h |

---

## Architectural Layers

Auto-detected from path patterns, naming conventions, and imported frameworks.

| Layer | Files |
|-------|-------|
| utility | 23 |
| testing | 16 |
| infrastructure | 2 |

### utility

- `COFFLoader.h` (h, 1 symbols)
- `COFFLoader3.c` (c, 23 symbols)
- `aes.c` (c, 43 symbols)
- `aes.h` (h, 13 symbols)
- `app.py` (py, 0 symbols)
- `beacon.c` (c, 145 symbols)
- `beacon.h` (h, 3 symbols)
- `beacon.h` (h, 3 symbols)
- `calc.c` (c, 1 symbols)
- `beacon.h` (h, 3 symbols)
- `etw.c` (c, 1 symbols)
- `beacon.h` (h, 3 symbols)
- `whoami.c` (c, 1 symbols)
- `cJSON.c` (c, 122 symbols)
- `cJSON.h` (h, 34 symbols)
- *... and 8 more*

### testing

- `Test.c` (c, 1 symbols)
- `amsibypass.c` (c, 1 symbols)
- `beacon.h` (h, 3 symbols)
- `cmdwhoami.c` (c, 1 symbols)
- `loadvnc.c` (c, 4 symbols)
- `make_table.c` (c, 2 symbols)
- `persist.c` (c, 1 symbols)
- `persistsvc.c` (c, 11 symbols)
- `scan_shellcode.c` (c, 2 symbols)
- `shellcode.c` (c, 1 symbols)
- `sock5.c` (c, 29 symbols)
- `tel.py` (py, 6 symbols)
- `uacbypass.c` (c, 2 symbols)
- `upload.c` (c, 33 symbols)
- `vncrelay.c` (c, 3 symbols)
- *... and 1 more*

### infrastructure

- `disablelog.c` (c, 4 symbols)
- `getenv.c` (c, 1 symbols)

---

## Ranked Context

Files ranked by composite score for the current query context. The ranking combines Personalized PageRank (query relevance), global authority, test coverage, documentation coverage, and code freshness. Model: v1.0.

| Rank | File | Composite | PPR | Authority | Test | Doc |
|------|------|-----------|-----|-----------|------|-----|
| 1 | `beacon.h` | 0.2525 | 0.3884 | 0.3884 | 0.00 | 0.00 |
| 2 | `Test.c` | 0.2145 | 0.0224 | 0.0224 | 0.00 | 2.00 |
| 3 | `gen_dll_rev.sh` | 0.2000 | 0.0000 | 0.0000 | 0.00 | 2.00 |
| 4 | `gen_dll_ss.sh` | 0.2000 | 0.0000 | 0.0000 | 0.00 | 2.00 |
| 5 | `gen_key.sh` | 0.2000 | 0.0000 | 0.0000 | 0.00 | 2.00 |
| 6 | `gen_module.sh` | 0.1500 | 0.0000 | 0.0000 | 0.00 | 1.50 |
| 7 | `calc.c` | 0.1145 | 0.0224 | 0.0224 | 0.00 | 1.00 |
| 8 | `amsibypass.c` | 0.1145 | 0.0224 | 0.0224 | 0.00 | 1.00 |
| 9 | `uacbypass.c` | 0.1145 | 0.0224 | 0.0224 | 0.00 | 1.00 |
| 10 | `vncrelay.c` | 0.1145 | 0.0224 | 0.0224 | 0.00 | 1.00 |

---

## God Nodes

Most architecturally central files ranked by combined import/export degree and symbol richness.

| File | Score | Connections | PageRank |
|------|-------|-------------|----------|
| `beacon.h` | 40.3 | | 0.3884 |
| `beacon.c` | 22.5 | | 0.0000 |
| `cJSON.c` | 14.2 | | 0.0000 |
| `cJSON.h` | 7.4 | | 0.0000 |
| `aes.c` | 6.3 | | 0.0000 |
| `upload.c` | 5.3 | | 0.0000 |
| `aes.h` | 5.3 | | 0.0000 |
| `sock5.c` | 4.9 | | 0.0000 |
| `COFFLoader3.c` | 4.3 | | 0.0000 |
| `persistsvc.c` | 3.1 | | 0.0000 |

---

## Community Analysis

Files grouped by import-based community detection. Cohesion measures how tightly connected each community is internally.

### root (Cohesion: 0.83)

**6 files** in this community:

- `COFFLoader.h` (h, 1 symbols)
- `aes.c` (c, 43 symbols)
- `aes.h` (h, 13 symbols)
- `beacon.c` (c, 145 symbols)
- `cJSON.c` (c, 122 symbols)
- `cJSON.h` (h, 34 symbols)

### bof/test (Cohesion: 0.95)

**20 files** in this community:

- `COFFLoader3.c` (c, 23 symbols)
- `beacon.h` (h, 3 symbols)
- `calc.c` (c, 1 symbols)
- `etw.c` (c, 1 symbols)
- `Test.c` (c, 1 symbols)
- `amsibypass.c` (c, 1 symbols)
- `cmdwhoami.c` (c, 1 symbols)
- `disablelog.c` (c, 4 symbols)
- `getenv.c` (c, 1 symbols)
- `loadvnc.c` (c, 4 symbols)
- `persist.c` (c, 1 symbols)
- `persistsvc.c` (c, 11 symbols)
- `scan_shellcode.c` (c, 2 symbols)
- `shellcode.c` (c, 1 symbols)
- `sock5.c` (c, 29 symbols)
- `uacbypass.c` (c, 2 symbols)
- `upload.c` (c, 33 symbols)
- `vncrelay.c` (c, 3 symbols)
- `winver.c` (c, 1 symbols)
- `whoami.c` (c, 1 symbols)

---

## Surprising Connections

Files in different communities connected through 3+ indirect hops.

- `COFFLoader3.c` <-> `aes.c` (4 hops, across 2 communities)
- `COFFLoader3.c` <-> `cJSON.c` (4 hops, across 2 communities)
- `aes.c` <-> `calc.c` (4 hops, across 2 communities)
- `aes.c` <-> `etw.c` (4 hops, across 2 communities)
- `aes.c` <-> `Test.c` (4 hops, across 2 communities)

---

## Suggested Questions

Auto-generated exploration prompts based on graph structure:

- What does beacon.h depend on, and what depends on it? (20 connections)
- What does beacon.c depend on, and what depends on it? (4 connections)
- What does cJSON.c depend on, and what depends on it? (1 connections)
- How are the 6 files in 'root' related to each other?
- Why are COFFLoader3.c and aes.c connected through 4 hops across 2 communities?

---

## Taint Propagation Map

Taint analysis traces how dangerous imports propagate through the codebase via transitive dependencies. Source files import dangerous modules directly; sink files receive the danger indirectly.

**Taint Sources:** 1 | **Taint Sinks:** 1 | **Propagation Paths:** 1

- `tel.py` imports `requests` (0 hop to `tel.py`) [medium]
  Path: tel.py

---

## Hotspot Analysis

Files ranked by combined complexity (symbol count) and centrality (connection count). High-scoring files are architecturally critical and may need refactoring attention.

| File | Complexity | Centrality | Combined | Symbols | Connections |
|------|-----------|------------|----------|---------|-------------|
| `beacon.h` | 0.021 | 0.808 | 0.493 | 3 | 21 |
| `Test.c` | 0.007 | 0.038 | 0.026 | 1 | 1 |
| `gen_dll_rev.sh` | 0.007 | 0.000 | 0.003 | 1 | 0 |
| `gen_dll_ss.sh` | 0.007 | 0.000 | 0.003 | 1 | 0 |
| `gen_key.sh` | 0.007 | 0.000 | 0.003 | 1 | 0 |
| `gen_module.sh` | 0.014 | 0.000 | 0.005 | 2 | 0 |
| `calc.c` | 0.007 | 0.077 | 0.049 | 1 | 2 |
| `amsibypass.c` | 0.007 | 0.077 | 0.049 | 1 | 2 |
| `uacbypass.c` | 0.014 | 0.077 | 0.052 | 2 | 2 |
| `vncrelay.c` | 0.021 | 0.115 | 0.077 | 3 | 3 |
| `beacon.c` | 1.000 | 1.000 | 1.000 | 145 | 26 |
| `cJSON.c` | 0.841 | 0.346 | 0.544 | 122 | 9 |
| `COFFLoader3.c` | 0.159 | 0.231 | 0.202 | 23 | 6 |
| `aes.c` | 0.297 | 0.077 | 0.165 | 43 | 2 |
| `cJSON.h` | 0.234 | 0.115 | 0.163 | 34 | 3 |

---

## Change Impact Analysis

Files sorted by how many other files would be affected if they changed. High-impact files should be changed with caution.

| File | Direct Dependents | Transitive Dependents | Total Impact |
|------|------------------|----------------------|--------------|
| `COFFLoader.h` | 0 | 0 | 0 |
| `COFFLoader3.c` | 0 | 0 | 0 |
| `aes.c` | 0 | 0 | 0 |
| `aes.h` | 0 | 0 | 0 |
| `app.py` | 0 | 0 | 0 |
| `beacon.c` | 0 | 0 | 0 |
| `beacon.h` | 0 | 0 | 0 |
| `beacon.h` | 0 | 0 | 0 |
| `calc.c` | 0 | 0 | 0 |
| `beacon.h` | 0 | 0 | 0 |
| `etw.c` | 0 | 0 | 0 |
| `Test.c` | 0 | 0 | 0 |
| `amsibypass.c` | 0 | 0 | 0 |
| `beacon.h` | 0 | 0 | 0 |
| `cmdwhoami.c` | 0 | 0 | 0 |

---

## Suggested Linting Rules

Automatically suggested linting and security rules based on patterns detected in the codebase. These can be exported as Semgrep rules using the `--export-rules` flag.

| Rule ID | Severity | Description | Language | Matches |
|---------|----------|-------------|----------|---------|
| `RM005` | error | Hardcoded credential detected | multi | 4 |
| `RM001` | info | Large number of functions in c: 288 total | c | 288 |
| `RM002` | info | Large number of functions in py: 10 total | py | 10 |
| `RM003` | info | Large number of functions in sh: 8 total | sh | 8 |
| `RM004` | info | Print statement found (consider logging instead) | python | 17 |

---

## Orphans

Files with no documentation or low connectivity. These are candidates for documentation investment or cleanup.

- `beacon.h` (3 symbols, no doc)
- `COFFLoader.h` (1 symbols, no doc)
- `beacon.h` (3 symbols, no doc)
- `beacon.h` (3 symbols, no doc)
- `etw.c` (1 symbols, no doc)
- `beacon.h` (3 symbols, no doc)
- `cmdwhoami.c` (1 symbols, no doc)
- `getenv.c` (1 symbols, no doc)
- `make_table.c` (2 symbols, no doc)
- `persist.c` (1 symbols, no doc)
- `scan_shellcode.c` (2 symbols, no doc)
- `shellcode.c` (1 symbols, no doc)
- `winver.c` (1 symbols, no doc)
- `beacon.h` (3 symbols, no doc)
- `generate_hashs.py` (4 symbols, no doc)
- `install.sh` (0 symbols, no doc)

---

## Query Recipes

Example queries you can run against this knowledge base using the ranking engine:

```
# Find files most relevant to a concept
readmenator query "Where is the import resolver implemented?"

# Rank files by relevance to a topic
readmenator query "How does documentation generation work?"

# Explain why a file ranks highly
readmenator query "explain readmenator/_documentation.py"

# Trace dependency paths with ranked context
readmenator query "path from CLI to exporter"
```

The ranking model uses the following signals:

- **Personalized PageRank** (45% weight): query-specific relevance via seed propagation
- **Global Authority** (20% weight): structural importance via standard PageRank
- **Test Coverage** (15% weight): fraction of symbols referenced in test files
- **Doc Coverage** (10% weight): presence of docstrings and file-level docs
- **Freshness** (10% weight): recent modification activity

Results include score decomposition and justification paths for each ranked item.

---

## Structural Knowledge Map

```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
    subgraph community_0 ["root"]
    beacon_c["beacon.c (c)"]
    class beacon_c mod;
    beacon_c__PROCESS_BASIC_INFORMATION["_PROCESS_BASIC_INFORMATION"]
    class beacon_c__PROCESS_BASIC_INFORMATION cls;
    beacon_c --> beacon_c__PROCESS_BASIC_INFORMATION
    beacon_c__UNICODE_STRING["_UNICODE_STRING"]
    class beacon_c__UNICODE_STRING cls;
    beacon_c --> beacon_c__UNICODE_STRING
    beacon_c__LDR_DATA_TABLE_ENTRY["_LDR_DATA_TABLE_ENTRY"]
    class beacon_c__LDR_DATA_TABLE_ENTRY cls;
    beacon_c --> beacon_c__LDR_DATA_TABLE_ENTRY
    beacon_c__PEB_LDR_DATA["_PEB_LDR_DATA"]
    class beacon_c__PEB_LDR_DATA cls;
    beacon_c --> beacon_c__PEB_LDR_DATA
    beacon_c__PEB["_PEB"]
    class beacon_c__PEB cls;
    beacon_c --> beacon_c__PEB
    cJSON_c["cJSON.c (c)"]
    class cJSON_c mod;
    end
    subgraph community_1 ["bof/test"]
    COFFLoader3_c["COFFLoader3.c (c)"]
    class COFFLoader3_c mod;
    bof_test_tel_py["tel.py (py)"]
    class bof_test_tel_py mod;
    generate_hashs_py["generate_hashs.py (py)"]
    class generate_hashs_py mod;
    bof_test_disablelog_c["disablelog.c (c)"]
    class bof_test_disablelog_c mod;
    bof_test_vncrelay_c["vncrelay.c (c)"]
    class bof_test_vncrelay_c mod;
    bof_test_scan_shellcode_c["scan_shellcode.c (c)"]
    class bof_test_scan_shellcode_c mod;
    aes_c["aes.c (c)"]
    class aes_c mod;
    bof_test_upload_c["upload.c (c)"]
    class bof_test_upload_c mod;
    bof_test_sock5_c["sock5.c (c)"]
    class bof_test_sock5_c mod;
    aes_h["aes.h (h)"]
    class aes_h mod;
    bof_test_persistsvc_c["persistsvc.c (c)"]
    class bof_test_persistsvc_c mod;
    bof_test_loadvnc_c["loadvnc.c (c)"]
    class bof_test_loadvnc_c mod;
    bof_test_make_table_c["make_table.c (c)"]
    class bof_test_make_table_c mod;
    bof_test_uacbypass_c["uacbypass.c (c)"]
    class bof_test_uacbypass_c mod;
    bof_calc_calc_c["calc.c (c)"]
    class bof_calc_calc_c mod;
    bof_etw_etw_c["etw.c (c)"]
    class bof_etw_etw_c mod;
    bof_test_amsibypass_c["amsibypass.c (c)"]
    class bof_test_amsibypass_c mod;
    bof_test_cmdwhoami_c["cmdwhoami.c (c)"]
    class bof_test_cmdwhoami_c mod;
    bof_test_getenv_c["getenv.c (c)"]
    class bof_test_getenv_c mod;
    bof_test_persist_c["persist.c (c)"]
    class bof_test_persist_c mod;
    bof_test_shellcode_c["shellcode.c (c)"]
    class bof_test_shellcode_c mod;
    bof_test_winver_c["winver.c (c)"]
    class bof_test_winver_c mod;
    bof_whoami_whoami_c["whoami.c (c)"]
    class bof_whoami_whoami_c mod;
    cJSON_h["cJSON.h (h)"]
    class cJSON_h mod;
    beacon_h["beacon.h (h)"]
    class beacon_h mod;
    bof_calc_beacon_h["beacon.h (h)"]
    class bof_calc_beacon_h mod;
    bof_etw_beacon_h["beacon.h (h)"]
    class bof_etw_beacon_h mod;
    bof_test_beacon_h["beacon.h (h)"]
    class bof_test_beacon_h mod;
    bof_whoami_beacon_h["beacon.h (h)"]
    class bof_whoami_beacon_h mod;
    COFFLoader_h["COFFLoader.h (h)"]
    class COFFLoader_h mod;
    bof_test_Test_c["Test.c (c)"]
    class bof_test_Test_c mod;
    app_py["app.py (py)"]
    class app_py mod;
    gen_beacon_sh["gen_beacon.sh (sh)"]
    class gen_beacon_sh mod;
    gen_module_sh["gen_module.sh (sh)"]
    class gen_module_sh mod;
    gen_dll_rev_sh["gen_dll_rev.sh (sh)"]
    class gen_dll_rev_sh mod;
    gen_dll_ss_sh["gen_dll_ss.sh (sh)"]
    class gen_dll_ss_sh mod;
    gen_key_sh["gen_key.sh (sh)"]
    class gen_key_sh mod;
    gen_dll_sh["gen_dll.sh (sh)"]
    class gen_dll_sh mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    end
    ext_windows_h["windows.h"]
    class ext_windows_h ext;
    COFFLoader_h -.->|imports| ext_windows_h
    COFFLoader3_c -.->|imports| ext_windows_h
    ext_stdio_h["stdio.h"]
    class ext_stdio_h ext;
    COFFLoader3_c -.->|imports| ext_stdio_h
    ext_stdlib_h["stdlib.h"]
    class ext_stdlib_h ext;
    COFFLoader3_c -.->|imports| ext_stdlib_h
    ext_string_h["string.h"]
    class ext_string_h ext;
    COFFLoader3_c -.->|imports| ext_string_h
    ext_stdint_h["stdint.h"]
    class ext_stdint_h ext;
    COFFLoader3_c -.->|imports| ext_stdint_h
    ext_beacon_h["beacon.h"]
    class ext_beacon_h ext;
    COFFLoader3_c -.->|imports| ext_beacon_h
    ext_aes_h["aes.h"]
    class ext_aes_h ext;
    aes_c -.->|imports| ext_aes_h
    aes_c -.->|imports| ext_string_h
    aes_h -.->|imports| ext_stdint_h
    ext_stddef_h["stddef.h"]
    class ext_stddef_h ext;
    aes_h -.->|imports| ext_stddef_h
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
    ext_winsock2_h["winsock2.h"]
    class ext_winsock2_h ext;
    beacon_c -.->|imports| ext_winsock2_h
    ext_ws2tcpip_h["ws2tcpip.h"]
    class ext_ws2tcpip_h ext;
    beacon_c -.->|imports| ext_ws2tcpip_h
    beacon_c -.->|imports| ext_windows_h
    ext_winnt_h["winnt.h"]
    class ext_winnt_h ext;
    beacon_c -.->|imports| ext_winnt_h
    ext_winhttp_h["winhttp.h"]
    class ext_winhttp_h ext;
    beacon_c -.->|imports| ext_winhttp_h
    ext_wincrypt_h["wincrypt.h"]
    class ext_wincrypt_h ext;
    beacon_c -.->|imports| ext_wincrypt_h
    ext_ntstatus_h["ntstatus.h"]
    class ext_ntstatus_h ext;
    beacon_c -.->|imports| ext_ntstatus_h
    ext_tlhelp32_h["tlhelp32.h"]
    class ext_tlhelp32_h ext;
    beacon_c -.->|imports| ext_tlhelp32_h
    beacon_c -.->|imports| ext_stdio_h
    beacon_c -.->|imports| ext_stdlib_h
    beacon_c -.->|imports| ext_string_h
    ext_io_h["io.h"]
    class ext_io_h ext;
    beacon_c -.->|imports| ext_io_h
    ext_process_h["process.h"]
    class ext_process_h ext;
    beacon_c -.->|imports| ext_process_h
    ext_time_h["time.h"]
    class ext_time_h ext;
    beacon_c -.->|imports| ext_time_h
    ext_iphlpapi_h["iphlpapi.h"]
    class ext_iphlpapi_h ext;
    beacon_c -.->|imports| ext_iphlpapi_h
    ext_icmpapi_h["icmpapi.h"]
    class ext_icmpapi_h ext;
    beacon_c -.->|imports| ext_icmpapi_h
    ext_bcrypt_h["bcrypt.h"]
    class ext_bcrypt_h ext;
    beacon_c -.->|imports| ext_bcrypt_h
    ext_shlobj_h["shlobj.h"]
    class ext_shlobj_h ext;
    beacon_c -.->|imports| ext_shlobj_h
    ext_objbase_h["objbase.h"]
    class ext_objbase_h ext;
    beacon_c -.->|imports| ext_objbase_h
    ext_shellapi_h["shellapi.h"]
    class ext_shellapi_h ext;
    beacon_c -.->|imports| ext_shellapi_h
    ext_winioctl_h["winioctl.h"]
    class ext_winioctl_h ext;
    beacon_c -.->|imports| ext_winioctl_h
    ext_setjmp_h["setjmp.h"]
    class ext_setjmp_h ext;
    beacon_c -.->|imports| ext_setjmp_h
    beacon_c -.->|imports| ext_aes_h
    ext_cJSON_h["cJSON.h"]
    class ext_cJSON_h ext;
    beacon_c -.->|imports| ext_cJSON_h
    beacon_c -.->|imports| ext_beacon_h
    ext_COFFLoader_h["COFFLoader.h"]
    class ext_COFFLoader_h ext;
    beacon_c -.->|imports| ext_COFFLoader_h
    beacon_h -.->|imports| ext_windows_h
    bof_calc_beacon_h -.->|imports| ext_windows_h
    bof_calc_calc_c -.->|imports| ext_windows_h
    bof_calc_calc_c -.->|imports| ext_beacon_h
    bof_etw_beacon_h -.->|imports| ext_windows_h
    bof_etw_etw_c -.->|imports| ext_windows_h
    bof_etw_etw_c -.->|imports| ext_beacon_h
    bof_test_Test_c -.->|imports| ext_beacon_h
    bof_test_amsibypass_c -.->|imports| ext_windows_h
    bof_test_amsibypass_c -.->|imports| ext_beacon_h
    bof_test_beacon_h -.->|imports| ext_windows_h
    bof_test_cmdwhoami_c -.->|imports| ext_windows_h
    bof_test_cmdwhoami_c -.->|imports| ext_beacon_h
    bof_test_disablelog_c -.->|imports| ext_windows_h
    bof_test_disablelog_c -.->|imports| ext_tlhelp32_h
    ext_psapi_h["psapi.h"]
    class ext_psapi_h ext;
    bof_test_disablelog_c -.->|imports| ext_psapi_h
    ext_winternl_h["winternl.h"]
    class ext_winternl_h ext;
    bof_test_disablelog_c -.->|imports| ext_winternl_h
    bof_test_disablelog_c -.->|imports| ext_beacon_h
    bof_test_getenv_c -.->|imports| ext_windows_h
    bof_test_getenv_c -.->|imports| ext_beacon_h
    bof_test_loadvnc_c -.->|imports| ext_windows_h
    bof_test_loadvnc_c -.->|imports| ext_beacon_h
    bof_test_make_table_c -.->|imports| ext_stdint_h
    bof_test_make_table_c -.->|imports| ext_stdio_h
    bof_test_persist_c -.->|imports| ext_windows_h
    bof_test_persist_c -.->|imports| ext_beacon_h
    bof_test_persistsvc_c -.->|imports| ext_windows_h
    bof_test_persistsvc_c -.->|imports| ext_beacon_h
    bof_test_scan_shellcode_c -.->|imports| ext_windows_h
    bof_test_scan_shellcode_c -.->|imports| ext_tlhelp32_h
    bof_test_scan_shellcode_c -.->|imports| ext_beacon_h
    bof_test_shellcode_c -.->|imports| ext_windows_h
    bof_test_shellcode_c -.->|imports| ext_beacon_h
    bof_test_sock5_c -.->|imports| ext_windows_h
    bof_test_sock5_c -.->|imports| ext_beacon_h
    ext_requests["requests"]
    class ext_requests ext;
    bof_test_tel_py -.->|imports| ext_requests
    ext_re["re"]
    class ext_re ext;
    bof_test_tel_py -.->|imports| ext_re
    ext_uuid["uuid"]
    class ext_uuid ext;
    bof_test_tel_py -.->|imports| ext_uuid
    ext_json["json"]
    class ext_json ext;
    bof_test_tel_py -.->|imports| ext_json
    ext_Crypto_Cipher["Crypto.Cipher"]
    class ext_Crypto_Cipher ext;
    bof_test_tel_py -.->|imports| ext_Crypto_Cipher
    ext_datetime["datetime"]
    class ext_datetime ext;
    bof_test_tel_py -.->|imports| ext_datetime
    bof_test_uacbypass_c -.->|imports| ext_windows_h
    bof_test_uacbypass_c -.->|imports| ext_beacon_h
    bof_test_upload_c -.->|imports| ext_windows_h
    bof_test_upload_c -.->|imports| ext_beacon_h
    bof_test_vncrelay_c -.->|imports| ext_winsock2_h
    bof_test_vncrelay_c -.->|imports| ext_windows_h
    bof_test_vncrelay_c -.->|imports| ext_beacon_h
    bof_test_winver_c -.->|imports| ext_windows_h
    bof_test_winver_c -.->|imports| ext_beacon_h
    bof_whoami_beacon_h -.->|imports| ext_windows_h
    bof_whoami_whoami_c -.->|imports| ext_windows_h
    bof_whoami_whoami_c -.->|imports| ext_beacon_h
    cJSON_c -.->|imports| ext_string_h
    cJSON_c -.->|imports| ext_stdio_h
    ext_math_h["math.h"]
    class ext_math_h ext;
    cJSON_c -.->|imports| ext_math_h
    cJSON_c -.->|imports| ext_stdlib_h
    ext_limits_h["limits.h"]
    class ext_limits_h ext;
    cJSON_c -.->|imports| ext_limits_h
    ext_ctype_h["ctype.h"]
    class ext_ctype_h ext;
    cJSON_c -.->|imports| ext_ctype_h
    ext_float_h["float.h"]
    class ext_float_h ext;
    cJSON_c -.->|imports| ext_float_h
    ext_locale_h["locale.h"]
    class ext_locale_h ext;
    cJSON_c -.->|imports| ext_locale_h
    cJSON_c -.->|imports| ext_cJSON_h
    cJSON_h -.->|imports| ext_stddef_h
    ext_argparse["argparse"]
    class ext_argparse ext;
    generate_hashs_py -.->|imports| ext_argparse
    ext_sys["sys"]
    class ext_sys ext;
    generate_hashs_py -.->|imports| ext_sys
    generate_hashs_py -.->|imports| ext_re
    ext_pygments["pygments"]
    class ext_pygments ext;
    generate_hashs_py -.->|imports| ext_pygments
    ext_pygments_lexers["pygments.lexers"]
    class ext_pygments_lexers ext;
    generate_hashs_py -.->|imports| ext_pygments_lexers
    ext_pygments_formatters["pygments.formatters"]
    class ext_pygments_formatters ext;
    generate_hashs_py -.->|imports| ext_pygments_formatters
```

---

## Code Property Graph

Machine-readable Code Property Graph (CPG) in JSON-LD format. This block allows AI agents to parse the full structural graph without additional file reads. Compatible with GraphRAG pipelines.

```json
{"@context": "https://readmenator.dev/cpg/v1", "analysis": {"communities": [{"cohesion": 0.833, "id": 0, "label": "root", "size": 6}, {"cohesion": 0.95, "id": 1, "label": "bof/test", "size": 20}], "god_nodes": [{"node_id": "beacon.h", "score": 40.3}, {"node_id": "beacon.c", "score": 22.5}, {"node_id": "cJSON.c", "score": 14.2}, {"node_id": "cJSON.h", "score": 7.4}, {"node_id": "aes.c", "score": 6.3}, {"node_id": "bof/test/upload.c", "score": 5.3}, {"node_id": "aes.h", "score": 5.3}, {"node_id": "bof/test/sock5.c", "score": 4.9}, {"node_id": "COFFLoader3.c", "score": 4.3}, {"node_id": "bof/test/persistsvc.c", "score": 3.1}], "surprising_connections": [{"hops": 4, "source": "COFFLoader3.c", "target": "aes.c"}, {"hops": 4, "source": "COFFLoader3.c", "target": "cJSON.c"}, {"hops": 4, "source": "aes.c", "target": "bof/calc/calc.c"}, {"hops": 4, "source": "aes.c", "target": "bof/etw/etw.c"}, {"hops": 4, "source": "aes.c", "target": "bof/test/Test.c"}]}, "edges": [{"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "COFFLoader3.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.h", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "aes.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "app.py", "target": "os"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "winsock2.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "ws2tcpip.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "winnt.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "winhttp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "wincrypt.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "ntstatus.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "tlhelp32.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "io.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "process.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "time.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "iphlpapi.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "icmpapi.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "bcrypt.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "shlobj.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "objbase.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "shellapi.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "winioctl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "setjmp.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "aes.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.c", "target": "COFFLoader.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "beacon.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/calc/beacon.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/calc/calc.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/calc/calc.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/etw/beacon.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/etw/etw.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/etw/etw.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/Test.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/amsibypass.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/amsibypass.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/beacon.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/cmdwhoami.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/cmdwhoami.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/disablelog.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/disablelog.c", "target": "tlhelp32.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/disablelog.c", "target": "psapi.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/disablelog.c", "target": "winternl.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/disablelog.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/getenv.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/getenv.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/loadvnc.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/loadvnc.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/make_table.c", "target": "stdint.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/make_table.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/persist.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/persist.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/persistsvc.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/persistsvc.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/scan_shellcode.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/scan_shellcode.c", "target": "tlhelp32.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/scan_shellcode.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/shellcode.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/shellcode.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/sock5.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/sock5.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "requests"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "re"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "uuid"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "json"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "Crypto.Cipher"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/tel.py", "target": "datetime"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/uacbypass.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/uacbypass.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/upload.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/upload.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/vncrelay.c", "target": "winsock2.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/vncrelay.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/vncrelay.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/winver.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/test/winver.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/whoami/beacon.h", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/whoami/whoami.c", "target": "windows.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "bof/whoami/whoami.c", "target": "beacon.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "string.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "stdio.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "math.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "stdlib.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "limits.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "ctype.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "float.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "locale.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.c", "target": "cJSON.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "cJSON.h", "target": "stddef.h"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "argparse"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "sys"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "re"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "pygments"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "pygments.lexers"}, {"confidence": "EXTRACTED", "relation": "imports", "source": "generate_hashs.py", "target": "pygments.formatters"}], "generator": "readmenator", "metadata": {"edge_count": 203, "file_count": 41, "language_count": 4, "symbol_count": 514}, "nodes": [{"id": "COFFLoader.h", "kind": "module", "label": "COFFLoader.h", "language": "h", "sha256": "fb8f42ff4d8704ce", "symbol_count": 1, "symbols": [{"kind": "macro", "line": 21, "name": "COFFLOADER_H"}]}, {"id": "COFFLoader3.c", "kind": "module", "label": "COFFLoader3.c", "language": "c", "sha256": "12290cb5dc16762c", "symbol_count": 23, "symbols": [{"doc": "=== Función hash DJB2 ===", "kind": "function", "line": 632, "name": "djb2_hash", "signature": "static uint32_t djb2_hash(const char* str)"}, {"kind": "function", "line": 912, "name": "create_trampoline", "signature": "static void* create_trampoline(void* target)"}, {"kind": "function", "line": 940, "name": "handle_relocation", "signature": "BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, \n                    ..."}, {"kind": "function", "line": 1079, "name": "get_symbol_name", "signature": "static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)"}, {"kind": "function", "line": 1102, "name": "__attribute__", "signature": "__attribute__((noinline))\nstatic void call_go_aligned(void* func, char* arg1, int arg2)"}, {"doc": "=== Cargador COFF  ===", "kind": "function", "line": 1112, "name": "RunCOFF", "signature": "int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*..."}, {"kind": "macro", "line": 568, "name": "IMAGE_REL_AMD64_ABSOLUTE"}, {"kind": "macro", "line": 569, "name": "IMAGE_REL_AMD64_ADDR64"}, {"kind": "macro", "line": 570, "name": "IMAGE_REL_AMD64_ADDR32"}, {"kind": "macro", "line": 571, "name": "IMAGE_REL_AMD64_ADDR32NB"}, {"kind": "macro", "line": 572, "name": "IMAGE_REL_AMD64_REL32"}, {"kind": "macro", "line": 573, "name": "IMAGE_REL_AMD64_REL32_1"}, {"kind": "macro", "line": 574, "name": "IMAGE_REL_AMD64_REL32_2"}, {"kind": "macro", "line": 575, "name": "IMAGE_REL_AMD64_REL32_3"}, {"kind": "macro", "line": 576, "name": "IMAGE_REL_AMD64_REL32_4"}, {"kind": "macro", "line": 577, "name": "IMAGE_REL_AMD64_REL32_5"}, {"kind": "macro", "line": 578, "name": "IMAGE_REL_AMD64_SECTION"}, {"kind": "macro", "line": 579, "name": "IMAGE_REL_AMD64_SECREL"}, {"kind": "macro", "line": 580, "name": "IMAGE_REL_AMD64_SECREL7"}, {"kind": "macro", "line": 581, "name": "IMAGE_REL_AMD64_TOKEN"}, {"kind": "macro", "line": 582, "name": "IMAGE_REL_AMD64_SREL32"}, {"kind": "macro", "line": 583, "name": "IMAGE_REL_AMD64_PAIR"}, {"kind": "macro", "line": 584, "name": "IMAGE_REL_AMD64_SSPAN32"}]}, {"doc": "aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include \"aes.h\" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "id": "aes.c", "kind": "module", "label": "aes.c", "language": "c", "sha256": "90bb0430dbddaeb8", "symbol_count": 43, "symbols": [{"doc": "define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16", "kind": "function", "line": 12, "name": "getSBoxValue", "signature": "static uint8_t getSBoxValue(uint8_t num)"}, {"kind": "function", "line": 34, "name": "getSBoxInvert", "signature": "static uint8_t getSBoxInvert(uint8_t num)"}, {"kind": "function", "line": 56, "name": "Td0", "signature": "static uint8_t Td0(int x)"}, {"kind": "function", "line": 58, "name": "Td1", "signature": "static uint8_t Td1(int x)"}, {"kind": "function", "line": 59, "name": "Td2", "signature": "static uint8_t Td2(int x)"}, {"kind": "function", "line": 60, "name": "Td3", "signature": "static uint8_t Td3(int x)"}, {"kind": "function", "line": 61, "name": "Td4", "signature": "static uint8_t Td4(int x)"}, {"doc": "This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.", "kind": "function", "line": 166, "name": "KeyExpansion", "signature": "static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)"}, {"kind": "function", "line": 238, "name": "AES_init_ctx", "signature": "void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)"}, {"doc": "if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))", "kind": "function", "line": 244, "name": "AES_init_ctx_iv", "signature": "void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)"}, {"kind": "function", "line": 249, "name": "AES_ctx_set_iv", "signature": "void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)"}, {"doc": "This function adds the round key to state. The round key is added to the state by an XOR function.", "kind": "function", "line": 257, "name": "AddRoundKey", "signature": "static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 271, "name": "SubBytes", "signature": "static void SubBytes(state_t* state)"}, {"doc": "The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.", "kind": "function", "line": 286, "name": "ShiftRows", "signature": "static void ShiftRows(state_t* state)"}, {"kind": "function", "line": 313, "name": "xtime", "signature": "static uint8_t xtime(uint8_t x)"}, {"doc": "MixColumns function mixes the columns of the state matrix", "kind": "function", "line": 320, "name": "MixColumns", "signature": "static void MixColumns(state_t* state)"}, {"doc": "Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION", "kind": "function", "line": 340, "name": "Multiply", "signature": "static uint8_t Multiply(uint8_t x, uint8_t y)"}, {"doc": "MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.", "kind": "function", "line": 370, "name": "InvMixColumns", "signature": "static void InvMixColumns(state_t* state)"}, {"doc": "The SubBytes Function Substitutes the values in the state matrix with values in an S-box.", "kind": "function", "line": 391, "name": "InvSubBytes", "signature": "static void InvSubBytes(state_t* state)"}, {"kind": "function", "line": 402, "name": "InvShiftRows", "signature": "static void InvShiftRows(state_t* state)"}, {"doc": "Cipher is the main function that encrypts the PlainText.", "kind": "function", "line": 433, "name": "Cipher", "signature": "static void Cipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)", "kind": "function", "line": 459, "name": "InvCipher", "signature": "static void InvCipher(state_t* state, const uint8_t* RoundKey)"}, {"doc": "AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)", "kind": "function", "line": 488, "name": "AES_ECB_encrypt", "signature": "void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"kind": "function", "line": 495, "name": "AES_ECB_decrypt", "signature": "void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)"}, {"doc": "if defined(CBC) && (CBC == 1)", "kind": "function", "line": 510, "name": "XorWithIv", "signature": "static void XorWithIv(uint8_t* buf, const uint8_t* Iv)"}, {"kind": "function", "line": 520, "name": "AES_CBC_encrypt_buffer", "signature": "void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)"}, {"kind": "function", "line": 535, "name": "AES_CBC_decrypt_buffer", "signature": "void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"doc": "XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key", "kind": "function", "line": 558, "name": "AES_CTR_xcrypt_buffer", "signature": "void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)"}, {"kind": "macro", "line": 4, "name": "Nb"}, {"kind": "macro", "line": 6, "name": "KEYLEN_256"}, {"kind": "macro", "line": 10, "name": "RKLENGTH"}, {"kind": "macro", "line": 11, "name": "BLOCKLEN"}, {"kind": "macro", "line": 67, "name": "Nb"}, {"kind": "macro", "line": 70, "name": "Nk"}, {"kind": "macro", "line": 71, "name": "Nr"}, {"kind": "macro", "line": 73, "name": "Nk"}, {"kind": "macro", "line": 74, "name": "Nr"}, {"kind": "macro", "line": 76, "name": "Nk"}, {"kind": "macro", "line": 77, "name": "Nr"}, {"kind": "macro", "line": 84, "name": "MULTIPLY_AS_A_FUNCTION"}, {"kind": "macro", "line": 163, "name": "getSBoxValue"}, {"kind": "macro", "line": 349, "name": "Multiply"}, {"kind": "macro", "line": 365, "name": "getSBoxInvert"}]}, {"doc": "ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176", "id": "aes.h", "kind": "module", "label": "aes.h", "language": "h", "sha256": "b10d39289cfb8328", "symbol_count": 13, "symbols": [{"kind": "struct", "line": 33, "name": "AES_ctx"}, {"kind": "macro", "line": 2, "name": "_AES_H_"}, {"kind": "macro", "line": 9, "name": "CBC"}, {"kind": "macro", "line": 12, "name": "ECB"}, {"kind": "macro", "line": 15, "name": "CTR"}, {"kind": "macro", "line": 17, "name": "AES256"}, {"kind": "macro", "line": 19, "name": "AES_BLOCKLEN"}, {"kind": "macro", "line": 23, "name": "AES_KEYLEN"}, {"kind": "macro", "line": 24, "name": "AES_keyExpSize"}, {"kind": "macro", "line": 26, "name": "AES_KEYLEN"}, {"kind": "macro", "line": 27, "name": "AES_keyExpSize"}, {"kind": "macro", "line": 29, "name": "AES_KEYLEN"}, {"kind": "macro", "line": 30, "name": "AES_keyExpSize"}]}, {"doc": "_*_ coding: utf8 _*_   This file is part of Black Basalt Beacon.  Black Basalt Beacon is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.  Black Basalt Beacon is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.  You should have received a copy of the GNU General Public License along with Black Basalt Beacon.  If not, see <https://www.gnu.org/licenses/>.  Copyright (c) LazyOwn RedTeam 2025. All rights reserved.", "id": "app.py", "kind": "module", "label": "app.py", "language": "py", "sha256": "57b21bdb023585b8", "symbol_count": 0, "symbols": []}, {"id": "beacon.c", "kind": "module", "label": "beacon.c", "language": "c", "sha256": "28ef9be11445e1ca", "symbol_count": 145, "symbols": [{"kind": "struct", "line": 129, "name": "_PROCESS_BASIC_INFORMATION"}, {"doc": "=== ESTRUCTURAS NECESARIAS (MinGW-safe) ===", "kind": "struct", "line": 262, "name": "_UNICODE_STRING"}, {"kind": "struct", "line": 268, "name": "_LDR_DATA_TABLE_ENTRY"}, {"kind": "struct", "line": 278, "name": "_PEB_LDR_DATA"}, {"kind": "struct", "line": 287, "name": "_PEB"}, {"kind": "function", "line": 253, "name": "ExceptionFilter", "signature": "static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)"}, {"kind": "function", "line": 334, "name": "get_shell_cmd", "signature": "const char* get_shell_cmd()"}, {"doc": "=== Beacon API: implementaciones exportables para BOFs ===", "kind": "function", "line": 416, "name": "__declspec", "signature": "__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)"}, {"kind": "function", "line": 422, "name": "__declspec", "signature": "__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)"}, {"kind": "function", "line": 430, "name": "__declspec", "signature": "__declspec(dllexport) int BeaconDataInt(datap * parser)"}, {"kind": "function", "line": 435, "name": "__declspec", "signature": "__declspec(dllexport) short BeaconDataShort(datap * parser)"}, {"kind": "function", "line": 440, "name": "__declspec", "signature": "__declspec(dllexport) int BeaconDataLength(datap * parser)"}, {"kind": "function", "line": 445, "name": "__declspec", "signature": "__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)"}, {"kind": "function", "line": 455, "name": "__declspec", "signature": "__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)"}, {"kind": "function", "line": 503, "name": "__declspec", "signature": "__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)"}, {"doc": "=== MAP DLL NAME TO REAL DLL ===", "kind": "function", "line": 521, "name": "MapDllNameToModule", "signature": "HMODULE MapDllNameToModule(char* dllName)"}, {"kind": "function", "line": 548, "name": "GetSyscallNumber", "signature": "DWORD GetSyscallNumber(PVOID func_addr)"}, {"kind": "function", "line": 560, "name": "HellsGate", "signature": "DWORD HellsGate(DWORD ssn)"}, {"kind": "function", "line": 565, "name": "__attribute__", "signature": "__attribute__((naked))\nNTSTATUS HellDescent(\n    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,\n    DW..."}, {"kind": "function", "line": 581, "name": "GetProcessIdByName", "signature": "DWORD GetProcessIdByName(const char* processName)"}, {"doc": "=== EJECUTAR TLS CALLBACKS ===", "kind": "function", "line": 600, "name": "ExecuteTLSCallbacks", "signature": "void ExecuteTLSCallbacks(PVOID moduleBase)"}, {"doc": "=== Carga un módulo en memoria ===", "kind": "function", "line": 617, "name": "MapModuleToMemory", "signature": "PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)"}, {"doc": "=== Ejecuta el módulo (DllMain o EntryPoint) ===", "kind": "function", "line": 706, "name": "ExecuteModule", "signature": "BOOL ExecuteModule(PVOID moduleBase)"}, {"doc": "=== Carga y ejecuta un módulo desde URL ===", "kind": "function", "line": 751, "name": "LoadModuleFromURL", "signature": "BOOL LoadModuleFromURL(const char* url)"}, {"doc": "=== XOR ===", "kind": "function", "line": 915, "name": "xor_string", "signature": "void xor_string(char* data, size_t len, char key)"}, {"doc": "=== ANTI-ANALYSIS ===", "kind": "function", "line": 922, "name": "anti_analysis", "signature": "BOOL anti_analysis()"}, {"kind": "function", "line": 945, "name": "load_lazyconf", "signature": "BOOL load_lazyconf()"}, {"kind": "function", "line": 1183, "name": "GetNtdllBase", "signature": "HMODULE GetNtdllBase()"}, {"kind": "function", "line": 1231, "name": "isVMByMAC", "signature": "BOOL isVMByMAC()"}, {"doc": "=== EXTRAER SHELLCODE ===", "kind": "function", "line": 1303, "name": "extract_shellcode", "signature": "int extract_shellcode(const char* input, size_t len, unsigned char** out)"}, {"doc": "Función para convertir hex a bytes", "kind": "function", "line": 1334, "name": "hex_char_to_byte", "signature": "BYTE hex_char_to_byte(char c)"}, {"kind": "function", "line": 1340, "name": "hex_to_bytes", "signature": "void hex_to_bytes(const char* hex, BYTE* output, size_t len)"}, {"doc": "=== executeLoader ===", "kind": "function", "line": 1348, "name": "executeLoader", "signature": "void executeLoader(void *arg)"}, {"doc": "======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================", "kind": "function", "line": 1404, "name": "ReverseShell", "signature": "void __cdecl ReverseShell(void* arg)"}, {"doc": "=== Hilo para leer salida del proceso (como en el ejemplo que funciona) ===", "kind": "function", "line": 1513, "name": "ReadFromProcess", "signature": "DWORD WINAPI ReadFromProcess(LPVOID lpParam)"}, {"kind": "function", "line": 1586, "name": "GetJitteredSleep", "signature": "DWORD GetJitteredSleep(DWORD base_ms)"}, {"kind": "function", "line": 1591, "name": "GetUsefulSoftware", "signature": "char* GetUsefulSoftware()"}, {"kind": "function", "line": 1626, "name": "base64_encode", "signature": "char* base64_encode(const unsigned char* data, size_t inputLen)"}, {"kind": "function", "line": 1662, "name": "base64_decode", "signature": "char* base64_decode(const char* input, size_t* out_len)"}, {"kind": "function", "line": 1695, "name": "discoverLocalHosts", "signature": "void discoverLocalHosts()"}, {"doc": "startProxy.c", "kind": "function", "line": 1752, "name": "initProxy", "signature": "void initProxy()"}, {"doc": "Función para reenviar datos entre sockets", "kind": "function", "line": 1763, "name": "relay_thread", "signature": "void WINAPI relay_thread(void* param)"}, {"doc": "Tu función proxy_thread usando tus estructuras exactas", "kind": "function", "line": 1784, "name": "proxy_thread", "signature": "void WINAPI proxy_thread(void* param)"}, {"doc": "Thread para aceptar conexiones", "kind": "function", "line": 1855, "name": "proxy_accept_thread", "signature": "void WINAPI proxy_accept_thread(void* param)"}, {"kind": "function", "line": 1922, "name": "startProxy", "signature": "BOOL startProxy(const char* listenAddr, const char* targetAddr)"}, {"kind": "function", "line": 2009, "name": "stopProxy", "signature": "BOOL stopProxy(const char* listenAddr)"}, {"kind": "function", "line": 2061, "name": "cleanupProxy", "signature": "void cleanupProxy()"}, {"doc": "Función simplificada para compresión de directorios", "kind": "function", "line": 2094, "name": "compressDirectory", "signature": "BOOL compressDirectory(const char* dirPath)"}, {"doc": "Para netconfig", "kind": "function", "line": 2104, "name": "getNetworkConfig", "signature": "char* getNetworkConfig()"}, {"kind": "function", "line": 2107, "name": "UploadFileToC2", "signature": "BOOL UploadFileToC2(const char* url, const char* filePath)"}, {"doc": "=== handleUpload: envía del beacon al C2 ===", "kind": "function", "line": 2280, "name": "handleUpload", "signature": "BOOL handleUpload(const char* command)"}, {"doc": "Función para verificar si un archivo existe", "kind": "function", "line": 2301, "name": "FileExistsA", "signature": "BOOL FileExistsA(const char* filePath)"}, {"doc": "selfdestruct.c", "kind": "function", "line": 2306, "name": "selfDestruct", "signature": "void selfDestruct()"}, {"kind": "function", "line": 2361, "name": "stristr", "signature": "char* stristr(const char* str, const char* pattern)"}, {"kind": "function", "line": 2378, "name": "isSensitiveFile", "signature": "int isSensitiveFile(const char* filename)"}, {"kind": "function", "line": 2424, "name": "searchCredentials", "signature": "char* searchCredentials(const char* basePath)"}, {"doc": "Convierte UTF-8 a wide string", "kind": "function", "line": 2551, "name": "UTF8ToWide", "signature": "WCHAR* UTF8ToWide(const char* utf8)"}, {"doc": "Ofusca los timestamps de un archivo", "kind": "function", "line": 2562, "name": "obfuscateFileTimestamp", "signature": "BOOL obfuscateFileTimestamp(const char* filepath)"}, {"doc": "Recorre directorios buscando archivos sensibles", "kind": "function", "line": 2592, "name": "obfuscateFileTimestamps", "signature": "void obfuscateFileTimestamps(const char* basePath, int depth)"}, {"doc": "traffic.c", "kind": "function", "line": 2656, "name": "simulateLegitimateTraffic", "signature": "void simulateLegitimateTraffic(void* param)"}, {"kind": "function", "line": 2734, "name": "restartClient", "signature": "void restartClient()"}, {"kind": "function", "line": 2776, "name": "checkDebuggers", "signature": "BOOL checkDebuggers()"}, {"kind": "function", "line": 2837, "name": "MapPEToMemory", "signature": "unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)"}, {"kind": "function", "line": 2860, "name": "downloadAndExecute", "signature": "BOOL downloadAndExecute(const char* url, const char* targetProcess)"}, {"kind": "function", "line": 2910, "name": "DecryptPacket", "signature": "BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)"}, {"kind": "function", "line": 3006, "name": "GetIPs", "signature": "char* GetIPs()"}, {"kind": "function", "line": 3039, "name": "GetHostname", "signature": "char* GetHostname()"}, {"kind": "function", "line": 3056, "name": "GetUsername", "signature": "char* GetUsername()"}, {"kind": "function", "line": 3072, "name": "patchAMSI", "signature": "BOOL patchAMSI(void)"}, {"doc": "==================================================================== PE HELPERS (usando winnt.h) ====================================================================", "kind": "function", "line": 3092, "name": "get_nt_headers", "signature": "PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)"}, {"kind": "function", "line": 3100, "name": "is_64bit", "signature": "BOOL is_64bit(BYTE* buffer)"}, {"kind": "function", "line": 3106, "name": "get_image_size", "signature": "DWORD get_image_size(BYTE* buffer)"}, {"kind": "function", "line": 3112, "name": "get_entry_point_rva", "signature": "DWORD get_entry_point_rva(BYTE* buffer)"}, {"kind": "function", "line": 3117, "name": "pe_buffer_to_virtual_image", "signature": "BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)"}, {"doc": "==================================================================== PROCESS MANIPULATION ====================================================================", "kind": "function", "line": 3148, "name": "create_suspended_process", "signature": "BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)"}, {"kind": "function", "line": 3154, "name": "get_remote_image_base", "signature": "ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)"}, {"kind": "function", "line": 3249, "name": "update_remote_entry_point", "signature": "BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)"}, {"doc": "==================================================================== MAIN FUNCTION: overWrite ====================================================================", "kind": "function", "line": 3277, "name": "overWrite", "signature": "void overWrite(const char* targetPath, const char* payloadPath)"}, {"doc": "Limpia el historial de comandos de la consola actual", "kind": "function", "line": 3384, "name": "cleanSystemLogs", "signature": "void cleanSystemLogs()"}, {"doc": "ensurePersistence.c", "kind": "function", "line": 3421, "name": "ensurePersistence", "signature": "BOOL ensurePersistence()"}, {"doc": "isSandboxEnvironment.c", "kind": "function", "line": 3482, "name": "isSandboxEnvironment", "signature": "BOOL isSandboxEnvironment()"}, {"kind": "function", "line": 3551, "name": "tryPrivilegeEscalation", "signature": "void tryPrivilegeEscalation()"}, {"kind": "function", "line": 3556, "name": "executeUACBypass", "signature": "BOOL executeUACBypass(const char* payloadPath)"}, {"kind": "function", "line": 3610, "name": "scanPort", "signature": "void scanPort(void* arg)"}, {"doc": "PortScanner.c", "kind": "function", "line": 3661, "name": "PortScanner", "signature": "void PortScanner(char* targetIP, int* ports, int numPorts)"}, {"kind": "function", "line": 3705, "name": "PortScannerWrapper", "signature": "void PortScannerWrapper(void* arg)"}, {"doc": "=== INYECCIÓN EARLY BIRD + SYSCALL ===", "kind": "function", "line": 3729, "name": "EarlyBirdInject", "signature": "BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)"}, {"kind": "function", "line": 3898, "name": "init_aes_context", "signature": "PacketEncryptionContext* init_aes_context(const char* key_hex)"}, {"doc": "retry_http_request.c", "kind": "function", "line": 3918, "name": "retry_http_request", "signature": "char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)"}, {"doc": "exec_cmd.c", "kind": "function", "line": 4172, "name": "exec_cmd", "signature": "char* exec_cmd(const char* cmd)"}, {"doc": "c2.c (reemplaza la función actual)", "kind": "function", "line": 4200, "name": "GetC2Command", "signature": "char* GetC2Command(const char* host, const char* path)"}, {"kind": "function", "line": 4346, "name": "DownloadToBuffer", "signature": "unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)"}, {"kind": "function", "line": 4422, "name": "DownloadFromURL", "signature": "BOOL DownloadFromURL(const char* url, const char* filepath)"}, {"kind": "function", "line": 4452, "name": "encrypt_data", "signature": "char* encrypt_data(const char* data)"}, {"kind": "function", "line": 4511, "name": "isValidUUID", "signature": "BOOL isValidUUID(const char* uuid)"}, {"kind": "function", "line": 4536, "name": "deleteFilesDelay", "signature": "void deleteFilesDelay(void* arg)"}, {"kind": "function", "line": 4550, "name": "executeCommand", "signature": "void executeCommand(void* cmdPtr)"}, {"kind": "function", "line": 4559, "name": "handleAtomic", "signature": "void handleAtomic(char* command)"}, {"doc": "=== handleDownload: descarga del C2 al beacon ===", "kind": "function", "line": 4683, "name": "handleDownload", "signature": "BOOL handleDownload(const char* command)"}, {"kind": "function", "line": 4702, "name": "SerializeBeaconString", "signature": "void SerializeBeaconString(char* buffer, int* offset, const char* str)"}, {"kind": "function", "line": 4711, "name": "BeaconDataSerializeString", "signature": "void BeaconDataSerializeString(char* buffer, int* offset, const char* str)"}, {"kind": "function", "line": 4719, "name": "go", "signature": "void go(unsigned char * bof_data, int bof_size, char * args, int args_len)"}, {"doc": "Función principal de manejo de comandos", "kind": "function", "line": 4738, "name": "handleAdversary", "signature": "void handleAdversary(char* command)"}, {"doc": "main.c", "kind": "function", "line": 5233, "name": "main", "signature": "int main()"}, {"kind": "macro", "line": 19, "name": "PSAPI_VERSION"}, {"kind": "macro", "line": 21, "name": "WIN32_LEAN_AND_MEAN"}, {"kind": "macro", "line": 71, "name": "XOR_KEY"}, {"kind": "macro", "line": 72, "name": "DEBUG"}, {"kind": "macro", "line": 73, "name": "TIMEOUT"}, {"kind": "macro", "line": 74, "name": "MAX_RESPONSE_SIZE"}, {"kind": "macro", "line": 75, "name": "C2_URL"}, {"kind": "macro", "line": 76, "name": "MALEABLE"}, {"kind": "macro", "line": 77, "name": "CLIENT_ID"}, {"kind": "macro", "line": 78, "name": "SLEEP_BASE"}, {"kind": "macro", "line": 79, "name": "MIN_JITTER"}, {"kind": "macro", "line": 80, "name": "MAX_JITTER"}, {"kind": "macro", "line": 81, "name": "MAX_RETRIES"}, {"kind": "macro", "line": 82, "name": "C2_HOST"}, {"kind": "macro", "line": 83, "name": "LC2_HOST"}, {"kind": "macro", "line": 84, "name": "C2_USER"}, {"kind": "macro", "line": 85, "name": "C2_PASS"}, {"kind": "macro", "line": 86, "name": "C2_PORT"}, {"kind": "macro", "line": 87, "name": "CONFIG_PATH"}, {"kind": "macro", "line": 88, "name": "C2_PATH"}, {"kind": "macro", "line": 89, "name": "LC2_PATH"}, {"kind": "macro", "line": 91, "name": "min"}, {"kind": "macro", "line": 94, "name": "SECURITY_FLAG_IGNORE_REVOCATION"}, {"kind": "macro", "line": 97, "name": "INVALID_SOCKET"}, {"kind": "macro", "line": 99, "name": "USER_AGENT"}, {"kind": "macro", "line": 100, "name": "USER_AGENT_A"}, {"kind": "macro", "line": 101, "name": "IMAGE_DOS_SIGNATURE"}, {"kind": "macro", "line": 102, "name": "IMAGE_NT_SIGNATURE"}, {"kind": "macro", "line": 103, "name": "IMAGE_NT_OPTIONAL_HDR32_MAGIC"}, {"kind": "macro", "line": 104, "name": "IMAGE_NT_OPTIONAL_HDR64_MAGIC"}, {"kind": "macro", "line": 106, "name": "SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE"}, {"kind": "macro", "line": 109, "name": "SECURITY_FLAG_IGNORE_INVALID_POLICY"}, {"kind": "macro", "line": 112, "name": "_SECURITY_PACKAGE_DEFINITION_"}, {"kind": "macro", "line": 115, "name": "_PROCESS_BASIC_INFORMATION_"}, {"kind": "macro", "line": 117, "name": "_SP_LSA_MODE_INITIALIZE_DEFINED_"}, {"kind": "macro", "line": 123, "name": "ProcessBasicInformation"}, {"kind": "macro", "line": 125, "name": "CHECK_ERROR"}, {"kind": "macro", "line": 231, "name": "NUM_USER_AGENTS"}, {"kind": "macro", "line": 240, "name": "NUM_URLS"}, {"kind": "macro", "line": 247, "name": "NUM_UAS"}, {"kind": "macro", "line": 300, "name": "NT_SUCCESS"}]}, {"id": "beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "7544cca0fc60f0eb", "symbol_count": 3, "symbols": [{"kind": "macro", "line": 21, "name": "BEACON_H"}, {"kind": "macro", "line": 40, "name": "CALLBACK_OUTPUT"}, {"kind": "macro", "line": 42, "name": "CALLBACK_ERROR"}]}, {"id": "bof/calc/beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "73851fadbad93a09", "symbol_count": 3, "symbols": [{"kind": "macro", "line": 21, "name": "BEACON_H"}, {"kind": "macro", "line": 40, "name": "CALLBACK_OUTPUT"}, {"kind": "macro", "line": 42, "name": "CALLBACK_ERROR"}]}, {"id": "bof/calc/calc.c", "kind": "module", "label": "calc.c", "language": "c", "sha256": "be4f9af92f13489f", "symbol_count": 1, "symbols": [{"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 34, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/etw/beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "98968bae69bb188f", "symbol_count": 3, "symbols": [{"kind": "macro", "line": 21, "name": "BEACON_H"}, {"kind": "macro", "line": 40, "name": "CALLBACK_OUTPUT"}, {"kind": "macro", "line": 42, "name": "CALLBACK_ERROR"}]}, {"id": "bof/etw/etw.c", "kind": "module", "label": "etw.c", "language": "c", "sha256": "c5263935776ccdf6", "symbol_count": 1, "symbols": [{"kind": "function", "line": 26, "name": "go", "signature": "void go(char *a,int l)"}]}, {"doc": "include \"beacon.h\"", "id": "bof/test/Test.c", "kind": "module", "label": "Test.c", "language": "c", "sha256": "7da43e2a5a074e21", "symbol_count": 1, "symbols": [{"doc": "include \"beacon.h\"", "kind": "function", "line": 2, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/amsibypass.c", "kind": "module", "label": "amsibypass.c", "language": "c", "sha256": "4658bd0d194c4ad9", "symbol_count": 1, "symbols": [{"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 34, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "985a47cdd9022c90", "symbol_count": 3, "symbols": [{"kind": "macro", "line": 21, "name": "BEACON_H"}, {"kind": "macro", "line": 40, "name": "CALLBACK_OUTPUT"}, {"kind": "macro", "line": 42, "name": "CALLBACK_ERROR"}]}, {"id": "bof/test/cmdwhoami.c", "kind": "module", "label": "cmdwhoami.c", "language": "c", "sha256": "4e535032b0023588", "symbol_count": 1, "symbols": [{"kind": "function", "line": 42, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/disablelog.c", "kind": "module", "label": "disablelog.c", "language": "c", "sha256": "0a9282aecb0900b4", "symbol_count": 4, "symbols": [{"doc": "ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif", "kind": "function", "line": 36, "name": "my_wcscmp", "signature": "static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)"}, {"kind": "function", "line": 68, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 20, "name": "WIN32_LEAN_AND_MEAN"}, {"kind": "macro", "line": 34, "name": "NT_SUCCESS"}]}, {"id": "bof/test/getenv.c", "kind": "module", "label": "getenv.c", "language": "c", "sha256": "79279d9d8c69b801", "symbol_count": 1, "symbols": [{"kind": "function", "line": 24, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/loadvnc.c", "kind": "module", "label": "loadvnc.c", "language": "c", "sha256": "4f05e790da8eafdd", "symbol_count": 4, "symbols": [{"kind": "struct", "line": 35, "name": "_PROCESSENTRY32"}, {"doc": "================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================", "kind": "function", "line": 51, "name": "execute_cmd_hidden", "signature": "void execute_cmd_hidden(char* cmd)"}, {"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 81, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 33, "name": "TH32CS_SNAPPROCESS"}]}, {"id": "bof/test/make_table.c", "kind": "module", "label": "make_table.c", "language": "c", "sha256": "2e6860f3d4c15c35", "symbol_count": 2, "symbols": [{"kind": "function", "line": 16, "name": "Copyright", "signature": "Copyright (c) LazyOwn RedTeam 2025. All rights reserved.\n*/\n\n#include <stdint.h>\n#include <stdio...."}, {"kind": "function", "line": 33, "name": "main", "signature": "void main()"}]}, {"id": "bof/test/persist.c", "kind": "module", "label": "persist.c", "language": "c", "sha256": "c57896982e8073de", "symbol_count": 1, "symbols": [{"kind": "function", "line": 26, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/persistsvc.c", "kind": "module", "label": "persistsvc.c", "language": "c", "sha256": "bcd0480847e87e2a", "symbol_count": 11, "symbols": [{"doc": "================================ FUNCIONES AUXILIARES ================================", "kind": "function", "line": 33, "name": "my_memcpy", "signature": "static void* my_memcpy(void* dst, const void* src, size_t len)"}, {"kind": "function", "line": 39, "name": "my_strlen", "signature": "static int my_strlen(const char* str)"}, {"kind": "function", "line": 46, "name": "my_strcat", "signature": "static char* my_strcat(char* dest, const char* src)"}, {"kind": "function", "line": 54, "name": "my_strcmp", "signature": "static int my_strcmp(const char* s1, const char* s2)"}, {"doc": "================================ MANEJADOR DE CONTROL DEL SERVICIO ================================", "kind": "function", "line": 82, "name": "ServiceHandler", "signature": "DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont..."}, {"doc": "================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================", "kind": "function", "line": 116, "name": "ServiceMain", "signature": "VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)"}, {"doc": "================================ FUNCIÓN PRINCIPAL DEL BOF ================================", "kind": "function", "line": 251, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 19, "name": "WIN32_LEAN_AND_MEAN"}, {"kind": "macro", "line": 65, "name": "RESOLVE_API"}, {"kind": "macro", "line": 131, "name": "cleanup"}, {"kind": "macro", "line": 183, "name": "cleanup"}]}, {"id": "bof/test/scan_shellcode.c", "kind": "module", "label": "scan_shellcode.c", "language": "c", "sha256": "377c77657afce9b6", "symbol_count": 2, "symbols": [{"kind": "function", "line": 84, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 19, "name": "WIN32_LEAN_AND_MEAN"}]}, {"id": "bof/test/shellcode.c", "kind": "module", "label": "shellcode.c", "language": "c", "sha256": "b37083ba368d228b", "symbol_count": 1, "symbols": [{"kind": "function", "line": 25, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"doc": "define WIN32_LEAN_AND_MEAN include <windows.h> include \"beacon.h\"  ===== DECLARACIONES QUE FALTABAN =====", "id": "bof/test/sock5.c", "kind": "module", "label": "sock5.c", "language": "c", "sha256": "71a4294c3d0f3b79", "symbol_count": 29, "symbols": [{"doc": "pragma pack(push,1)", "kind": "struct", "line": 16, "name": "WSAData"}, {"kind": "struct", "line": 27, "name": "fd_set"}, {"kind": "struct", "line": 32, "name": "timeval"}, {"kind": "struct", "line": 47, "name": "in_addr"}, {"kind": "struct", "line": 49, "name": "sockaddr_in"}, {"kind": "struct", "line": 56, "name": "sockaddr"}, {"kind": "struct", "line": 58, "name": "hostent"}, {"doc": "typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typedef int       (WINAPI *CONNECT)(SOCKET, const struct sockaddr*, int); typedef int       (WINAPI *RECV)(SOCKET, char*, int, int); typedef int       (WINAPI *SEND)(SOCKET, const char*, int, int); typedef int       (WINAPI *SELECT)(int, fd_set*, fd_set*, fd_set*, const struct timeval*); typedef int       (WINAPI *CLOSESOCKET)(SOCKET); typedef int       (WINAPI *WSACLEANUP)(void); typedef int       (WINAPI *WSAGETLASTERROR)(void); typedef ULONG     (WINAPI *HTONL)(ULONG); typedef USHORT    (WINAPI *HTONS)(USHORT); typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES =====", "kind": "function", "line": 107, "name": "my_FD_ISSET", "signature": "static int my_FD_ISSET(SOCKET s, fd_set *set)"}, {"doc": "typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if (!set) return 0; for (u_int i = 0; i < set->fd_count; ++i) if (set->fd_array[i] == s) return 1; return 0; } /* ===== VARIABLE GLOBAL ===== static HANDLE g_hShutdownEvent = NULL; /* ===== MANEJADOR SOCKS5 (solo después de handshake confirmado) =====", "kind": "function", "line": 118, "name": "HandleSocks5Connection", "signature": "static void HandleSocks5Connection(SOCKET client_sock,\n    CONNECT pConnect, RECV pRecv, SEND pSe..."}, {"doc": "break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, \"[SOCKS5] Falló al reenviar al cliente\\n\"); break; } BeaconPrintf(CALLBACK_OUTPUT, \"[SOCKS5] Reenviados %d bytes destino→cliente\\n\", n); } } pCloseSocket(tgt); BeaconPrintf(CALLBACK_OUTPUT, \"[SOCKS5] Túnel cerrado\\n\"); } /* ===== HILO PRINCIPAL DEL PROXY =====", "kind": "function", "line": 261, "name": "ProxyThread", "signature": "DWORD WINAPI ProxyThread(LPVOID _)"}, {"doc": "cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HANDLE))__imp_CloseHandle)(g_hShutdownEvent); g_hShutdownEvent = NULL; } return 0; } /* ===== ENTRY POINT BOF =====", "kind": "function", "line": 358, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 1, "name": "WIN32_LEAN_AND_MEAN"}, {"kind": "macro", "line": 7, "name": "INVALID_SOCKET"}, {"kind": "macro", "line": 8, "name": "SOCKET_ERROR"}, {"kind": "macro", "line": 9, "name": "AF_INET"}, {"kind": "macro", "line": 10, "name": "SOCK_STREAM"}, {"kind": "macro", "line": 11, "name": "IPPROTO_TCP"}, {"kind": "macro", "line": 12, "name": "INADDR_ANY"}, {"kind": "macro", "line": 13, "name": "INADDR_LOOPBACK"}, {"kind": "macro", "line": 36, "name": "FD_SETSIZE"}, {"kind": "macro", "line": 38, "name": "FD_CLR"}, {"kind": "macro", "line": 39, "name": "FD_SET"}, {"kind": "macro", "line": 40, "name": "FD_ZERO"}, {"kind": "macro", "line": 41, "name": "FD_ISSET"}, {"kind": "macro", "line": 64, "name": "h_addr"}, {"kind": "macro", "line": 75, "name": "SOCKS5_LISTEN_PORT"}, {"kind": "macro", "line": 76, "name": "SOCKS5_CONTROL_PORT"}, {"kind": "macro", "line": 77, "name": "MAX_PENDING_CONNECTIONS"}, {"kind": "macro", "line": 78, "name": "BUFFER_SIZE"}]}, {"id": "bof/test/tel.py", "kind": "module", "label": "tel.py", "language": "py", "sha256": "2c888a79357c13cd", "symbol_count": 6, "symbols": [{"kind": "function", "line": 8, "name": "get_machine_id", "signature": "def get_machine_id()"}, {"kind": "function", "line": 20, "name": "get_version", "signature": "def get_version()"}, {"doc": "Simula la función toNumbers de JavaScript", "kind": "function", "line": 31, "name": "to_numbers", "signature": "def to_numbers(hex_str)"}, {"doc": "Simula la función toHex de JavaScript", "kind": "function", "line": 35, "name": "to_hex", "signature": "def to_hex(byte_list)"}, {"doc": "Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))", "kind": "function", "line": 39, "name": "decrypt_cookie", "signature": "def decrypt_cookie(encrypted, key, iv)"}, {"doc": "Sistema de telemetría de uso por instalación no invasiva.", "kind": "function", "line": 45, "name": "main", "signature": "def main()"}]}, {"id": "bof/test/uacbypass.c", "kind": "module", "label": "uacbypass.c", "language": "c", "sha256": "3dbffbb48364195b", "symbol_count": 2, "symbols": [{"doc": "================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================", "kind": "function", "line": 33, "name": "execute_hidden_cmd", "signature": "void execute_hidden_cmd(char* cmd)"}, {"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 61, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"doc": "define WIN32_LEAN_AND_MEAN include <windows.h> include \"beacon.h\"  ================================ IMPORTS DIRECTOS ================================", "id": "bof/test/upload.c", "kind": "module", "label": "upload.c", "language": "c", "sha256": "5dfb306c95d53b02", "symbol_count": 33, "symbols": [{"doc": "================================ FUNCIONES AUXILIARES ================================", "kind": "function", "line": 53, "name": "my_strlen", "signature": "static int my_strlen(const char *s)"}, {"kind": "function", "line": 58, "name": "my_memcpy", "signature": "static void* my_memcpy(void* dst, const void* src, size_t len)"}, {"kind": "function", "line": 65, "name": "my_memset", "signature": "static void* my_memset(void* dst, int val, size_t len)"}, {"kind": "function", "line": 71, "name": "my_contains_dotdot", "signature": "static BOOL my_contains_dotdot(const char* path)"}, {"kind": "function", "line": 80, "name": "my_strchr", "signature": "static char* my_strchr(const char *s, int c)"}, {"doc": "================================ AES (sin datos globales) ================================", "kind": "function", "line": 93, "name": "xtime", "signature": "static uint8_t xtime(uint8_t x)"}, {"kind": "function", "line": 98, "name": "AddRoundKey", "signature": "static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)"}, {"kind": "function", "line": 105, "name": "SubBytes", "signature": "static void SubBytes(state_t* state, const uint8_t* sbox)"}, {"kind": "function", "line": 112, "name": "ShiftRows", "signature": "static void ShiftRows(state_t* state)"}, {"kind": "function", "line": 120, "name": "MixColumns", "signature": "static void MixColumns(state_t* state)"}, {"kind": "function", "line": 132, "name": "Cipher", "signature": "static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)"}, {"kind": "function", "line": 145, "name": "KeyExpansion", "signature": "static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_..."}, {"kind": "function", "line": 173, "name": "AES_init_ctx", "signature": "void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)"}, {"kind": "function", "line": 177, "name": "AES_CFB_encrypt_buffer", "signature": "void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8..."}, {"doc": "================================ BASE64 ================================", "kind": "function", "line": 205, "name": "my_base64_encode", "signature": "static char* my_base64_encode(const uint8_t* data, uint32_t len,\n    LPVOID (WINAPI *pVirtualAllo..."}, {"kind": "function", "line": 230, "name": "ParseUploadArgs", "signature": "static void ParseUploadArgs(const char* args, int alen,\n                            char* local_p..."}, {"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 273, "name": "go", "signature": "void go(char *args, int alen)"}, {"kind": "macro", "line": 1, "name": "WIN32_LEAN_AND_MEAN"}, {"kind": "macro", "line": 20, "name": "PROV_RSA_AES"}, {"kind": "macro", "line": 21, "name": "CRYPT_VERIFYCONTEXT"}, {"kind": "macro", "line": 22, "name": "AES_BLOCKLEN"}, {"kind": "macro", "line": 24, "name": "AES256_KEYLEN"}, {"kind": "macro", "line": 25, "name": "Nr"}, {"kind": "macro", "line": 26, "name": "Nk"}, {"kind": "macro", "line": 27, "name": "Nb"}, {"kind": "macro", "line": 28, "name": "SECURITY_FLAG_IGNORE_UNKNOWN_CA"}, {"kind": "macro", "line": 30, "name": "SECURITY_FLAG_IGNORE_CERT_CN_INVALID"}, {"kind": "macro", "line": 31, "name": "SECURITY_FLAG_IGNORE_CERT_DATE_INVALID"}, {"kind": "macro", "line": 32, "name": "WINHTTP_OPTION_SECURITY_FLAGS"}, {"kind": "macro", "line": 35, "name": "WINHTTP_ACCESS_TYPE_NO_PROXY"}, {"kind": "macro", "line": 39, "name": "WINHTTP_NO_PROXY_NAME"}, {"kind": "macro", "line": 43, "name": "WINHTTP_NO_PROXY_BYPASS"}, {"kind": "macro", "line": 244, "name": "NEXT_TOKEN"}]}, {"id": "bof/test/vncrelay.c", "kind": "module", "label": "vncrelay.c", "language": "c", "sha256": "92dd162e67890bed", "symbol_count": 3, "symbols": [{"doc": "================================ FD_ISSET MANUAL ================================", "kind": "function", "line": 62, "name": "my_FD_ISSET", "signature": "int my_FD_ISSET(SOCKET sock, fd_set *set)"}, {"doc": "================================ RELAY TRAFFIC ================================", "kind": "function", "line": 75, "name": "relay_traffic", "signature": "void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)"}, {"doc": "================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================", "kind": "function", "line": 132, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/test/winver.c", "kind": "module", "label": "winver.c", "language": "c", "sha256": "565ade4ee0ab194f", "symbol_count": 1, "symbols": [{"kind": "function", "line": 24, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "bof/whoami/beacon.h", "kind": "module", "label": "beacon.h", "language": "h", "sha256": "69392f65423df75c", "symbol_count": 3, "symbols": [{"kind": "macro", "line": 21, "name": "BEACON_H"}, {"kind": "macro", "line": 40, "name": "CALLBACK_OUTPUT"}, {"kind": "macro", "line": 42, "name": "CALLBACK_ERROR"}]}, {"id": "bof/whoami/whoami.c", "kind": "module", "label": "whoami.c", "language": "c", "sha256": "88281e98274693a7", "symbol_count": 1, "symbols": [{"doc": "================================ FUNCIÓN PRINCIPAL ================================", "kind": "function", "line": 34, "name": "go", "signature": "void go(char *args, int alen)"}]}, {"id": "cJSON.c", "kind": "module", "label": "cJSON.c", "language": "c", "sha256": "3affbc3ab9c6182a", "symbol_count": 122, "symbols": [{"kind": "struct", "line": 157, "name": "internal_hooks"}, {"kind": "function", "line": 94, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)"}, {"kind": "function", "line": 99, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)"}, {"kind": "function", "line": 109, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)"}, {"doc": "CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif", "kind": "function", "line": 124, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(const char*) cJSON_Version(void)"}, {"doc": "/* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, \"%i.%i.%i\", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though", "kind": "function", "line": 134, "name": "case_insensitive_strcmp", "signature": "static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)"}, {"doc": "} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static", "kind": "function", "line": 166, "name": "internal_malloc", "signature": "static void * CJSON_CDECL internal_malloc(size_t size)"}, {"kind": "function", "line": 170, "name": "internal_free", "signature": "static void CJSON_CDECL internal_free(void *pointer)"}, {"kind": "function", "line": 174, "name": "internal_realloc", "signature": "static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)"}, {"kind": "function", "line": 188, "name": "cJSON_strdup", "signature": "static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)"}, {"kind": "function", "line": 209, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)"}, {"doc": "if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.", "kind": "function", "line": 242, "name": "cJSON_New_Item", "signature": "static cJSON *cJSON_New_Item(const internal_hooks * const hooks)"}, {"doc": "item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale", "kind": "function", "line": 281, "name": "get_decimal_point", "signature": "static unsigned char get_decimal_point(void)"}, {"doc": "size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.", "kind": "function", "line": 309, "name": "parse_number", "signature": "static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least \"needed\" bytes more", "kind": "function", "line": 494, "name": "ensure", "signature": "static unsigned char* ensure(printbuffer * const p, size_t needed)"}, {"doc": "p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset", "kind": "function", "line": 579, "name": "update_offset", "signature": "static void update_offset(printbuffer * const buffer)"}, {"doc": "/* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables", "kind": "function", "line": 592, "name": "compare_double", "signature": "static cJSON_bool compare_double(double a, double b)"}, {"doc": "} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.", "kind": "function", "line": 599, "name": "print_number", "signature": "static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number", "kind": "function", "line": 669, "name": "parse_hex4", "signature": "static unsigned parse_hex4(const unsigned char * const input)"}, {"doc": "converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \\uXXXX", "kind": "function", "line": 706, "name": "utf16_literal_to_utf8", "signature": "static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig..."}, {"doc": "else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.", "kind": "function", "line": 827, "name": "parse_string", "signature": "static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.", "kind": "function", "line": 957, "name": "print_string_ptr", "signature": "static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_..."}, {"doc": "/* escape and print as unicode codepoint sprintf((char*)output_pointer, \"u%04x\", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '\"'; output[output_length + 2] = '\\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.", "kind": "function", "line": 1079, "name": "print_string", "signature": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)"}, {"doc": "static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf", "kind": "function", "line": 1093, "name": "buffer_skip_whitespace", "signature": "static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)"}, {"doc": "while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer", "kind": "function", "line": 1119, "name": "skip_utf8_bom", "signature": "static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)"}, {"kind": "function", "line": 1133, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON..."}, {"kind": "function", "line": 1235, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)"}, {"doc": "define cjson_min(a, b) (((a) < (b)) ? (a) : (b))", "kind": "function", "line": 1242, "name": "print", "signature": "static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c..."}, {"kind": "function", "line": 1315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)"}, {"kind": "function", "line": 1320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)"}, {"kind": "function", "line": 1351, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con..."}, {"doc": "return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.", "kind": "function", "line": 1372, "name": "parse_value", "signature": "static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.", "kind": "function", "line": 1427, "name": "print_value", "signature": "static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.", "kind": "function", "line": 1501, "name": "parse_array", "signature": "static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text", "kind": "function", "line": 1599, "name": "print_array", "signature": "static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)"}, {"doc": "output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\\0'; output_buffer->depth--; return true; } /* Build an object from the text.", "kind": "function", "line": 1661, "name": "parse_object", "signature": "static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)"}, {"doc": "input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.", "kind": "function", "line": 1780, "name": "print_object", "signature": "static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)"}, {"kind": "function", "line": 1915, "name": "get_array_item", "signature": "static cJSON* get_array_item(const cJSON *array, size_t index)"}, {"kind": "function", "line": 1934, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)"}, {"kind": "function", "line": 1944, "name": "get_object_item", "signature": "static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo..."}, {"kind": "function", "line": 1976, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)"}, {"kind": "function", "line": 1981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c..."}, {"kind": "function", "line": 1986, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)"}, {"doc": "return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.", "kind": "function", "line": 1993, "name": "suffix_object", "signature": "static void suffix_object(cJSON *prev, cJSON *item)"}, {"doc": "CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.", "kind": "function", "line": 2000, "name": "create_reference", "signature": "static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)"}, {"kind": "function", "line": 2020, "name": "add_item_to_array", "signature": "static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)"}, {"doc": "/* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored \"-Wcast-qual\" #endif /* helper function to cast away const", "kind": "function", "line": 2066, "name": "cast_away_const", "signature": "static void* cast_away_const(const void* string)"}, {"doc": "if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif", "kind": "function", "line": 2073, "name": "add_item_to_object", "signature": "static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con..."}, {"kind": "function", "line": 2111, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)"}, {"kind": "function", "line": 2122, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)"}, {"kind": "function", "line": 2132, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ..."}, {"kind": "function", "line": 2142, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2154, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2166, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2178, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c..."}, {"kind": "function", "line": 2190, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2202, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const..."}, {"kind": "function", "line": 2214, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch..."}, {"kind": "function", "line": 2226, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2238, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)"}, {"kind": "function", "line": 2250, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)"}, {"kind": "function", "line": 2286, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2296, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)"}, {"kind": "function", "line": 2301, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2308, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2315, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)"}, {"kind": "function", "line": 2320, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)"}, {"kind": "function", "line": 2362, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ..."}, {"kind": "function", "line": 2412, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)"}, {"kind": "function", "line": 2422, "name": "replace_item_in_object", "signature": "static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c..."}, {"kind": "function", "line": 2445, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi..."}, {"kind": "function", "line": 2450, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string..."}, {"kind": "function", "line": 2467, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)"}, {"kind": "function", "line": 2478, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)"}, {"kind": "function", "line": 2489, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)"}, {"kind": "function", "line": 2500, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)"}, {"kind": "function", "line": 2525, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)"}, {"kind": "function", "line": 2542, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)"}, {"kind": "function", "line": 2554, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)"}, {"kind": "function", "line": 2566, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)"}, {"kind": "function", "line": 2578, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)"}, {"kind": "function", "line": 2595, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)"}, {"kind": "function", "line": 2606, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)"}, {"kind": "function", "line": 2658, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)"}, {"kind": "function", "line": 2698, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)"}, {"kind": "function", "line": 2738, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)"}, {"kind": "function", "line": 2785, "name": "cJSON_Duplicate_rec", "signature": "cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)"}, {"kind": "function", "line": 2872, "name": "skip_oneline_comment", "signature": "static void skip_oneline_comment(char **input)"}, {"kind": "function", "line": 2885, "name": "skip_multiline_comment", "signature": "static void skip_multiline_comment(char **input)"}, {"kind": "function", "line": 2899, "name": "minify_string", "signature": "static void minify_string(char **input, char **output)"}, {"kind": "function", "line": 2921, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_Minify(char *json)"}, {"kind": "function", "line": 2971, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)"}, {"kind": "function", "line": 2981, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)"}, {"kind": "function", "line": 2991, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)"}, {"kind": "function", "line": 3001, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)"}, {"kind": "function", "line": 3011, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)"}, {"kind": "function", "line": 3021, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)"}, {"kind": "function", "line": 3031, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)"}, {"kind": "function", "line": 3041, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)"}, {"kind": "function", "line": 3051, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)"}, {"kind": "function", "line": 3061, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)"}, {"kind": "function", "line": 3071, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_..."}, {"kind": "function", "line": 3157, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(a_element, a)"}, {"doc": "doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now", "kind": "function", "line": 3173, "name": "cJSON_ArrayForEach", "signature": "cJSON_ArrayForEach(b_element, b)"}, {"kind": "function", "line": 3193, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void *) cJSON_malloc(size_t size)"}, {"kind": "function", "line": 3198, "name": "CJSON_PUBLIC", "signature": "CJSON_PUBLIC(void) cJSON_free(void *object)"}, {"kind": "macro", "line": 28, "name": "_CRT_SECURE_NO_DEPRECATE"}, {"kind": "macro", "line": 65, "name": "true"}, {"kind": "macro", "line": 70, "name": "false"}, {"kind": "macro", "line": 74, "name": "isinf"}, {"kind": "macro", "line": 77, "name": "isnan"}, {"kind": "macro", "line": 82, "name": "NAN"}, {"kind": "macro", "line": 84, "name": "NAN"}, {"kind": "macro", "line": 179, "name": "internal_malloc"}, {"kind": "macro", "line": 180, "name": "internal_free"}, {"kind": "macro", "line": 181, "name": "internal_realloc"}, {"kind": "macro", "line": 185, "name": "static_strlen"}, {"kind": "macro", "line": 301, "name": "can_read"}, {"kind": "macro", "line": 303, "name": "can_access_at_index"}, {"kind": "macro", "line": 304, "name": "cannot_access_at_index"}, {"kind": "macro", "line": 306, "name": "buffer_at_offset"}, {"kind": "macro", "line": 1240, "name": "cjson_min"}]}, {"id": "cJSON.h", "kind": "module", "label": "cJSON.h", "language": "h", "sha256": "2a35f7617625a3fc", "symbol_count": 34, "symbols": [{"doc": "#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:", "kind": "struct", "line": 92, "name": "cJSON"}, {"kind": "struct", "line": 114, "name": "cJSON_Hooks"}, {"kind": "macro", "line": 24, "name": "cJSON__h"}, {"kind": "macro", "line": 32, "name": "__WINDOWS__"}, {"kind": "macro", "line": 43, "name": "CJSON_CDECL"}, {"kind": "macro", "line": 45, "name": "CJSON_STDCALL"}, {"kind": "macro", "line": 49, "name": "CJSON_EXPORT_SYMBOLS"}, {"kind": "macro", "line": 53, "name": "CJSON_PUBLIC"}, {"kind": "macro", "line": 55, "name": "CJSON_PUBLIC"}, {"kind": "macro", "line": 57, "name": "CJSON_PUBLIC"}, {"kind": "macro", "line": 60, "name": "CJSON_CDECL"}, {"kind": "macro", "line": 61, "name": "CJSON_STDCALL"}, {"kind": "macro", "line": 64, "name": "CJSON_PUBLIC"}, {"kind": "macro", "line": 66, "name": "CJSON_PUBLIC"}, {"kind": "macro", "line": 71, "name": "CJSON_VERSION_MAJOR"}, {"kind": "macro", "line": 72, "name": "CJSON_VERSION_MINOR"}, {"kind": "macro", "line": 73, "name": "CJSON_VERSION_PATCH"}, {"kind": "macro", "line": 78, "name": "cJSON_Invalid"}, {"kind": "macro", "line": 79, "name": "cJSON_False"}, {"kind": "macro", "line": 80, "name": "cJSON_True"}, {"kind": "macro", "line": 81, "name": "cJSON_NULL"}, {"kind": "macro", "line": 82, "name": "cJSON_Number"}, {"kind": "macro", "line": 83, "name": "cJSON_String"}, {"kind": "macro", "line": 84, "name": "cJSON_Array"}, {"kind": "macro", "line": 85, "name": "cJSON_Object"}, {"kind": "macro", "line": 86, "name": "cJSON_Raw"}, {"kind": "macro", "line": 87, "name": "cJSON_IsReference"}, {"kind": "macro", "line": 89, "name": "cJSON_StringIsConst"}, {"kind": "macro", "line": 126, "name": "CJSON_NESTING_LIMIT"}, {"kind": "macro", "line": 132, "name": "CJSON_CIRCULAR_LIMIT"}, {"kind": "macro", "line": 270, "name": "cJSON_SetIntValue"}, {"kind": "macro", "line": 273, "name": "cJSON_SetNumberValue"}, {"kind": "macro", "line": 278, "name": "cJSON_SetBoolValue"}, {"kind": "macro", "line": 285, "name": "cJSON_ArrayForEach"}]}, {"doc": "=== beacon-GEN v1.2 ===", "id": "gen_beacon.sh", "kind": "module", "label": "gen_beacon.sh", "language": "sh", "sha256": "edb3968c6d56a01d", "symbol_count": 3, "symbols": [{"doc": "=== FUNCIONES ===", "kind": "function", "line": 34, "name": "show_help"}, {"doc": "=== XOR STRING TO BYTES ===", "kind": "function", "line": 138, "name": "xor_string"}, {"kind": "function", "line": 5916, "name": "crc32"}]}, {"doc": "1. Generar DLL", "id": "gen_dll.sh", "kind": "module", "label": "gen_dll.sh", "language": "sh", "sha256": "141d825c9678889d", "symbol_count": 0, "symbols": []}, {"doc": "=== CONFIGURACIÓN POR DEFECTO ===", "id": "gen_dll_rev.sh", "kind": "module", "label": "gen_dll_rev.sh", "language": "sh", "sha256": "cac4b7ee93482f34", "symbol_count": 1, "symbols": [{"doc": "=== USO ===", "kind": "function", "line": 12, "name": "usage"}]}, {"doc": "=== CONFIGURACIÓN POR DEFECTO ===", "id": "gen_dll_ss.sh", "kind": "module", "label": "gen_dll_ss.sh", "language": "sh", "sha256": "8e2701eb6df73daa", "symbol_count": 1, "symbols": [{"doc": "=== USO ===", "kind": "function", "line": 10, "name": "usage"}]}, {"doc": "=== CONFIGURACIÓN POR DEFECTO ===", "id": "gen_key.sh", "kind": "module", "label": "gen_key.sh", "language": "sh", "sha256": "ad30fa886634b88b", "symbol_count": 1, "symbols": [{"doc": "=== USO ===", "kind": "function", "line": 10, "name": "usage"}]}, {"doc": "=== gen_cmd_dll.sh v1.0 === Genera DLL y shellcode ofuscado para ejecutar un comando Uso: ./gen_cmd_dll.sh --cmd \"powershell...\" [--key 0x33] [--output payload]", "id": "gen_module.sh", "kind": "module", "label": "gen_module.sh", "language": "sh", "sha256": "5100dba85d246ece", "symbol_count": 2, "symbols": [{"doc": "=== FUNCIONES ===", "kind": "function", "line": 18, "name": "show_help"}, {"doc": "Función para ofuscar binario con XOR y convertir a \\x..", "kind": "function", "line": 35, "name": "xor_obfuscate"}]}, {"id": "generate_hashs.py", "kind": "module", "label": "generate_hashs.py", "language": "py", "sha256": "023ebad2d7b8e8cd", "symbol_count": 4, "symbols": [{"kind": "function", "line": 23, "name": "djb2", "signature": "def djb2(s)"}, {"kind": "function", "line": 223, "name": "generate_coff_loader", "signature": "def generate_coff_loader()"}, {"kind": "function", "line": 491, "name": "generate_bof_test", "signature": "def generate_bof_test()"}, {"kind": "function", "line": 553, "name": "main", "signature": "def main()"}]}, {"id": "install.sh", "kind": "module", "label": "install.sh", "language": "sh", "sha256": "c907d80fd6734993", "symbol_count": 0, "symbols": []}], "type": "CodePropertyGraph", "version": "1.0"}
```

---

## Architecture Reference

### C (23 files)

#### `COFFLoader3.c`
**Path:** `COFFLoader3.c`

**Functions:**
- `djb2_hash` (line 632) `static uint32_t djb2_hash(const char* str)` - *=== Función hash DJB2 ===*
- `create_trampoline` (line 912) `static void* create_trampoline(void* target)`
- `handle_relocation` (line 940) `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...`
- `get_symbol_name` (line 1079) `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)`
- `__attribute__` (line 1102) `__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2)`
- `RunCOFF` (line 1112) `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...` - *=== Cargador COFF  ===*

**Macros:**
- `IMAGE_REL_AMD64_ABSOLUTE` (line 568)
- `IMAGE_REL_AMD64_ADDR64` (line 569)
- `IMAGE_REL_AMD64_ADDR32` (line 570)
- `IMAGE_REL_AMD64_ADDR32NB` (line 571)
- `IMAGE_REL_AMD64_REL32` (line 572)
- `IMAGE_REL_AMD64_REL32_1` (line 573)
- `IMAGE_REL_AMD64_REL32_2` (line 574)
- `IMAGE_REL_AMD64_REL32_3` (line 575)
- `IMAGE_REL_AMD64_REL32_4` (line 576)
- `IMAGE_REL_AMD64_REL32_5` (line 577)
- `IMAGE_REL_AMD64_SECTION` (line 578)
- `IMAGE_REL_AMD64_SECREL` (line 579)
- `IMAGE_REL_AMD64_SECREL7` (line 580)
- `IMAGE_REL_AMD64_TOKEN` (line 581)
- `IMAGE_REL_AMD64_SREL32` (line 582)
- `IMAGE_REL_AMD64_PAIR` (line 583)
- `IMAGE_REL_AMD64_SSPAN32` (line 584)

#### `aes.c`
**Path:** `aes.c`
**File Doc:** *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h>  define Nb 4    define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*

**Functions:**
- `getSBoxValue` (line 12) `static uint8_t getSBoxValue(uint8_t num)` - *define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*
- `getSBoxInvert` (line 34) `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (line 56) `static uint8_t Td0(int x)`
- `Td1` (line 58) `static uint8_t Td1(int x)`
- `Td2` (line 59) `static uint8_t Td2(int x)`
- `Td3` (line 60) `static uint8_t Td3(int x)`
- `Td4` (line 61) `static uint8_t Td4(int x)`
- `KeyExpansion` (line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - *This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.*
- `AES_init_ctx` (line 238) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - *This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) `static void SubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) `static void ShiftRows(state_t* state)` - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row is not shifted.*
- `xtime` (line 313) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (line 320) `static void MixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)` - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary The compiler seems to be able to vectorize the operation better this way. See https://github.com/kokke/tiny-AES-c/pull/34 if MULTIPLY_AS_A_FUNCTION*
- `InvMixColumns` (line 370) `static void InvMixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please use the references to gain more information.*
- `InvSubBytes` (line 391) `static void InvSubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402) `static void InvShiftRows(state_t* state)`
- `Cipher` (line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)` - *Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)` - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)  /* Public functions:  if defined(ECB) && (ECB == 1)*
- `AES_ECB_decrypt` (line 495) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (line 510) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (line 535) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(CTR) && (CTR == 1) /* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key*

**Macros:**
- `Nb` (line 4)
- `KEYLEN_256` (line 6)
- `RKLENGTH` (line 10)
- `BLOCKLEN` (line 11)
- `Nb` (line 67)
- `Nk` (line 70)
- `Nr` (line 71)
- `Nk` (line 73)
- `Nr` (line 74)
- `Nk` (line 76)
- `Nr` (line 77)
- `MULTIPLY_AS_A_FUNCTION` (line 84)
- `getSBoxValue` (line 163)
- `Multiply` (line 349)
- `getSBoxInvert` (line 365)

#### `beacon.c`
**Path:** `beacon.c`

**Functions:**
- `ExceptionFilter` (line 253) `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)`
- `get_shell_cmd` (line 334) `const char* get_shell_cmd()`
- `__declspec` (line 416) `__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)` - *=== Beacon API: implementaciones exportables para BOFs ===*
- `__declspec` (line 422) `__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)`
- `__declspec` (line 430) `__declspec(dllexport) int BeaconDataInt(datap * parser)`
- `__declspec` (line 435) `__declspec(dllexport) short BeaconDataShort(datap * parser)`
- `__declspec` (line 440) `__declspec(dllexport) int BeaconDataLength(datap * parser)`
- `__declspec` (line 445) `__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)`
- `__declspec` (line 455) `__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)`
- `__declspec` (line 503) `__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)`
- `MapDllNameToModule` (line 521) `HMODULE MapDllNameToModule(char* dllName)` - *=== MAP DLL NAME TO REAL DLL ===*
- `GetSyscallNumber` (line 548) `DWORD GetSyscallNumber(PVOID func_addr)`
- `HellsGate` (line 560) `DWORD HellsGate(DWORD ssn)`
- `__attribute__` (line 565) `__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DW...`
- `GetProcessIdByName` (line 581) `DWORD GetProcessIdByName(const char* processName)`
- `ExecuteTLSCallbacks` (line 600) `void ExecuteTLSCallbacks(PVOID moduleBase)` - *=== EJECUTAR TLS CALLBACKS ===*
- `MapModuleToMemory` (line 617) `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)` - *=== Carga un módulo en memoria ===*
- `ExecuteModule` (line 706) `BOOL ExecuteModule(PVOID moduleBase)` - *=== Ejecuta el módulo (DllMain o EntryPoint) ===*
- `LoadModuleFromURL` (line 751) `BOOL LoadModuleFromURL(const char* url)` - *=== Carga y ejecuta un módulo desde URL ===*
- `xor_string` (line 915) `void xor_string(char* data, size_t len, char key)` - *=== XOR ===*
- `anti_analysis` (line 922) `BOOL anti_analysis()` - *=== ANTI-ANALYSIS ===*
- `load_lazyconf` (line 945) `BOOL load_lazyconf()`
- `GetNtdllBase` (line 1183) `HMODULE GetNtdllBase()`
- `isVMByMAC` (line 1231) `BOOL isVMByMAC()`
- `extract_shellcode` (line 1303) `int extract_shellcode(const char* input, size_t len, unsigned char** out)` - *=== EXTRAER SHELLCODE ===*
- `hex_char_to_byte` (line 1334) `BYTE hex_char_to_byte(char c)` - *Función para convertir hex a bytes*
- `hex_to_bytes` (line 1340) `void hex_to_bytes(const char* hex, BYTE* output, size_t len)`
- `executeLoader` (line 1348) `void executeLoader(void *arg)` - *=== executeLoader ===*
- `ReverseShell` (line 1404) `void __cdecl ReverseShell(void* arg)` - *======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================*
- `ReadFromProcess` (line 1513) `DWORD WINAPI ReadFromProcess(LPVOID lpParam)` - *=== Hilo para leer salida del proceso (como en el ejemplo que funciona) ===*
- `GetJitteredSleep` (line 1586) `DWORD GetJitteredSleep(DWORD base_ms)`
- `GetUsefulSoftware` (line 1591) `char* GetUsefulSoftware()`
- `base64_encode` (line 1626) `char* base64_encode(const unsigned char* data, size_t inputLen)`
- `base64_decode` (line 1662) `char* base64_decode(const char* input, size_t* out_len)`
- `discoverLocalHosts` (line 1695) `void discoverLocalHosts()`
- `initProxy` (line 1752) `void initProxy()` - *startProxy.c*
- `relay_thread` (line 1763) `void WINAPI relay_thread(void* param)` - *Función para reenviar datos entre sockets*
- `proxy_thread` (line 1784) `void WINAPI proxy_thread(void* param)` - *Tu función proxy_thread usando tus estructuras exactas*
- `proxy_accept_thread` (line 1855) `void WINAPI proxy_accept_thread(void* param)` - *Thread para aceptar conexiones*
- `startProxy` (line 1922) `BOOL startProxy(const char* listenAddr, const char* targetAddr)`
- `stopProxy` (line 2009) `BOOL stopProxy(const char* listenAddr)`
- `cleanupProxy` (line 2061) `void cleanupProxy()`
- `compressDirectory` (line 2094) `BOOL compressDirectory(const char* dirPath)` - *Función simplificada para compresión de directorios*
- `getNetworkConfig` (line 2104) `char* getNetworkConfig()` - *Para netconfig*
- `UploadFileToC2` (line 2107) `BOOL UploadFileToC2(const char* url, const char* filePath)`
- `handleUpload` (line 2280) `BOOL handleUpload(const char* command)` - *=== handleUpload: envía del beacon al C2 ===*
- `FileExistsA` (line 2301) `BOOL FileExistsA(const char* filePath)` - *Función para verificar si un archivo existe*
- `selfDestruct` (line 2306) `void selfDestruct()` - *selfdestruct.c*
- `stristr` (line 2361) `char* stristr(const char* str, const char* pattern)`
- `isSensitiveFile` (line 2378) `int isSensitiveFile(const char* filename)`
- `searchCredentials` (line 2424) `char* searchCredentials(const char* basePath)`
- `UTF8ToWide` (line 2551) `WCHAR* UTF8ToWide(const char* utf8)` - *Convierte UTF-8 a wide string*
- `obfuscateFileTimestamp` (line 2562) `BOOL obfuscateFileTimestamp(const char* filepath)` - *Ofusca los timestamps de un archivo*
- `obfuscateFileTimestamps` (line 2592) `void obfuscateFileTimestamps(const char* basePath, int depth)` - *Recorre directorios buscando archivos sensibles*
- `simulateLegitimateTraffic` (line 2656) `void simulateLegitimateTraffic(void* param)` - *traffic.c*
- `restartClient` (line 2734) `void restartClient()`
- `checkDebuggers` (line 2776) `BOOL checkDebuggers()`
- `MapPEToMemory` (line 2837) `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)`
- `downloadAndExecute` (line 2860) `BOOL downloadAndExecute(const char* url, const char* targetProcess)`
- `DecryptPacket` (line 2910) `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)`
- `GetIPs` (line 3006) `char* GetIPs()`
- `GetHostname` (line 3039) `char* GetHostname()`
- `GetUsername` (line 3056) `char* GetUsername()`
- `patchAMSI` (line 3072) `BOOL patchAMSI(void)`
- `get_nt_headers` (line 3092) `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)` - *==================================================================== PE HELPERS (usando winnt.h) ====================================================================*
- `is_64bit` (line 3100) `BOOL is_64bit(BYTE* buffer)`
- `get_image_size` (line 3106) `DWORD get_image_size(BYTE* buffer)`
- `get_entry_point_rva` (line 3112) `DWORD get_entry_point_rva(BYTE* buffer)`
- `pe_buffer_to_virtual_image` (line 3117) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- `create_suspended_process` (line 3148) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` - *==================================================================== PROCESS MANIPULATION ====================================================================*
- `get_remote_image_base` (line 3154) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- `update_remote_entry_point` (line 3249) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)`
- `overWrite` (line 3277) `void overWrite(const char* targetPath, const char* payloadPath)` - *==================================================================== MAIN FUNCTION: overWrite ====================================================================*
- `cleanSystemLogs` (line 3384) `void cleanSystemLogs()` - *Limpia el historial de comandos de la consola actual*
- `ensurePersistence` (line 3421) `BOOL ensurePersistence()` - *ensurePersistence.c*
- `isSandboxEnvironment` (line 3482) `BOOL isSandboxEnvironment()` - *isSandboxEnvironment.c*
- `tryPrivilegeEscalation` (line 3551) `void tryPrivilegeEscalation()`
- `executeUACBypass` (line 3556) `BOOL executeUACBypass(const char* payloadPath)`
- `scanPort` (line 3610) `void scanPort(void* arg)`
- `PortScanner` (line 3661) `void PortScanner(char* targetIP, int* ports, int numPorts)` - *PortScanner.c*
- `PortScannerWrapper` (line 3705) `void PortScannerWrapper(void* arg)`
- `EarlyBirdInject` (line 3729) `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)` - *=== INYECCIÓN EARLY BIRD + SYSCALL ===*
- `init_aes_context` (line 3898) `PacketEncryptionContext* init_aes_context(const char* key_hex)`
- `retry_http_request` (line 3918) `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)` - *retry_http_request.c*
- `exec_cmd` (line 4172) `char* exec_cmd(const char* cmd)` - *exec_cmd.c*
- `GetC2Command` (line 4200) `char* GetC2Command(const char* host, const char* path)` - *c2.c (reemplaza la función actual)*
- `DownloadToBuffer` (line 4346) `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)`
- `DownloadFromURL` (line 4422) `BOOL DownloadFromURL(const char* url, const char* filepath)`
- `encrypt_data` (line 4452) `char* encrypt_data(const char* data)`
- `isValidUUID` (line 4511) `BOOL isValidUUID(const char* uuid)`
- `deleteFilesDelay` (line 4536) `void deleteFilesDelay(void* arg)`
- `executeCommand` (line 4550) `void executeCommand(void* cmdPtr)`
- `handleAtomic` (line 4559) `void handleAtomic(char* command)`
- `handleDownload` (line 4683) `BOOL handleDownload(const char* command)` - *=== handleDownload: descarga del C2 al beacon ===*
- `SerializeBeaconString` (line 4702) `void SerializeBeaconString(char* buffer, int* offset, const char* str)`
- `BeaconDataSerializeString` (line 4711) `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)`
- `go` (line 4719) `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)`
- `handleAdversary` (line 4738) `void handleAdversary(char* command)` - *Función principal de manejo de comandos*
- `main` (line 5233) `int main()` - *main.c*

**Macros:**
- `PSAPI_VERSION` (line 19)
- `WIN32_LEAN_AND_MEAN` (line 21)
- `XOR_KEY` (line 71)
- `DEBUG` (line 72)
- `TIMEOUT` (line 73)
- `MAX_RESPONSE_SIZE` (line 74)
- `C2_URL` (line 75)
- `MALEABLE` (line 76)
- `CLIENT_ID` (line 77)
- `SLEEP_BASE` (line 78)
- `MIN_JITTER` (line 79)
- `MAX_JITTER` (line 80)
- `MAX_RETRIES` (line 81)
- `C2_HOST` (line 82)
- `LC2_HOST` (line 83)
- `C2_USER` (line 84)
- `C2_PASS` (line 85)
- `C2_PORT` (line 86)
- `CONFIG_PATH` (line 87)
- `C2_PATH` (line 88)
- `LC2_PATH` (line 89)
- `min` (line 91)
- `SECURITY_FLAG_IGNORE_REVOCATION` (line 94)
- `INVALID_SOCKET` (line 97)
- `USER_AGENT` (line 99)
- `USER_AGENT_A` (line 100)
- `IMAGE_DOS_SIGNATURE` (line 101)
- `IMAGE_NT_SIGNATURE` (line 102)
- `IMAGE_NT_OPTIONAL_HDR32_MAGIC` (line 103)
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC` (line 104)
- `SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE` (line 106)
- `SECURITY_FLAG_IGNORE_INVALID_POLICY` (line 109)
- `_SECURITY_PACKAGE_DEFINITION_` (line 112)
- `_PROCESS_BASIC_INFORMATION_` (line 115)
- `_SP_LSA_MODE_INITIALIZE_DEFINED_` (line 117)
- `ProcessBasicInformation` (line 123)
- `CHECK_ERROR` (line 125)
- `NUM_USER_AGENTS` (line 231)
- `NUM_URLS` (line 240)
- `NUM_UAS` (line 247)
- `NT_SUCCESS` (line 300)

**Structs:**
- `_PROCESS_BASIC_INFORMATION` (line 129)
- `_UNICODE_STRING` (line 262) - *=== ESTRUCTURAS NECESARIAS (MinGW-safe) ===*
- `_LDR_DATA_TABLE_ENTRY` (line 268)
- `_PEB_LDR_DATA` (line 278)
- `_PEB` (line 287)

#### `calc.c`
**Path:** `bof/calc/calc.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `etw.c`
**Path:** `bof/etw/etw.c`

**Functions:**
- `go` (line 26) `void go(char *a,int l)`

#### `Test.c`
**Path:** `bof/test/Test.c`
**File Doc:** *include "beacon.h"*

**Functions:**
- `go` (line 2) `void go(char *args, int alen)` - *include "beacon.h"*

#### `amsibypass.c`
**Path:** `bof/test/amsibypass.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cmdwhoami.c`
**Path:** `bof/test/cmdwhoami.c`

**Functions:**
- `go` (line 42) `void go(char *args, int alen)`

#### `disablelog.c`
**Path:** `bof/test/disablelog.c`

**Functions:**
- `my_wcscmp` (line 36) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)` - *ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif*
- `go` (line 68) `void go(char *args, int alen)`

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 20)
- `NT_SUCCESS` (line 34)

#### `getenv.c`
**Path:** `bof/test/getenv.c`

**Functions:**
- `go` (line 24) `void go(char *args, int alen)`

#### `loadvnc.c`
**Path:** `bof/test/loadvnc.c`

**Functions:**
- `execute_cmd_hidden` (line 51) `void execute_cmd_hidden(char* cmd)` - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 81) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

**Macros:**
- `TH32CS_SNAPPROCESS` (line 33)

**Structs:**
- `_PROCESSENTRY32` (line 35)

#### `make_table.c`
**Path:** `bof/test/make_table.c`

**Functions:**
- `Copyright` (line 16) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
- `main` (line 33) `void main()`

#### `persist.c`
**Path:** `bof/test/persist.c`

**Functions:**
- `go` (line 26) `void go(char *args, int alen)`

#### `persistsvc.c`
**Path:** `bof/test/persistsvc.c`

**Functions:**
- `my_memcpy` (line 33) `static void* my_memcpy(void* dst, const void* src, size_t len)` - *================================ FUNCIONES AUXILIARES ================================*
- `my_strlen` (line 39) `static int my_strlen(const char* str)`
- `my_strcat` (line 46) `static char* my_strcat(char* dest, const char* src)`
- `my_strcmp` (line 54) `static int my_strcmp(const char* s1, const char* s2)`
- `ServiceHandler` (line 82) `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...` - *================================ MANEJADOR DE CONTROL DEL SERVICIO ================================*
- `ServiceMain` (line 116) `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)` - *================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================*
- `go` (line 251) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL DEL BOF ================================*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)
- `RESOLVE_API` (line 65)
- `cleanup` (line 131)
- `cleanup` (line 183)

#### `scan_shellcode.c`
**Path:** `bof/test/scan_shellcode.c`

**Functions:**
- `go` (line 84) `void go(char *args, int alen)`

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)

#### `shellcode.c`
**Path:** `bof/test/shellcode.c`

**Functions:**
- `go` (line 25) `void go(char *args, int alen)`

#### `sock5.c`
**Path:** `bof/test/sock5.c`
**File Doc:** *define WIN32_LEAN_AND_MEAN include <windows.h> include "beacon.h"  ===== DECLARACIONES QUE FALTABAN =====*

**Functions:**
- `my_FD_ISSET` (line 107) `static int my_FD_ISSET(SOCKET s, fd_set *set)` - *typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typedef int       (WINAPI *CONNECT)(SOCKET, const struct sockaddr*, int); typedef int       (WINAPI *RECV)(SOCKET, char*, int, int); typedef int       (WINAPI *SEND)(SOCKET, const char*, int, int); typedef int       (WINAPI *SELECT)(int, fd_set*, fd_set*, fd_set*, const struct timeval*); typedef int       (WINAPI *CLOSESOCKET)(SOCKET); typedef int       (WINAPI *WSACLEANUP)(void); typedef int       (WINAPI *WSAGETLASTERROR)(void); typedef ULONG     (WINAPI *HTONL)(ULONG); typedef USHORT    (WINAPI *HTONS)(USHORT); typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES =====*
- `HandleSocks5Connection` (line 118) `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...` - *typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if (!set) return 0; for (u_int i = 0; i < set->fd_count; ++i) if (set->fd_array[i] == s) return 1; return 0; } /* ===== VARIABLE GLOBAL ===== static HANDLE g_hShutdownEvent = NULL; /* ===== MANEJADOR SOCKS5 (solo después de handshake confirmado) =====*
- `ProxyThread` (line 261) `DWORD WINAPI ProxyThread(LPVOID _)` - *break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n"); break; } BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Reenviados %d bytes destino→cliente\n", n); } } pCloseSocket(tgt); BeaconPrintf(CALLBACK_OUTPUT, "[SOCKS5] Túnel cerrado\n"); } /* ===== HILO PRINCIPAL DEL PROXY =====*
- `go` (line 358) `void go(char *args, int alen)` - *cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HANDLE))__imp_CloseHandle)(g_hShutdownEvent); g_hShutdownEvent = NULL; } return 0; } /* ===== ENTRY POINT BOF =====*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 1)
- `INVALID_SOCKET` (line 7)
- `SOCKET_ERROR` (line 8)
- `AF_INET` (line 9)
- `SOCK_STREAM` (line 10)
- `IPPROTO_TCP` (line 11)
- `INADDR_ANY` (line 12)
- `INADDR_LOOPBACK` (line 13)
- `FD_SETSIZE` (line 36)
- `FD_CLR` (line 38)
- `FD_SET` (line 39)
- `FD_ZERO` (line 40)
- `FD_ISSET` (line 41)
- `h_addr` (line 64)
- `SOCKS5_LISTEN_PORT` (line 75)
- `SOCKS5_CONTROL_PORT` (line 76)
- `MAX_PENDING_CONNECTIONS` (line 77)
- `BUFFER_SIZE` (line 78)

**Structs:**
- `WSAData` (line 16) - *pragma pack(push,1)*
- `fd_set` (line 27)
- `timeval` (line 32)
- `in_addr` (line 47)
- `sockaddr_in` (line 49)
- `sockaddr` (line 56)
- `hostent` (line 58)

#### `uacbypass.c`
**Path:** `bof/test/uacbypass.c`

**Functions:**
- `execute_hidden_cmd` (line 33) `void execute_hidden_cmd(char* cmd)` - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 61) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `upload.c`
**Path:** `bof/test/upload.c`
**File Doc:** *define WIN32_LEAN_AND_MEAN include <windows.h> include "beacon.h"  ================================ IMPORTS DIRECTOS ================================*

**Functions:**
- `my_strlen` (line 53) `static int my_strlen(const char *s)` - *================================ FUNCIONES AUXILIARES ================================*
- `my_memcpy` (line 58) `static void* my_memcpy(void* dst, const void* src, size_t len)`
- `my_memset` (line 65) `static void* my_memset(void* dst, int val, size_t len)`
- `my_contains_dotdot` (line 71) `static BOOL my_contains_dotdot(const char* path)`
- `my_strchr` (line 80) `static char* my_strchr(const char *s, int c)`
- `xtime` (line 93) `static uint8_t xtime(uint8_t x)` - *================================ AES (sin datos globales) ================================*
- `AddRoundKey` (line 98) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- `SubBytes` (line 105) `static void SubBytes(state_t* state, const uint8_t* sbox)`
- `ShiftRows` (line 112) `static void ShiftRows(state_t* state)`
- `MixColumns` (line 120) `static void MixColumns(state_t* state)`
- `Cipher` (line 132) `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
- `KeyExpansion` (line 145) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
- `AES_init_ctx` (line 173) `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
- `AES_CFB_encrypt_buffer` (line 177) `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
- `my_base64_encode` (line 205) `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...` - *================================ BASE64 ================================*
- `ParseUploadArgs` (line 230) `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
- `go` (line 273) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 1)
- `PROV_RSA_AES` (line 20)
- `CRYPT_VERIFYCONTEXT` (line 21)
- `AES_BLOCKLEN` (line 22)
- `AES256_KEYLEN` (line 24)
- `Nr` (line 25)
- `Nk` (line 26)
- `Nb` (line 27)
- `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (line 28)
- `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` (line 30)
- `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` (line 31)
- `WINHTTP_OPTION_SECURITY_FLAGS` (line 32)
- `WINHTTP_ACCESS_TYPE_NO_PROXY` (line 35)
- `WINHTTP_NO_PROXY_NAME` (line 39)
- `WINHTTP_NO_PROXY_BYPASS` (line 43)
- `NEXT_TOKEN` (line 244)

#### `vncrelay.c`
**Path:** `bof/test/vncrelay.c`

**Functions:**
- `my_FD_ISSET` (line 62) `int my_FD_ISSET(SOCKET sock, fd_set *set)` - *================================ FD_ISSET MANUAL ================================*
- `relay_traffic` (line 75) `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)` - *================================ RELAY TRAFFIC ================================*
- `go` (line 132) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================*

#### `winver.c`
**Path:** `bof/test/winver.c`

**Functions:**
- `go` (line 24) `void go(char *args, int alen)`

#### `whoami.c`
**Path:** `bof/whoami/whoami.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (line 99) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 109) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 124) `CJSON_PUBLIC(const char*) cJSON_Version(void)` - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble; } /* This is a safeguard to prevent copy-pasters from using incompatible C and header files if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) error cJSON.h and cJSON.c have different versions. Make sure that both have the same. endif*
- `case_insensitive_strcmp` (line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR != 7) || (CJSON_VERSION_PATCH != 18) #error cJSON.h and cJSON.c have different versions. Make sure that both have the same. #endif CJSON_PUBLIC(const char*) cJSON_Version(void) { static char version[15]; sprintf(version, "%i.%i.%i", CJSON_VERSION_MAJOR, CJSON_VERSION_MINOR, CJSON_VERSION_PATCH); return version; } /* Case insensitive string comparison, doesn't consider two NULL pointers equal though*
- `internal_malloc` (line 166) `static void * CJSON_CDECL internal_malloc(size_t size)` - *} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *deallocate)(void *pointer); void *(CJSON_CDECL *reallocate)(void *pointer, size_t size); } internal_hooks; #if defined(_MSC_VER) /* work around MSVC error C2322: '...' address of dllimport '...' is not static*
- `internal_free` (line 170) `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (line 188) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (line 209) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (line 242) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.reallocate = NULL; if ((global_hooks.allocate == malloc) && (global_hooks.deallocate == free)) { global_hooks.reallocate = realloc; } } /* Internal constructor.*
- `get_decimal_point` (line 281) `static unsigned char get_decimal_point(void)` - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->string = NULL; } global_hooks.deallocate(item); item = next; } } /* get the decimal point character of the current locale*
- `parse_number` (line 309) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* check if the given size is left to read in a given parse buffer (starting with 1) #define can_read(buffer, size) ((buffer != NULL) && (((buffer)->offset + size) <= (buffer)->length)) /* check if the buffer can be accessed at the given index (starting with 0) #define can_access_at_index(buffer, index) ((buffer != NULL) && (((buffer)->offset + index) < (buffer)->length)) #define cannot_access_at_index(buffer, index) (!can_access_at_index(buffer, index)) /* get a pointer to the buffer at the position #define buffer_at_offset(buffer) ((buffer)->content + (buffer)->offset) /* Parse the input text to generate a number, and populate the result into item.*
- `ensure` (line 494) `static unsigned char* ensure(printbuffer * const p, size_t needed)` - *} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool noalloc; cJSON_bool format; /* is this print a formatted print internal_hooks hooks; } printbuffer; /* realloc printbuffer if necessary to have at least "needed" bytes more*
- `update_offset` (line 579) `static void update_offset(printbuffer * const buffer)` - *p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = newbuffer; return newbuffer + p->offset; } /* calculate the new length of the string in a printbuffer and update the offset*
- `compare_double` (line 592) `static cJSON_bool compare_double(double a, double b)` - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsigned char *buffer_pointer = NULL; if ((buffer == NULL) || (buffer->buffer == NULL)) { return; } buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables*
- `print_number` (line 599) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` - *} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-point variables static cJSON_bool compare_double(double a, double b) { double maxVal = fabs(a) > fabs(b) ? fabs(a) : fabs(b); return (fabs(a - b) <= maxVal * DBL_EPSILON); } /* Render the number nicely from the given item into a string.*
- `parse_hex4` (line 669) `static unsigned parse_hex4(const unsigned char * const input)` - *output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->offset += (size_t)length; return true; } /* parse 4 digit hexadecimal number*
- `utf16_literal_to_utf8` (line 706) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Parse the input text into an unescaped cinput, and populate item.*
- `print_string_ptr` (line 957) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` - *{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffer->content); } return false; } /* Render the cstring provided to an escaped version that can be printed.*
- `print_string` (line 1079) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_length + 1] = '"'; output[output_length + 2] = '\0'; return true; } /* Invoke print_string_ptr (which is useful) on an item.*
- `buffer_skip_whitespace` (line 1093) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } /* Predeclare these prototypes. static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer); static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer); static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer); /* Utility to jump whitespace and cr/lf*
- `skip_utf8_bom` (line 1119) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer->offset--; } return buffer; } /* skip the UTF-8 BOM (byte order mark) if it is at the beginning of a buffer*
- `CJSON_PUBLIC` (line 1133) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (line 1235) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (line 1242) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (line 1320) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (line 1351) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` - *return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_hooks; return print_value(item, &p); } /* Parser core - when encountering text, process appropriately.*
- `print_value` (line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '{')) { return parse_object(item, input_buffer); } return false; } /* Render a value to text.*
- `parse_array` (line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` - *return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, output_buffer); default: return false; } } /* Build an array from input text.*
- `print_array` (line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text*
- `parse_object` (line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buffer->depth--; return true; } /* Build an object from the text.*
- `print_object` (line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.*
- `get_array_item` (line 1915) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (line 1934) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (line 1944) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (line 1976) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (line 1981) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (line 1986) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (line 1993) `static void suffix_object(cJSON *prev, cJSON *item)` - *return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) { return get_object_item(object, string, true); } CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling.*
- `create_reference` (line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Utility for array list handling. static void suffix_object(cJSON *prev, cJSON *item) { prev->next = item; item->prev = prev; } /* Utility for handling references.*
- `add_item_to_array` (line 2020) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (line 2066) `static void* cast_away_const(const void* string)` - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) #pragma GCC diagnostic push #endif #ifdef __GNUC__ #pragma GCC diagnostic ignored "-Wcast-qual" #endif /* helper function to cast away const*
- `add_item_to_object` (line 2073) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (line 2122) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (line 2132) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (line 2142) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2154) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2166) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2178) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (line 2190) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2202) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2214) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (line 2226) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2238) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2250) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (line 2286) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2296) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2301) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2308) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2315) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2320) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2362) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (line 2412) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (line 2422) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (line 2445) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (line 2450) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (line 2467) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (line 2478) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (line 2489) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (line 2500) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (line 2525) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (line 2542) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (line 2554) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2566) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2578) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (line 2595) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (line 2606) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (line 2658) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (line 2698) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (line 2738) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (line 2785) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (line 2872) `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (line 2885) `static void skip_multiline_comment(char **input)`
- `minify_string` (line 2899) `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (line 2921) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (line 2971) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2981) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2991) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3001) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3011) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3021) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3031) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3041) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3051) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3061) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3071) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (line 3157) `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (line 3173) `cJSON_ArrayForEach(b_element, b)` - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (line 3198) `CJSON_PUBLIC(void) cJSON_free(void *object)`

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28)
- `true` (line 65)
- `false` (line 70)
- `isinf` (line 74)
- `isnan` (line 77)
- `NAN` (line 82)
- `NAN` (line 84)
- `internal_malloc` (line 179)
- `internal_free` (line 180)
- `internal_realloc` (line 181)
- `static_strlen` (line 185)
- `can_read` (line 301)
- `can_access_at_index` (line 303)
- `cannot_access_at_index` (line 304)
- `buffer_at_offset` (line 306)
- `cjson_min` (line 1240)

**Structs:**
- `internal_hooks` (line 157)

### H (8 files)

#### `COFFLoader.h`
**Path:** `COFFLoader.h`

**Imported by:** `beacon.c`

**Macros:**
- `COFFLOADER_H` (line 21)

#### `aes.h`
**Path:** `aes.h`
**File Doc:** *ifndef _AES_H_ define _AES_H_  include <stdint.h> include <stddef.h>  #define the macros below to 1/0 to enable/disable the mode of operation. ifndef CBC define CBC 1 endif ifndef ECB define ECB 1 endif ifndef CTR define CTR 1 endif  define AES256 1  // ✅ Clave de 256 bits  define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only  if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExpSize 240 elif defined(AES192) && (AES192 == 1) define AES_KEYLEN 24 define AES_keyExpSize 208 else define AES_KEYLEN 16   // Key length in bytes define AES_keyExpSize 176*

**Imported by:** `aes.c`, `beacon.c`

**Macros:**
- `_AES_H_` (line 2)
- `CBC` (line 9)
- `ECB` (line 12)
- `CTR` (line 15)
- `AES256` (line 17)
- `AES_BLOCKLEN` (line 19)
- `AES_KEYLEN` (line 23)
- `AES_keyExpSize` (line 24)
- `AES_KEYLEN` (line 26)
- `AES_keyExpSize` (line 27)
- `AES_KEYLEN` (line 29)
- `AES_keyExpSize` (line 30)

**Structs:**
- `AES_ctx` (line 33)

#### `beacon.h`
**Path:** `beacon.h`

**Imported by:** `COFFLoader3.c`, `Test.c`, `beacon.c`, `calc.c`, `etw.c`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/calc/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/etw/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/test/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/whoami/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `cJSON.h`
**Path:** `cJSON.h`

**Imported by:** `beacon.c`, `cJSON.c`

**Macros:**
- `cJSON__h` (line 24)
- `__WINDOWS__` (line 32)
- `CJSON_CDECL` (line 43)
- `CJSON_STDCALL` (line 45)
- `CJSON_EXPORT_SYMBOLS` (line 49)
- `CJSON_PUBLIC` (line 53)
- `CJSON_PUBLIC` (line 55)
- `CJSON_PUBLIC` (line 57)
- `CJSON_CDECL` (line 60)
- `CJSON_STDCALL` (line 61)
- `CJSON_PUBLIC` (line 64)
- `CJSON_PUBLIC` (line 66)
- `CJSON_VERSION_MAJOR` (line 71)
- `CJSON_VERSION_MINOR` (line 72)
- `CJSON_VERSION_PATCH` (line 73)
- `cJSON_Invalid` (line 78)
- `cJSON_False` (line 79)
- `cJSON_True` (line 80)
- `cJSON_NULL` (line 81)
- `cJSON_Number` (line 82)
- `cJSON_String` (line 83)
- `cJSON_Array` (line 84)
- `cJSON_Object` (line 85)
- `cJSON_Raw` (line 86)
- `cJSON_IsReference` (line 87)
- `cJSON_StringIsConst` (line 89)
- `CJSON_NESTING_LIMIT` (line 126)
- `CJSON_CIRCULAR_LIMIT` (line 132)
- `cJSON_SetIntValue` (line 270)
- `cJSON_SetNumberValue` (line 273)
- `cJSON_SetBoolValue` (line 278)
- `cJSON_ArrayForEach` (line 285)

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1 << 6) #define cJSON_Raw    (1 << 7) /* raw json #define cJSON_IsReference 256 #define cJSON_StringIsConst 512 /* The cJSON structure:*
- `cJSON_Hooks` (line 114)

### PY (3 files)

#### `app.py`
**Path:** `app.py`
**File Doc:** *_*_ coding: utf8 _*_   This file is part of Black Basalt Beacon.  Black Basalt Beacon is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.  Black Basalt Beacon is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.  You should have received a copy of the GNU General Public License along with Black Basalt Beacon.  If not, see <https://www.gnu.org/licenses/>.  Copyright (c) LazyOwn RedTeam 2025. All rights reserved.*

*No symbols extracted*

#### `tel.py`
**Path:** `bof/test/tel.py`

**Functions:**
- `get_machine_id` (line 8) `def get_machine_id()`
- `get_version` (line 20) `def get_version()`
- `to_numbers` (line 31) `def to_numbers(hex_str)` - *Simula la función toNumbers de JavaScript*
- `to_hex` (line 35) `def to_hex(byte_list)` - *Simula la función toHex de JavaScript*
- `decrypt_cookie` (line 39) `def decrypt_cookie(encrypted, key, iv)` - *Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))*
- `main` (line 45) `def main()` - *Sistema de telemetría de uso por instalación no invasiva.*

#### `generate_hashs.py`
**Path:** `generate_hashs.py`

**Functions:**
- `djb2` (line 23) `def djb2(s)`
- `generate_coff_loader` (line 223) `def generate_coff_loader()`
- `generate_bof_test` (line 491) `def generate_bof_test()`
- `main` (line 553) `def main()`

### SH (7 files)

#### `gen_beacon.sh`
**Path:** `gen_beacon.sh`
**File Doc:** *=== beacon-GEN v1.2 ===*

**Functions:**
- `show_help` (line 34) - *=== FUNCIONES ===*
- `xor_string` (line 138) - *=== XOR STRING TO BYTES ===*
- `crc32` (line 5916)

#### `gen_dll.sh`
**Path:** `gen_dll.sh`
**File Doc:** *1. Generar DLL*

*No symbols extracted*

#### `gen_dll_rev.sh`
**Path:** `gen_dll_rev.sh`
**File Doc:** *=== CONFIGURACIÓN POR DEFECTO ===*

**Functions:**
- `usage` (line 12) - *=== USO ===*

#### `gen_dll_ss.sh`
**Path:** `gen_dll_ss.sh`
**File Doc:** *=== CONFIGURACIÓN POR DEFECTO ===*

**Functions:**
- `usage` (line 10) - *=== USO ===*

#### `gen_key.sh`
**Path:** `gen_key.sh`
**File Doc:** *=== CONFIGURACIÓN POR DEFECTO ===*

**Functions:**
- `usage` (line 10) - *=== USO ===*

#### `gen_module.sh`
**Path:** `gen_module.sh`
**File Doc:** *=== gen_cmd_dll.sh v1.0 === Genera DLL y shellcode ofuscado para ejecutar un comando Uso: ./gen_cmd_dll.sh --cmd "powershell..." [--key 0x33] [--output payload]*

**Functions:**
- `show_help` (line 18) - *=== FUNCIONES ===*
- `xor_obfuscate` (line 35) - *Función para ofuscar binario con XOR y convertir a \x..*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*
