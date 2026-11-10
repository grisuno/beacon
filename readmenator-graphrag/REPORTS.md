# GraphRAG Community Reports

Entities: 1009 | Relationships: 1447 | Communities: 3 | Themes: 2 | Text units: 877

Query with `readmenator . ask "<question>"` (local: BM25 + Personalized PageRank; global: map-reduce over these reports) or the MCP tool `readmenator.graphrag`.

## Project overview (`root`, root, rating 7.0)

41 files in 3 communities and 2 themes. Highest-impact communities: bof/test (7.0), unassigned files (1.9), root (1.4). God nodes: beacon.h, bof/test/beacon.h, COFFLoader3.c, beacon.c, cJSON.c.

- [bof/test] rating 7.0: `bof/test/beacon.h` ranks 1 by PageRank, 15 importers, 4 symbols.
- [unassigned files] rating 1.9: `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: This file is part of Black Basalt Beacon.
- [root] rating 1.4: `aes.h` ranks 1 by PageRank, 2 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- Key entities: file:COFFLoader3.c, file:bof/test/sock5.c, file:bof/test/tel.py, file:generate_hashs.py, file:beacon.c, file:cJSON.c
- Children: t0, t1
- Root rating = highest community rating.

## bof/test + root (`t0`, theme, rating 7.0)

Theme of 2 communities and 30 files: bof/test (24 files, rating 7.0); root (6 files, rating 1.4).

- [bof/test] `bof/test/beacon.h` ranks 1 by PageRank, 15 importers, 4 symbols.
- [bof/test] `beacon.h` ranks 2 by PageRank, 2 importers, 4 symbols.
- [root] `aes.h` ranks 1 by PageRank, 2 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- [root] `cJSON.h` ranks 2 by PageRank, 2 importers, 37 symbols: cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1...
- Key entities: file:COFFLoader3.c, file:bof/test/sock5.c, file:beacon.c, file:cJSON.c
- Children: c0, c1
- Theme rating = highest child community rating.

## unassigned files (`t1`, theme, rating 1.9)

Theme of 1 communities and 11 files: unassigned files (11 files, rating 1.9).

- [unassigned files] `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: This file is part of Black Basalt Beacon.
- [unassigned files] `bof/test/make_table.c` ranks 2 by PageRank, 0 importers, 2 symbols.
- Key entities: file:bof/test/tel.py, file:generate_hashs.py
- Children: c2
- Theme rating = highest child community rating.

## bof/test (`c0`, community, rating 7.0)

24 files under bof/test (c 19, h 5), mostly testing. Core file bof/test/beacon.h (PageRank 0.2303, imported by 15 files). Key abstractions: datap, BEACON_H, CALLBACK_OUTPUT, CALLBACK_ERROR, datap, BEACON_H. Used by root (1).

- `bof/test/beacon.h` ranks 1 by PageRank, 15 importers, 4 symbols.
- `beacon.h` ranks 2 by PageRank, 2 importers, 4 symbols.
- `bof/calc/beacon.h` ranks 3 by PageRank, 1 importers, 4 symbols.
- Hotspot `COFFLoader3.c`: 258 symbols, 7 connections (score 0.54).
- Hotspot `beacon.h`: 4 symbols, 23 connections (score 0.45).
- Surprising bridge: aes.c <-> beacon.h (5 hops across communities).
- Key entities: file:COFFLoader3.c, file:bof/test/sock5.c, file:bof/test/upload.c, file:bof/test/beacon.h, file:bof/test/persistsvc.c, file:bof/test/disablelog.c, file:bof/test/scan_shellcode.c, file:bof/test/vncrelay.c
- Rating 7.0/10 = 7 x PageRank share 1.00 + 3 x risk 0.00. Internal imports: 19.

## unassigned files (`c2`, community, rating 1.9)

11 files under root (sh 7, py 3, c 1), mostly utility. Core file app.py (PageRank 0.0168, imported by 0 files): This file is part of Black Basalt Beacon. Key abstractions: Copyright, main, get_machine_id, get_version, to_numbers, to_hex.

- `app.py` ranks 1 by PageRank, 0 importers, 0 symbols: This file is part of Black Basalt Beacon.
- `bof/test/make_table.c` ranks 2 by PageRank, 0 importers, 2 symbols.
- `bof/test/tel.py` ranks 3 by PageRank, 0 importers, 6 symbols: to_numbers: Simula la función toNumbers de JavaScript
- Hotspot `bof/test/tel.py`: 6 symbols, 6 connections (score 0.13).
- Hotspot `generate_hashs.py`: 4 symbols, 6 connections (score 0.12).
- Taint: 1 paths reach this group via requests.
- Dataflow: 6 INFERRED issues (first: DEAD_STORE in xor_string).
- Key entities: file:bof/test/tel.py, file:generate_hashs.py, file:gen_beacon.sh, file:gen_module.sh, sym:bof/test/tel.py::main@45, file:bof/test/make_table.c, sym:generate_hashs.py::main@553, file:gen_dll_rev.sh
- Rating 1.9/10 = 7 x PageRank share 0.27 + 3 x risk 0.00. Internal imports: 0.

## root (`c1`, community, rating 1.4)

6 files under root (c 3, h 3), mostly utility. Core file aes.h (PageRank 0.0345, imported by 2 files): #define the macros below to 1/0 to enable/disable the mode of operation. Key abstractions: AES_ctx, CBC, ECB, CTR, AES256, AES_BLOCKLEN. Depends on bof/test (1).

- `aes.h` ranks 1 by PageRank, 2 importers, 21 symbols: #define the macros below to 1/0 to enable/disable the mode of operation.
- `cJSON.h` ranks 2 by PageRank, 2 importers, 37 symbols: cJSON: #define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #define cJSON_String (1 << 4) #define cJSON_Array  (1 << 5) #define cJSON_Object (1...
- `COFFLoader.h` ranks 3 by PageRank, 1 importers, 1 symbols.
- Hotspot `beacon.c`: 179 symbols, 31 connections (score 0.88).
- Hotspot `cJSON.c`: 125 symbols, 10 connections (score 0.39).
- Dataflow: 9 INFERRED issues (first: UNCHECKED_ALLOC in extract_shellcode).
- Surprising bridge: aes.c <-> beacon.h (5 hops across communities).
- Key entities: file:beacon.c, file:cJSON.c, file:aes.c, file:cJSON.h, file:aes.h, sym:cJSON.c::print@1243, file:COFFLoader.h, sym:cJSON.h::CJSON_CDECL@44
- Rating 1.4/10 = 7 x PageRank share 0.21 + 3 x risk 0.00. Internal imports: 5.
