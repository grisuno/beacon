# Project Memory

> Cross-session context for agents. Sections 1-6 are regenerated from the source tree with zero LLM tokens: declared rules are quoted verbatim with `file:line`, measured baselines come from the scan. Section 7 is written by agents and humans and is preserved across rebuilds.

Generated from 41 files at commit `0cda7db121d3`. Read this first, then `readmenator-wiki/index.md`, then `readmenator . ask "<question>"` for anything specific.

## 1. Purpose and domain

- What it is: beacon-GEN is a next-generation Bash-based configuration engine designed to generate highly customizable, stealthy C2 beacons for offensive operations. (`README.md:18`)
- Domain vocabulary (term, files): `bof` (25), `get` (20), `imp` (18), `address` (15), `load` (14), `proc` (14), `library` (13), `handle` (12), `funci` (12), `beacon` (11), `close` (10), `imports` (10), `principal` (10), `output` (9), `error` (9)
- Subsystem `bof/test`: 24 files, core `COFFLoader3.c`: SymbolHash: === Tabla de símbolos por hash ===
- Subsystem `root`: 6 files, core `beacon.c`: UTF8ToWide: Convierte UTF-8 a wide string
- Business rules that the code cannot show live in section 7: record them there.

## 2. Workflow

Detected commands:
- `python -m pytest -q` (tests/ layout)
- `make windows` (Makefile)
- `make clean` (Makefile)
- `make upx` (Makefile)
- `CI workflow c-cpp.yml` (.github/workflows/c-cpp.yml)
- `CI workflow github-actions-demo.yml` (workflows/github-actions-demo.yml)

Session protocol:
1. Start: read this file, then `readmenator . fresh` (exit 1 means run `readmenator . --rebuild`).
2. Orient: `readmenator-wiki/index.md`; for a question use `readmenator . ask "<question>"` (local = entities + sources, `--global` = community reports).
3. Before editing a file: `grep -n '<file>' readmenator-agent/GOTCHAS.md readmenator-agent/SECURITY.md`.
4. After the change: run the tests above, then `readmenator . --rebuild` so the maps, wiki, and this file stay true.
5. End: record decisions, business rules, and gotchas with `readmenator . remember "<note>" --kind decision`.

## 3. Rules and constraints

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- Security findings at medium or above: 0 (see `readmenator-agent/SECURITY.md`); do not add new ones.
- Dependency cycles: 0; layer violations: 0 (see `readmenator-agent/GOTCHAS.md`).

## 4. Style norms

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- c: 23 files, 778 symbols; docstrings on 16% of symbols; functions snake_case (38%); types PascalCase (47%); median file 127 lines, max 5694.
- h: 8 files, 79 symbols; docstrings on 8% of symbols; functions snake_case (11%); types PascalCase (0%); median file 44 lines, max 295.
- sh: 7 files, 8 symbols; docstrings on 88% of symbols; functions snake_case (100%); median file 163 lines, max 6360.
- py: 3 files, 10 symbols; docstrings on 40% of symbols; functions snake_case (100%); median file 91 lines, max 596.
- Tests: 18 files under bof/test; follow the existing naming (e.g. `Test.c`).

## 5. Minimum deliverables

Declared:
- none declared in instruction files (add them to AGENTS.md or record them in section 7)

Measured baseline:
- Tests pass: `python -m pytest -q`.
- Docstring coverage stays at or above 17%.
- No new security findings at medium or above (current: 0).
- No new dependency cycles (current: 0).
- Files stay under 300 lines where possible (`readmenator . lint`).
- Docs refreshed: `readmenator . --rebuild`, and decisions recorded in section 7.

## 6. Risks to respect

- God nodes (changes ripple widely): `beacon.h`, `bof/test/beacon.h`, `COFFLoader3.c`, `beacon.c`, `cJSON.c`
- Hotspots (complex and central): `beacon.c`, `COFFLoader3.c`, `beacon.h`, `cJSON.c`, `bof/test/beacon.h`
- Full blast radius: `readmenator-agent/GOTCHAS.md`; findings: `readmenator-agent/SECURITY.md`.

## 7. Session log (preserved across rebuilds)

Append with `readmenator . remember "<note>" --kind <kind>` (kinds: business, decision, rule, workflow, style, deliverable, gotcha, todo, note) or the MCP tool `readmenator.remember`. Record business rules, decisions and their reasons, workflow changes, and anything the next session must not rediscover.

<!-- readmenator:memory:notes:begin -->
<!-- readmenator:memory:notes:end -->
