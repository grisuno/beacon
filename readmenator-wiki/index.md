# Second Brain

*Last synthesized: 2026-10-07 | 41 files | 3 concept pages | offline, zero tokens*

> Raw sources -> readmenator wiki -> links (Karpathy LLM Wiki Pattern, deterministic).
> Start here, then open one community page. Prefer grep over full reads.

## Vault Overview

The codebase centres on `beacon.h`, `bof/test/beacon.h`, `COFFLoader3.c`. Architecturally it is 2 layers, dominant utility (23 files) across 3 import-based communities. Recorded risk surface: 0 security findings and 0 dependency cycles.

Surprising tissue lives between bof/test, root, orphans: 1 extracted cross-community imports and 6 inferred bridges. Follow `connections.json` sorted by strength before refactoring.

Open work clusters around documentation (29% file coverage), 0 security findings, 1 taint paths, and 5 suggested exploration questions in `queries.md`.

## Stats

| Metric | Value |
|--------|-------|
| Files | 41 |
| Symbols | 856 |
| Resolved imports | 25 |
| Languages | c, h, py, sh |
| Communities | 3 |
| Doc coverage | 29% (12/41 files) |
| Security findings | 0 |
| Estimated read cost | ~8823 tokens (chars/4, offline so $0) |

## Reading Order

1. Skim Stats and God Nodes below for blast radius.
2. Open the largest community page first, then follow Connections.
3. Use `queries.md` for the next question; log the answer there.

```
grep -rn '<keyword>' index.md community_*.md
readmenator query "<question>" --target readmenator_beacon_6rdotks8
```

## Concept Wiki

- [bof/test (24 files, cohesion 0.97)](./community_0_bof_test.md)
- [root (6 files, cohesion 0.83)](./community_1_root.md)
- [orphans (11 files, cohesion 0.00)](./community_2_orphans.md)

## God Nodes

| File | Score |
|------|-------|
| `beacon.h` | 40.4 |
| `bof/test/beacon.h` | 30.4 |
| `COFFLoader3.c` | 27.8 |
| `beacon.c` | 24.0 |
| `cJSON.c` | 14.5 |

## Strongest Connections

- 1 -> 0: depends_on (strength 0.9, EXTRACTED)
- 1 -> 0: bridges (strength 0.5, INFERRED)
- 1 -> 0: bridges (strength 0.5, INFERRED)
- 1 -> 0: bridges (strength 0.5, INFERRED)
- 1 -> 0: bridges (strength 0.5, INFERRED)
- 0 -> 1: bridges (strength 0.5, INFERRED)
- 1 -> 2: shares_context (strength 0.5, INFERRED)

## Navigation Tips

- Obsidian Graph View works: every community page links back here.
- `connections.json` is machine-readable for GraphRAG pipelines.
- `REPORT.md` states what was extracted vs inferred and current limits.
- Regenerate offline: `readmenator . --rebuild` (no network, no tokens).
