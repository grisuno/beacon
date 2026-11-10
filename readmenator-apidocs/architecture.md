# beacon Architecture and Execution Flows

[Back to index](index.md)

## Architecture Overview

3 components stacked in 2 dependency tiers (weighted Eades-Lin-Smyth ordering: arrows point from dependent to dependency, top to bottom). Labels are import counts, thick arrows the top quartile; 0 transitively implied edges are omitted. Dashed red arrows are upward dependencies: the smallest set of imports that closes every cycle and breaks the layering. Cyan components hold entry points. Interactive version: `readmenator-apidocs/index.html#/flows`.

```mermaid
flowchart TB
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    subgraph lane_0["Tier 1 - entry / orchestration"]
        direction LR
        n_d__root_["(root)<br/>9 files, 12 symbols<br/>Core / utility"]:::entry
        n_c1["root<br/>6 files, 406 symbols<br/>Core / utility"]:::default
    end
    subgraph lane_1["Tier 2 - foundation"]
        direction LR
        n_c0["bof/test<br/>8 files, 290 symbols<br/>Core / utility"]:::default
    end
    n_c1 -->|"1"| n_c0
    n_d__root_ ~~~ n_c0
```

---

## Execution Flows

Entry points are scored from `__main__` guards, `main` functions, entry-style names and files, and call-graph sources. Each flow walks resolved calls in call-site order (depth <= 4, <= 40 steps); numbers give the call order, dashed arrows revisit an already expanded callee, red arrows are recursion. Interactive version with zoom and per-node docs: `readmenator-apidocs/index.html#/flows`.

### `cJSON.CJSON_PUBLIC`

`cJSON.c:1134`, score 13: call-graph source with 6 calls; call-graph source with 3 calls; call-graph source with 4 calls.

Call tree:

```mermaid
flowchart LR
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_cJSON_c__CJSON_PUBLIC["cJSON.CJSON_PUBLIC<br/>cJSON.c:95"]:::entry
    n_cJSON_c__CJSON_PUBLIC -.->|"recursion"| n_cJSON_c__CJSON_PUBLIC
    linkStyle 0 stroke:#f87171,stroke-width:2px;
```

### `generate_hashs (__main__)`

`generate_hashs.py:595`, score 8: `if __name__ == "__main__"` guard.

Call tree:

```mermaid
flowchart LR
    classDef default fill:#111827,stroke:#38bdf8,color:#e5e7eb;
    classDef entry fill:#0e7490,stroke:#22d3ee,color:#ecfeff,stroke-width:2px;
    n_generate_hashs_py___main_["generate_hashs (__main__)<br/>generate_hashs.py"]:::entry
    n_generate_hashs_py__main["generate_hashs.main<br/>generate_hashs.py:553"]:::default
    n_generate_hashs_py__generate_coff_loader["generate_hashs.generate_coff_loader<br/>generate_hashs.py:223"]:::default
    n_generate_hashs_py__djb2["generate_hashs.djb2<br/>generate_hashs.py:23"]:::default
    n_generate_hashs_py__generate_bof_test["generate_hashs.generate_bof_test<br/>generate_hashs.py:491"]:::default
    n_generate_hashs_py___main_ -->|"1"| n_generate_hashs_py__main
    n_generate_hashs_py__main -->|"1"| n_generate_hashs_py__generate_coff_loader
    n_generate_hashs_py__generate_coff_loader -->|"1"| n_generate_hashs_py__djb2
    n_generate_hashs_py__main -->|"2"| n_generate_hashs_py__generate_bof_test
```

---
