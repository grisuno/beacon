# `gen_module.sh`

> Source: [gen_module.sh:1](../../gen_module.sh#L1) | language `sh` | coverage 100.0% | [API index](../index.md)

=== gen_cmd_dll.sh v1.0 === Generates DLL and obfuscated shellcode to run a command Usage: ./gen_cmd_dll.sh --cmd "powershell..." [--key 0x33] [--output payload]

## Contents

- **Functions:** [`show_help`](#show_help), [`xor_obfuscate`](#xor_obfuscate)

## Functions

<a id="show_help"></a>

### `show_help`

`function` | [gen_module.sh:18](../../gen_module.sh#L18)

```bash
show_help()
```

=== FUNCTIONS ===

---

<a id="xor_obfuscate"></a>

### `xor_obfuscate`

`function` | [gen_module.sh:35](../../gen_module.sh#L35)

```bash
xor_obfuscate()
```

Function to obfuscate binary with XOR and convert to \x..

---
