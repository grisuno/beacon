# `gen_module.sh`

> Source: [gen_module.sh:1](../../gen_module.sh#L1) | language `sh` | coverage 100.0% | [API index](../index.md)

=== gen_cmd_dll.sh v1.0 === Genera DLL y shellcode ofuscado para ejecutar un comando Uso: ./gen_cmd_dll.sh --cmd "powershell..." [--key 0x33] [--output payload]

## Contents

- **Functions:** [`show_help`](#show_help), [`xor_obfuscate`](#xor_obfuscate)

## Functions

<a id="show_help"></a>

### `show_help`

`function` | [gen_module.sh:18](../../gen_module.sh#L18)

```bash
show_help()
```

=== FUNCIONES ===

---

<a id="xor_obfuscate"></a>

### `xor_obfuscate`

`function` | [gen_module.sh:35](../../gen_module.sh#L35)

```bash
xor_obfuscate()
```

Función para ofuscar binario con XOR y convertir a \x..

---
