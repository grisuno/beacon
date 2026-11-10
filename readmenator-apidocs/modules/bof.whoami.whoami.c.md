# `bof/whoami/whoami.c`

> Source: [bof/whoami/whoami.c:1](../../bof/whoami/whoami.c#L1) | language `c` | coverage 50.0% | [API index](../index.md)

## Contents

- **Functions:** [`go`](#go)
- **Variables:** [`__imp_GetModuleHandleA`](#__imp_getmodulehandlea), [`__imp_GetProcAddress`](#__imp_getprocaddress), [`__imp_LoadLibraryA`](#__imp_loadlibrarya), [`__imp_GetComputerNameA`](#__imp_getcomputernamea)

## Functions

<a id="go"></a>

### `go`

`function` | [bof/whoami/whoami.c:34](../../bof/whoami/whoami.c#L34)

```c
void go(char *args, int alen)
```

FUNCIÓN PRINCIPAL

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `args` | `char *` |  |  |
| `alen` | `int` |  |  |

---

## Variables

<a id="__imp_getmodulehandlea"></a>

### `__imp_GetModuleHandleA`

`variable` `extern` | [bof/whoami/whoami.c:26](../../bof/whoami/whoami.c#L26)

```c
extern FARPROC __imp_GetModuleHandleA;
```

IMPORTS DIRECTOS

---

<a id="__imp_getprocaddress"></a>

### `__imp_GetProcAddress`

`variable` `extern` | [bof/whoami/whoami.c:27](../../bof/whoami/whoami.c#L27)

```c
extern FARPROC __imp_GetProcAddress;
```

---

<a id="__imp_loadlibrarya"></a>

### `__imp_LoadLibraryA`

`variable` `extern` | [bof/whoami/whoami.c:28](../../bof/whoami/whoami.c#L28)

```c
extern FARPROC __imp_LoadLibraryA;
```

---

<a id="__imp_getcomputernamea"></a>

### `__imp_GetComputerNameA`

`variable` `extern` | [bof/whoami/whoami.c:29](../../bof/whoami/whoami.c#L29)

```c
extern FARPROC __imp_GetComputerNameA;
```

---
