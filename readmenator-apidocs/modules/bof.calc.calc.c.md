# `bof/calc/calc.c`

> Source: [bof/calc/calc.c:1](../../bof/calc/calc.c#L1) | language `c` | coverage 50.0% | [API index](../index.md)

## Contents

- **Functions:** [`go`](#go)
- **Variables:** [`__imp_GetModuleHandleA`](#__imp_getmodulehandlea), [`__imp_GetProcAddress`](#__imp_getprocaddress), [`__imp_LoadLibraryA`](#__imp_loadlibrarya), [`__imp_GetComputerNameA`](#__imp_getcomputernamea), [`__imp_CloseHandle`](#__imp_closehandle)

## Functions

<a id="go"></a>

### `go`

`function` | [bof/calc/calc.c:34](../../bof/calc/calc.c#L34)

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

`variable` `extern` | [bof/calc/calc.c:26](../../bof/calc/calc.c#L26)

```c
extern FARPROC __imp_GetModuleHandleA;
```

IMPORTS DIRECTOS

---

<a id="__imp_getprocaddress"></a>

### `__imp_GetProcAddress`

`variable` `extern` | [bof/calc/calc.c:27](../../bof/calc/calc.c#L27)

```c
extern FARPROC __imp_GetProcAddress;
```

---

<a id="__imp_loadlibrarya"></a>

### `__imp_LoadLibraryA`

`variable` `extern` | [bof/calc/calc.c:28](../../bof/calc/calc.c#L28)

```c
extern FARPROC __imp_LoadLibraryA;
```

---

<a id="__imp_getcomputernamea"></a>

### `__imp_GetComputerNameA`

`variable` `extern` | [bof/calc/calc.c:29](../../bof/calc/calc.c#L29)

```c
extern FARPROC __imp_GetComputerNameA;
```

---

<a id="__imp_closehandle"></a>

### `__imp_CloseHandle`

`variable` `extern` | [bof/calc/calc.c:30](../../bof/calc/calc.c#L30)

```c
extern FARPROC __imp_CloseHandle;
```

---
