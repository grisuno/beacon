# `bof/etw/etw.c`

> Source: [bof/etw/etw.c:1](../../bof/etw/etw.c#L1) | language `c` | coverage 0.0% | [API index](../index.md)

## Contents

- **Functions:** [`go`](#go)
- **Variables:** [`__imp_GetModuleHandleA`](#__imp_getmodulehandlea), [`__imp_GetProcAddress`](#__imp_getprocaddress), [`__imp_VirtualProtect`](#__imp_virtualprotect), [`__imp_RtlCopyMemory`](#__imp_rtlcopymemory)

## Functions

<a id="go"></a>

### `go`

`function` | [bof/etw/etw.c:26](../../bof/etw/etw.c#L26)

```c
void go(char *a,int l)
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `a` | `char *` |  |  |
| `l` | `int` |  |  |

---

## Variables

<a id="__imp_getmodulehandlea"></a>

### `__imp_GetModuleHandleA`

`variable` `extern` | [bof/etw/etw.c:22](../../bof/etw/etw.c#L22)

```c
extern PVOID __imp_GetModuleHandleA;
```

include <windows.h> include "beacon.h"

---

<a id="__imp_getprocaddress"></a>

### `__imp_GetProcAddress`

`variable` `extern` | [bof/etw/etw.c:23](../../bof/etw/etw.c#L23)

```c
extern PVOID __imp_GetProcAddress;
```

---

<a id="__imp_virtualprotect"></a>

### `__imp_VirtualProtect`

`variable` `extern` | [bof/etw/etw.c:24](../../bof/etw/etw.c#L24)

```c
extern PVOID __imp_VirtualProtect;
```

---

<a id="__imp_rtlcopymemory"></a>

### `__imp_RtlCopyMemory`

`variable` `extern` | [bof/etw/etw.c:25](../../bof/etw/etw.c#L25)

```c
extern PVOID __imp_RtlCopyMemory;
```

---
