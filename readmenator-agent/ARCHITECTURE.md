# Architecture

## Internal Dependencies

- `COFFLoader3.c` -> `beacon.h`
- `aes.c` -> `aes.h`
- `beacon.c` -> `COFFLoader.h`
- `beacon.c` -> `aes.h`
- `beacon.c` -> `beacon.h`
- `beacon.c` -> `cJSON.h`
- `bof/calc/calc.c` -> `bof/calc/beacon.h`
- `bof/etw/etw.c` -> `bof/etw/beacon.h`
- `bof/test/Test.c` -> `bof/test/beacon.h`
- `bof/test/amsibypass.c` -> `bof/test/beacon.h`
- `bof/test/cmdwhoami.c` -> `bof/test/beacon.h`
- `bof/test/disablelog.c` -> `bof/test/beacon.h`
- `bof/test/getenv.c` -> `bof/test/beacon.h`
- `bof/test/loadvnc.c` -> `bof/test/beacon.h`
- `bof/test/persist.c` -> `bof/test/beacon.h`
- `bof/test/persistsvc.c` -> `bof/test/beacon.h`
- `bof/test/scan_shellcode.c` -> `bof/test/beacon.h`
- `bof/test/shellcode.c` -> `bof/test/beacon.h`
- `bof/test/sock5.c` -> `bof/test/beacon.h`
- `bof/test/uacbypass.c` -> `bof/test/beacon.h`
- `bof/test/upload.c` -> `bof/test/beacon.h`
- `bof/test/vncrelay.c` -> `bof/test/beacon.h`
- `bof/test/winver.c` -> `bof/test/beacon.h`
- `bof/whoami/whoami.c` -> `bof/whoami/beacon.h`
- `cJSON.c` -> `cJSON.h`

## External Imports

- `COFFLoader.h` -> windows.h
- `COFFLoader3.c` -> stdint.h, stdio.h, stdlib.h, string.h, windows.h
- `aes.c` -> string.h
- `aes.h` -> stddef.h, stdint.h
- `app.py` -> os
- `beacon.c` -> bcrypt.h, icmpapi.h, io.h, iphlpapi.h, ntstatus.h, objbase.h, process.h, setjmp.h, shellapi.h, shlobj.h, stdio.h, stdlib.h, string.h, time.h, tlhelp32.h, wincrypt.h, windows.h, winhttp.h, winioctl.h, winnt.h, winsock2.h, ws2tcpip.h
- `beacon.h` -> windows.h
- `bof/calc/beacon.h` -> windows.h
- `bof/calc/calc.c` -> windows.h
- `bof/etw/beacon.h` -> windows.h
- `bof/etw/etw.c` -> windows.h
- `bof/test/amsibypass.c` -> windows.h
- `bof/test/beacon.h` -> windows.h
- `bof/test/cmdwhoami.c` -> windows.h
- `bof/test/disablelog.c` -> psapi.h, tlhelp32.h, windows.h, winternl.h
- `bof/test/getenv.c` -> windows.h
- `bof/test/loadvnc.c` -> windows.h
- `bof/test/make_table.c` -> stdint.h, stdio.h
- `bof/test/persist.c` -> windows.h
- `bof/test/persistsvc.c` -> windows.h
- `bof/test/scan_shellcode.c` -> tlhelp32.h, windows.h
- `bof/test/shellcode.c` -> windows.h
- `bof/test/sock5.c` -> windows.h
- `bof/test/tel.py` -> Crypto.Cipher, datetime, json, re, requests, uuid
- `bof/test/uacbypass.c` -> windows.h
- `bof/test/upload.c` -> windows.h
- `bof/test/vncrelay.c` -> windows.h, winsock2.h
- `bof/test/winver.c` -> windows.h
- `bof/whoami/beacon.h` -> windows.h
- `bof/whoami/whoami.c` -> windows.h
- `cJSON.c` -> ctype.h, float.h, limits.h, locale.h, math.h, stdio.h, stdlib.h, string.h
- `cJSON.h` -> stddef.h
- `generate_hashs.py` -> argparse, pygments, pygments.formatters, pygments.lexers, re, sys
