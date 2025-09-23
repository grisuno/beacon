#!/bin/bash
sudo apt install mingw-w64
python3 app.py

# Preguntar al usuario si quiere salir
read -p "    [?] do you wannna install the C2 ? (y/n): " respuesta

if [[ "$respuesta" == "n" || "$respuesta" == "N" ]]; then
    echo "    [*] Happy Hacking ..."
    exit 0
else
    git clone https://github.com/grisuno/LazyOwn.git

fi
