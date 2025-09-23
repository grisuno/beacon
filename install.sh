#!/bin/bash
sudo apt install mingw-w64
python3 app.py

# Espera 10 segundos por la respuesta del usuario
read -t 10 -p "   [?] do you wanna install the C2 ? (y/n): " respuesta

# Si el usuario no respondió, la variable 'respuesta' estará vacía
if [ -z "$respuesta" ]; then
  # Asume la opción 'y' y procede con la instalación
  respuesta="y"
  echo
  echo "Installing afer 10 seconds ..."
fi

# Ahora puedes usar la variable 'respuesta' para continuar
if [ "$respuesta" = "y" ] || [ "$respuesta" = "Y" ]; then
    echo "Installing the C2..."
    git clone https://github.com/grisuno/LazyOwn.git
fi
echo "Happy hacking."
