#!/bin/bash
sudo apt install mingw-w64
pip3 install -r requirements.txt
python3 app.py

read -t 10 -p "   [?] do you wanna install the C2 ? (y/n): " respuesta

if [ -z "$respuesta" ]; then
  respuesta="y"
  echo
  echo "Installing afer 10 seconds ..."
fi

if [ "$respuesta" = "y" ] || [ "$respuesta" = "Y" ]; then
    echo "Installing the C2..."
    git clone https://github.com/grisuno/LazyOwn.git
fi
echo "Happy hacking."
