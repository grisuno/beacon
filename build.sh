#!/bin/bash

x86_64-w64-mingw32-gcc -c COFFLoader3.c -o COFFLoader.o -D_CRT_SECURE_NO_WARNINGS
chmod +x bof/test/build.sh && cd bof/test && ./build.sh
cd ../../
chmod +x bof/whoami/build.sh && cd bof/whoami && ./build.sh
cd ../../
chmod +x bof/calc/build.sh && cd bof/calc && ./build.sh
cd ../../
chmod +x bof/etw/build.sh && cd bof/etw && ./build.sh
