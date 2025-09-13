#!/bin/bash

x86_64-w64-mingw32-gcc -c COFFLoader3.c -o COFFLoader.o -D_CRT_SECURE_NO_WARNINGS
chmod +x bof/test/build.sh && ./bof/test/build.sh
chmod +x bof/whoami/build.sh && ./bof/whoami/build.sh
