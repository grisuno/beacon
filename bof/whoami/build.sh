#!/bin/bash
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector whoami.c -o whoami.x64.o
