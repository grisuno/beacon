#!/bin/bash
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector Test.c -o test.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector winver.c -o winver.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector getenv.c -o getenv.x64.o
