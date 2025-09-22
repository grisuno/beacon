#!/bin/bash
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector Test.c -o test.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector winver.c -o winver.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector getenv.c -o getenv.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector cmdwhoami.c -o cmdwhoami.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector shellcode.c -o shellcode.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector persist.c -o persist.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector scan_shellcode.c -o scan_shellcode.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector disablelog.c -o disablelog.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector vncrelay.c -o vncrelay.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector loadvnc.c -o loadvnc.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector uacbypass.c -o uacbypass.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector amsibypass.c -o amsibypass.x64.o
x86_64-w64-mingw32-gcc -c -fPIC -O2 -fno-stack-protector persistsvc.c -o psvc.x64.o


