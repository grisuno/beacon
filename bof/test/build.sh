if [ -z "$1" ] || [ -z "$2" ]; then
  echo "usage: build.sh <source.c> <output.o> [args...]"
else
  x86_64-w64-mingw32-gcc -c -fno-stack-protector -s -O2 -masm=intel "$@" && cp "$2" /home/grisun0/LazyOwn/sessions
fi
