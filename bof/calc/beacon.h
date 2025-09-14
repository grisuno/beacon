#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

typedef struct {
    char * original;
    char * buffer;
    int    length;
} datap;

// === Declaraciones Beacon ===
__declspec(dllexport) __attribute__((ms_abi)) void BeaconDataParse(datap * parser, char * buffer, int size);
__declspec(dllexport) __attribute__((ms_abi)) char * BeaconDataPtr(datap * parser, int size);
__declspec(dllexport) __attribute__((ms_abi)) int BeaconDataInt(datap * parser);
__declspec(dllexport) __attribute__((ms_abi)) short BeaconDataShort(datap * parser);
__declspec(dllexport) __attribute__((ms_abi)) int BeaconDataLength(datap * parser);
__declspec(dllexport) __attribute__((ms_abi)) char * BeaconDataExtract(datap * parser, int * size);
__declspec(dllexport) __attribute__((ms_abi)) void BeaconPrintf(int type, const char * fmt, ...);
__declspec(dllexport) __attribute__((ms_abi)) void BeaconOutput(int type, const char * data, int len);

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

#endif // BEACON_H
