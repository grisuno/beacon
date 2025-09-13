#ifndef COFFLOADER_H
#define COFFLOADER_H

#include <windows.h>

int RunCOFF(char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char* argumentdata, int argumentSize);

#endif
