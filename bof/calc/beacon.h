/*
	This file is part of Black Basalt Beacon.

	Black Basalt Beacon is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	Black Basalt Beacon is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with Black Basalt Beacon.  If not, see <https://www.gnu.org/licenses/>.

	Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

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
