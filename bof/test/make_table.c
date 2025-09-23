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

#include <stdint.h>
#include <stdio.h>


// === Función hash DJB2 ===
static uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

void main() {
    const char* names[] = {

        "BeaconDataParse",
        "BeaconDataInt",
        "BeaconDataShort",
        "BeaconDataExtract",
        "BeaconPrintf",
        "BeaconOutput",
        NULL
    };

    for (int i = 0; names[i]; i++) {
        uint32_t h = djb2_hash(names[i]);
        printf("Hash for '%s' = 0x%08X\n", names[i], h);
    }
}

void main();
