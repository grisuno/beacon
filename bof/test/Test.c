#include "beacon.h"

void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[CoffTest] I am alive! . Args=%.*s\n", alen, args);
}
