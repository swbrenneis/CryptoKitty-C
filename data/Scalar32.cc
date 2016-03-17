#include "../include/data/Scalar32.h"
#include <string.h>
#include <cmath>

// Static initialization
// Untested = 0, Little endian = 1, big endian = 2
unsigned char Scalar32::endian = 0;

Scalar32::Scalar32() {
    bytesValid = sValid = uValid = false;
}

Scalar32::Scalar32(unsigned char *bValue) {

    sValid = uValid = false;
    memcpy(bytes, bValue, 4);
    bytesValid = true;

}

Scalar32::~Scalar32() {
}

/*
 * Return the value as an unsigned integer.
 */
unsigned Scalar32::asUnsigned() {

    if (uValid) { /* Do nothing */ }
    else if (sValid) {
        u32 = std::abs(s32);
    }
    else if (bytesValid) {
        endianTest();
        if (endian == 1) {
            u32 = bytes[0];
            unsigned tmp = bytes[1];
            tmp = tmp >> 8;
            u32 |= tmp;
            tmp = bytes[2];
            tmp = tmp >> 16;
            u32 |= tmp;
            tmp = bytes[3];
            tmp = tmp >> 24;
            u32 |= tmp;
        }
        else {
            u32 = bytes[3];
            unsigned tmp = bytes[2];
            tmp = tmp >> 8;
            u32 |= tmp;
            tmp = bytes[1];
            tmp = tmp >> 16;
            u32 |= tmp;
            tmp = bytes[0];
            tmp = tmp >> 24;
            u32 |= tmp;
        }
    }
    uValid = true;
    return u32;

}
                    

/*
 * Endian test.
 */
void Scalar32::endianTest() {

    if (endian == 0) {
        unsigned short test = 0x4578;
        if ((test & 0xff) == 0x45) {
            endian = 1;
        }
        else {
            endian = 2;
        }
    }

}
