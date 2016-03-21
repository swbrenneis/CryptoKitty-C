#include "../include/data/Scalar32.h"
#include "../include/data/OutOfRangeException.h"
#include <string.h>
#include <cmath>

// Static initialization
// Untested = 0, Little endian = 1, big endian = 2
unsigned char Scalar32::endian = 0;
const unsigned char Scalar32::LITTLEENDIAN = 1;
const unsigned char Scalar32::BIGENDIAN = 2;

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
        u32 = std::fabs(s32);
    }
    else if (bytesValid) {
        endianTest();
        unsigned tmp;
        switch (endian) {
            case LITTLEENDIAN:
                u32 = bytes[0];
                tmp = bytes[1];
                tmp = tmp >> 8;
                u32 |= tmp;
                tmp = bytes[2];
                tmp = tmp >> 16;
                u32 |= tmp;
                tmp = bytes[3];
                tmp = tmp >> 24;
                u32 |= tmp;
                break;
            case BIGENDIAN:
                u32 = bytes[3];
                tmp = bytes[2];
                tmp = tmp >> 8;
                u32 |= tmp;
                tmp = bytes[1];
                tmp = tmp >> 16;
                u32 |= tmp;
                tmp = bytes[0];
                tmp = tmp >> 24;
                u32 |= tmp;
                break;
            default:
                throw OutOfRangeException("Illegal endian value");
        }
    }
    uValid = true;
    return u32;

}
                   
/*
 * Encode an unsigned integer according to
 * the endian-ness indicator.
 */
unsigned char *Scalar32::encode(unsigned u32, int endian) {

    unsigned char *result = new unsigned char[4];
    unsigned tmp = u32;
    switch(endian) {
        case LITTLEENDIAN:
            result[0] = tmp & 0xff;
            tmp = tmp >> 8;
            result[1] = tmp & 0xff;
            tmp = tmp >> 8;
            result[2] = tmp & 0xff;
            tmp = tmp >> 8;
            result[3] = tmp & 0xff;
            break;
        case BIGENDIAN:
            result[3] = tmp & 0xff;
            tmp = tmp >> 8;
            result[2] = tmp & 0xff;
            tmp = tmp >> 8;
            result[1] = tmp & 0xff;
            tmp = tmp >> 8;
            result[0] = tmp & 0xff;
            break;
        default:
            throw OutOfRangeException("Illegal endian value");
    }
    return result;

}

/*
 * Endian test.
 */
void Scalar32::endianTest() {

    if (endian == 0) {
        unsigned short test = 0x4578;
        if ((test & 0xff) == 0x45) {
            endian = BIGENDIAN;
        }
        else {
            endian = LITTLEENDIAN;
        }
    }

}

