#include "data/Scalar64.h"

// Static initializations
const int Scalar64::BIGENDIAN = 1;
const int Scalar64::LITTLEENDIAN = 2;
int Scalar64::endian = 0;

Scalar64::Scalar64() 
: value(0) {

    endianTest();
}

Scalar64::Scalar64(long v) 
: value(v) {

    endianTest();

}

Scalar64::~Scalar64() {
}

/*
 * Convenience function. Returns encoded array in native
 * endian format.
 */
ByteArray Scalar64::encode(long value) {

    return Scalar64(value).getEncoded();

}

/*
 * Endian test.
 */
void Scalar64::endianTest() {

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

