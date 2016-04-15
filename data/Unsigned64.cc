#include "data/Unsigned64.h"
#include "exceptions/OutOfRangeException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Unsigned64::BIGENDIAN = 1;
const int Unsigned64::LITTLEENDIAN = 2;
int Unsigned64::endian = 0;

Unsigned64::Unsigned64() 
: value(0) {

    endianTest();
}

Unsigned64::Unsigned64(uint64_t v) 
: value(v) {

    endianTest();

}

Unsigned64::Unsigned64(const ByteArray& encoded) {

    if (encoded.getLength() < 8) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, endian);

}

Unsigned64::Unsigned64(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 8) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, eType);

}

Unsigned64::Unsigned64(const Unsigned64& other)
: value(other.value) {
}

Unsigned64& Unsigned64::operator= (const Unsigned64& other) {

    value = other.value;
    return *this;

}

Unsigned64::~Unsigned64() {
}

/*
 * Convenience function. Returns a uint64_t value decoded
 * from a byte array in native endian order.
 */
uint64_t Unsigned64::decode(const ByteArray& encoded) {

    return Unsigned64(encoded).getUnsignedValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Unsigned64::decode(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 8) {
        throw OutOfRangeException("Invalid encoding length");
    }

    value = 0;
    switch (eType) {
        case BIGENDIAN:
            for (int n = 0; n < 8; ++n) {
                value = value << 8;
                value |= encoded[n];
            }
            break;
        case LITTLEENDIAN:
            for (int n = 7; n >= 0; --n) {
                value = value << 8;
                value |= encoded[n];
            }
            break;
        default:
            throw OutOfRangeException("Illegal endian value");
    }


}

/*
 * Convenience function. Returns encoded array in native
 * endian format.
 */
ByteArray Unsigned64::encode(uint64_t v) {

    return Unsigned64(v).getEncoded();

}

/*
 * Endian test.
 */
void Unsigned64::endianTest() {

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

/*
 * Returns the value encoded in an 8 byte array in native
 * endian order.
 */
ByteArray Unsigned64::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Unsigned64::getEncoded(int eType) const {

    ByteArray result(8);
    uint64_t tmp = value;
    switch(eType) {
        case LITTLEENDIAN:
            for (int n = 0; n < 8; ++n) {
                result[n] = tmp & 0xff;
                tmp = tmp >> 8;
            }
            break;
        case BIGENDIAN:
            for (int n = 7; n >= 0; --n) {
                result[n] = tmp & 0xff;
                tmp = tmp >> 8;
            }
            break;
        default:
            throw OutOfRangeException("Illegal endian value");
    }
    return result;

}

/*
 * Returns an unsigned uint64_t value.
 */
uint64_t Unsigned64::getUnsignedValue() const {

    return value;

}

}

