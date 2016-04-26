#include "data/Unsigned32.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/BadParameterException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Unsigned32::BIGENDIAN = 1;
const int Unsigned32::LITTLEENDIAN = 2;
int Unsigned32::endian = 0;

Unsigned32::Unsigned32() 
: value(0) {

    endianTest();
}

Unsigned32::Unsigned32(uint32_t v) 
: value(v) {

    endianTest();

}

Unsigned32::Unsigned32(const ByteArray& encoded) {

    if (encoded.getLength() < 4) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, endian);

}

Unsigned32::Unsigned32(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 4) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, eType);

}

Unsigned32::Unsigned32(const Unsigned32& other)
: value(other.value) {
}

Unsigned32& Unsigned32::operator= (const Unsigned32& other) {

    value = other.value;
    return *this;

}

Unsigned32::~Unsigned32() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
uint32_t Unsigned32::decode(const ByteArray& encoded) {

    return Unsigned32(encoded).getUnsignedValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Unsigned32::decode(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 4) {
        throw OutOfRangeException("Invalid encoding length");
    }

    value = 0;
    switch (eType) {
        case BIGENDIAN:
            for (int n = 0; n < 4; ++n) {
                value = value << 8;
                value |= encoded[n];
            }
            break;
        case LITTLEENDIAN:
            for (int n = 3; n >= 0; --n) {
                value = value << 8;
                value |= encoded[n];
            }
            break;
        default:
            throw BadParameterException("Illegal endian value");
    }

}

/*
 * Convenience function. Returns encoded array in native
 * endian format.
 */
ByteArray Unsigned32::encode(uint32_t v) {

    return Unsigned32(v).getEncoded();

}

/*
 * Endian test.
 */
void Unsigned32::endianTest() {

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
ByteArray Unsigned32::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Unsigned32::getEncoded(int eType) const {

    ByteArray result(4);
    long tmp = value;
    switch(eType) {
        case LITTLEENDIAN:
            for (int n = 0; n < 4; ++n) {
                result[n] = tmp & 0xff;
                tmp = tmp >> 8;
            }
            break;
        case BIGENDIAN:
            for (int n = 3; n >= 0; --n) {
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
 * Returns an unsigned integer value.
 */
uint32_t Unsigned32::getUnsignedValue() const {

    return value;

}

/*
 * Set the unsigned value.
 */
void Unsigned32::setValue(uint32_t v) {

    value = v;

}

}

