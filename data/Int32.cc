#include "data/Int32.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/BadParameterException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Int32::BIGENDIAN = 1;
const int Int32::LITTLEENDIAN = 2;
int Int32::endian = 0;

Int32::Int32() 
: value(0) {

    endianTest();
}

Int32::Int32(int32_t v) 
: value(v) {

    endianTest();

}

Int32::Int32(const ByteArray& encoded) {

    endianTest();
    decode(encoded, endian);

}

Int32::Int32(const ByteArray& encoded, int eType) {

    endianTest();
    decode(encoded, eType);

}

Int32::Int32(const Int32& other)
: value(other.value) {
}

Int32& Int32::operator= (const Int32& other) {

    value = other.value;
    return *this;

}

Int32::~Int32() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
int32_t Int32::decode(const ByteArray& encoded) {

    return Int32(encoded).getIntValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Int32::decode(const ByteArray& encoded, int eType) {

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
ByteArray Int32::encode(int32_t v) {

    return Int32(v).getEncoded();

}

/*
 * Endian test.
 */
void Int32::endianTest() {

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
ByteArray Int32::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Int32::getEncoded(int eType) const {

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
 * Returns a signed integer value.
 */
int32_t Int32::getIntValue() const {

    return value;

}

}

