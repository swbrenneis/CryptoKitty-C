#include "data/Int64.h"
#include "exceptions/OutOfRangeException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Int64::BIGENDIAN = 1;
const int Int64::LITTLEENDIAN = 2;
int Int64::endian = 0;

Int64::Int64() 
: value(0) {

    endianTest();
}

Int64::Int64(int64_t v) 
: value(v) {

    endianTest();

}

Int64::Int64(const ByteArray& encoded) {

    if (encoded.getLength() < 8) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, endian);

}

Int64::Int64(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 8) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, eType);

}

Int64::Int64(const Int64& other)
: value(other.value) {
}

Int64& Int64::operator= (const Int64& other) {

    value = other.value;
    return *this;

}

Int64::~Int64() {
}

/*
 * Convenience function. Returns a int64_t value decoded
 * from a byte array in native endian order.
 */
int64_t Int64::decode(const ByteArray& encoded) {

    return Int64(encoded).getLongValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Int64::decode(const ByteArray& encoded, int eType) {

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
ByteArray Int64::encode(int64_t v) {

    return Int64(v).getEncoded();

}

/*
 * Endian test.
 */
void Int64::endianTest() {

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
ByteArray Int64::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Int64::getEncoded(int eType) const {

    ByteArray result(8);
    int64_t tmp = value;
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
 * Returns a signed int64_t value.
 */
int64_t Int64::getLongValue() const {

    return value;

}

}

