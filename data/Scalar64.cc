#include "data/Scalar64.h"
#include "exceptions/OutOfRangeException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Scalar64::BIGENDIAN = 1;
const int Scalar64::LITTLEENDIAN = 2;
int Scalar64::endian = 0;

Scalar64::Scalar64() 
: value(0),
  uvalue(0) {

    endianTest();
}

Scalar64::Scalar64(int64_t v) 
: value(v) {

    endianTest();
    uvalue = abs(value);

}

Scalar64::Scalar64(const ByteArray& encoded) {

    endianTest();
    decode(encoded, endian);

}

Scalar64::Scalar64(const ByteArray& encoded, int eType) {

    endianTest();
    decode(encoded, eType);

}

Scalar64::Scalar64(const Scalar64& other)
: value(other.value),
  uvalue(other.uvalue) {
}

Scalar64& Scalar64::operator= (const Scalar64& other) {

    value = other.value;
    uvalue = other.uvalue;
    return *this;

}

Scalar64::~Scalar64() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
long Scalar64::decode(const ByteArray& encoded) {

    return Scalar64(encoded).getLongValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Scalar64::decode(const ByteArray& encoded, int eType) {

    value = 0;
    switch (eType) {
        case BIGENDIAN:
            for (int n = 0; n < 8; ++n) {
                value = value << 8;
                value |= encoded[n];
                uvalue = uvalue << 8;
                uvalue |= encoded[n];
            }
            break;
        case LITTLEENDIAN:
            for (int n = 7; n >= 0; --n) {
                value = value << 8;
                value |= encoded[n];
                uvalue = uvalue << 8;
                uvalue |= encoded[n];
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
ByteArray Scalar64::encode(int64_t v) {

    return Scalar64(v).getEncoded();

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

/*
 * Returns the value encoded in an 8 byte array in native
 * endian order.
 */
ByteArray Scalar64::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Scalar64::getEncoded(int eType) const {

    ByteArray result(8);
    long tmp = value;
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
 * Returns a signed long value.
 */
int64_t Scalar64::getLongValue() const {

    return value;

}

/*
 * Returns an unsigned long value.
 */
uint64_t Scalar64::getUnsignedValue() const {

    return uvalue;

}

}

