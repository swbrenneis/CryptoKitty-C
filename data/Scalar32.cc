#include "data/Scalar32.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/BadParameterException.h"
#include <cmath>

namespace CK {

// Static initializations
const int Scalar32::BIGENDIAN = 1;
const int Scalar32::LITTLEENDIAN = 2;
const bool Scalar32::UNSIGNED = true;
int Scalar32::endian = 0;

Scalar32::Scalar32() 
: value(0),
  uvalue(0){

    endianTest();
}

Scalar32::Scalar32(int32_t v) 
: value(v) {

    endianTest();
    uvalue = abs(value);

}

Scalar32::Scalar32(uint32_t v, bool u) 
: value(v),
  uvalue(v) {

    endianTest();

}

Scalar32::Scalar32(const ByteArray& encoded) {

    endianTest();
    decode(encoded, endian);

}

Scalar32::Scalar32(const ByteArray& encoded, int eType) {

    endianTest();
    decode(encoded, eType);

}

Scalar32::Scalar32(const Scalar32& other)
: value(other.value),
  uvalue(other.uvalue) {
}

Scalar32& Scalar32::operator= (const Scalar32& other) {

    value = other.value;
    uvalue = other.uvalue;
    return *this;

}

Scalar32::~Scalar32() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
int32_t Scalar32::decode(const ByteArray& encoded) {

    return Scalar32(encoded).getIntValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Scalar32::decode(const ByteArray& encoded, int eType) {

    value = 0;
    switch (eType) {
        case BIGENDIAN:
            for (int n = 0; n < 4; ++n) {
                value = value << 8;
                value |= encoded[n];
                uvalue = uvalue << 8;
                uvalue |= encoded[n];
            }
            break;
        case LITTLEENDIAN:
            for (int n = 3; n >= 0; --n) {
                value = value << 8;
                value |= encoded[n];
                uvalue = uvalue << 8;
                uvalue |= encoded[n];
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
ByteArray Scalar32::encode(int32_t v) {

    return Scalar32(v).getEncoded();

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

/*
 * Returns the value encoded in an 8 byte array in native
 * endian order.
 */
ByteArray Scalar32::getEncoded(bool u) const {

    return getEncoded(endian, u);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Scalar32::getEncoded(int eType, bool u) const {

    ByteArray result(4);
    long tmp = u ? uvalue : value;
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
int32_t Scalar32::getIntValue() const {

    return value;

}

/*
 * Returns an unsigned integer value.
 */
int32_t Scalar32::getUnsignedValue() const {

    return uvalue;

}

}

