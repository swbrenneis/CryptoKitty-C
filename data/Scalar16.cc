#include "data/Scalar16.h"
#include "exceptions/OutOfRangeException.h"

namespace CK {

// Static initializations
const int Scalar16::BIGENDIAN = 1;
const int Scalar16::LITTLEENDIAN = 2;
int Scalar16::endian = 0;

Scalar16::Scalar16() 
: value(0) {

    endianTest();
}

Scalar16::Scalar16(int16_t v) 
: value(v) {

    endianTest();

}

Scalar16::Scalar16(const ByteArray& encoded) {

    endianTest();
    decode(encoded, endian);

}

Scalar16::Scalar16(const ByteArray& encoded, int eType) {

    endianTest();
    decode(encoded, eType);

}

Scalar16::Scalar16(const Scalar16& other)
: value(other.value) {
}

Scalar16& Scalar16::operator= (const Scalar16& other) {

    value = other.value;
    return *this;

}

Scalar16::~Scalar16() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
int16_t Scalar16::decode(const ByteArray& encoded) {

    return Scalar16(encoded).getIntValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Scalar16::decode(const ByteArray& encoded, int eType) {

    value = 0;
    switch (eType) {
        case BIGENDIAN:
            value = encoded[0];
            value = value << 8;
            value |= encoded[1];
            break;
        case LITTLEENDIAN:
            value = encoded[1];
            value = value << 8;
            value |= encoded[0];
            break;
        default:
            throw OutOfRangeException("Illegal endian value");
    }

}

/*
 * Convenience function. Returns encoded array in native
 * endian format.
 */
ByteArray Scalar16::encode(int16_t v) {

    return Scalar16(v).getEncoded();

}

/*
 * Endian test.
 */
void Scalar16::endianTest() {

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
ByteArray Scalar16::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Scalar16::getEncoded(int eType) const {

    ByteArray result(2);
    long tmp = value;
    switch(eType) {
        case LITTLEENDIAN:
            result[0] = tmp & 0xff;
            tmp = tmp >> 8;
            result[1] = tmp & 0xff;
            break;
        case BIGENDIAN:
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
 * Returns a signed integer value.
 */
int16_t Scalar16::getIntValue() const {

    return value;

}

}

