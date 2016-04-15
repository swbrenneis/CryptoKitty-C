#include "data/Int16.h"
#include "exceptions/OutOfRangeException.h"

namespace CK {

// Static initializations
const int Int16::BIGENDIAN = 1;
const int Int16::LITTLEENDIAN = 2;
int Int16::endian = 0;

Int16::Int16() 
: value(0) {

    endianTest();
}

Int16::Int16(int16_t v) 
: value(v) {

    endianTest();

}

Int16::Int16(const ByteArray& encoded) {

    if (encoded.getLength() < 2) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, endian);

}

Int16::Int16(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 2) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, eType);

}

Int16::Int16(const Int16& other)
: value(other.value) {
}

Int16& Int16::operator= (const Int16& other) {

    value = other.value;
    return *this;

}

Int16::~Int16() {
}

/*
 * Convenience function. Returns a long value decoded
 * from a byte array in native endian order.
 */
int16_t Int16::decode(const ByteArray& encoded) {

    return Int16(encoded).getIntValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Int16::decode(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 2) {
        throw OutOfRangeException("Invalid encoding length");
    }

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
ByteArray Int16::encode(int16_t v) {

    return Int16(v).getEncoded();

}

/*
 * Endian test.
 */
void Int16::endianTest() {

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
ByteArray Int16::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Int16::getEncoded(int eType) const {

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
int16_t Int16::getIntValue() const {

    return value;

}

}

