#include "data/Unsigned16.h"
#include "exceptions/OutOfRangeException.h"

namespace CK {

// Static initializations
const int Unsigned16::BIGENDIAN = 1;
const int Unsigned16::LITTLEENDIAN = 2;
int Unsigned16::endian = 0;

Unsigned16::Unsigned16() 
: value(0) {

    endianTest();
}

Unsigned16::Unsigned16(uint16_t v) 
: value(v) {

    endianTest();

}

Unsigned16::Unsigned16(const ByteArray& encoded) {

    if (encoded.getLength() < 2) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, endian);

}

Unsigned16::Unsigned16(const ByteArray& encoded, int eType) {

    if (encoded.getLength() < 2) {
        throw OutOfRangeException("Invalid encoding length");
    }

    endianTest();
    decode(encoded, eType);

}

Unsigned16::Unsigned16(const Unsigned16& other)
: value(other.value) {
}

Unsigned16& Unsigned16::operator= (const Unsigned16& other) {

    value = other.value;
    return *this;

}

Unsigned16::~Unsigned16() {
}

/*
 * Convenience function. Returns a short value decoded
 * from a byte array in native endian order.
 */
uint16_t Unsigned16::decode(const ByteArray& encoded) {

    return Unsigned16(encoded).getUnsignedValue();

}

/*
 * Decode the encoded array in the specified endian format.
 */
void Unsigned16::decode(const ByteArray& encoded, int eType) {

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
ByteArray Unsigned16::encode(uint16_t v) {

    return Unsigned16(v).getEncoded();

}

/*
 * Endian test.
 */
void Unsigned16::endianTest() {

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
ByteArray Unsigned16::getEncoded() const {

    return getEncoded(endian);

}

/*
 * Returns the value encoded in an 8 byte array in the
 * specified endian order.
 */
ByteArray Unsigned16::getEncoded(int eType) const {

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
uint16_t Unsigned16::getUnsignedValue() const {

    return value;

}

}

