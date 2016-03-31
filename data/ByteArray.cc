#include "data/ByteArray.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/BadParameterException.h"

namespace CK {

ByteArray::ByteArray() {
}

ByteArray::ByteArray(const ByteArray& other)
: bytes(other.bytes) {
}

/*
 * Construct a ByteArray object from another ByteArray's range.
 */
ByteArray::ByteArray(const ByteArray& other, unsigned offset, unsigned length) {

    if (offset + length > other.getLength()) {
        throw OutOfRangeException("Array parameters out of range");
    }

    uint8_t *array = other.range(offset, length).asArray();
    bytes = Array(array, array+length);

}

/*
 * Construct a ByteArray object from a C array.
 */
ByteArray::ByteArray(const uint8_t *bytearray, unsigned length)
: bytes(bytearray, bytearray+length) {
}

/*
 * Construct a ByteArray object from a standard string.
 */
ByteArray::ByteArray(const std::string& str) {

    const uint8_t *string =
            reinterpret_cast<const uint8_t*>(str.c_str());
    unsigned length = str.length();
    bytes = Array(string, string+length);

}

/*
 * Construct a ByteArray of a specified size. The content is
 * undefined.
 */
ByteArray::ByteArray(unsigned size, uint8_t fill) {

    bytes.resize(size, fill);

}

/*
 * Cconstruct a ByteArray object from an Array object.
 */
ByteArray::ByteArray(const Array& array)
: bytes(array) {
}

ByteArray::~ByteArray() {
}

ByteArray& ByteArray::operator= (const ByteArray& other) {

    bytes = other.bytes;
    return *this;

}

uint8_t& ByteArray::operator[] (unsigned index) {

    return bytes[index];

}

uint8_t ByteArray::operator[] (unsigned index) const {

    return bytes[index];

}

void ByteArray::append(const ByteArray& other) {

    bytes.insert(bytes.end(), other.bytes.begin(), other.bytes.end());

}

void ByteArray::append(const ByteArray& other, unsigned offset, unsigned length) {

    if (offset + length > other.getLength()) {
        throw OutOfRangeException("Array parameters out of range");
    }
    append(other.range(offset, length));

}

void ByteArray::append(const uint8_t *byte, unsigned length) {

    Array appendix(byte, byte+length);
    bytes.insert(bytes.end(), appendix.begin(), appendix.end());

}

void ByteArray::append(uint8_t c) {

    bytes.push_back(c);

}

uint8_t *ByteArray::asArray() const {

    uint8_t *result = new uint8_t[bytes.size()];
    uint8_t *resultptr = result;
    ArrayConstIter it = bytes.begin();
    while (it != bytes.end()) {
        *resultptr = *it;
        resultptr++;
        it++;
    }
    return result;

}

std::string ByteArray::asHex(unsigned index) const {

    if (index >= bytes.size()) {
        throw OutOfRangeException("Index out of range");
    }

    std::string result("0x");

    uint8_t u = bytes[index] >> 4;
    if (u < 0x0a) {
        result += (u + '0');
    }
    else {
        result += ((u - 0x0a) + 'a');
    }

    uint8_t l = bytes[index] & 0x0f;
    if (l < 0x0a) {
        result += (l + '0');
    }
    else {
        result += ((l - 0x0a) + 'a');
    }

    return result;

}

void ByteArray::clear() {

    bytes.clear();

}

/*
 * Copy a subrange of this another array array to this one. Existing
 * elements within the copy range are overwritten. The array size
 * is adjusted accordingly. OutOfRangeException if the other array
 * size is violated. If length is zero, the copy size is calculated from
 * the size of the other array.
 */
void ByteArray::copy(unsigned offset, const ByteArray& other,
                        unsigned otherOffset, unsigned length) {

    unsigned transfer = length;
    if (length == 0) {
        transfer = other.getLength() - otherOffset;
    }
    if (otherOffset > other.getLength()
                    || otherOffset + transfer > other.getLength()) {
        throw OutOfRangeException("ByteArray copy out of range");
    }
    if (offset + transfer > bytes.size()) {
        bytes.resize(offset + transfer);
    }
    ArrayConstIter otherIt = other.bytes.begin();
    otherIt += otherOffset;
    ArrayIter it = bytes.begin();
    it += offset;
    while (otherIt < other.bytes.end()) {
        *it++ = *otherIt++;
    }

}

bool ByteArray::equals(const ByteArray& other) const {

    return bytes == other.bytes;

}

unsigned ByteArray::getLength() const {

    return bytes.size();

}


/*
 * Push a byte onto the front of the array.
 */
void ByteArray::push(uint8_t b) {

    bytes.push_front(b);

}

ByteArray ByteArray::range(unsigned offset, unsigned length) const {

    if (offset + length > bytes.size()) {
        throw OutOfRangeException("Array parameters out of range");
    }

    ArrayConstIter it = bytes.begin() + offset;
    Array result(it, it+length);
    return result;

}

void ByteArray::setLength(unsigned newLength) {

    bytes.resize(newLength, 0);

}

// Global operators
bool operator== (const ByteArray& lhs, const ByteArray& rhs) {
    return lhs.equals(rhs);
}

bool operator!= (const ByteArray& lhs, const ByteArray& rhs) {
    return !lhs.equals(rhs);
}

}

// Global operators.
bool operator== (const CK::ByteArray& lhs, const CK::ByteArray& rhs)
{ return lhs.equals(rhs); }
bool operator!= (const CK::ByteArray& lhs, const CK::ByteArray& rhs)
{ return !lhs.equals(rhs); }
std::ostream& operator <<(std::ostream& out, const CK::ByteArray& bytes) {

    int linecount = 0;
    for (unsigned n = 0; n < bytes.getLength(); ++n) {
        out << bytes.asHex(n) << ", ";
        linecount++;
        if (linecount == 16) {
            out << std::endl;
            linecount = 0;
        }
    }

    return out;

}

CK::ByteArray operator^ (const CK::ByteArray& lhs, const CK::ByteArray& rhs) {

    if (lhs.getLength() != rhs.getLength()) {
        throw CK::BadParameterException("XOR operator: Array sizes not equal.");
    }

    CK::ByteArray result(lhs.getLength());
    for (unsigned n = 0; n < lhs.getLength(); ++n) {
        result[n] = lhs[n] ^ rhs[n];
    }

    return result;

}

