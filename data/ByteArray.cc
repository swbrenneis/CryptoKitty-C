#include "../include/data/ByteArray.h"
#include "../include/data/DataOutOfRangeException.h"

ByteArray::ByteArray() {
}

ByteArray::ByteArray(const ByteArray& other)
: bytes(other.bytes) {
}

/*
 * Create a ByteArray object from a C array.
 */
ByteArray::ByteArray(const unsigned char *bytearray, int length)
: bytes(bytearray, bytearray+length) {
}

/*
 * Create a ByteArray of a specified size. The content is
 * undefined.
 */
ByteArray::ByteArray(int size) {

    bytes.resize(size);

}

/*
 * Creates a ByteArray object from an Array object.
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

unsigned char& ByteArray::operator[] (unsigned index) {

    return bytes[index];

}

unsigned char ByteArray::operator[] (unsigned index) const {

    return bytes[index];

}

void ByteArray::append(const ByteArray& other) {

    bytes.insert(bytes.end(), other.bytes.begin(), other.bytes.end());

}

void ByteArray::append(const unsigned char *byte, int length) {

    Array appendix(byte, byte+length);
    bytes.insert(bytes.end(), appendix.begin(), appendix.end());

}

void ByteArray::append(unsigned char c) {

    bytes.push_back(c);

}

unsigned char *ByteArray::asArray() const {

    unsigned char *result = new unsigned char[bytes.size()];
    unsigned char *resultptr = result;
    ArrayConstIter it = bytes.begin();
    while (it != bytes.end()) {
        *resultptr++ = *it++;
    }
    return result;

}

void ByteArray::clear() {

    bytes.clear();

}

/*
 * Copy a subrange of this another array array to this one. Existing
 * elements within the copy range are overwritten. The array size
 * is adjusted accordingly. DataOutOfRangeException if the other array
 * size is violated. If length is zero, the copy size is calculated from
 * the size of the other array.
 */
void ByteArray::copy(unsigned offset, const ByteArray& other,
                        unsigned otherOffset, unsigned length) {

    unsigned transfer = length;
    if (length == 0) {
        transfer = other.length() - otherOffset;
    }
    if (otherOffset > other.length()
                    || otherOffset + transfer > other.length()) {
        throw DataOutOfRangeException("ByteArray copy out of range");
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

unsigned ByteArray::length() const {

    return bytes.size();

}

ByteArray ByteArray::range(unsigned offset, unsigned length) const {

    ArrayConstIter it = bytes.begin() + offset;
    Array result(it, it+length);
    return result;

}

void ByteArray::setLength(unsigned newLength) {

    bytes.resize(newLength);

}

