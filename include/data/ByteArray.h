#ifndef BYTEARRAY_H_INCLUDED
#define BYTEARRAY_H_INCLUDED

#include <deque>
#include <string>
#include <ostream>

namespace CK {

/*
 * This really just encapsulates a deque, but it provides
 * some convenience methods and extra management
 */
class ByteArray {

    private:
        typedef std::deque<unsigned char> Array;

    public:
        ByteArray();
        ByteArray(const ByteArray& other);
        // Construct a ByteArray from anther ByteArray's range
        ByteArray(const ByteArray& other, unsigned offset, unsigned length);
        // Construct a ByteArray from an array of unsigned char
        ByteArray(const unsigned char *bytes, unsigned length);
        // Construct a ByteArray from a standard string.
        ByteArray(const std::string& str);
        // Construct a ByteArray with an initial size
        ByteArray(unsigned size, unsigned char fill=0);
        ~ByteArray();

    private:
        ByteArray(const Array& byteArray);

    public:
        ByteArray& operator= (const ByteArray& other);
        unsigned char& operator[] (unsigned index);
        unsigned char operator[] (unsigned index) const;

    public:
        void append(const ByteArray& other);
        void append(const ByteArray& other, unsigned offset, unsigned length);
        void append(const unsigned char *byte, unsigned length);
        void append(unsigned char c);
        unsigned char *asArray() const;   // Returns an array of bytes.
        std::string asHex(unsigned index) const;
        void clear();
        void copy(unsigned offset, const ByteArray& other,
                        unsigned otherOffset, unsigned length=0);
        bool equals(const ByteArray& other) const;
        unsigned getLength() const;
        void push(const ByteArray& b);
        void push(unsigned char b);
        ByteArray range(unsigned offset, unsigned length) const;
        void setLength(unsigned newLength);

    private:
        Array bytes;
        typedef Array::const_iterator ArrayConstIter;
        typedef Array::iterator ArrayIter;

};

}

// Global operators
bool operator== (const CK::ByteArray& lhs, const CK::ByteArray& rhs);
bool operator!= (const CK::ByteArray& lhs, const CK::ByteArray& rhs);
CK::ByteArray operator^ (const CK::ByteArray& lhs, const CK::ByteArray& rhs);
std::ostream& operator <<(std::ostream& out, const CK::ByteArray& bytes);

#endif // BYTEARRAY_H_INCLUDED
