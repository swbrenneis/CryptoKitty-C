#ifndef BYTEARRAY_H_INCLUDED
#define BYTEARRAY_H_INCLUDED

#include <deque>

/*
 * This really just encapsulates a deque, but it provides
 * some convenience methods and extra management
 */
class ByteArray {

    public:
        ByteArray();
        ByteArray(const ByteArray& other);
        // Create a ByteArray from an array of unsigned char
        ByteArray(const unsigned char *bytes, int length);
        // Create a ByteArray with an initial size
        ByteArray(int size);
        ~ByteArray();

    public:
        ByteArray& operator= (const ByteArray& other);
        unsigned char& operator[] (unsigned index);
        unsigned char operator[] (unsigned index) const;

    public:
        void append(const ByteArray& other);
        void append(const unsigned char *byte, int length);
        unsigned char *asArray();   // Returns an array of bytes.
        void copy(unsigned offset, const ByteArray& other,
                        unsigned otherOffset, unsigned length=0);
        unsigned length() const;
        ByteArray range(unsigned offset, unsigned length) const;
        void setLength(unsigned newLength)();

    private:
        typedef std::deque<unsigned char> Array;
        Array bytes;

};

#endif // BYTEARRAY_H_INCLUDED
