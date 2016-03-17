#ifndef BYTEARRAY_H_INCLUDED
#define BYTEARRAY_H_INCLUDED

#include <deque>

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
        // Create a ByteArray from an array of unsigned char
        ByteArray(const unsigned char *bytes, int length);
        // Create a ByteArray with an initial size
        ByteArray(int size);
        ~ByteArray();

    private:
        ByteArray(const Array& byteArray);

    public:
        ByteArray& operator= (const ByteArray& other);
        unsigned char& operator[] (unsigned index);
        unsigned char operator[] (unsigned index) const;

    public:
        void append(const ByteArray& other);
        void append(const unsigned char *byte, int length);
        void append(unsigned char c);
        unsigned char *asArray() const;   // Returns an array of bytes.
        void clear();
        void copy(unsigned offset, const ByteArray& other,
                        unsigned otherOffset, unsigned length=0);
        bool equals(const ByteArray& other) const;
        unsigned length() const;
        ByteArray range(unsigned offset, unsigned length) const;
        void setLength(unsigned newLength);

    private:
        Array bytes;
        typedef Array::const_iterator ArrayConstIter;
        typedef Array::iterator ArrayIter;

};

// Global operators
bool operator== (const ByteArray& lhs, const ByteArray& rhs);
bool operator!= (const ByteArray& lhs, const ByteArray& rhs);

#endif // BYTEARRAY_H_INCLUDED
