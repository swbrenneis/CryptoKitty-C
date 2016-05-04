#ifndef INT16_H_INCLUDED
#define INT16_H_INCLUDED

#include "ByteArray.h"
#include <cstdint>

namespace CK {

class Int16 {

    public:
        Int16();
        Int16(int16_t v);
        Int16(const ByteArray& encoded);
        Int16(const ByteArray& encoded, int endian);
        Int16(const Int16& other);

        ~Int16();

    public:
        Int16& operator= (const Int16& other);

    public:
        // Decode a byte array.
        void decode(const ByteArray& encoded, int endian);
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns a signed integer.
        int16_t getIntValue() const;

    public:
        static ByteArray encode(int16_t value);
        static int16_t decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int16_t value;
        static int endian;

};

}

#endif  // INT16_H_INCLUDED
