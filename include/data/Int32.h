#ifndef INT32_H_INCLUDED
#define INT32_H_INCLUDED

#include "ByteArray.h"
#include <cstdint>

namespace CK {

class Int32 {

    public:
        Int32();
        Int32(int32_t v);
        Int32(const ByteArray& encoded);
        Int32(const ByteArray& encoded, int endian);
        Int32(const Int32& other);

        ~Int32();

    public:
        Int32& operator= (const Int32& other);

    public:
        // Decode a byte array.
        void decode(const ByteArray& encoded, int endian);
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns a signed integer.
        int32_t getIntValue() const;

    public:
        static ByteArray encode(int32_t value);
        static int32_t decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int32_t value;
        static int endian;

};

}

#endif  // INT32_H_INCLUDED
