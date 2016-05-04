#ifndef INT64_H_INCLUDED
#define INT64_H_INCLUDED

#include "ByteArray.h"
#include <cstdlib>

namespace CK {

class Int64 {

    public:
        Int64();
        Int64(int64_t v);
        Int64(const ByteArray& encoded);
        Int64(const ByteArray& encoded, int endian);
        Int64(const Int64& other);

        ~Int64();

    public:
        Int64& operator= (const Int64& other);

    public:
        // Decode a byte array.
        void decode(const ByteArray& encoded, int endian);
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns a signed long integer.
        int64_t getLongValue() const;

    public:
        static ByteArray encode(int64_t value);
        static int64_t decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int64_t value;
        static int endian;

};

}

#endif  // INT64_H_INCLUDED
