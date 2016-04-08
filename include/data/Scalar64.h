#ifndef SCALAR64_H_INCLUDED
#define SCALAR64_H_INCLUDED

#include "ByteArray.h"
#include <cstdlib>

namespace CK {

class Scalar64 {

    public:
        Scalar64();
        Scalar64(int64_t v);
        Scalar64(const ByteArray& encoded);
        Scalar64(const ByteArray& encoded, int endian);
        Scalar64(const Scalar64& other);

        ~Scalar64();

    public:
        Scalar64& operator= (const Scalar64& other);

    public:
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns a signed long integer.
        int64_t getLongValue() const;
        // Returns an unsigned long integer.
        uint64_t getUnsignedValue() const;

    public:
        static ByteArray encode(int64_t value);
        static int64_t decode(const ByteArray& value);
                
    private:
        void decode(const ByteArray& encoded, int endian);
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int64_t value;
        uint64_t uvalue;
        static int endian;

};

}

#endif  // SCALAR64_H_INCLUDED
