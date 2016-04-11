#ifndef UNSIGNED64_H_INCLUDED
#define UNSIGNED64_H_INCLUDED

#include "ByteArray.h"
#include <cstdlib>

namespace CK {

class Unsigned64 {

    public:
        Unsigned64();
        Unsigned64(uint64_t v);
        Unsigned64(const ByteArray& encoded);
        Unsigned64(const ByteArray& encoded, int endian);
        Unsigned64(const Unsigned64& other);

        ~Unsigned64();

    public:
        Unsigned64& operator= (const Unsigned64& other);

    public:
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns an unsigned long integer.
        uint64_t getUnsignedValue() const;

    public:
        static ByteArray encode(uint64_t value);
        static uint64_t decode(const ByteArray& value);
                
    private:
        void decode(const ByteArray& encoded, int endian);
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        uint64_t value;
        static int endian;

};

}

#endif  // UNSIGNED64_H_INCLUDED
