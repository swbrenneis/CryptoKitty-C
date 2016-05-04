#ifndef UNSIGNED32_H_INCLUDED
#define UNSIGNED32_H_INCLUDED
#include <cstdlib>

#include "ByteArray.h"

namespace CK {

class Unsigned32 {

    public:
        Unsigned32();
        Unsigned32(uint32_t v);
        Unsigned32(const ByteArray& encoded);
        Unsigned32(const ByteArray& encoded, int endian);
        Unsigned32(const Unsigned32& other);

        ~Unsigned32();

    public:
        Unsigned32& operator= (const Unsigned32& other);

    public:
        // Decode a byte array.
        void decode(const ByteArray& encoded, int endian);
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns an unsigned integer.
        uint32_t getUnsignedValue() const;
        // Sets the unsigned value.
        void setValue(uint32_t v);

    public:
        static ByteArray encode(uint32_t value);
        static uint32_t decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        uint32_t value;
        static int endian;

};

}

#endif  // UNSIGNED32_H_INCLUDED
