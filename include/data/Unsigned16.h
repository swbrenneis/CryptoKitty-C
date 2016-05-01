#ifndef UNSIGNED16_H_INCLUDED
#define UNSIGNED16_H_INCLUDED
#include <cstdlib>

#include "ByteArray.h"

namespace CK {

class Unsigned16 {

    public:
        Unsigned16();
        Unsigned16(uint16_t v);
        Unsigned16(const ByteArray& encoded);
        Unsigned16(const ByteArray& encoded, int endian);
        Unsigned16(const Unsigned16& other);

        ~Unsigned16();

    public:
        Unsigned16& operator= (const Unsigned16& other);

    public:
        // Decode a byte array.
        void decode(const ByteArray& encoded, int endian);
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns an unsigned integer.
        uint16_t getUnsignedValue() const;
        // Sets the unsigned value.
        void setValue(uint16_t v);

    public:
        static ByteArray encode(uint16_t value);
        static uint16_t decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        uint16_t value;
        static int endian;

};

}

#endif  // UNSIGNED16_H_INCLUDED
