#ifndef SCALAR32_H_INCLUDED
#define SCALAR32_H_INCLUDED
#include <cstdlib>

#include "ByteArray.h"

namespace CK {

class Scalar32 {

    public:
        Scalar32();
        Scalar32(int32_t v);
        Scalar32(uint32_t v, bool u);
        Scalar32(const ByteArray& encoded);
        Scalar32(const ByteArray& encoded, int endian);
        Scalar32(const Scalar32& other);

        ~Scalar32();

    public:
        Scalar32& operator= (const Scalar32& other);

    public:
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded(bool u = false) const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian, bool u = false) const;
        // Returns a signed integer.
        int32_t getIntValue() const;
        // Returns an unsigned integer.
        int32_t getUnsignedValue() const;

    public:
        static ByteArray encode(int32_t value);
        static int32_t decode(const ByteArray& value);
                
    private:
        void decode(const ByteArray& encoded, int endian);
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;
        static const bool UNSIGNED;

    private:
        int32_t value;
        uint32_t uvalue;
        static int endian;

};

}

#endif  // SCALAR32_H_INCLUDED
