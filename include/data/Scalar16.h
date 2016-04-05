#ifndef SCALAR16_H_INCLUDED
#define SCALAR16_H_INCLUDED
#include <cstdlib>

#include "ByteArray.h"

namespace CK {

class Scalar16 {

    public:
        Scalar16();
        Scalar16(int16_t v);
        Scalar16(const ByteArray& encoded);
        Scalar16(const ByteArray& encoded, int endian);
        Scalar16(const Scalar16& other);

        ~Scalar16();

    public:
        Scalar16& operator= (const Scalar16& other);

    public:
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
        void decode(const ByteArray& encoded, int endian);
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int16_t value;
        static int endian;

};

}

#endif  // SCALAR16_H_INCLUDED
