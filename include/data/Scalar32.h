#ifndef SCALAR32_H_INCLUDED
#define SCALAR32_H_INCLUDED

#include "ByteArray.h"

class Scalar32 {

    public:
        Scalar32();
        Scalar32(int v);
        Scalar32(const ByteArray& encoded);
        Scalar32(const ByteArray& encoded, int endian);
        Scalar32(const Scalar32& other);

        ~Scalar32();

    public:
        Scalar32& operator= (const Scalar32& other);

    public:
        // Returns an encoded array in the native endian order.
        ByteArray getEncoded() const;
        // Returns an encoded array in the specified endian order.
        ByteArray getEncoded(int endian) const;
        // Returns a signed integer.
        int getIntValue() const;

    public:
        static ByteArray encode(int value);
        static int decode(const ByteArray& value);
                
    private:
        void decode(const ByteArray& encoded, int endian);
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        int value;
        static int endian;

};

#endif  // SCALAR32_H_INCLUDED
