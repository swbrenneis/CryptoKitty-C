#ifndef SCALAR64_H_INCLUDED
#define SCALAR64_H_INCLUDED

#include "ByteArray.h"

class Scalar64 {

    public:
        Scalar64();
        Scalar64(long v);
        Scalar64(const Scalar64& other);

        ~Scalar64();

    public:
        Scalar64& operator= (const Scalar64& other);

    public:
        // Returns an encoded array in the native endian format.
        ByteArray getEncoded();
        // Returns an encoded array in the specified endian format.
        ByteArray getEncoded(int endian);

    public:
        static ByteArray encode(long value);
        static long decode(const ByteArray& value);
                
    private:
        void endianTest();

    public:
        static const int BIGENDIAN;
        static const int LITTLEENDIAN;

    private:
        long value;
        static int endian;

};

#endif  // SCALAR64_H_INCLUDED