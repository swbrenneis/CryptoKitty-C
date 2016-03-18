#ifndef SCALAR32_H_INCLUDED
#define SCALAR32_H_INCLUDED

/*
 * This class provides various transformation and
 * codec functions for signed and unsigned 32 bit
 * integers.
 */
class Scalar32 {

    public:
        static const unsigned char LITTLEENDIAN;
        static const unsigned char BIGENDIAN;

    public:
        Scalar32();
        Scalar32(unsigned char* bValue);
        Scalar32(unsigned uValue);
        Scalar32(int iValue);
        Scalar32(const Scalar32& other);

        ~Scalar32();

    public:
        Scalar32& operator= (const Scalar32& other);

    public:
        // Endian-ness test.
        static void endianTest();

    public:
	unsigned char *asArray();
        int asSigned();
        unsigned asUnsigned();

    public:
        static unsigned char *encode(unsigned u32,
                                            int endian);
        static unsigned decode(unsigned char *bytes,
                                            int endian);

    public:
        static unsigned char endian;

    private:
        unsigned u32;
        bool uValid;
        int s32;
        bool sValid;
        unsigned char bytes[4];
        bool bytesValid;

};

#endif  // SCALAR32_H_INCLUDED
