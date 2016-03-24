#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#include "data/BigInteger.h"

namespace CK {

class RSA {

    protected:
        RSA();

    public:
        virtual ~RSA();

    private:
        static const BigInteger MASK;

    protected:

        struct PublicKey {
            BigInteger n;
            BigInteger e;
            int bitSize;
        };

        struct ModulusPrivateKey {
            BigInteger n;
            BigInteger d;
            int bitSize;
        };

        struct CRTPrivateKey {
            // First prime.
            BigInteger p;
            // Second prime.
            BigInteger q;
            // First prime CRT exponent.
            BigInteger dP;
            // Second prime CRT exponent.
            BigInteger dQ;
            // CRT coefficient.
            BigInteger qInv;
            int bitSize;
        };

    public:
        virtual ByteArray
                decrypt(const ModulusPrivateKey& K,
                            const ByteArray& C)=0;
        virtual ByteArray
                decrypt(const CRTPrivateKey& K,
                            const ByteArray& C)=0 ;
        virtual ByteArray
                decrypt(const PublicKey& K,
                            const ByteArray& C)=0;
};

}

#endif  // RSA_H_INCLUDED
