#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#include "data/BigInteger.h"

namespace CK {

class RSAPublicKey;
class RSAPrivateKey;

class RSA {

    protected:
        RSA();

    public:
        virtual ~RSA();

    private:
        static const BigInteger MASK;

    public:
        virtual ByteArray
                decrypt(const RSAPrivateKey& K, const ByteArray& C)=0;
        virtual ByteArray
                encrypt(const RSAPublicKey& K, const ByteArray& C)=0;
        virtual ByteArray sign(const RSAPrivateKey& K, const ByteArray& M)=0;
        virtual bool
                verify(const RSAPublicKey& K, const ByteArray& M,
                                    const ByteArray& S)=0;

    protected:
        ByteArray i2osp(const BigInteger& X, unsigned xLen);
        BigInteger os2ip(const ByteArray& X);
        BigInteger rsavp1(const RSAPublicKey& K, const BigInteger& s); 
        //ByteArray rsaXor(const ByteArray& a, const ByteArray& b) const;

};

}

#endif  // RSA_H_INCLUDED
