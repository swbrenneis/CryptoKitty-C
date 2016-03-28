#ifndef PSSRSASSA_H_INCLUDED
#define PSSRSASSA_H_INCLUDED

#include "cipher/RSA.h"

namespace CK {

class Digest;

class PSSrsassa : public RSA {

    public:
        PSSrsassa(Digest *digest); // Default salt length 10.
        PSSrsassa(Digest *digest, int sLen);
        ~PSSrsassa();

    private:
        PSSrsassa();
        PSSrsassa(const PSSrsassa& other);
        PSSrsassa& operator= (const PSSrsassa& other);

    public:
        ByteArray decrypt(const RSAPrivateKey& K, const ByteArray& C);
        ByteArray encrypt(const RSAPublicKey& K,
                                const ByteArray& C);
        ByteArray sign(const RSAPrivateKey& K, const ByteArray& M);
        bool verify(const RSAPublicKey& K, const ByteArray& M,
                                const ByteArray& S);

    private:
        ByteArray emsaPSSEncode(const ByteArray&  M, int emLen);
        bool emsaPSSVerify(const ByteArray& M, const ByteArray& EM,
                                                            int emBits);

    private:
        Digest *digest;
        ByteArray algorithmOID;
        int saltLength;

};

}
#endif  // PSSRSASSA_H_INCLUDED
