#ifndef PKCS1RSASSA_H_INCLUDED
#define PKCS1RSASSA_H_INCLUDED

#include "cipher/RSA.h"

namespace CK {

class Digest;

class PKCS1rsassa : public RSA {

    public:
        PKCS1rsassa(Digest *digest);
        PKCS1rsassa(Digest *digest, int saltLength);
        ~PKCS1rsassa();

    private:
        PKCS1rsassa();
        PKCS1rsassa(const PKCS1rsassa& other);
        PKCS1rsassa& operator= (const PKCS1rsassa& other);

    public:
        ByteArray decrypt(const RSAPrivateKey& K, const ByteArray& C);
        ByteArray encrypt(const RSAPublicKey& K,
                                const ByteArray& C);
        ByteArray sign(const RSAPrivateKey& K, const ByteArray& M);
        bool verify(const RSAPublicKey& K, const ByteArray& M,
                                const ByteArray& S);

    private:
        ByteArray emsaPKCS1Encode(const ByteArray&  M, int emLen);

    private:
        Digest *digest;
        ByteArray algorithmOID;

};

}
#endif  // PKCS1RSASSA_H_INCLUDED
