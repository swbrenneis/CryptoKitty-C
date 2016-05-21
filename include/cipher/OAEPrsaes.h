#ifndef OAEPRSAES_H_INCLUDED
#define OAEPRSAES_H_INCLUDED

#include "cipher/RSA.h"
#include "coder/ByteArray.h"

namespace CK {

class Digest;

class OAEPrsaes : public RSA {

    public:
        enum HashAlgorithm { sha1, sha256, sha384, sha512 };

    public:
        OAEPrsaes(HashAlgorithm ha, const coder::ByteArray& l);
        ~OAEPrsaes();

    private:
        OAEPrsaes(const OAEPrsaes& other);
        OAEPrsaes& operator= (const OAEPrsaes& other);

    public:
        coder::ByteArray
                decrypt(const RSAPrivateKey& K, const coder::ByteArray& C);
        coder::ByteArray
                encrypt(const RSAPublicKey& K, const coder::ByteArray& P);
        coder::ByteArray sign(const RSAPrivateKey& K, const coder::ByteArray& M);
        bool verify(const RSAPublicKey& K, const coder::ByteArray& M,
                                                    const coder::ByteArray& S);

    private:
        coder::ByteArray emeOAEPDecode(uint32_t k, const coder::ByteArray& em);
        coder::ByteArray emeOAEPEncode(uint32_t k, const coder::ByteArray& p);

    private:
        HashAlgorithm algorithm;
        coder::ByteArray label;
        Digest *digest;

};

}

#endif  // OAEPRSAES_H_INCLUDED
