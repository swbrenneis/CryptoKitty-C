#ifndef PEMCODEC_H_INCLUDED
#define PEMCODEC_H_INCLUDED

#include <coder/ByteArray.h>
#include <iostream>
#include <cstdint>

namespace CK {

class RSAPublicKey;
class RSAPrivateCrtKey;
class RSAPrivateKey;
class DERCodec;

class PEMCodec {

    public:
        PEMCodec();
        PEMCodec(bool x509Keys);
        ~PEMCodec();

    private:
        PEMCodec(const PEMCodec& other);
        PEMCodec& operator= (const PEMCodec& other);

    public:
        RSAPublicKey *decodePublicKey(std::istream& in);
        RSAPrivateKey *decodePrivateKey(std::istream& in);
        void encode(std::ostream& out, const RSAPublicKey& key);
        void encode(std::ostream& out, const RSAPublicKey& publicKey,
                                    const RSAPrivateCrtKey& privateKey);

    private:
        void encodePrimes(coder::ByteArray& primes, const RSAPublicKey& publicKey,
                                                    const RSAPrivateCrtKey& privateKey);
        RSAPrivateKey *getPrivateKey(const coder::ByteArray& key);
        RSAPublicKey *getPublicKey(const coder::ByteArray& key);
        RSAPrivateKey *parsePrivateKey(const coder::ByteArray& key);
        RSAPublicKey *parsePublicKey(const coder::ByteArray& key);
        void setPrivateKeyType(std::istream& in, const std::string& preamble);
        void setPublicKeyType(std::istream& in, const std::string& preamble);

    private:
        bool x509Keys;
        DERCodec *derCodec;

};

}

#endif // PEMCODEC_H_INCLUDED

