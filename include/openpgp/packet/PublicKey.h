#ifndef CKPGPPUBLICKEY_H_INCLUDED
#define CKPGPPUBLICKEY_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/BigInteger.h"

namespace CK {
    class RSAPublicKey;
}

#ifndef CKPGPPACKET_H_INCLUDED
#error CK::Packet not defined!
#endif

namespace CKPGP {

class PublicKey : public CKPGP::Packet {

    public:
        PublicKey();
        PublicKey(const CK::BigInteger& m, const CK::BigInteger& e,
                                                        uint8_t alg);    // RSA key
        PublicKey(const CK::BigInteger& p, const CK::BigInteger& o,
                    const CK::BigInteger g, const CK::BigInteger& v);    // DSA key
        PublicKey(const CK::BigInteger& p, const CK::BigInteger& g,
                    const CK::BigInteger& v);                           // Elgamal key
        PublicKey(const coder::ByteArray& encoded);
        ~PublicKey();

    protected:
        PublicKey(uint8_t tag);

    public:
        PublicKey(const PublicKey& other);
        PublicKey& operator= (const PublicKey& other);

    public:
        uint8_t getAlgorithm() const;
        const CK::BigInteger& getRSAExponent() const;
        CK::RSAPublicKey *getRSAPublicKey();
        void setPublicKey(CK::RSAPublicKey *pk, uint8_t algorithm);

    public:
        static const uint8_t RSASIGN;
        static const uint8_t RSAENCRYPT;
        static const uint8_t RSAANY;
        static const uint8_t DSA;
        static const uint8_t ELGAMAL;

    public:
        void encode();

    private:
        void decode(const coder::ByteArray& encoded);
        void decodeDSAIntegers(const coder::ByteArray& encoded);
        void decodeElgamalIntegers(const coder::ByteArray& encoded);
        void decodeRSAIntegers(const coder::ByteArray& encoded);
        coder::ByteArray encodeDSAIntegers() const;
        coder::ByteArray encodeElgamalIntegers() const;
        coder::ByteArray encodeRSAIntegers() const;

    private:
        uint8_t version;
        uint32_t createTime;
        uint8_t algorithm;
        CK::BigInteger rsaModulus;
        CK::BigInteger rsaExponent;
        CK::BigInteger dsaPrime;
        CK::BigInteger dsaOrder;
        CK::BigInteger dsaGenerator;
        CK::BigInteger dsaValue;
        CK::BigInteger elgamalPrime;
        CK::BigInteger elgamalGenerator;
        CK::BigInteger elgamalValue;

};

}

#endif  // CKPGPPUBLICKEY_H_INCLUDED
