#ifndef CKPGPSECRETKEY_H_INCLUDED
#define CKPGPSECRETKEY_H_INCLUDED

#include "openpgp/packet/PublicKey.h"
#include "data/BigInteger.h"
#include "data/Unsigned16.h"

namespace CK {
    class RSAPrivateCrtKey;
}

namespace CKPGP {

class SecretKey : public Packet {

    public:
        SecretKey(const PublicKey& pk);
        SecretKey(const CK::BigInteger& d, const CK::BigInteger& p,
                   const CK::BigInteger& q, const CK::BigInteger& qInv,
                                                const PublicKey& pk);    // RSA key
        SecretKey(const CK::BigInteger& x, const PublicKey& pk);         // DSA or Elgamal
                                                                        // Alogirthm of the public
                                                                        // key determines.
        SecretKey(const CK::ByteArray& encoded);
        ~SecretKey();

    protected:
        SecretKey(uint8_t tag, const PublicKey& pk);

    public:
        SecretKey(const SecretKey& other);
        SecretKey& operator= (const SecretKey& other);

    public:
        void setPrivateKey(CK::RSAPrivateCrtKey *pk);

    public:
        void encode();

    private:
        void decode(const CK::ByteArray& encoded);
        void decodeRSAIntegers(const CK::ByteArray& encoded);
        CK::ByteArray encodeRSAIntegers();

    private:
        PublicKey *publicKey;
        uint8_t s2kUsage;
        uint8_t algorithm;  // Symmetric cipher
        CK::ByteArray s2kSpecifier;
        CK::ByteArray iv;
        CK::BigInteger rsaExponent;
        CK::BigInteger rsap;
        CK::BigInteger rsaq;
        CK::BigInteger rsaqInv;
        CK::BigInteger dsax;
        CK::BigInteger elgamalx;
        CK::Unsigned16 checksum;    // Calculated at encoding.

};

}

#endif  // CKPGPSECRETKEY_H_INCLUDED
