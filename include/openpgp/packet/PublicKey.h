#ifndef PUBLICKEY_H_INCLUDED
#define PUBLICKEY_H_INCLUDED

#include "packet/Packet.h"
#include "data/BigInteger.h"

namespace CKPGP {

class PublicKey : public Packet {

    public:
        PublicKey();
        ~PublicKey();

    private:
        PublicKey(const PublicKey& other);
        PublicKey& operator= (const PublicKey& other);

    public:
        CK::ByteArray encode() const;

    private:
        uint8_t version;
        uint32_t createTime;
        uint8_t algorithm;
        CK::BigInteger RSAModulus;
        CK::BigInteger RSAExponent;
        CK::BigInteger DSAPrime;
        CK::BigInteger DSAOrder;
        CK::BigInteger DSAGenerator;
        CK::BigInteger DSAValue;
        CK::BigInteger elgamalPrime;
        CK::BigInteger elgamalGenerator;
        CK::BigInteger elgamalValue;

};

}

#endif  // PUBLICKEY_H_INCLUDED
