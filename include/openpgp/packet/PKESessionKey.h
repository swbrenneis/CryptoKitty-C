#ifndef PKESESSIONKEY_H_INCLUDED
#define PKESESSIONKEY_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/BigInteger.h"

namespace CKPGP {

class PKESessionKey : public Packet {

    public:
        PKESessionKey();
        PKESessionKey(const coder::ByteArray& encoded);
        ~PKESessionKey();

    private:
        PKESessionKey(const PKESessionKey& other);
        PKESessionKey& operator= (const PKESessionKey& other);

    public:
        void encode();

    private:
        uint8_t version;
        uint64_t keyID;
        uint8_t algorithm;
        coder::ByteArray sessionKey;
        CK::BigInteger RSASessionKey;
        CK::BigInteger ElgamalSessionKey;
        CK::BigInteger ElgamalBase;

};

}

#endif  // PKESESSIONKEY_H_INCLUDED
