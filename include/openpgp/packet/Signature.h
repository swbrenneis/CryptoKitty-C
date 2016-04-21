#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#include "packet/Packet.h"
#include "data/BigInteger.h"
#include "data/ByteArray.h"
#include <deque>

namespace CKPGP {

class Signature : public Packet {

    public:
        Signature();
        ~Signature();

    private:
        Signature(const Signature& other);
        Signature& operator= (const Signature& other);

    public:
        static const uint8_t BINARY;
        static const uint8_t TEXT;
        static const uint8_t STANDALONE;
        static const uint8_t GENERICPK;
        static const uint8_t PERSONAPK;
        static const uint8_t CASUALPK;
        static const uint8_t POSITIVEPK;
        static const uint8_t SUBKEY;
        static const uint8_t PRIMARYKEY;
        static const uint8_t DIRECT;
        static const uint8_t KEYREVOKE;
        static const uint8_t SUBKEYREVOKE;
        static const uint8_t CERTREVOKE;
        static const uint8_t TIMESTAMP;
        static const uint8_t CONFIRMATION;

    public:
        void setType(uint8_t t);

    private:
        uint8_t version;
        uint8_t type;
        uint8_t pkAlgorithm;
        uint8_t hashAlgorithm;
        uint16_t subpacketCount;

        typedef std::deque<CK::ByteArray> SubpacketList;
        SubpacketList hashedSubpackets;
        SubpacketList unhashedSubpackets;

        uint8_t hashFragment[2];
        CK::BigInteger RSASig;
        CK::BigInteger DSAr;
        CK::BigInteger DSAs;

};

}

#endif  // SIGNATURE_H_INCLUDED
