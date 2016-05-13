#ifndef SIGNATURE_H_INCLUDED
#define SIGNATURE_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/BigInteger.h"
#include <deque>

namespace CK {
    class RSAPublicKey;
    class RSAPrivateKey;
}

namespace CKPGP {

class PublicKey;
class Signature;
class UserID;
class UserAttribute;

class Signature : public Packet {

    public:
        Signature();
        Signature(uint8_t type, uint8_t pk, uint8_t hash);
        Signature(const coder::ByteArray& encoded);
        ~Signature();

    public:
        Signature(Signature *other);                // Consumes the pointer.
        Signature(const Signature& other);
        Signature& operator= (Signature *other);    // Consumes the pointer.
        Signature& operator= (const Signature& other);

    public:
        void encode();

    public:
        // Signature types.
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

        // Key algorithms.
        static const uint8_t RSASIGN;
        static const uint8_t RSAANY;
        static const uint8_t DSA;

        //Hash algorithms.
        static const uint8_t MD5;
        static const uint8_t SHA1;
        static const uint8_t RIPEMD160;
        static const uint8_t SHA256;
        static const uint8_t SHA384;
        static const uint8_t SHA512;
        static const uint8_t SHA224;

    public:
        void setKeyMaterial(PublicKey& pk);
        void setSignatureMaterial(Signature& pk);
        void setUserIDMaterial(UserID& uid);
        void setUserAttrMaterial(UserAttribute& uid);
        void sign(const CK::RSAPrivateKey& pk);
        bool verify(const CK::RSAPublicKey& pk);

    private:
        void createMessage();
        void decode(const coder::ByteArray& encoded);
        void decodeHashedSubpackets(const coder::ByteArray& encoded);
        void decodeUnhashedSubpackets(const coder::ByteArray& encoded);
        coder::ByteArray encodeHashedSubpackets() const;
        using Packet::encodeLength;
        coder::ByteArray encodeLength(uint32_t len) const;
        coder::ByteArray encodeUnhashedSubpackets() const;

    private:
        uint8_t version;
        uint8_t type;
        uint8_t pkAlgorithm;
        uint8_t hashAlgorithm;

        typedef std::deque<coder::ByteArray> SubpacketList;
        typedef SubpacketList::const_iterator SubConstIter;
        SubpacketList hashedSubpackets;
        SubpacketList unhashedSubpackets;

        uint8_t hashFragment[2];
        CK::BigInteger RSASig;
        CK::BigInteger DSAr;
        CK::BigInteger DSAs;

        coder::ByteArray keyMaterial;
        coder::ByteArray uidMaterial;
        coder::ByteArray attrMaterial;
        coder::ByteArray sigMaterial;
        coder::ByteArray message;

};

}

#endif  // SIGNATURE_H_INCLUDED
