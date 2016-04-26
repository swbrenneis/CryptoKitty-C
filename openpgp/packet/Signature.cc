#include "openpgp/packet/Signature.h"
#include "openpgp/packet/PublicKey.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"

namespace CKPGP {

// Static intialization
const uint8_t Signature::BINARY = 0x00;
const uint8_t Signature::TEXT = 0x01;
const uint8_t Signature::STANDALONE = 0x02;
const uint8_t Signature::GENERICPK = 0x10;
const uint8_t Signature::PERSONAPK = 0x11;
const uint8_t Signature::CASUALPK = 0x12;
const uint8_t Signature::POSITIVEPK = 0x13;
const uint8_t Signature::SUBKEY = 0x18;
const uint8_t Signature::PRIMARYKEY = 0x19;
const uint8_t Signature::DIRECT = 0x1f;
const uint8_t Signature::KEYREVOKE = 0x20;
const uint8_t Signature::SUBKEYREVOKE = 0x28;
const uint8_t Signature::CERTREVOKE = 0x30;
const uint8_t Signature::TIMESTAMP = 0x40;
const uint8_t Signature::CONFIRMATION = 0x50;

const uint8_t Signature::RSAANY = 1;
const uint8_t Signature::RSASIGN = 3;
const uint8_t Signature::DSA = 17;

Signature::Signature()
: Packet(SIGNATURE),
  version(4) {
}

Signature::Signature(const CK::ByteArray& encoded)
: Packet(SIGNATURE) {

    decode(encoded);

}

Signature::Signature(const Signature& other)
: Packet(other),
  version(other.version),
  type(other.type),
  pkAlgorithm (other.pkAlgorithm),
  hashAlgorithm(other.hashAlgorithm),
  hashedSubpackets(other.hashedSubpackets),
  unhashedSubpackets(other.unhashedSubpackets),
  RSASig(other.RSASig),
  DSAr(other.DSAr),
  DSAs(other.DSAs) {

    hashFragment[0] = other.hashFragment[0];
    hashFragment[1] = other.hashFragment[1];

}

Signature::~Signature() {
}

Signature& Signature::operator= (const Signature& other) {

    Packet::operator= (other);
    version = other.version;
    type = other.type;
    pkAlgorithm  = other.pkAlgorithm;
    hashAlgorithm = other.hashAlgorithm;
    hashedSubpackets = other.hashedSubpackets;
    unhashedSubpackets = other.unhashedSubpackets;
    RSASig = other.RSASig;
    DSAr = other.DSAr;
    DSAs = other.DSAs;
    hashFragment[0] = other.hashFragment[0];
    hashFragment[1] = other.hashFragment[1];
    return *this;

}

void Signature::decode(const CK::ByteArray& encoded) {

    version = encoded[0];
    type = encoded[1];
    pkAlgorithm = encoded[2];
    hashAlgorithm = encoded[3];

    unsigned index = 4;
    CK::Unsigned16 hc(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
    index += 2;
    unsigned count = hc.getUnsignedValue();
    decodeHashedSubpackets(encoded.range(index, count));
    index += count;
    CK::Unsigned16 uc(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
    index += 2;
    count = uc.getUnsignedValue();
    decodeUnhashedSubpackets(encoded.range(index, count));
    index += count;

    CK::Unsigned16 len;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            len = CK::Unsigned16(encoded.range(index, 2),
                                                CK::Unsigned16::BIGENDIAN);
            index += 2;
            RSASig = CK::BigInteger(encoded.range(index, len.getUnsignedValue()),
                                                CK::BigInteger::BIGENDIAN);
            break;
        case DSA:
            len = CK::Unsigned16(encoded.range(index, 2),
                                                CK::Unsigned16::BIGENDIAN);
            index += 2;
            DSAr = CK::BigInteger(encoded.range(index, len.getUnsignedValue()),
                                                CK::BigInteger::BIGENDIAN);
            index += len.getUnsignedValue();
            len = CK::Unsigned16(encoded.range(index, 2),
                                                CK::Unsigned16::BIGENDIAN);
            index += 2;
            DSAs = CK::BigInteger(encoded.range(index, len.getUnsignedValue()),
                                                CK::BigInteger::BIGENDIAN);
            break;
    }

}

void Signature::decodeHashedSubpackets(const CK::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[0];
            index++;
        }
        else if (encoded[index] == 0xff) {
            CK::Unsigned32 len(encoded.range(index + 1, 4),
                                            CK::Unsigned32::BIGENDIAN);
            index += 5;
            length = len.getUnsignedValue();
        }
        else {
            CK::Unsigned16 len(encoded.range(index, 2),
                                            CK::Unsigned16::BIGENDIAN);
            index += 2;
            length = len.getUnsignedValue();
        }
        hashedSubpackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void Signature::decodeUnhashedSubpackets(const CK::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[0];
            index++;
        }
        else if (encoded[index] == 0xff) {
            CK::Unsigned32 len(encoded.range(index + 1, 4),
                                            CK::Unsigned32::BIGENDIAN);
            index += 5;
            length = len.getUnsignedValue();
        }
        else {
            CK::Unsigned16 len(encoded.range(index, 2),
                                            CK::Unsigned16::BIGENDIAN);
            index += 2;
            length = len.getUnsignedValue();
        }
        unhashedSubpackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void Signature::encode() {

    encoded.append(encodeTag());
    CK::ByteArray sig;

    sig.append(version);
    sig.append(type);
    sig.append(pkAlgorithm);
    sig.append(hashAlgorithm);


    CK::ByteArray sub(encodeHashedSubpackets());
    CK::Unsigned16 sublen(sub.getLength());
    sig.append(sublen.getEncoded(CK::Unsigned16::BIGENDIAN));
    sig.append(sub);

    sub = encodeUnhashedSubpackets();
    sublen.setValue(sub.getLength());
    sig.append(sublen.getEncoded(CK::Unsigned16::BIGENDIAN));
    sig.append(sub);

    sig.append(hashFragment, 2);

    CK::Unsigned16 siglen;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            siglen.setValue(RSASig.bitLength());
            sig.append(siglen.getEncoded(CK::Unsigned16::BIGENDIAN));
            sig.append(RSASig.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
        case DSA:
            siglen.setValue(DSAr.bitLength());
            sig.append(siglen.getEncoded(CK::Unsigned16::BIGENDIAN));
            sig.append(DSAr.getEncoded(CK::BigInteger::BIGENDIAN));
            siglen.setValue(DSAs.bitLength());
            sig.append(siglen.getEncoded(CK::Unsigned16::BIGENDIAN));
            sig.append(DSAs.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
    }

    packetLength = sig.getLength();
    encoded.append(encodeLength());
    encoded.append(sig);

}

CK::ByteArray Signature::encodeHashedSubpackets() const {

    CK::ByteArray sub;
    for (SubConstIter it = hashedSubpackets.begin();
                    it != hashedSubpackets.end(); it++) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    return sub;

}

CK::ByteArray Signature::encodeLength(uint32_t len) const {

    CK::ByteArray encoded;
    if (len < 192) {
        encoded.append(len);
    }
    else if (len < 8384) {
        CK::Unsigned16 len(len);
        encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    }
    else {
        encoded.append(0xff);
        CK::Unsigned32 len(len);
        encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    }

    return encoded;
    
}

CK::ByteArray Signature::encodeUnhashedSubpackets() const {

    CK::ByteArray sub;
    for (SubConstIter it = unhashedSubpackets.begin();
                    it != unhashedSubpackets.end(); it++) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    return sub;

}

void Signature::setType(uint8_t t) {

    type = t;

}

}

