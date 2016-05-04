#include "openpgp/packet/Signature.h"
#include "openpgp/packet/PublicKey.h"
#include "openpgp/packet/Signature.h"
#include "openpgp/packet/UserAttribute.h"
#include "openpgp/packet/UserID.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"
#include "cipher/PKCS1rsassa.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include "exceptions/openpgp/UnsupportedAlgorithmException.h"
#include <cmath>

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

const uint8_t Signature::MD5 = 1;
const uint8_t Signature::SHA1 = 2;
const uint8_t Signature::RIPEMD160 = 3;
const uint8_t Signature::SHA256 = 8;
const uint8_t Signature::SHA384 = 9;
const uint8_t Signature::SHA512 = 10;
const uint8_t Signature::SHA224 = 11;

Signature::Signature()
: Packet(SIGNATURE) {
}

Signature::Signature(uint8_t t, uint8_t pk, uint8_t hash)
: Packet(SIGNATURE),
  version(4),
  type(t),
  pkAlgorithm(pk),
  hashAlgorithm(hash),
  keyMaterial(0),
  message(0) {
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

Signature::Signature(Signature *other)
: Packet(*other),
  version(other->version),
  type(other->type),
  pkAlgorithm (other->pkAlgorithm),
  hashAlgorithm(other->hashAlgorithm),
  hashedSubpackets(other->hashedSubpackets),
  unhashedSubpackets(other->unhashedSubpackets),
  RSASig(other->RSASig),
  DSAr(other->DSAr),
  DSAs(other->DSAs) {

    hashFragment[0] = other->hashFragment[0];
    hashFragment[1] = other->hashFragment[1];

    delete other;

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

Signature& Signature::operator= (Signature *other) {

    Packet::operator= (*other);
    version = other->version;
    type = other->type;
    pkAlgorithm  = other->pkAlgorithm;
    hashAlgorithm = other->hashAlgorithm;
    hashedSubpackets = other->hashedSubpackets;
    unhashedSubpackets = other->unhashedSubpackets;
    RSASig = other->RSASig;
    DSAr = other->DSAr;
    DSAs = other->DSAs;
    hashFragment[0] = other->hashFragment[0];
    hashFragment[1] = other->hashFragment[1];
    delete other;

    return *this;

}

void Signature::createMessage() {

    message.clear();
    message.append(keyMaterial);    // May be empty.

    switch(type) {
        case GENERICPK:
        case PERSONAPK:
        case CASUALPK:
        case POSITIVEPK:
            message.append(uidMaterial);
            break;
        case CONFIRMATION:
            message.append(sigMaterial);
            break;
    }

    message.append(version);
    message.append(type);
    message.append(pkAlgorithm);
    message.append(hashAlgorithm);
    CK::ByteArray hashed(encodeHashedSubpackets());
    CK::Unsigned16 len(hashed.getLength());
    message.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    message.append(hashed);

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

    hashFragment[0] = encoded[index++];
    hashFragment[1] = encoded[index++];

    CK::Unsigned16 len;
    double dlen;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            len.decode(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            index += 2;
            dlen = len.getUnsignedValue();
            RSASig.decode(encoded.range(index, ceil(dlen / 8)),
                                                CK::BigInteger::BIGENDIAN);
            break;
        case DSA:
            len.decode(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            index += 2;
            dlen = len.getUnsignedValue();
            DSAr.decode(encoded.range(index, ceil(dlen / 8)),
                                                CK::BigInteger::BIGENDIAN);
            index += len.getUnsignedValue();
            len.decode(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            index += 2;
            dlen = len.getUnsignedValue();
            DSAs.decode(encoded.range(index, ceil(dlen / 8)),
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
            CK::ByteArray enc16(2);
            enc16[0] = encoded[index] - 192;
            enc16[1] = encoded[index + 1] + 192;
            CK::Unsigned16 len(enc16, CK::Unsigned16::BIGENDIAN);
            length = len.getUnsignedValue();
            index += 2;
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
        CK::ByteArray enc16(len.getEncoded(CK::Unsigned16::BIGENDIAN));
        encoded.append(enc16[0] + 192);
        encoded.append(enc16[1] - 192);
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

void Signature::setKeyMaterial(PublicKey& pk) {

    CK::ByteArray key(pk.getEncoded());

    // Strip the header.
    uint16_t strip = 1;     // Type octet
    if (key[strip] < 192) {
        strip++;
    }
    else if (key[strip] == 0xff) {
        strip += 5;
    }
    else {
        strip += 2;
    }

    keyMaterial.clear();
    keyMaterial.append(0x99);
    CK::Unsigned16 length(key.getLength());
    keyMaterial.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
    keyMaterial.append(key);

}

void Signature::setSignatureMaterial(Signature& s) {

    CK::ByteArray sig(s.getEncoded());

    // Strip the header.
    uint16_t strip = 1;     // Type octet
    if (sig[strip] < 192) {
        strip++;
    }
    else if (sig[strip] == 0xff) {
        strip += 5;
    }
    else {
        strip += 2;
    }

    sigMaterial.clear();
    sigMaterial.append(0x88);
    CK::Unsigned16 length(sig.getLength());
    sigMaterial.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
    sigMaterial.append(sig);

}

void Signature::setUserAttrMaterial(UserAttribute& u) {

    CK::ByteArray attr(u.getEncoded());

    // Strip the header.
    uint16_t strip = 1;     // Type octet
    if (attr[strip] < 192) {
        strip++;
    }
    else if (attr[strip] == 0xff) {
        strip += 5;
    }
    else {
        strip += 2;
    }

    attrMaterial.clear();
    attrMaterial.append(0xd1);
    CK::Unsigned16 length(attr.getLength());
    attrMaterial.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
    attrMaterial.append(attr);

}

void Signature::setUserIDMaterial(UserID& u) {

    CK::ByteArray uid(u.getEncoded());

    // Strip the header.
    uint16_t strip = 1;     // Type octet
    if (uid[strip] < 192) {
        strip++;
    }
    else if (uid[strip] == 0xff) {
        strip += 5;
    }
    else {
        strip += 2;
    }

    uidMaterial.clear();
    uidMaterial.append(0xb4);
    CK::Unsigned16 length(uid.getLength());
    uidMaterial.append(length.getEncoded(CK::Unsigned16::BIGENDIAN));
    uidMaterial.append(uid);

}

void Signature::sign(const CK::RSAPrivateKey& pk) {

    CK::Digest *digest = 0;
    switch (hashAlgorithm) {
        case SHA256:
            digest = new CK::SHA256;
            break;
        case SHA384:
            digest = new CK::SHA384;
            break;
        case SHA512:
            digest = new CK::SHA512;
            break;
        default:
            throw UnsupportedAlgorithmException("Unsupported hash algorithm");
    }

    createMessage();
    CK::ByteArray hash(digest->digest(message));
    hashFragment[0] = hash[hash.getLength() - 2];
    hashFragment[1] = hash[hash.getLength() - 1];

    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            {
            // Cipher owns digest pointer.
            CK::PKCS1rsassa rsa(digest);
            CK::ByteArray sig(rsa.sign(pk, hash));
            RSASig.decode(sig, CK::BigInteger::BIGENDIAN);
            }
            break;
        default:
            throw UnsupportedAlgorithmException("Unsupported public key algorithm");
    }

}

bool Signature::verify(const CK::RSAPublicKey& pk) {

    CK::Digest *digest = 0;
    switch (hashAlgorithm) {
        case SHA256:
            digest = new CK::SHA256;
            break;
        case SHA384:
            digest = new CK::SHA384;
            break;
        case SHA512:
            digest = new CK::SHA512;
            break;
        default:
            throw UnsupportedAlgorithmException("Unsupported hash algorithm");
    }

    createMessage();
    CK::ByteArray hash(digest->digest(message));
    if ( hashFragment[0] != hash[hash.getLength() - 2]
                    || hashFragment[1] != hash[hash.getLength() - 1]) {
        return false;
    }

    bool verified = false;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            {
            CK::PKCS1rsassa rsa(digest);
            CK::ByteArray sig(RSASig.getEncoded(CK::BigInteger::BIGENDIAN));
            verified = rsa.verify(pk, hash, sig);
            }
            break;
        default:
            throw UnsupportedAlgorithmException("Unsupported public key algorithm");
    }

    delete digest;
    return verified;

}

}

