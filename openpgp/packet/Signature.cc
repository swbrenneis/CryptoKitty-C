#include "openpgp/packet/Signature.h"
#include "openpgp/packet/PublicKey.h"
#include "openpgp/packet/Signature.h"
#include "openpgp/packet/UserAttribute.h"
#include "openpgp/packet/UserID.h"
#include "coder/Unsigned16.h"
#include "coder/Unsigned32.h"
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

Signature::Signature(const coder::ByteArray& encoded)
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
    coder::ByteArray hashed(encodeHashedSubpackets());
    coder::Unsigned16 len(hashed.getLength());
    message.append(len.getEncoded(coder::bigendian));
    message.append(hashed);

}

void Signature::decode(const coder::ByteArray& encoded) {

    version = encoded[0];
    type = encoded[1];
    pkAlgorithm = encoded[2];
    hashAlgorithm = encoded[3];

    unsigned index = 4;
    coder::Unsigned16 hc(encoded.range(index, 2), coder::bigendian);
    index += 2;
    unsigned count = hc.getValue();
    decodeHashedSubpackets(encoded.range(index, count));
    index += count;
    coder::Unsigned16 uc(encoded.range(index, 2), coder::bigendian);
    index += 2;
    count = uc.getValue();
    decodeUnhashedSubpackets(encoded.range(index, count));
    index += count;

    hashFragment[0] = encoded[index++];
    hashFragment[1] = encoded[index++];

    coder::Unsigned16 len;
    double dlen;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            len.decode(encoded.range(index, 2), coder::bigendian);
            index += 2;
            dlen = len.getValue();
            RSASig.decode(encoded.range(index, ceil(dlen / 8)),
                                                CK::BigInteger::BIGENDIAN);
            break;
        case DSA:
            len.decode(encoded.range(index, 2), coder::bigendian);
            index += 2;
            dlen = len.getValue();
            DSAr.decode(encoded.range(index, ceil(dlen / 8)),
                                                CK::BigInteger::BIGENDIAN);
            index += len.getValue();
            len.decode(encoded.range(index, 2), coder::bigendian);
            index += 2;
            dlen = len.getValue();
            DSAs.decode(encoded.range(index, ceil(dlen / 8)),
                                                CK::BigInteger::BIGENDIAN);
            break;
    }

}

void Signature::decodeHashedSubpackets(const coder::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[0];
            index++;
        }
        else if (encoded[index] == 0xff) {
            coder::Unsigned32 len(encoded.range(index + 1, 4),
                                            coder::bigendian);
            index += 5;
            length = len.getValue();
        }
        else {
            coder::Unsigned16 len(encoded.range(index, 2),
                                            coder::bigendian);
            index += 2;
            length = len.getValue();
        }
        hashedSubpackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void Signature::decodeUnhashedSubpackets(const coder::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[0];
            index++;
        }
        else if (encoded[index] == 0xff) {
            coder::Unsigned32 len(encoded.range(index + 1, 4),
                                            coder::bigendian);
            index += 5;
            length = len.getValue();
        }
        else {
            coder::ByteArray enc16(2);
            enc16[0] = encoded[index] - 192;
            enc16[1] = encoded[index + 1] + 192;
            coder::Unsigned16 len(enc16, coder::bigendian);
            length = len.getValue();
            index += 2;
        }
        unhashedSubpackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void Signature::encode() {

    encoded.append(encodeTag());
    coder::ByteArray sig;

    sig.append(version);
    sig.append(type);
    sig.append(pkAlgorithm);
    sig.append(hashAlgorithm);


    coder::ByteArray sub(encodeHashedSubpackets());
    coder::Unsigned16 sublen(sub.getLength());
    sig.append(sublen.getEncoded(coder::bigendian));
    sig.append(sub);

    sub = encodeUnhashedSubpackets();
    sublen.setValue(sub.getLength());
    sig.append(sublen.getEncoded(coder::bigendian));
    sig.append(sub);

    sig.append(hashFragment, 2);

    coder::Unsigned16 siglen;
    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            siglen.setValue(RSASig.bitLength());
            sig.append(siglen.getEncoded(coder::bigendian));
            sig.append(RSASig.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
        case DSA:
            siglen.setValue(DSAr.bitLength());
            sig.append(siglen.getEncoded(coder::bigendian));
            sig.append(DSAr.getEncoded(CK::BigInteger::BIGENDIAN));
            siglen.setValue(DSAs.bitLength());
            sig.append(siglen.getEncoded(coder::bigendian));
            sig.append(DSAs.getEncoded(CK::BigInteger::BIGENDIAN));
            break;
    }

    packetLength = sig.getLength();
    encoded.append(encodeLength());
    encoded.append(sig);

}

coder::ByteArray Signature::encodeHashedSubpackets() const {

    coder::ByteArray sub;
    for (SubConstIter it = hashedSubpackets.begin();
                    it != hashedSubpackets.end(); it++) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    return sub;

}

coder::ByteArray Signature::encodeLength(uint32_t len) const {

    coder::ByteArray encoded;
    if (len < 192) {
        encoded.append(len);
    }
    else if (len < 8384) {
        coder::Unsigned16 len(len);
        coder::ByteArray enc16(len.getEncoded(coder::bigendian));
        encoded.append(enc16[0] + 192);
        encoded.append(enc16[1] - 192);
    }
    else {
        encoded.append(0xff);
        coder::Unsigned32 len(len);
        encoded.append(len.getEncoded(coder::bigendian));
    }

    return encoded;
    
}

coder::ByteArray Signature::encodeUnhashedSubpackets() const {

    coder::ByteArray sub;
    for (SubConstIter it = unhashedSubpackets.begin();
                    it != unhashedSubpackets.end(); it++) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    return sub;

}

void Signature::setKeyMaterial(PublicKey& pk) {

    coder::ByteArray key(pk.getEncoded());

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
    coder::Unsigned16 length(key.getLength());
    keyMaterial.append(length.getEncoded(coder::bigendian));
    keyMaterial.append(key);

}

void Signature::setSignatureMaterial(Signature& s) {

    coder::ByteArray sig(s.getEncoded());

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
    coder::Unsigned16 length(sig.getLength());
    sigMaterial.append(length.getEncoded(coder::bigendian));
    sigMaterial.append(sig);

}

void Signature::setUserAttrMaterial(UserAttribute& u) {

    coder::ByteArray attr(u.getEncoded());

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
    coder::Unsigned16 length(attr.getLength());
    attrMaterial.append(length.getEncoded(coder::bigendian));
    attrMaterial.append(attr);

}

void Signature::setUserIDMaterial(UserID& u) {

    coder::ByteArray uid(u.getEncoded());

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
    coder::Unsigned16 length(uid.getLength());
    uidMaterial.append(length.getEncoded(coder::bigendian));
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
    coder::ByteArray hash(digest->digest(message));
    hashFragment[0] = hash[hash.getLength() - 2];
    hashFragment[1] = hash[hash.getLength() - 1];

    switch (pkAlgorithm) {
        case RSASIGN:
        case RSAANY:
            {
            // Cipher owns digest pointer.
            CK::PKCS1rsassa rsa(digest);
            coder::ByteArray sig(rsa.sign(pk, hash));
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
    coder::ByteArray hash(digest->digest(message));
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
            coder::ByteArray sig(RSASig.getEncoded(CK::BigInteger::BIGENDIAN));
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

