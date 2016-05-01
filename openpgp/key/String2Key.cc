#include "openpgp/key/String2Key.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include "exceptions/openpgp/BadParameterException.h"
#include <cmath>

namespace CKPGP {

// Static initialization
const uint8_t String2Key::SIMPLE = 0;
const uint8_t String2Key::SALTED = 1;
const uint8_t String2Key::ITERSALT = 2;

const uint8_t String2Key::MD5 = 1;
const uint8_t String2Key::SHA1 = 2;
const uint8_t String2Key::RIPEMD160 = 3;
const uint8_t String2Key::SHA256 = 8;
const uint8_t String2Key::SHA384 = 9;
const uint8_t String2Key::SHA512 = 10;
const uint8_t String2Key::SHA224 = 11;

String2Key::String2Key(uint8_t alg)
: type(0) {
}

String2Key::String2Key(uint8_t alg, const CK::ByteArray& s)
: type(1),
  algorithm(alg),
  salt(s) {

    if (salt.getLength() != 8) {
        throw BadParameterException("Invalid salt length");
    }

}

String2Key::String2Key(uint8_t alg, const CK::ByteArray& s, uint8_t c)
: type(2),
  algorithm(alg),
  salt(s),
  c(c) {

    if (salt.getLength() != 8) {
        throw BadParameterException("Invalid salt length");
    }

    int32_t sixteen = 16;
    uint8_t expbias = 6;
    count = (sixteen + (c & 0x0f)) << ((c >> 4) + expbias);

}

String2Key::~String2Key() {
}

CK::ByteArray String2Key::generateKey(const std::string& passphrase,
                                                        unsigned bitsize) const {

    double bits = bitsize;
    uint32_t keySize = ceil(bits / 8);
    CK::ByteArray key;
    CK::ByteArray pass(passphrase);

    CK::Digest *digest;
    switch (algorithm) {
        case SHA256:
            digest = new CK::SHA256;
            break;
        case SHA384:
            digest = new CK::SHA384;
            break;
        case SHA512:
            digest = new CK::SHA512;
            break;
    }

    CK::ByteArray context;
    switch (type) {
        case SIMPLE:
            context.append(pass);
            break;
        case SALTED:
            context.append(salt);
            context.append(pass);
            break;
        case ITERSALT:
            while (context.getLength() < count) {
                context.append(salt);
                context.append(pass);
            }
            context = context.range(0, count);
            break;
    }

    uint32_t digestLength = digest->getDigestLength();
    if (keySize <= digestLength) {
        CK::ByteArray hash(digest->digest(context));
        key.append(hash.range(digestLength - keySize, keySize));
    }
    else {
        CK::ByteArray pad;
        while (key.getLength() < keySize) {
            digest->update(pad);
            digest->update(context);
            key.append(digest->digest());
            digest->reset();
            pad.append(0);
        }
        key = key.range(digestLength - keySize, keySize);
    }

    return key;

}

CK::ByteArray String2Key::getSpecifier() const {

    CK::ByteArray spec(1, type);
    spec.append(algorithm);

    switch (type) {
        case SALTED:
            spec.append(salt);
            break;
        case ITERSALT:
            spec.append(salt);
            spec.append(c);
            break;
    }

    return spec;

}

} 
