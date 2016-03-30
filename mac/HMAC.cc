#include "mac/HMAC.h"
#include "exceptions/IllegalStateException.h"
#include "exceptions/BadParameterException.h"
#include "random/SecureRandom.h"
#include "random/CMWCRandom.h"
#include "data/NanoTime.h"
#include "digest/Digest.h"

namespace CK {

HMAC::HMAC(Digest *digest)
: hash(digest) {

    B = hash->getBlockSize();
    L = hash->getDigestLength();
    ipad = ByteArray(B, 0x36);
    opad = ByteArray(B, 0x5C);

}

HMAC::~HMAC() {

    delete hash;

}

bool HMAC::authenticate(const ByteArray& hmac) {

    return getHMAC() == hmac;

}

/*
 * Generate an HMAC key. The key size will be rounded
 * to a byte boundary. The Key must be at least L bytes.
 */
ByteArray HMAC::generateKey(unsigned bitsize) {

    if (bitsize / 8 < L) {
        throw BadParameterException("Invalid key size");
    }

    CMWCRandom rnd;
    NanoTime nt;
    rnd.setSeed(nt.getFullTime());
    SecureRandom* secure = SecureRandom::getSecureRandom("BBS");
    secure->setSeed(rnd.nextLong());
    K.setLength(bitsize / 8);
    secure->nextBytes(K);
    return K;

}

/*
 * Generate the HMAC.
 *
 * H(K XOR opad, H(K XOR ipad, text))
 *
 */
ByteArray HMAC::getHMAC() {

    if (K.getLength() == 0) {
        throw IllegalStateException("Key not set");
    }

    // Pad or truncate the key until it is B bytes.
    ByteArray k;
    if (K.getLength() > B) {
        k = hash->digest(K);
    }
    else {
        k = K;
    }
    while (k.getLength() < B) {
        k.append(0);
    }
    hash->reset();

    // First mask.
    ByteArray i(k ^ ipad);
    i.append(text);
    ByteArray h1(hash->digest(i));
    hash->reset();
    ByteArray o(k ^ opad);
    o.append(h1);
    return hash->digest(o);

}

void HMAC::setKey(const ByteArray& k) {

    if (k.getLength() < L) {
        throw BadParameterException("Invalid key");
    }

    K = k;

}

void HMAC::setMessage(const ByteArray& m) {

    text = m;

}

}

