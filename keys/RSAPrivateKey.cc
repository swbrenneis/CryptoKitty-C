#include "keys/RSAPrivateKey.h"

namespace CK {

RSAPrivateKey::RSAPrivateKey(const std::string& alg)
: PrivateKey(alg) {
}

RSAPrivateKey::~RSAPrivateKey() {
}

/*
 * Return the bit length of the key.
 */
int RSAPrivateKey::getBitLength() const {

    return bitLength;

}

}
