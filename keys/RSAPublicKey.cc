#include "keys/RSAPublicKey.h"

namespace CK {

RSAPublicKey::RSAPublicKey(const BigInteger& n, const BigInteger& e)
: PublicKey("RSA"),
  exp(e),
  mod(n) {

      bitLength = mod.bitLength();

}

RSAPublicKey::~RSAPublicKey() {
}

int RSAPublicKey::getBitLength() const {

    return bitLength;

}

const BigInteger& RSAPublicKey::getExponent() const {

    return exp;

}

const BigInteger& RSAPublicKey::getModulus() const {

    return mod;

}

}

