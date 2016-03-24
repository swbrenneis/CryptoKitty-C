#include "keys/RSAPublicKey.h"

namespace CK {

RSAPublicKey::RSAPublicKey(const BigInteger& n, const BigInteger& e)
: exp(e),
  mod(n) {
}

RSAPublicKey::~RSAPublicKey() {
}

const BigInteger& RSAPublicKey::getExponent() const {

    return exp;

}

const BigInteger& RSAPublicKey::getModulus() const {

    return mod;

}

}

