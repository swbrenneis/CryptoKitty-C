#include "keys/RSAPrivateCrtKey.h"

namespace CK {

RSAPrivateCrtKey::RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                                    const BigInteger& d, const BigInteger& e)
: prvExp(d),
  pubExp(e),
  pPrime(p),
  qPrime(q) {

    mod = p * q;
    BigInteger pp = p - BigInteger::ONE;
    BigInteger qq = q - BigInteger::ONE;
    pPrimeExp = pubExp.modInverse(pp);
    qPrimeExp = pubExp.modInverse(qq);
    crtCoeff = qPrime.modInverse(p);

}

RSAPrivateCrtKey::~RSAPrivateCrtKey() {
}

}

