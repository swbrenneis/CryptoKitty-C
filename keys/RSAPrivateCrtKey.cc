#include "keys/RSAPrivateCrtKey.h"
#include "exceptions/BadParameterException.h"

namespace CK {

RSAPrivateCrtKey::RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                                    const BigInteger& d, const BigInteger& e)
: RSAPrivateKey("RSA CRT"),
  prvExp(d),
  pubExp(e),
  pPrime(p),
  qPrime(q) {

    mod = p * q;
    BigInteger pp = p - BigInteger::ONE;
    BigInteger qq = q - BigInteger::ONE;
    pPrimeExp = pubExp.modInverse(pp);
    qPrimeExp = pubExp.modInverse(qq);
    crtCoeff = qPrime.modInverse(p);
    bitLength = mod.bitLength();

}

RSAPrivateCrtKey::~RSAPrivateCrtKey() {
}

/*
 * RSA signature primitive, CRT method.
 */
BigInteger RSAPrivateCrtKey::rsasp1(const BigInteger& m) const {

    // We have to compute the modulus for the range check
    BigInteger n(pPrime * qPrime);

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (m < BigInteger::ZERO || m >= n) {
        throw BadParameterException("Message representative out of range");
    }

    // i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
    BigInteger s_1(m.modPow(pPrimeExp, pPrime));
    BigInteger s_2(m.modPow(qPrimeExp, qPrime));

    // iii.  Let h = (s_1 - s_2) * qInv mod p.
    BigInteger h(((s_1 - s_2) * crtCoeff) % pPrime);

    // iv.   Let s = s_2 + q * h.
    return BigInteger((qPrime * h) + s_2);

}

}

