#include "keys/RSAPrivateCrtKey.h"
#include "exceptions/BadParameterException.h"

namespace CK {

RSAPrivateCrtKey::RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                                    const BigInteger& d, const BigInteger& e)
: RSAPrivateKey("RSA CRT"),
  d(d),
  e(e),
  p(p),
  q(q) {

    BigInteger pp(p - BigInteger::ONE);
    BigInteger qq(q - BigInteger::ONE);
    dP = e.modInverse(pp);
    dQ = e.modInverse(qq);
    qInv = q.modInverse(p);
    n = p * q;
    bitLength = n.bitLength();

}

RSAPrivateCrtKey::~RSAPrivateCrtKey() {
}

/*
 * RSA signature primitive, CRT method.
 */
BigInteger RSAPrivateCrtKey::rsasp1(const BigInteger& m) const {

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (m < BigInteger::ZERO || m >= n) {
        /* std::cout << "m = " << m << std::endl << "n = " << n << std::endl;
        std::cout << "m bit length = " << m.bitLength()
                << std::endl << "n bit length = " << n.bitLength() << std::endl; */
        throw BadParameterException("Message representative out of range");
    }

    //std::cout << "rsasp1 (CRT) m = " << m << std::endl;
    // i.    Let s_1 = m^dP mod p and s_2 = m^dQ mod q.
    BigInteger s_1(m.modPow(dP, p));
    BigInteger s_2(m.modPow(dQ, q));

    // iii.  Let h = (s_1 - s_2) * qInv mod p.
    BigInteger h(((s_1 - s_2) * qInv) % p);

    // iv.   Let s = s_2 + q * h.
    BigInteger result((q * h) + s_2);
    //std::cout << "rsasp1 (CRT) result = " << result << std::endl;
    return result;

}

}

