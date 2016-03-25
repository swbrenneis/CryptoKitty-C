#include "keys/RSAPrivateModKey.h"
#include "exceptions/BadParameterException.h"

namespace CK {

RSAPrivateModKey::RSAPrivateModKey(const BigInteger& d,
                const BigInteger& n)
: RSAPrivateKey("RSA Modulus"),
  prvExp(d),
  mod(n) {

    bitLength = mod.bitLength();

}

RSAPrivateModKey::~RSAPrivateModKey() {
}

/*
 * Modulus method RSA signature primitive.
 */
BigInteger RSAPrivateModKey::rsasp1(const BigInteger& m) const {

    //   1. If the message representative c is not between 0 and n - 1,
    //      output "message representative out of range" and stop.
    if (m < BigInteger::ZERO || m >= mod) {
        throw BadParameterException("Message representative out of range");
    }

    // Let s = m^d mod n.
    return BigInteger(m.modPow(prvExp, mod));

}

}
