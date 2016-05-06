#include "keys/DHKeyExchange.h"
#include "data/BigInteger.h"
#include "random/SecureRandom.h"

namespace CK {

/*
 * Diffie-Hellman key exchange.
 */

DHKeyExchange::DHKeyExchange()
: bitsize(2048),
  g(BigInteger::ZERO),
  p(BigInteger::ZERO),
  a(BigInteger::ZERO),
  s(BigInteger::ZERO),
  publicKey(BigInteger::ZERO) {
}

DHKeyExchange::~DHKeyExchange() {
}

const BigInteger& DHKeyExchange::generatePublicKey() {

    SecureRandom *rnd = SecureRandom::getSecureRandom("Fortuna");

    if (p == BigInteger::ZERO) {
        p = BigInteger(bitsize, false, *rnd);
        while (p.bitLength() < bitsize) {
            p = BigInteger(bitsize, false, *rnd);
        }
        g = BigInteger(bitsize/2, false, *rnd);
        g = g % p;
    }

    if (a == BigInteger::ZERO) {
        a = BigInteger(512, false, *rnd);
    }

    publicKey = g.modPow(a, p);

    delete rnd;
    return publicKey;

}

/*
 * Return the generator. Will be ZERO if not explicitly set or if
 * the public key has not been generated.
 */
const BigInteger& DHKeyExchange::getGenerator() const {

    return g;

}

/*
 * Return the modulus. Will be ZERO if not explicitly set or if
 * the public key has not been generated.
 */
const BigInteger& DHKeyExchange::getModulus() const {

    return p;

}

/*
 * Return the D-H public key. Will be ZERO if not explicitly set or if
 * the public key has not been generated.
 */
const BigInteger& DHKeyExchange::getPublicKey() const {

    return publicKey;

}

/*
 * Generate and return the D-H public key.
 */
const BigInteger& DHKeyExchange::getSecret(const BigInteger& fpk) {

    if (a == BigInteger::ZERO) {
        SecureRandom *rnd = SecureRandom::getSecureRandom("Fortuna");
        a = BigInteger(512, false, *rnd);
    }

    s = fpk.modPow(a, p);
    return s;

}

/*
 * Return the D-H public key. Will be ZERO if if hasn't been
 * generated with the foreign public key.
 */
const BigInteger& DHKeyExchange::getSecret() {

    return s;

}

void DHKeyExchange::setBitsize(int b) {

    bitsize = b;

}

void DHKeyExchange::setGenerator(const BigInteger& gen) {

    g = gen;

}

void DHKeyExchange::setModulus(const BigInteger& mod) {

    p = mod;

}

}

