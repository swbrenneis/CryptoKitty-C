#include "keys/RSAKeyPairGenerator.h"
#include "keys/RSAPublicKey.h"
#include "keys/RSAPrivateCrtKey.h"
#include "random/SecureRandom.h"

namespace CK {

// Static initialization
const BigInteger RSAKeyPairGenerator::THREE(3);

/*
 * The class defaults to a key size of 1024 bits and
 * a BBSRandom secure PRNG.
 */
RSAKeyPairGenerator::RSAKeyPairGenerator()
: keySize(1024),
  random(SecureRandom::getSecureRandom("BBS")) {
}

RSAKeyPairGenerator::~RSAKeyPairGenerator() {

    delete random;

}

/*
 * Initialize the key generator with a new bit size
 * and/or a new secure RNG. If secure is null, the
 * existing RNG doesn't change.
 */
void RSAKeyPairGenerator::initialize(int bits,
                                SecureRandom *secure) {

    keySize = bits;
    if (secure != 0) {
        delete random;
        random = secure;
    }

}

/*
 * Generate the key pair.
 */
KeyPair<RSAPublicKey, RSAPrivateKey> *RSAKeyPairGenerator::generateKeyPair() {

    // Create SG primes.
    BigInteger p(keySize / 2, false, *random);
    BigInteger q(keySize / 2, false, *random);
    // Get the modulus and make sure it is the right bit size.
    BigInteger n = p * q;
    while (n.bitLength() != keySize) {
        q = BigInteger(keySize / 2, false, *random);
        p = BigInteger(keySize / 2, false, *random);
        n = p * q;
    }

    // Calculate phi(n) = (p - 1) * (q - 1)
    BigInteger pp = p - BigInteger::ONE;
    BigInteger qq = q - BigInteger::ONE;
    BigInteger phi = pp * qq;
    // Calculate the public exponent.
    // e is coprime (gcd = 1) with phi.
    bool eFound = false;
    BigInteger e;
    while (!eFound) {
        e = BigInteger(64, false, *random);
        // 3 < e <= n-1
        if (e > THREE && e < n) {
            eFound = e.gcd(phi) == BigInteger::ONE;
        }
    }

    // d * e = 1 mod phi (d = e^{1} mod phi)
    BigInteger d = e.modInverse(phi);

    // Create the public key.
    RSAPublicKey *pub = new RSAPublicKey(n, e);
    // Create the private key.
    // PrivateKey prv = new RSAPrivateKey(n, d);
    // We're going to create a Chinese Remainder Theorem key.
    // Leaving the line creating a simple key here for reference.
    RSAPrivateKey *prv = new RSAPrivateCrtKey(p, q, d, e);

    return new KeyPair<RSAPublicKey, RSAPrivateKey>(pub, prv);

}

}
