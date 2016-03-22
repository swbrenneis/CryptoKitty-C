#include "random/BBSSecureRandom.h"
#include "random/CMWCRandom.h"
#include "data/BigInteger.h"
#include "data/NanoTime.h"
#include "data/Scalar64.h"
#include "data/Scalar32.h"

// Static initializers
const BigInteger BBSSecureRandom::TWO(2);
const BigInteger BBSSecureRandom::THREE(3);
const BigInteger BBSSecureRandom::FOUR(4);
// Reseed every 900 KBytes.
static const unsigned RESEED = 900 * 1024;

BBSSecureRandom::BBSSecureRandom()
: initialized(false),
  reseed(0) {
}

BBSSecureRandom::~BBSSecureRandom() {
}

/*
 * Initialize the RNG state.
 */
void BBSSecureRandom::initialize() {

    CMWCRandom rnd;
    BigInteger p(512, false, rnd);
    // Check for congruence to 3 (mod 4). Generate new prime if not.
    while (p % FOUR != THREE) {
        p = BigInteger(512, false, rnd);
    }
    BigInteger q(512, false, rnd);
    // Check for inequality and congruence
    while  (p == q || q % FOUR != THREE) {
        q = BigInteger(512, false, rnd);
    }
    // Compute the modulus
    M = p * q;
    // Compute the initial seed.
    NanoTime nt;
    setState(nt.getFullTime());

}

/*
 * Get the next series of random bytes.
 */
void BBSSecureRandom::nextBytes(ByteArray& bytes) {

    if (!initialized) {
        initialize();
    }

    if (reseed + bytes.length() > RESEED) {
        NanoTime nt;
        setState(nt.getFullTime());
        reseed = 0;
    }
    reseed += bytes.length();

    X = X.modPow(TWO, M);   // X(n) = X(n-1)**2 mod M.
    int bitLength = X.bitLength();
    int byteCount = bytes.length() - 1;

    while (byteCount >= 0) {
        // Count bits to make a byte.
        unsigned char thisByte = 0;
        for (int b = 0; b < 8; ++b) {
            thisByte = thisByte << 1;
            // Parity test.
            int parity = 0;
            for (int l = 0; l < bitLength; ++l) {
                if (X.testBit(l)) {
                    ++parity;
                }
            }
            // If parity is even, set the bit
            thisByte |= (parity % 2 == 0) ? 1 : 0;
            X = X >> 1;
            bitLength--;
            if (bitLength == 0) {
                // We ran out of bits. Need another random.
                X = X.modPow(TWO, M);
                // This is an unsigned operation. Not really important.
                bitLength = X.bitLength();
            }
        }
        bytes[byteCount--] = thisByte;
    }

}

/*
 * Returns the next 32 bits of entropy.
 */
int BBSSecureRandom::nextInt() {

    ByteArray bytes(4);
    nextBytes(bytes);
    return Scalar32::decode(bytes);

}

/*
 * Returns the next 64 bits of entropy.
 */
long BBSSecureRandom::nextLong() {

    ByteArray bytes(8);
    nextBytes(bytes);
    return Scalar64::decode(bytes);

}

/*
 * Set the RNG state.
 */
void BBSSecureRandom::setState(unsigned long seed) {

    CMWCRandom rnd;
    rnd.setSeed(seed);
    X = BigInteger(64, false, rnd);
    while (X.gcd(M) != BigInteger::ONE) {
        X = BigInteger(64, false, rnd);
    }

}

