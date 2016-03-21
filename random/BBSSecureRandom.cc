#include "random/BBSSecureRandom.h"
#include "random/CMWCRandom.h"
#include "data/BigInteger.h"
#include "data/NanoTime.h"

// Static initializers
const BigInteger BBSSecureRandom::THREE(3);
const BigInteger BBSSecureRandom::FOUR(4);

BBSSecureRandom::BBSSecureRandom()
: initialized(false) {
}

BBSSecureRandom::~BBSSecureRandom() {
}

/*
 * Initialize the RNG state.
 */
void BBSSecureRandom::initialize() {

    CMWCRandom rnd;
    BigInteger p(512, 100, rnd);
    // Check for congruence to 3 (mod 4). Generate new prime if not.
    while (p % FOUR != THREE) {
        p = BigInteger(512, 20, rnd);
    }
    BigInteger q(512, 100, rnd);
    // Check for inequality and congruence
    while  (p == q || q % FOUR != THREE) {
        q = BigInteger(512, 100, rnd);
    }
    // Compute the modulus
    M = p * q;
    // Compute the initial seed.
    NanoTime nt;
    setState(nt.getFullTime());

}

