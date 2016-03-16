#include "../include/random/Random.h"
#include <stdlib.h>

/*
 * This is mostly used as a base class. It provides
 * a value from the built-in OS RNG. It is not a secure
 * PRNG.
 */
Random::Random() {
}

Random::~Random() {
}

/*
 * Returns a value from the system PRNG. If bits is greater
 * than the long word size, the maximum available
 * bits will be returned.
 */
long Random::next(unsigned bits) {

    long rnd = random();
    unsigned long mask = 1 << bits;
    return rnd & mask;
    
}

/*
 * Does nothing.
 */
void Random::setSeed(unsigned long newSeed) {
}

