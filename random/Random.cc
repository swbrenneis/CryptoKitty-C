#include "../include/random/Random.h"
#include "../include/data/ByteArray.h"
#include <stdlib.h>
#include <climits>
#include <cmath>

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
unsigned long Random::next(int bits) {

    long rnd = random();
    unsigned long mask = 1 << bits;
    return rnd & mask;
    
}

/*
 * Return a series of random bytes. The length of the series
 * is determined by the length of the ByteArray object.
 */
void Random::nextBytes(ByteArray& bytes) {

    // Bit length.
    int l = bytes.length() * 8;
    int lSize = sizeof(long) * 8;
    unsigned index = 0;
    while (l > 0) {
        int getBits = std::min(l, lSize);
        long rnd = next(getBits);
        int shifted = lSize;
        while (shifted > 0 && l > 0 && index < bytes.length()) {
            bytes[index++] = rnd & 0xff;
            rnd = rnd >> 8;
            shifted -= 8;
            l-= 8;
        }
    }
}

/*
 * Return a random signed integer;
 */
int Random::nextInt() {

    return next(sizeof(int) * 8) & ULONG_MAX;

}

/*
 * Return a random signed long integer.
 */
long Random::nextLong() {

    return next(sizeof(long) * 8);

}

/*
 * Does nothing.
 */
void Random::setSeed(unsigned long newSeed) {
}

