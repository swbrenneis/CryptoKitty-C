#include "../include/random/CMWCRandom.h"
#include "../include/data/BigInteger.h"
#include "../include/data/NanoTime.h"
#include <time.h>
#include <string.h>

CMWCRandom::CMWCRandom() {

    NanoTime time;
    seed = time.getFullTime();

}

CMWCRandom::CMWCRandom(unsigned long seedValue)
: seed(seedValue){
}

CMWCRandom::~CMWCRandom() {
}

void CMWCRandom::seedGenerator() {

    unsigned char fill[4096 * 8];
    CKSHA256 digest;
    NanoTime nt;
    unsigned long nonce = seed;
    byte *context = 0;
    int filled = 0;
    while (filled < 4096) {
        if (context != 0) {
            digest.update(context);
        }
        BigInteger biNonce(nonce);
        digest.update(biNonce.byteArray);
        nonce++;
        BigInteger l(nt.getFullTime());
        digest.update(l.byteArray());
        context = digest.digest();
        memcpy(fill+(filled*8), context, something);
        filled += context.length;
    }
    for (int q = 0; q < 4096; ++q) {
        Q[q] = new BigInteger(Arrays.copyOfRange(fill, q, q + 8)).longValue();
    }
    c.newTime();
    c = nt.getFullTime % 809430659;  // Reset the reseed counter.

}

void CMWCRandom::setSeed(unsigned long seedValue) {

    seed = seedValue;
    seedGenerator(); // Generate new Q

}

