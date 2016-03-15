#include "../include/random/CMWCRandom.h"
#include "../include/data/BigInteger.h"
#include "../include/data/NanoTime.h"
#include "../include/data/ByteArray.h"
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

    ByteArray fill(4096 * 8);
    CKSHA256 digest;
    NanoTime nt;
    unsigned long nonce = seed;
    ByteArray context
    int filled = 0;
    while (filled < 4096) {
        if (context.length() != 0) {
            digest.update(context);
        }
        BigInteger biNonce(nonce);
        digest.update(biNonce.byteArray);
        nonce++;
        BigInteger l(nt.getFullTime());
        digest.update(l.byteArray());
        context = digest.digest();
        fill.copy(filled*8, context, 0);
        filled += context.length();
    }
    for (int qi = 0; qi < 4096; ++qi) {
        BigInteger qInt(fill.range(qi, 8));
        Q[q] = qInt.longValue();
    }
    nt.newTime();
    c = nt.getFullTime % 809430659;  // Reset the reseed counter.

}

void CMWCRandom::setSeed(unsigned long seedValue) {

    seed = seedValue;
    seedGenerator(); // Generate new Q

}

