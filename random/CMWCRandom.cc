#include "../include/random/CMWCRandom.h"
#include "../include/data/NanoTime.h"
#include "../include/data/ByteArray.h"
#include "../include/digest/CKSHA256.h"
#include <time.h>
#include <string.h>

// Static initializations
unsigned CMWCRandom::i = 4095;
const BigInteger CMWCRandom::A(18782L);
const unsigned CMWCRandom::R = 0xfffffffe;

CMWCRandom::CMWCRandom() {

    NanoTime time;
    seed = time.getFullTime();

}

CMWCRandom::CMWCRandom(unsigned long seedValue)
: seed(seedValue){
}

CMWCRandom::~CMWCRandom() {
}

/*
 * Generate the random number.
 */
long CMWCRandom::cmwc4096() {

    BigInteger t;
    BigInteger x;
    BigInteger ci(c);

    i = (i + 1) & 4095;
    BigInteger qi(q[i]);
    t = (A * qi) + ci;
    ci = t >> 32;
    x = t + ci;
    c = ci.longValue();
    if (x < ci) {
        x = x + BigInteger::ONE;
        c++;
    }
    return (q[i] = R - x.longValue());

}

/*
 * Provide the next bits of entropy. If bits
 * exceeds UINT_MAX, the output will be truncated
 * silently.
 */
unsigned long CMWCRandom::next(unsigned bits) {

    if (bits > (sizeof(unsigned long) * 8)) {
        bits = sizeof(unsigned long) * 8;
    }
    if (q.size() == 0) {
        seedGenerator();
    }
    unsigned mask = bits << 1;;
    return (cmwc4096() & mask);

}

/*
 * See the generator.
 */
void CMWCRandom::seedGenerator() {

    ByteArray fill(4096 * 8);
    CKSHA256 digest;
    NanoTime nt;
    unsigned long nonce = seed;
    ByteArray context;
    int filled = 0;

    q.resize(4096, 0);
    while (filled < 4096) {
        if (context.length() != 0) {
            digest.update(context);
        }
        BigInteger biNonce(nonce);
        digest.update(biNonce.byteArray());
        nonce++;
        BigInteger l(nt.getFullTime());
        digest.update(l.byteArray());
        context = digest.digest();
        fill.copy(filled*8, context, 0);
        filled += context.length();
    }
    for (int qi = 0; qi < 4096; ++qi) {
        BigInteger qInt(fill.range(qi, 8));
        q[qi] = qInt.longValue();
    }
    nt.newTime();
    c = nt.getFullTime() % 809430659;  // Reset the reseed counter.

}

void CMWCRandom::setSeed(unsigned long seedValue) {

    seed = seedValue;
    seedGenerator(); // Generate new Q

}

