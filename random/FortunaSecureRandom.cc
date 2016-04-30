#include "random/FortunaSecureRandom.h"
#include "random/FortunaGenerator.h"
#include "data/Unsigned64.h"
#include "data/Unsigned32.h"
#include "cthread/Mutex.h"
#include "cthread/Lock.h"
#include <fstream>
#include <cmath>

namespace CK {

// Static initializers
bool FortunaSecureRandom::initialized = false;
FortunaGenerator *FortunaSecureRandom::generator = 0;

FortunaSecureRandom::FortunaSecureRandom() {

    Lock lock(new Mutex);

    if (!initialized) {
        initialize();
    }

}

FortunaSecureRandom::~FortunaSecureRandom() {
}

void FortunaSecureRandom::initialize() {

    generator = new FortunaGenerator;
    generator->start();
    initialized = true;

}

void FortunaSecureRandom::nextBytes(ByteArray& bytes) {

    uint32_t length = bytes.getLength();
    uint32_t offset = 0;
    uint32_t limit = 0x100000;
    while (length > 0) {
        uint32_t count = std::min(length, limit);    // Length limited to 2**20 by generator
        ByteArray rnd;
        generator->generateRandomData(rnd, count);
        bytes.copy(offset, rnd, 0, count);
        length -= count;
        offset += count;
    }

}

/*
 * Returns the next 32 bits of entropy.
 */
uint32_t FortunaSecureRandom::nextInt() {

    ByteArray bytes(4);
    nextBytes(bytes);
    return Unsigned32::decode(bytes);

}

/*
 * Returns the next 64 bits of entropy.
 */
uint64_t FortunaSecureRandom::nextLong() {

    ByteArray bytes(8);
    nextBytes(bytes);
    return Unsigned64::decode(bytes);

}

}
