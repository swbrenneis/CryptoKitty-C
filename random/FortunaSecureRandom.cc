#include "random/FortunaSecureRandom.h"
#include "random/FortunaGenerator.h"
#include "coder/Unsigned64.h"
#include "coder/Unsigned32.h"
#include "cthread/Mutex.h"
#include "cthread/Lock.h"
#include <fstream>
#include <cmath>

namespace CK {

// Static initializers
bool FortunaSecureRandom::initialized = false;
FortunaGenerator *FortunaSecureRandom::generator = 0;

FortunaSecureRandom::FortunaSecureRandom() {

    Lock lock();

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

void FortunaSecureRandom::nextBytes(coder::ByteArray& bytes) {

    uint32_t length = bytes.getLength();
    uint32_t offset = 0;
    uint32_t limit = 0x100000;
    while (length > 0) {
        uint32_t count = std::min(length, limit);    // Length limited to 2**20 by generator
        coder::ByteArray rnd;
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

    coder::ByteArray bytes(4);
    nextBytes(bytes);
    coder::Unsigned32 u32(bytes);
    return u32.getValue();

}

/*
 * Returns the next 64 bits of entropy.
 */
uint64_t FortunaSecureRandom::nextLong() {

    coder::ByteArray bytes(8);
    nextBytes(bytes);
    coder::Unsigned64 u64(bytes);
    return u64.getValue();

}

}

