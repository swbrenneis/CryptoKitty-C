#include "random/FortunaGenerator.h"
#include "exceptions/OutOfRangeException.h"
#include "cipher/AES.h"
#include "digest/SHA256.h"
#include "data/Int32.h"
#include "data/Unsigned32.h"
#include "data/Unsigned64.h"
#include "data/NanoTime.h"
#include "cthread/Lock.h"
#include "cthread/Mutex.h"
#include <fstream>
#include <cmath>

namespace CK {

FortunaGenerator::FortunaGenerator()
: run(false),
  cipher(new AES(AES::AES256)),
  counter(0L) {

      limit.setBit(256);    // Limits counter to 16 bytes

}

FortunaGenerator::~FortunaGenerator() {
}

void FortunaGenerator::end() {

    reseed(pools.front());

}

ByteArray FortunaGenerator::generateBlocks(uint16_t k) {

    ByteArray r;

    for (unsigned i = 0; i < k; ++i) {
        ByteArray c(counter.getEncoded(BigInteger::LITTLEENDIAN));
        ByteArray pad(16 - c.getLength(), 0);
        c.append(pad);
        r.append(cipher->encrypt(c, key));
        counter++;
        if (counter >= limit) {
            counter = 1L;
        }
    }
    return r;

}

void FortunaGenerator::generateRandomData(ByteArray& bytes, uint32_t length) {

    if (length > 0x100000) {    // 2**20
        throw OutOfRangeException("Requested byte count out of range");
    }

    double n = length;
    ByteArray blocks(generateBlocks(ceil(n / 16)));
    bytes.append(blocks.range(0, length));
    key = generateBlocks(2);

}

void FortunaGenerator::reseed(const ByteArray& seed) {

    SHA256 sha;
    key.append(seed);
    key = sha.digest(key);
    counter++;
    if (counter >= limit) {
        counter = 1L;
    }
    std::ofstream seedstr("fgseed", std::ios::trunc|std::ios::binary);
    uint8_t *bytes = key.asArray();
    char *cbuf = reinterpret_cast<char*>(bytes);
    seedstr.write(cbuf, seed.getLength());
    seedstr.close();
    delete[] bytes;

}

void FortunaGenerator::start() {

    Lock lock(new Mutex);

    if (!run) {
        // Initialize pools
        for (int n = 0; n < 32; ++n) {
            ByteArray pool(1,0);
            pools.push_back(pool);
        }

        // Get the seed
        char entr[32];
        uint8_t *ubuf = reinterpret_cast<uint8_t*>(entr);
        std::ifstream seedstr("fgseed", std::ios::binary);
        if (!seedstr.good()) {                  // Seed file doesn't exist
            std::ifstream rnd("/dev/random");    // Get some entropy from /dev/random
            rnd.get(entr, 32);
            rnd.close();
        }
        else {
            seedstr.get(entr, 32);
            seedstr.close();
        }
        ByteArray seed(ubuf, 32);
        reseed(seed);

        // Start the accumulator.
        thread = new Thread(this);
        thread->start();
        run = true;
    }

}

void *FortunaGenerator::threadFunction() {

    timespec delay = { 0, 0 };
    char ebuf[32];
    uint8_t *ubuf = reinterpret_cast<uint8_t*>(ebuf);
    uint64_t reseedCounter = 0;

    while (run) {
        ByteArray rd;
        generateRandomData(rd, 4);
        Int32 nsec(rd, Unsigned32::LITTLEENDIAN);
        delay.tv_nsec = abs(nsec.getIntValue());
        nanosleep(&delay, 0);

        // Add some timed entropy
        NanoTime tm;
        Unsigned32 timed(tm.getNanoseconds());
        ByteArray nano(timed.getEncoded(Unsigned32::LITTLEENDIAN));
        for (int i = 1; i < 8; ++i) {
            timed.setValue((timed.getUnsignedValue() * 2) + i);
            nano.append(timed.getEncoded(Unsigned32::LITTLEENDIAN));
        }
        for (int i = 0; i < 32; ++i) {
            pools[i].append(nano[i]);
        }

        // Hash the time value and distribute
        Unsigned64 htimed(tm.getFullTime());
        SHA256 sha;
        ByteArray hashed(sha.digest(htimed.getEncoded(Unsigned64::LITTLEENDIAN)));
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[0]);
        }

        // Add some system entropy
        std::ifstream rnd("/dev/random");
        rnd.read(ebuf, 32);
        for (int i = 0; i < 32; ++i) {
            pools[i].append(ubuf[i]);
        }

        // Hash the system entropy and distribute
        ByteArray hrnd(ubuf, 32);
        sha.reset();
        hashed = sha.digest(hrnd);
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[0]);
        }

        // Hash the time and system hashes
        sha.reset();
        sha.update(hashed);
        sha.update(hrnd);
        hashed = sha.digest();
        for (int i = 0; i < 32; ++i) {
            pools[i].append(hashed[0]);
        }

        // Generate the seed. pool 0 is always used. The other pools
        // are used if the reseed counter is 
        if (pools[0].getLength() >= 32) {
            reseedCounter++;
            if (reseedCounter > 0x100000000) {
                reseedCounter = 1;
            }
            uint32_t modulus = 2;
            ByteArray seed(pools[0]);
            pools[0].clear();
            for (int i = 1; i < 32; ++i) {
                if (reseedCounter % modulus == 0) {
                    seed.append(pools[i]);
                    pools[i].clear();
                    modulus = modulus << 2;
                }
                reseed(seed);
            }
        }

    }

    return 0;

}

}

