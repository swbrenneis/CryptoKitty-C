#ifndef FORTUNAGENERATOR_H_INCLUDED
#define FORTUNAGENERATOR_H_INCLUDED

#include "../data/BigInteger.h"
#include <cthread/Runnable.h>
#include <coder/ByteArray.h>
#include <deque>

namespace cthread {
    class Mutex;
    class Thread;
}

namespace CK {

class AES;

class FortunaGenerator : public cthread::Runnable {

    public:
        FortunaGenerator();
        ~FortunaGenerator();

    private:
        FortunaGenerator(const FortunaGenerator& other);
        FortunaGenerator& operator= (const FortunaGenerator& other);

    public:
        void generateRandomData(coder::ByteArray& bytes, uint32_t length);
        void start();

    private:
        coder::ByteArray generateBlocks(uint16_t k);
        void reseed(const coder::ByteArray& seed);
        void run();

    private:
        bool runFlag;
        cthread::Thread *thread;
        typedef std::deque<coder::ByteArray> EntropyPools;
        EntropyPools pools;
        uint32_t poolCounter;
        AES *cipher;
        coder::ByteArray key;
        BigInteger counter;
        BigInteger limit;
        cthread::Mutex *keyMutex;

};

}
#endif  // FORTUNAGENERATOR_H_INCLUDED
