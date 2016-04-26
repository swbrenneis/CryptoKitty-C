#ifndef FORTUNAGENERATOR_H_INCLUDED
#define FORTUNAGENERATOR_H_INCLUDED

#include "data/ByteArray.h"
#include "data/BigInteger.h"
#include "cthread/Thread.h"
#include <deque>

namespace CK {

class AES;

class FortunaGenerator : public Thread::Callback {

    public:
        FortunaGenerator();
        ~FortunaGenerator();

    private:
        FortunaGenerator(const FortunaGenerator& other);
        FortunaGenerator& operator= (const FortunaGenerator& other);

    public:
        void generateRandomData(ByteArray& bytes, uint32_t length);
        void start();

    private:
        void end();
        ByteArray generateBlocks(uint16_t k);
        void reseed(const ByteArray& seed);
        void *threadFunction();

    private:
        bool run;
        Thread *thread;
        typedef std::deque<ByteArray> EntropyPools;
        EntropyPools pools;
        uint32_t poolCounter;
        AES *cipher;
        ByteArray key;
        BigInteger counter;
        BigInteger limit;

};

}
#endif  // FORTUNAGENERATOR_H_INCLUDED
