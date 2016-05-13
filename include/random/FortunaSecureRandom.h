#ifndef FORTUNASECURERANDOM_H_INCLUDED
#define FORTUNASECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "data/BigInteger.h"
#include "coder/ByteArray.h"

namespace CK {

class FortunaGenerator;

class FortunaSecureRandom : public SecureRandom {

    private:
        friend class SecureRandom;
        FortunaSecureRandom();

    public:
        ~FortunaSecureRandom();

    public:
        virtual void nextBytes(coder::ByteArray& bytes);
        virtual uint32_t nextInt();
        virtual uint64_t nextLong();

    private:
        void initialize();

    private:
        static bool initialized;
        static FortunaGenerator *generator;

};

}

#endif  // FORTUNASECURERANDOM_H_INCLUDED
