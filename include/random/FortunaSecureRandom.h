#ifndef FORTUNASECURERANDOM_H_INCLUDED
#define FORTUNASECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "data/BigInteger.h"
#include "coder/ByteArray.h"

namespace CK {

class FortunaGenerator;

class FortunaSecureRandom : public SecureRandom {

    public:
        FortunaSecureRandom(bool standalone = false);
        ~FortunaSecureRandom();

    public:
        virtual void nextBytes(coder::ByteArray& bytes);
        virtual uint32_t nextInt();
        virtual uint64_t nextLong();

    private:
        uint32_t readBytes(coder::ByteArray& bytes, uint32_t count) const;

    private:
        bool standalone;
        FortunaGenerator *gen;

};

}

#endif  // FORTUNASECURERANDOM_H_INCLUDED
