#ifndef FORTUNASECURERANDOM_H_INCLUDED
#define FORTUNASECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "CryptoKitty-C/data/BigInteger.h"
#include "coder/ByteArray.h"

namespace CK {

class FortunaGenerator;

class FortunaSecureRandom : public SecureRandom {

    public:
        FortunaSecureRandom();
        ~FortunaSecureRandom();

    public:
        void nextBytes(coder::ByteArray& bytes);
        uint32_t nextInt();
        uint64_t nextLong();
        static void setStandalone(bool s);

    private:
        uint32_t readBytes(coder::ByteArray& bytes, uint32_t count) const;

    private:
        static bool standalone;
        static FortunaGenerator *gen;

};

}

#endif  // FORTUNASECURERANDOM_H_INCLUDED
