#ifndef BBSSECURERANDOM_H_INCLUDED
#define BBSSECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "data/BigInteger.h"

class BBSSecureRandom : public SecureRandom {

    private:
        friend class SecureRandom;
        BBSSecureRandom();

    public:
        ~BBSSecureRandom();

    private:
        void initialize();
        void setState(unsigned long seed);

    private:
        bool initialized;
        BigInteger M;

    private:
        static const BigInteger THREE;
        static const BigInteger FOUR;

};
#endif  // BBSSECURERANDOM_H_INCLUDED
