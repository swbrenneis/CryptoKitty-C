#ifndef BBSSECURERANDOM_H_INCLUDED
#define BBSSECURERANDOM_H_INCLUDED

#include "SecureRandom.h"
#include "data/BigInteger.h"

namespace CK {

class BBSSecureRandom : public SecureRandom {

    private:
        friend class SecureRandom;
        BBSSecureRandom();

    public:
        ~BBSSecureRandom();

    public:
        virtual void nextBytes(ByteArray& bytes);
        virtual int nextInt();
        virtual long nextLong();

    private:
        void initialize();
        void setState(unsigned long seed);

    private:
        bool initialized;
        BigInteger M;
        BigInteger Xn;  // X(n)
        BigInteger Xn1; // X(n-1)
        unsigned reseed;

    private:
        static const BigInteger TWO;
        static const BigInteger THREE;
        static const BigInteger FOUR;

};

}

#endif  // BBSSECURERANDOM_H_INCLUDED
