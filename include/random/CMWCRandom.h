#ifndef CMWCRANDOM_H_INCLUDED
#define CMWCRANDOM_H_INCLUDED

#include "Random.h"
#include <deque>

namespace CK {
/*
 * Complimentary Multiply With Carry entropy generator
 * Geroge Marsaglia et al.
 */
class CMWCRandom : public Random {

    public:
        CMWCRandom();
        CMWCRandom(unsigned long seed);

    private:    // No copying or assignment allowed
        CMWCRandom(const CMWCRandom& other);
        CMWCRandom& operator= (const CMWCRandom& other);

    public:
        ~CMWCRandom();

    public:
        void setSeed(unsigned long seedValue);

    protected:
        virtual unsigned long next(int bits);

    private:
        long cmwc4096();
        void seedGenerator();

    private:
        unsigned long seed; // Seed generator nonce.
        unsigned long c; // Reset mask.
        typedef std::deque<unsigned long> Q;    // Seed
        Q q;

        static unsigned i;  // Seed selector.
        static const unsigned long long A;
        static const unsigned long R;

};

}

#endif // CMWCRANDOM_H_INCLUDED
