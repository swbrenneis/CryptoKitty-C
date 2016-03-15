#ifndef CMWCRANDOM_H_INCLUDED
#define CMWCRANDOM_H_INCLUDED

#include <deque>

/*
 * Complimentary Multiply With Carry entropy generator
 * Geroge Marsaglia et al.
 */
class CMWCRandom {

    public:
        CMWCRandom();
        CMWCRandom(unsigned long seed);

    private:    // No copying or assignment allowed
        CMWCRandom(const CMWCRandom& other);
        CMWCRandom& operator= (const CMWCRandom& other);

    public:
        ~CMWCRandom();

    public:
        unsigned long next(unsigned bits);
        void setSeed(unsigned long seedValue);

    private:
        void seedGenerator();

    private:
        unsigned long seed;
        typedef std::deque<unsigned long> Q;
        Q q;

};

#endif // CMWCRANDOM_H_INCLUDED
