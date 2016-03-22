#include "../include/random/CMWCRandom.h"

class RandomTest {

    public:
        RandomTest();
        ~RandomTest();

    private:
        RandomTest(const RandomTest&);
        RandomTest& operator= (const RandomTest&);

    public:
        bool cmwcTest();
        bool BBSTest();

    private:
        CMWCRandom rnd;

};
