#include "../include/random/CMWCRandom.h"

class RandomTest {

    public:
        RandomTest();
        ~RandomTest();

    private:
        RandomTest(const RandomTest&);
        RandomTest& operator= (const RandomTest&);

    private:
        CMWCRandom rnd;

};
