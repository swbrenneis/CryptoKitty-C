#include "RandomTest.h"
#include <iostream>

RandomTest::RandomTest() {
}

RandomTest::~RandomTest() {
}

bool RandomTest::cmwcTest() {

    std::cout << "Repeated seed test" << std::endl;
    unsigned long seed = 2953602193602L;
    CMWCRandom cmwc;
    cmwc.setSeed(seed);
    unsigned long set1[20];
    std::cout << "First set ";
    for (int n = 0; n < 20; ++n) {
        set1[n] = cmwc.nextLong();
        std::cout << set1[n];
        if (n == 9) {
            std::cout << std::endl;
        }
        else {
            std::cout << ", ";
        }
    }
    std::cout << std::endl;

    return true;

}
