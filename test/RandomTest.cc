#include "RandomTest.h"
#include <iostream>
#include <deque>

RandomTest::RandomTest() {
}

RandomTest::~RandomTest() {
}

bool RandomTest::cmwcTest() {

    std::cout << "Repeated seed test" << std::endl;
    unsigned long seed = 2953602193602L;
    CMWCRandom cmwc;
    cmwc.setSeed(seed);
    std::deque<long> set1;
    std::cout << "First set ";
    for (int n = 0; n < 20; ++n) {
        set1.push_back(cmwc.nextLong());
        std::cout << ". ";
    }
    std::cout << std::endl;
    cmwc.setSeed(seed);
    std::deque<long> set2;
    std::cout << "Second set ";
    for (int n = 0; n < 20; ++n) {
        set2.push_back(cmwc.nextLong());
        std::cout << ". ";
    }
    std::cout << std::endl << std::endl;
    if (set1 == set2) {
        std:: cout << "Repeated seed test failed." << std::endl;
        return false;
    }
    std:: cout << "Repeated seed test passed." << std::endl;

    return true;

}
