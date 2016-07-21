#include "RandomTest.h"
#include "random/SecureRandom.h"
#include "random/CMWCRandom.h"
#include "coder/ByteArray.h"
#include <iostream>
#include <deque>

RandomTest::RandomTest() {
}

RandomTest::~RandomTest() {
}

bool RandomTest::BBSTest() {

/*    std::cout << "Reseed test" << std::endl;
    CK::SecureRandom *bbs = CK::SecureRandom::getSecureRandom("BBS");
    std::cout << "First long random " << std::flush;
    long firstRnd = bbs->nextLong();
    std::cout << firstRnd << std::endl;
    // 900 KBytes is the reseed period
    std::cout << "Getting 900 KBytes" << std::flush;
    coder::ByteArray bytes(1024);
    for (int n = 0; n < 899; ++n) {
        bbs->nextBytes(bytes);
        if (n % 50 == 0) {
            std::cout << " ." << std::flush;;
        }
    }
    bytes.setLength(1016);
    bbs->nextBytes(bytes);
    std::cout << std::endl << "Second long random " << std::flush;
    long secondRnd = bbs->nextLong();
    std::cout << secondRnd << std::endl;
    if (firstRnd == secondRnd) {
        std::cout << "Reseed test failed." << std::endl;
        return false;
    }
    std::cout << "Reseed test passed." << std::endl;
*/    return true;

}

bool RandomTest::cmwcTest() {

    std::cout << "Repeated seed test" << std::endl;
    unsigned long seed = 2953602193602L;
    CK::CMWCRandom cmwc;
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
