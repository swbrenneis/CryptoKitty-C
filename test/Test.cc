#include "DigestTest.h"
#include "RandomTest.h"
#include <string>
#include <iostream>

int main(int argc, char** argv) {

    std::string tests("all");
    if (argc > 1) {
        tests = argv[1];
    }

    if (tests == "digest" || tests == "all") {
        DigestTest digest;
        std::cout << "SHA-256 test" << std::endl << std::endl;
        if (!digest.sha256Test()) {
            std::cout << std::endl << "SHA-256 test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "SHA-256 test passed." << std::endl;
    }

    if (tests == "random" || tests == "all") {
        RandomTest random;
        std::cout << "CMWC Test." << std::endl << std::endl;
        if (!random.cmwcTest()) {
            std::cout << std::endl << "CMWC Test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "CMWC Test passed." << std::endl;
    }

    return 0;

}
