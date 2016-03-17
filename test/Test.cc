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
        std::cout << "SHA-256 test" << std::endl;
        if (!digest.sha256Test()) {
            std::cout << "SHA-256 test failed." << std::endl;
            return -1;
        }
    }

    return 0;

}
