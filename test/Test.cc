#include "DigestTest.h"
#include "MACTest.h"
#include "RandomTest.h"
#include "SignatureTest.h"
#include "CipherTest.h"
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

    std::cout << std::endl;
    if (tests == "random" || tests == "all") {
        RandomTest random;
        std::cout << "CMWC Test." << std::endl << std::endl;
        if (!random.cmwcTest()) {
            std::cout << std::endl << "CMWC Test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "CMWC Test passed." << std::endl;
        std::cout << std::endl << "BBS Test." << std::endl << std::endl;
        if (!random.BBSTest()) {
            std::cout << std::endl << "BBS Test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "BBS Test passed." << std::endl;
    }

    std::cout << std::endl;
    if (tests == "signature" || tests == "all") {
        SignatureTest sig;
        std::cout << "RSA signature using PKCS1 encoding and SHA-256 digest."
                << std::endl << std::endl;

        if (!sig.RSAPKCS1test(1024)) {
            std::cout << std::endl << "RSA PKCS v1.5 signature test failed." << std::endl;
            return -1;
        }
        
        if (!sig.RSAPKCS1test(2048)) {
            std::cout << std::endl << "RSA PKCS v1.5 signature test failed." << std::endl;
            return -1;
        }
        
        if (!sig.RSAPKCS1test(4096)) {
            std::cout << std::endl << "RSA PKCS v1.5 signature test failed." << std::endl;
            return -1;
        }
        std::cout << "RSA PKCS v1.5 signature test passed." << std::endl << std::endl;

        std::cout << "RSA signature using EMSA-PSS encoding and SHA-256 digest."
                << std::endl << std::endl;

        if (!sig.RSAPSStest(1024)) {
            std::cout << std::endl << "RSA PSS signature test failed." << std::endl;
            return -1;
        }
        
        if (!sig.RSAPSStest(2048)) {
            std::cout << std::endl << "RSA PSS signature test failed." << std::endl;
            return -1;
        }
        
        if (!sig.RSAPSStest(4096)) {
            std::cout << std::endl << "RSA PSS signature test failed." << std::endl;
            return -1;
        }
        std::cout << "RSA EMSA-PSS signature test passed." << std::endl << std::endl;

    }

    if (tests == "mac" || tests == "all") {

        std::cout << "HMAC test." << std::endl << std::endl;

        MACTest mac;
        if (!mac.HMACTest()) {
            std::cout << std::endl << "HMAC test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "HMAC test passed." << std::endl;

    }

    if (tests == "cipher" || tests == "all") {

        std::cout << "AES test." << std::endl << std::endl;

        CipherTest cipher;
        if (!cipher.AESTest()) {
            std::cout << std::endl << "AES test failed." << std::endl;
            return -1;
        }
        std::cout << std::endl << "AES test passed." << std::endl;

    }

    return 0;

}
