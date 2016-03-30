#include "MACTest.h"
#include "mac/HMAC.h"
#include "digest/SHA256.h"
#include "exceptions/Exception.h"
#include <string>
#include <iostream>

MACTest::MACTest() {
}

MACTest::~MACTest() {
}

bool MACTest::HMACTest() {

    try {
    CK::HMAC hmac_sha256_sign(new CK::SHA256);
    std::cout << "HMAC-SHA256 test with 256 bit key." << std::endl << std::endl;

    std::cout << "Generating key." << std::endl;
    CK::ByteArray key = hmac_sha256_sign.generateKey(256);
    std::string message("the quick brown fox jumped over the lazy dog");
    std::cout << "Setting message - " << message << std::endl;
    hmac_sha256_sign.setMessage(CK::ByteArray(message));
    std::cout << "Getting HMAC." << std::endl;
    CK::ByteArray hmac = hmac_sha256_sign.getHMAC();

    std::cout << "Authorizing..." << std::endl;
    CK::HMAC hmac_sha256_auth(new CK::SHA256);
    hmac_sha256_auth.setMessage(message);
    hmac_sha256_auth.setKey(key);
    if (!hmac_sha256_auth.authenticate(hmac)) {
        std::cout << "HMAC-SHA256 test with 128 bit key failed." << std::endl << std::endl;
        return false;
    }
    std::cout << "HMAC-SHA256 test with 128 bit key passed." << std::endl << std::endl;

    return true;
    }
    catch (CK::Exception& e) {
        std::cout << "Exception thrown: " << e.what() << std::endl;
        return false;
    }


}

