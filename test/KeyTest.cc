#include "KeyTest.h"
#include "keys/DHKeyExchange.h"
#include <iostream>

KeyTest::KeyTest() {
}

KeyTest::~KeyTest() {
}

bool KeyTest::DHtest(int keysize) {

    CK::DHKeyExchange bob;
    bob.setBitsize(keysize);
    CK::DHKeyExchange alice;
    alice.setBitsize(keysize);
    std::cout << "Diffie-Hellman key exchange test, " << keysize
            << " bit prime modulus." << std::endl;
    CK::BigInteger bpk = bob.generatePublicKey();
    alice.setGenerator(bob.getGenerator());
    alice.setModulus(bob.getModulus());
    CK::BigInteger apk = alice.generatePublicKey();
    CK::BigInteger as = alice.getSecret(bpk);
    std::cout << "Alice's secret: " << as << std::endl << std::endl;
    CK::BigInteger bs = bob.getSecret(apk);
    std::cout << "Bob's secret: " << as << std::endl << std::endl;
    if (as != bs) {
        std::cout << "Diffie-Hellman key exchange test failed."
                << std::endl;
        return false;
    }
    std::cout << "Diffie-Hellman key exchange test passed." << std::endl;
    return true;

}

