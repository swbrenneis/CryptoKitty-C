#include "DigestTest.h"
#include "data/ByteArray.h"
#include "digest/SHA256.h"
#include "digest/SHA384.h"
#include "digest/SHA512.h"
#include <iostream>

DigestTest::DigestTest() {
}

DigestTest::~DigestTest() {
}

bool DigestTest::sha256Test() {

    CK::SHA256 sha256;

    std::cout << "Empty message test." << std::endl;
    std::string empty("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    std::cout << "Expected " << empty << std::endl;
    std::string actual(sha256.digest().toString());
    std::cout << "Actual   " << actual << std::endl;
    if (actual != empty) {
        std::cout << "Empty message test failed." << std::endl;
        return false;
    }
    std::cout << "Empty message test passed." << std::endl << std::endl;

    sha256.reset();

    std::cout << "'abc' message test." << std::endl;
    std::string abc("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::cout << "Expected " << abc << std::endl;
    sha256.update(CK::ByteArray("abc"));
    actual = sha256.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != abc) {
        std::cout << "'abc' test failed." << std::endl;
        return false;
    }
    std::cout << "'abc' test passed." << std::endl << std::endl;

    sha256.reset();

    std::cout << "Padding test." << std::endl;
    std::string padTest("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    std::cout << "Expected " << padTest << std::endl;
    sha256.update(CK::ByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    actual = sha256.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != padTest) {
        std::cout << "Padding test failed." << std::endl;
        return false;
    }
    std::cout << "Padding test passed." << std::endl << std::endl;

    sha256.reset();

    std::cout << "Million test." << std::endl;
    std::string million("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    std::cout << "Expected " << million << std::endl;
    // Insert 1 million 'a' characters
    for (int n = 0; n < 1000000; ++n) {
        sha256.update('a');
    }
    actual = sha256.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != million) {
        std::cout << "Million test failed." << std::endl;
        return false;
    }
    std::cout << "Million test passed." << std::endl;

    return true;

}

bool DigestTest::sha384Test() {

    CK::SHA384 sha384;

    std::cout << "Empty message test." << std::endl;
    std::string empty("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    std::cout << "Expected " << empty << std::endl;
    std::string actual(sha384.digest().toString());
    std::cout << "Actual   " << actual << std::endl;
    if (actual != empty) {
        std::cout << "Empty message test failed." << std::endl;
        return false;
    }
    std::cout << "Empty message test passed." << std::endl << std::endl;

    sha384.reset();

    std::cout << "'abc' message test." << std::endl;
    std::string abc("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    std::cout << "Expected " << abc << std::endl;
    sha384.update(CK::ByteArray("abc"));
    actual = sha384.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != abc) {
        std::cout << "'abc' test failed." << std::endl;
        return false;
    }
    std::cout << "'abc' test passed." << std::endl << std::endl;

    sha384.reset();

    std::cout << "Padding test." << std::endl;
    std::string padTest("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    std::cout << "Expected " << padTest << std::endl;
    sha384.update(CK::ByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    actual = sha384.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != padTest) {
        std::cout << "Padding test failed." << std::endl;
        return false;
    }
    std::cout << "Padding test passed." << std::endl << std::endl;

    sha384.reset();

    std::cout << "Million test." << std::endl;
    std::string million("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");
    std::cout << "Expected " << million << std::endl;
    // Insert 1 million 'a' characters
    for (int n = 0; n < 1000000; ++n) {
        sha384.update('a');
    }
    actual = sha384.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != million) {
        std::cout << "Million test failed." << std::endl;
        return false;
    }
    std::cout << "Million test passed." << std::endl;

    return true;

}
bool DigestTest::sha512Test() {

    CK::SHA512 sha512;

    std::cout << "Empty message test." << std::endl;
    std::string empty("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    std::cout << "Expected " << empty << std::endl;
    std::string actual(sha512.digest().toString());
    std::cout << "Actual   " << actual << std::endl;
    if (actual != empty) {
        std::cout << "Empty message test failed." << std::endl;
        return false;
    }
    std::cout << "Empty message test passed." << std::endl << std::endl;

    sha512.reset();

    std::cout << "'abc' message test." << std::endl;
    std::string abc("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    std::cout << "Expected " << abc << std::endl;
    sha512.update(CK::ByteArray("abc"));
    actual = sha512.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != abc) {
        std::cout << "'abc' test failed." << std::endl;
        return false;
    }
    std::cout << "'abc' test passed." << std::endl << std::endl;

    sha512.reset();

    std::cout << "Padding test." << std::endl;
    std::string padTest("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    std::cout << "Expected " << padTest << std::endl;
    sha512.update(CK::ByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    actual = sha512.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != padTest) {
        std::cout << "Padding test failed." << std::endl;
        return false;
    }
    std::cout << "Padding test passed." << std::endl << std::endl;

    sha512.reset();

    std::cout << "Million test." << std::endl;
    std::string million("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    std::cout << "Expected " << million << std::endl;
    // Insert 1 million 'a' characters
    for (int n = 0; n < 1000000; ++n) {
        sha512.update('a');
    }
    actual = sha512.digest().toString();
    std::cout << "Actual   " << actual << std::endl;
    if (actual != million) {
        std::cout << "Million test failed." << std::endl;
        return false;
    }
    std::cout << "Million test passed." << std::endl;

    return true;

}

