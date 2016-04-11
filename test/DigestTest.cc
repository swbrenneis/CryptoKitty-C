#include "DigestTest.h"
#include "data/ByteArray.h"
#include "digest/SHA256.h"
#include "digest/SHA512.h"
#include <iostream>

static std::string hexByte2string(unsigned char b) {

    char s[3];
    s[2] = 0;
    char nybble = (b & 0xf0) >> 4;
    for (int n = 0; n < 2; ++n) {
        if (n == 1) {
            nybble = b & 0x0f;
        }
        if (nybble < 0x0a) {
            s[n] = nybble + '0';
        }
        else {
            s[n] = (nybble - 0x0a) + 'a';
        }
    }
    return std::string(s);
    
}

DigestTest::DigestTest() {
}

DigestTest::~DigestTest() {
}

bool DigestTest::sha256Test() {

    CK::SHA256 sha256;

    std::cout << "Empty message test." << std::endl;
    std::string empty("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    std::cout << "Expected " << expected << std::endl;
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
    std::cout << "Expected " << padTest >> std::endl;
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
    unsigned char millionExpected256[] =
            { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7,
                    0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4,
                    0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };

    std::cout << "Expected cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
                << std::endl;
    expected = CK::ByteArray(millionExpected256, 32);
    // Insert 1 million 'a' characters
    for (int n = 0; n < 1000000; ++n) {
        sha256.update('a');
    }
    actual = sha256.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.getLength(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Million test failed." << std::endl;
        return false;
    }
    std::cout << "Million test passed." << std::endl;

    return true;

}

bool DigestTest::sha512Test() {

    CK::SHA512 sha512;
    std::cout << "Empty message test." << std::endl;
    std::string emptyExpected("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    std::cout << "Expected " << emptyExpected << std::endl;
    unsigned char emptyExpected512[] =
            { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64,
                    0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
    CK::ByteArray expectedA(emptyExpected512, 32);
    CK::ByteArray actual = sha512.digest();
    std::cout << "Actual   ";
    std::string emptyActual;
    for (unsigned n = 0; n < actual.getLength(); ++n) {
        emptyActual += hexByte2string(actual[n]);
    }
    std::cout << emptyActual << std::endl;
    if (emptyExpected != emptyActual) {
        std::cout << "Empty message test failed." << std::endl;
        return false;
    }
    std::cout << "Empty message test passed." << std::endl << std::endl;

    sha512.reset();
    std::cout << "'abc' message test." << std::endl;
    std::cout << "Expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                << std::endl;

    unsigned char abcTest[] = "abc";;
    unsigned char abcExpected512[] =
            { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96,
                    0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
    CK::ByteArray expected(abcExpected512, 32);
    sha512.update(CK::ByteArray(abcTest, 3));
    actual = sha512.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.getLength(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "'abc' test failed." << std::endl;
        return false;
    }
    std::cout << "'abc' test passed." << std::endl << std::endl;

    sha512.reset();
    unsigned char padTest512[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char padExpected512[] =
            { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
                    0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64,
                    0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };

    std::cout << "Padding test." << std::endl;
    std::cout << "Expected 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                << std::endl;
    expected = CK::ByteArray(padExpected512, 32);
    sha512.update(CK::ByteArray(padTest512, 56));
    actual = sha512.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.getLength(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Padding test failed." << std::endl;
        return false;
    }
    std::cout << "Padding test passed." << std::endl << std::endl;

    sha512.reset();
    unsigned char millionExpected512[] =
            { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7,
                    0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4,
                    0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };

    std::cout << "Million test." << std::endl;
    std::cout << "Expected cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
                << std::endl;
    expected = CK::ByteArray(millionExpected512, 32);
    // Insert 1 million 'a' characters
    for (int n = 0; n < 1000000; ++n) {
        sha512.update('a');
    }
    actual = sha512.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.getLength(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Million test failed." << std::endl;
        return false;
    }
    std::cout << "Million test passed." << std::endl;

    return true;

}

