#include "DigestTest.h"
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

    std::cout << "Empty message test." << std::endl;
    std::cout << "Expected e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                << std::endl;
    unsigned char emptyExpected256[] =
            { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64,
                    0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
    ByteArray expected(emptyExpected256, 32);
    ByteArray actual = sha256.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.length(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Empty test failed." << std::endl;
        return false;
    }
    std::cout << "Empty test passed." << std::endl;

    sha256.reset();
    std::cout << "'abc' message test." << std::endl;
    std::cout << "Expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                << std::endl;

    unsigned char abcTest[] = "abc";;
    unsigned char abcExpected256[] =
            { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96,
                    0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
    expected = ByteArray(abcExpected256, 32);
    sha256.update(ByteArray(abcTest, 3));
    actual = sha256.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.length(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "'abc' test failed." << std::endl;
        return false;
    }
    std::cout << "'abc' test passed." << std::endl;

    sha256.reset();
    unsigned char progressionTest256[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char progressionExpected256[] =
            { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
                    0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64,
                    0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };

    std::cout << "Character progression test." << std::endl;
    std::cout << "Expected 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                << std::endl;
    expected = ByteArray(progressionExpected256, 32);
    sha256.update(ByteArray(progressionTest256, 56));
    actual = sha256.digest();
    std::cout << "Actual   ";
    for (unsigned n = 0; n < actual.length(); ++n) {
        std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Mixed character test failed." << std::endl;
        return false;
    }
    std::cout << "Mixed character test passed." << std::endl;

    return true;

}

