#include "DigestTest.h"
#include <iostream>

static std::string hexByte2string(unsigned char b) {

    char s[2];
    char nybble = (b & 0xf0) << 4;
    for (int n = 0; n < 2; ++n) {
        if (n == 1) {
            nybble = b & 0x0f;
        }
        if (nybble < 0x0a) {
            s[n] = nybble + '0';
        }
        else {
            switch (nybble) {
                case 0x0a:
                    s[n] = 'a';
                    break;
                case 0x0b:
                    s[n] = 'b';
                    break;
                case 0x0c:
                    s[n] = 'c';
                    break;
                case 0x0d:
                    s[n] = 'd';
                    break;
                case 0x0e:
                    s[n] = 'e';
                    break;
                case 0x0f:
                    s[n] = 'f';
                    break;
            }
        }
    }
    return std::string(s);
    
}

DigestTest::DigestTest() {
}

DigestTest::~DigestTest() {
}

bool DigestTest::sha256Test() {

    std::cout << "Input 61 62 63" << std::endl;
    std::cout << "Expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                << std::endl;

    unsigned char test1[] = { 61, 62, 63 };
    unsigned char e[] =
            { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                    0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96,
                    0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
    ByteArray expected(e, 32);
    sha256.update(ByteArray(test1, 3));
    ByteArray actual = sha256.digest();
    std::cout << "Actual ";
    for (unsigned n = 0; n < actual.length(); ++n) {
            std::cout << hexByte2string(actual[n]);
    }
    std::cout << std::endl;
    if (expected != actual) {
        std::cout << "Test failed." << std::endl;
        return false;
    }
    std::cout << "Test passed." << std::endl;

    return true;

}

