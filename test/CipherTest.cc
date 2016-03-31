#include "CipherTest.h"
#include "cipher/AES.h"
#include "data/ByteArray.h"
#include <iostream>


CipherTest::CipherTest() {
}

CipherTest::~CipherTest() {
}

bool CipherTest::AESTest() {

    uint8_t k128[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    CK::ByteArray key128(k128, 16);

    uint8_t k192[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    CK::ByteArray key192(k192, 24);

    uint8_t k256[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    CK::ByteArray key256(k256, 32);

    uint8_t p1[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    CK::ByteArray plaintext1(p1, 16);

    uint8_t v128[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    CK::ByteArray vector128(v128, 16);

    uint8_t v192[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    CK::ByteArray vector192(v192, 16);

    uint8_t v256[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
    CK::ByteArray vector256(v256, 16);

    std::cout << "AES 128 test." << std::endl;
    std::cout << "Key = " << key128 << std::endl;
    std::cout << "Plaintext = " << plaintext1 << std::endl;
    std::cout << "Vector = " << vector128 << std::endl;
    CK::AES cipher128(CK::AES::AES128);
    CK::ByteArray ciphertext128(cipher128.encrypt(plaintext1, key128));
    std::cout << "Ciphertext = " << ciphertext128 << std::endl;
    if (ciphertext128 != vector128) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    CK::ByteArray roundtrip128(cipher128.decrypt(ciphertext128, key128));
    std::cout << "Plaintext = " << roundtrip128 << std::endl;
    if (roundtrip128 != plaintext1) {
        std::cout << "AES 128 round trip failed." << std::endl;
        return false;
    }
    std::cout << "AES 128 test passed." << std::endl << std::endl;

    std::cout << "AES 192 test." << std::endl;
    std::cout << "Key = " << key192 << std::endl;
    std::cout << "Plaintext = " << plaintext1 << std::endl;
    std::cout << "Vector = " << vector192 << std::endl;
    CK::AES cipher192(CK::AES::AES192);
    CK::ByteArray ciphertext192(cipher192.encrypt(plaintext1, key192));
    std::cout << "Ciphertext = " << ciphertext192 << std::endl;
    if (ciphertext192 != vector192) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    CK::ByteArray roundtrip192(cipher192.decrypt(ciphertext192, key192));
    std::cout << "Plaintext = " << roundtrip192 << std::endl;
    if (roundtrip192 != plaintext1) {
        std::cout << "AES 192 round trip failed." << std::endl;
        return false;
    }
    std::cout << "AES 192 test passed." << std::endl << std::endl;

    std::cout << "AES 256 test." << std::endl;
    std::cout << "Key = " << key256 << std::endl;
    std::cout << "Plaintext = " << plaintext1 << std::endl;
    std::cout << "Vector = " << vector256 << std::endl;
    CK::AES cipher256(CK::AES::AES256);
    CK::ByteArray ciphertext256(cipher256.encrypt(plaintext1, key256));
    std::cout << "Ciphertext = " << ciphertext256 << std::endl;
    if (ciphertext256 != vector256) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    CK::ByteArray roundtrip256(cipher256.decrypt(ciphertext256, key256));
    std::cout << "Plaintext = " << roundtrip256 << std::endl;
    if (roundtrip256 != plaintext1) {
        std::cout << "AES 256 round trip failed." << std::endl;
        return false;
    }
    std::cout << "AES 256 test passed." << std::endl;

    return true;

}
