#include "CipherTest.h"
#include "cipher/AES.h"
#include "ciphermodes/CBC.h"
#include "ciphermodes/GCM.h"
#include "ciphermodes/MtE.h"
#include "data/ByteArray.h"
#include "mac/HMAC.h"
#include "digest/SHA256.h"
#include "random/CMWCRandom.h"
#include <iostream>


CipherTest::CipherTest() {
}

CipherTest::~CipherTest() {
}

bool CipherTest::AESTest() {

    /*uint8_t tk192[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    CK::ByteArray testKey192(tk192, 24);

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
    CK::ByteArray ciphertext192(cipher192.encrypt(plaintext1,key192));
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
    std::cout << "AES 256 test passed." << std::endl << std::endl;

    std::cout << "AES-256 CBC mode test." << std::endl;
    std::string rickroll("Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you");
    CK::ByteArray plaintext2(rickroll);
    std::cout << "Plaintext = " << plaintext2 << std::endl;
    CK::CMWCRandom rnd;
    rnd.setSeed(1546293757762033520);
    CK::ByteArray iv(16);
    rnd.nextBytes(iv);
    CK::CBC cbc(new CK::AES(CK::AES::AES256), iv);
    CK::ByteArray ciphertextCBC(cbc.encrypt(plaintext2, key256));
    std::cout << "Ciphertext = " << ciphertextCBC << std::endl;
    CK::ByteArray roundtripCBC(cbc.decrypt(ciphertextCBC, key256));
    std::cout << "Plaintext = " << roundtripCBC << std::endl;
    if (roundtripCBC != plaintext2) {
        std::cout << "AES-256 CBC mode test failed" << std::endl;
        return false;
    }
    std::cout << "AES-256 CBC mode test passed." << std::endl << std::endl;

    std::cout << "AES-256 CBC mode AEAD test." << std::endl;
    std::cout << "Plaintext = " << plaintext2 << std::endl;
    rnd.nextBytes(iv);
    CK::CBC *aeadS = new CK::CBC(new CK::AES(CK::AES::AES256), iv);
    CK::MtE mteSnd(aeadS, new CK::HMAC(new CK::SHA256));
    CK::ByteArray ciphertextAEAD(mteSnd.encrypt(plaintext2, key256));
    std::cout << "Ciphertext = " << ciphertextAEAD << std::endl;
    CK::CBC *aeadR = new CK::CBC(new CK::AES(CK::AES::AES256), iv);
    CK::MtE mteRcv(aeadR, new CK::HMAC(new CK::SHA256));
    CK::ByteArray roundtripAEAD(mteRcv.decrypt(ciphertextAEAD, key256));
    std::cout << "Plaintext = " << roundtripAEAD << std::endl;
    if (roundtripAEAD != plaintext2) {
        std::cout << "AES-256 CBC mode AEAD round trip failed" << std::endl;
        return false;
    }
    if (!mteRcv.authenticate()) {
        std::cout << "AES-256 CBC mode AEAD authentication failed" << std::endl;
        return false;
    }
    std::cout << "AES-256 CBC mode AEAD test passed." << std::endl << std::endl;*/

    std::cout << "AES-128 GCM mode test." << std::endl << std::endl;
    /*uint8_t pt[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t pt[] = { 0xa8, 0x45, 0x34, 0x8e, 0xc8, 0xc5, 0xb5, 0xf1,
                    0x26, 0xf5, 0x0e, 0x76, 0xfe, 0xfd, 0x1b, 0x1e };
    uint8_t pt[] = { 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
                    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
                    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
                    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
                    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
                    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
                    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
                    0xba, 0x63, 0x7b, 0x39 }; */
    //CK::ByteArray plaintext(pt, sizeof(pt));
    CK::ByteArray plaintext(0);
    /*uint8_t k[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t k[] = { 0xfb, 0x76, 0x15, 0xb2, 0x3d, 0x80, 0x89, 0x1d,
                    0xd4, 0x70, 0x98, 0x0b, 0xc7, 0x95, 0x84, 0xc8,
                    0xb2, 0xfb, 0x64, 0xce, 0x60, 0x97, 0x8f, 0x4d,
                    0x17, 0xfc, 0xe4, 0x5a, 0x49, 0xe8, 0x30, 0xb7 };*/
    uint8_t k[] = { 0xb5, 0x2c, 0x50, 0x5a, 0x37, 0xd7, 0x8e, 0xda,
                    0x5d, 0xd3, 0x4f, 0x20, 0xc2, 0x25, 0x40, 0xea,
                    0x1b, 0x58, 0x96, 0x3c, 0xf8, 0xe5, 0xbf, 0x8f,
                    0xfa, 0x85, 0xf9, 0xf2, 0x49, 0x25, 0x05, 0xb4 };
    /*uint8_t k[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
                    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };*/
    CK::ByteArray key(k, sizeof(k));
    /*uint8_t i[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00 };
    uint8_t i[] = { 0xdb, 0xd1, 0xa3, 0x63, 0x60, 0x24, 0xb7, 0xb4,
                    0x02, 0xda, 0x7d, 0x6f };*/
    uint8_t i[] = { 0x51, 0x6c, 0x33, 0x92, 0x9d, 0xf5, 0xa3, 0x28,
                    0x4f, 0xf4, 0x63, 0xd7 };
    /*uint8_t i[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
                    0xde, 0xca, 0xf8, 0x88 };*/
    CK::ByteArray iv(i, 12);
    /*uint8_t a[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xab, 0xad, 0xda, 0xd2 };
    CK::ByteArray ad(a, 20);*/
    CK::ByteArray ad(0);
    std::cout << "Plaintext = " << std::endl << plaintext
                    << std::endl << std::endl;
    std::cout << "Authentication data = " << std::endl << ad
                    << std::endl << std::endl;
    CK::GCM gcme(new CK::AES(CK::AES::AES256), iv);
    //CK::ByteArray authData("October 28, 1956");
    gcme.setAuthData(ad);
    CK::ByteArray ciphertext(gcme.encrypt(plaintext, key));
    std::cout << "Ciphertext = " << std::endl << ciphertext
                        << std::endl << std::endl;
    CK::ByteArray tag(gcme.getAuthTag());
    std::cout << "Authentication tag = " << std::endl << tag
                        << std::endl << std::endl;
    CK::GCM gcmd(new CK::AES(CK::AES::AES256), iv);
    gcmd.setAuthData(ad);
    gcmd.setAuthTag(tag);
    //gcmd.setAuthData(authData);
    CK::ByteArray roundtrip(gcmd.decrypt(ciphertext, key));
    std::cout << "Plaintext = " << std::endl << roundtrip
                        << std::endl << std::endl;
    if (roundtrip != plaintext) {
        std::cout << "AES-128 GCM mode round trip failed" << std::endl;
        return false;
    }
    std::cout << "AES-128 GCM mode test passed." << std::endl << std::endl;

    return true;

}

