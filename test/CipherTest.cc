#include "CipherTest.h"
#include <CryptoKitty-C/cipher/AES.h>
#include <CryptoKitty-C/cipher/OAEPrsaes.h>
#include <CryptoKitty-C/keys/RSAKeyPairGenerator.h>
#include <CryptoKitty-C/keys/RSAPrivateCrtKey.h>
#include <CryptoKitty-C/keys/RSAPrivateModKey.h>
#include <CryptoKitty-C/keys/RSAPublicKey.h>
#include <CryptoKitty-C/ciphermodes/CBC.h>
#include <CryptoKitty-C/ciphermodes/GCM.h>
#include <CryptoKitty-C/ciphermodes/MtE.h>
#include <coder/ByteArray.h>
#include <CryptoKitty-C/mac/HMAC.h>
#include <CryptoKitty-C/digest/SHA256.h>
#include <CryptoKitty-C/random/FortunaSecureRandom.h>
#include <CryptoKitty-C/data/BigInteger.h>
#include <iostream>
#include <memory>
#include <string>


CipherTest::CipherTest() {
}

CipherTest::~CipherTest() {
}

bool CipherTest::AESTest() {

    /*uint8_t tk192[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    coder::ByteArray testKey192(tk192, 24);

    uint8_t k128[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    coder::ByteArray key128(k128, 16);

    uint8_t k192[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
    coder::ByteArray key192(k192, 24);

    uint8_t k256[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    coder::ByteArray key256(k256, 32);

    uint8_t p1[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    coder::ByteArray plaintext1(p1, 16);

    uint8_t v128[] = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
    coder::ByteArray vector128(v128, 16);

    uint8_t v192[] = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
    coder::ByteArray vector192(v192, 16);

    uint8_t v256[] = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
    coder::ByteArray vector256(v256, 16);

    std::cout << "AES 128 test." << std::endl;
    std::cout << "Key = " << key128 << std::endl;
    std::cout << "Plaintext = " << plaintext1 << std::endl;
    std::cout << "Vector = " << vector128 << std::endl;
    CK::AES cipher128(CK::AES::AES128);
    coder::ByteArray ciphertext128(cipher128.encrypt(plaintext1, key128));
    std::cout << "Ciphertext = " << ciphertext128 << std::endl;
    if (ciphertext128 != vector128) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    coder::ByteArray roundtrip128(cipher128.decrypt(ciphertext128, key128));
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
    coder::ByteArray ciphertext192(cipher192.encrypt(plaintext1,key192));
    std::cout << "Ciphertext = " << ciphertext192 << std::endl;
    if (ciphertext192 != vector192) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    coder::ByteArray roundtrip192(cipher192.decrypt(ciphertext192, key192));
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
    coder::ByteArray ciphertext256(cipher256.encrypt(plaintext1, key256));
    std::cout << "Ciphertext = " << ciphertext256 << std::endl;
    if (ciphertext256 != vector256) {
        std::cout << "Ciphertext doesn't match." << std::endl;
        return false;
    }
    std::cout << "Ciphertext matches." << std::endl << std::endl;
    coder::ByteArray roundtrip256(cipher256.decrypt(ciphertext256, key256));
    std::cout << "Plaintext = " << roundtrip256 << std::endl;
    if (roundtrip256 != plaintext1) {
        std::cout << "AES 256 round trip failed." << std::endl;
        return false;
    }
    std::cout << "AES 256 test passed." << std::endl << std::endl;

    std::cout << "AES-256 CBC mode test." << std::endl;
    std::string rickroll("Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you");
    coder::ByteArray plaintext2(rickroll);
    std::cout << "Plaintext = " << plaintext2 << std::endl;
    CK::CMWCRandom rnd;
    rnd.setSeed(1546293757762033520);
    coder::ByteArray iv(16);
    rnd.nextBytes(iv);
    CK::CBC cbc(new CK::AES(CK::AES::AES256), iv);
    coder::ByteArray ciphertextCBC(cbc.encrypt(plaintext2, key256));
    std::cout << "Ciphertext = " << ciphertextCBC << std::endl;
    coder::ByteArray roundtripCBC(cbc.decrypt(ciphertextCBC, key256));
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
    coder::ByteArray ciphertextAEAD(mteSnd.encrypt(plaintext2, key256));
    std::cout << "Ciphertext = " << ciphertextAEAD << std::endl;
    CK::CBC *aeadR = new CK::CBC(new CK::AES(CK::AES::AES256), iv);
    CK::MtE mteRcv(aeadR, new CK::HMAC(new CK::SHA256));
    coder::ByteArray roundtripAEAD(mteRcv.decrypt(ciphertextAEAD, key256));
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
    //coder::ByteArray plaintext(pt, sizeof(pt));
    coder::ByteArray plaintext(0);
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
    coder::ByteArray key(k, sizeof(k));
    /*uint8_t i[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00 };
    uint8_t i[] = { 0xdb, 0xd1, 0xa3, 0x63, 0x60, 0x24, 0xb7, 0xb4,
                    0x02, 0xda, 0x7d, 0x6f };*/
    uint8_t i[] = { 0x51, 0x6c, 0x33, 0x92, 0x9d, 0xf5, 0xa3, 0x28,
                    0x4f, 0xf4, 0x63, 0xd7 };
    /*uint8_t i[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
                    0xde, 0xca, 0xf8, 0x88 };*/
    coder::ByteArray iv(i, 12);
    /*uint8_t a[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
                    0xab, 0xad, 0xda, 0xd2 };
    coder::ByteArray ad(a, 20);*/
    coder::ByteArray ad(0);
    std::cout << "Plaintext = " << std::endl << plaintext
                    << std::endl << std::endl;
    std::cout << "Authentication data = " << std::endl << ad
                    << std::endl << std::endl;
    CK::GCM gcme(new CK::AES(CK::AES::AES256), iv);
    //coder::ByteArray authData("October 28, 1956");
    gcme.setAuthData(ad);
    coder::ByteArray ciphertext(gcme.encrypt(plaintext, key));
    std::cout << "Ciphertext = " << std::endl << ciphertext
                        << std::endl << std::endl;
    coder::ByteArray tag(gcme.getAuthTag());
    std::cout << "Authentication tag = " << std::endl << tag
                        << std::endl << std::endl;
    CK::GCM gcmd(new CK::AES(CK::AES::AES256), iv);
    gcmd.setAuthData(ad);
    gcmd.setAuthTag(tag);
    //gcmd.setAuthData(authData);
    coder::ByteArray roundtrip(gcmd.decrypt(ciphertext, key));
    std::cout << "Plaintext = " << std::endl << roundtrip
                        << std::endl << std::endl;
    if (roundtrip != plaintext) {
        std::cout << "AES-128 GCM mode round trip failed" << std::endl;
        return false;
    }
    std::cout << "AES-128 GCM mode test passed." << std::endl << std::endl;

    return true;

}

bool CipherTest::RSAOAEPTest() {

    std::cout << "Generating 2048 bit key pair." << std::endl;
    CK::FortunaSecureRandom rnd;
    CK::RSAKeyPairGenerator keyGen;
    keyGen.initialize(2048, &rnd);
    std::unique_ptr<CK::KeyPair<CK::RSAPublicKey, CK::RSAPrivateKey> >
                                                pair(keyGen.generateKeyPair());

    coder::ByteArray label("This is my label");
    coder::ByteArray seed(32);
    rnd.nextBytes(seed);
    CK::OAEPrsaes rsae(CK::OAEPrsaes::sha256);
    rsae.setSeed(seed);
    rsae.setLabel(label);

    coder::ByteArray roundtrip("01020304818283842122232441424344");

    std::cout << "Encrypting round trip text." << std::endl;
    coder::ByteArray rtct(rsae.encrypt(*pair->publicKey(), roundtrip));

    CK::OAEPrsaes rsad(CK::OAEPrsaes::sha256);
    rsad.setLabel(label);
    std::cout << "Decrypting round trip text." << std::endl;
    coder::ByteArray rtpt(rsad.decrypt(*pair->privateKey(), rtct));

    if (rtpt != roundtrip) {
        std::cout << "OAEP round trip test failed." << std::endl;
        return false;
    }
    std::cout << "OAEP round trip passed." << std::endl;

    coder::ByteArray n1Bytes("a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb", true);
    CK::BigInteger n1(n1Bytes, CK::BigInteger::BIGENDIAN);
    coder::ByteArray e1Bytes("010001", true);
    CK::BigInteger e1(e1Bytes, CK::BigInteger::BIGENDIAN);
    coder::ByteArray p1Bytes("d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d", true);
    CK::BigInteger p1(p1Bytes, CK::BigInteger::BIGENDIAN);
    coder::ByteArray q1Bytes("cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77", true);
    CK::BigInteger q1(q1Bytes, CK::BigInteger::BIGENDIAN);
    coder::ByteArray d1Bytes("53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1", true);
    CK::BigInteger d1(d1Bytes, CK::BigInteger::BIGENDIAN);

    CK::RSAPublicKey pub1(n1, e1);
    CK::RSAPrivateCrtKey prv1(p1, q1, d1, e1);
    //CK::RSAPrivateModKey prv1(n1, d1);

    coder::ByteArray pt1("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34", true);
    coder::ByteArray s1("18b776ea21069d69776a33e96bad48e1dda0a5ef", true);

    std::string ex1("354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535fa9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a");
    coder::ByteArray ect1(ex1, true);
    CK::OAEPrsaes et1(CK::OAEPrsaes::sha1);
    et1.setSeed(s1);
    coder::ByteArray ct1(et1.encrypt(pub1, pt1));
    std::cout << "Expected ciphertext: " << ex1 << std::endl;
    std::cout << "Actual ciphertext: " << ct1.toHexString() << std::endl;

    CK::OAEPrsaes dt1(CK::OAEPrsaes::sha1);
    coder::ByteArray rpt1(dt1.decrypt(prv1, ct1));
    std::cout << "Plaintext: " << pt1.toHexString() << std::endl;
    std::cout << "Decrypted plaintext: " << rpt1.toHexString() << std::endl;

    if (pt1 != rpt1 || ct1 != ect1) {
        std::cout << "OAEP test vector 1 failed." << std::endl;
        return false;
    }
    std::cout << "OAEP test vector 1 passed." << std::endl << std::endl;

    coder::ByteArray pt2("750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5", true);
    coder::ByteArray s2("0cc742ce4a9b7f32f951bcb251efd925fe4fe35f", true);

    std::string ex2("640db1acc58e0568fe5407e5f9b701dff8c3c91e716c536fc7fcec6cb5b71c1165988d4a279e1577d730fc7a29932e3f00c81515236d8d8e31017a7a09df4352d904cdeb79aa583adcc31ea698a4c05283daba9089be5491f67c1a4ee48dc74bbbe6643aef846679b4cb395a352d5ed115912df696ffe0702932946d71492b44");
    coder::ByteArray ect2(ex2, true);
    CK::OAEPrsaes et2(CK::OAEPrsaes::sha1);
    et2.setSeed(s2);
    coder::ByteArray ct2(et2.encrypt(pub1, pt2));
    std::cout << "Expected ciphertext: " << ex2 << std::endl;
    std::cout << "Actual ciphertext: " << ct2.toHexString() << std::endl;

    CK::OAEPrsaes dt2(CK::OAEPrsaes::sha1);
    coder::ByteArray rpt2(dt2.decrypt(prv1, ct2));
    std::cout << "Plaintext: " << pt2.toHexString() << std::endl;
    std::cout << "Decrypted plaintext: " << rpt2.toHexString() << std::endl;

    if (pt2 != rpt2 || ct2 != ect2) {
        std::cout << "OAEP test vector 2 failed." << std::endl;
        return false;
    }
    std::cout << "OAEP test vector 2 passed." << std::endl;

    return true;

}

