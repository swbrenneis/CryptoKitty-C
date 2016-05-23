#include "SignatureTest.h"
#include "keys/RSAKeyPairGenerator.h"
#include "random/SecureRandom.h"
#include "signature/RSASignature.h"
#include "digest/SHA256.h"
#include "cipher/PKCS1rsassa.h"
#include "cipher/PSSrsassa.h"
#include "coder/ByteArray.h"
#include "exceptions/Exception.h"
#include <iostream>

SignatureTest::SignatureTest() {
}

SignatureTest::~SignatureTest() {
}

bool SignatureTest::RSAPKCS1test(int keysize) {

    std::string msg("the quick brown fox jumped over the lazy dog");
    std::cout << "Message - " << msg << std::endl;
    coder::ByteArray m(msg);

    CK::SecureRandom *rng = CK::SecureRandom::getSecureRandom("BBS");
    std::cout << keysize << " bit RSA Key pair." << std::endl;
    CK::RSAKeyPairGenerator gen;
    gen.initialize(keysize, rng);
    CK::KeyPair<CK::RSAPublicKey, CK::RSAPrivateKey> *pair =
                    gen.generateKeyPair();

    try {
        // Salt length of 10 bytes
        CK::RSASignature<CK::PKCS1rsassa, CK::SHA256> sign(10);
        sign.initSign(pair->privateKey());
        sign.update(m);
        std::cout << "Signing..." << std::endl;
        coder::ByteArray sig(sign.sign());

        std::cout << "Verify signature." << std::endl;
        // Salt length of 10 bytes
        CK::RSASignature<CK::PKCS1rsassa, CK::SHA256> verify(10);
        verify.initVerify(pair->publicKey());
        verify.update(m);
        std::cout << "Verifying..." << std::endl;
        if (!verify.verify(sig)) {
            std::cout << "Signature verification failed." << std::endl;
            delete pair;
            return false;
        }
        std::cout << "Signature verification passed." << std::endl << std::endl;
        
        delete pair;
        return true;
    }
    catch (CK::Exception& e) {
        std::cout << "Exception thrown: " << e.what() << std::endl;
        delete pair;
        return false;
    }

}

bool SignatureTest::RSAPSStest(int keysize) {

    std::string msg("the quick brown fox jumped over the lazy dog");
    std::cout << "Message - " << msg << std::endl;
    coder::ByteArray m(msg);

    CK::SecureRandom *rng = CK::SecureRandom::getSecureRandom("BBS");
    std::cout << keysize << " bit RSA Key pair." << std::endl;
    CK::RSAKeyPairGenerator gen;
    gen.initialize(keysize, rng);
    CK::KeyPair<CK::RSAPublicKey, CK::RSAPrivateKey> *pair =
                    gen.generateKeyPair();

    try {
        CK::RSASignature<CK::PSSrsassa, CK::SHA256> sign;
        sign.initSign(pair->privateKey());
        sign.update(m);
        std::cout << "Signing..." << std::endl;
        coder::ByteArray sig(sign.sign());

        std::cout << "Verify signature." << std::endl;
        CK::RSASignature<CK::PSSrsassa, CK::SHA256> verify;
        verify.initVerify(pair->publicKey());
        verify.update(m);
        std::cout << "Verifying..." << std::endl;
        if (!verify.verify(sig)) {
            std::cout << "Signature verification failed." << std::endl;
            delete pair;
            return false;
        }
        std::cout << "Signature verification passed." << std::endl << std::endl;
        
        delete pair;
        return true;
    }
    catch (CK::Exception& e) {
        std::cout << "Exception thrown: " << e.what() << std::endl;
        delete pair;
        return false;
    }

}

