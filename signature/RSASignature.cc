#include "signature/RSASignature.h"
#include "exceptions/IllegalStateException.h"
#include "cipher/RSA.h"

namespace CK {

template<class C, class D>
RSASignature<C,D>::RSASignature()
: signInit(false),
  verifyInit(false),
  cipher(new C(new D)) {
}

template<class C, class D>
RSASignature<C,D>::~RSASignature() {

    delete cipher;
}

/*
 * Initialize the signing function.
 */
template<class C, class D>
void RSASignature<C,D>::initSign(const RSAPrivateKey& prv) {

    privateKey = prv;
    signInit = true;

}

/*
 * Initialize the signature verification function.
 */
template<class C, class D>
void RSASignature<C,D>::initVerify(const RSAPublicKey& pub) {

    publicKey = pub;
    verifyInit = true;

}

/*
 * Sign the accumulated message.
 */
template<class C, class D>
ByteArray RSASignature<C,D>::sign() {

    if (!signInit) {
        throw IllegalStateException("Signature Not Initialized");
    }

    return cipher->sign(privateKey, accumulator);

}

/*
 * Update the message accumulator with a byte.
 */
template<class C, class D>
void RSASignature<C,D>::update(unsigned char b) {

    accumulator.append(b);

}

/*
 * Update the message accumulator with a byte array.
 */
template<class C, class D>
void RSASignature<C,D>::update(const ByteArray& bytes) {

    accumulator.append(bytes);

}

/*
 * Verify the accumulated message.
 */
template<class C, class D>
bool RSASignature<C,D>::verify(const ByteArray& sig) {

    if (!signInit) {
        throw IllegalStateException("Signature Not Initialized");
    }

    return cipher->verify(publicKey, accumulator, sig);

}

}

// PKCS1SHA256RSASignature with RSA CRT private key instantiation.
//#include "digest/SHA256.h"
//#include "cipher/PKCS1rsassa.h"
//#include "keys/RSAPrivateCrtKey.h"

//CK::RSASignature<CK::PKCS1rsassa<CK::RSAPrivateCrtKey>, CK::SHA256, CK::RSAPrivateCrtKey> pkcs1sha256sig;

