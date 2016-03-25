#include "digest/Digest.h"
#include "cipher/PKCS1rsassa.h"
#include "exceptions/IllegalOperationException.h"
#include "exceptions/EncodingException.h"
#include "exceptions/BadParameterException.h"
#include "keys/RSAPublicKey.h"
#include "keys/RSAPrivateKey.h"

namespace CK {

PKCS1rsassa::PKCS1rsassa(Digest *d)
: digest(d),
  algorithmOID(d->getDER()) {
}

PKCS1rsassa::~PKCS1rsassa() {

    delete digest;

}

ByteArray PKCS1rsassa::decrypt(const RSAPrivateKey& K, const ByteArray& C) {
    throw IllegalOperationException("Unsupported signature operation");
}

/*
 * EMSA-PKCS1 encoding.
 * 
 * M is the message to be encoded. emLen is the intended
 * length of the encoded message.
 * Returns the encoded message as an octet string
 */
ByteArray PKCS1rsassa::emsaPKCS1Encode(const ByteArray& M, int emLen) {

    // 1. Apply the hash function to the message M to produce a hash value
    //     H:
    //
    //         H = Digest(M).
    ByteArray H(digest->digest(M));

    // 2. Encode the algorithm ID for the hash function and the hash value
    //    into an ASN.1 value of type DigestInfo with the Distinguished
    //    Encoding Rules (DER), where the type DigestInfo has the syntax
    //
    //      DigestInfo ::= SEQUENCE {
    //          digestAlgorithm AlgorithmIdentifier,
    //          digest OCTET STRING
    //      }
    //
    //    The first field identifies the hash function and the second
    //    contains the hash value.  Let T be the DER encoding of the
    //    DigestInfo value and let tLen be the length in octets of T.
    int tLen = H.getLength() + algorithmOID.getLength();
    ByteArray T(tLen);
    T.append(algorithmOID);
    T.append(H);

    // 3. If emLen < tLen + 11, output "intended encoded message length too
    //    short" and stop.
    if (emLen < (tLen + 11)) {
        throw EncodingException("Intended encoded message length too short");
    }

    // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
    //    with hexadecimal value 0xff.  The length of PS will be at least 8
    //    octets.
    ByteArray PS((emLen - tLen) - 3, 0xff);

    // 5. Concatenate PS, the DER encoding T, and other padding to form the
    //    encoded message EM as
    //
    //       EM = 0x00 || 0x01 || PS || 0x00 || T.
    ByteArray EM;
    EM.append(0x00);
    EM.append(0x01);
    EM.append(PS);
    EM.append(0x00);
    EM.append(T);

    return EM;

}


ByteArray
PKCS1rsassa::encrypt(const RSAPublicKey& K, const ByteArray& C) {
    throw IllegalOperationException("Unsupported signature operation");
}

/*
 * PKCS 1 v1.5 signing
 * 
 * K is the signer's private key. M is the message to be signed.
 * Returns the signature as an octet string.
 */
ByteArray PKCS1rsassa::sign(const RSAPrivateKey& K, const ByteArray& M) {

    // 1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
    //    operation (Section 9.2) to the message M to produce an encoded
    //    message EM of length k octets:
    //
    // If the encoding operation outputs "message too long," output
    // "message too long" and stop.  If the encoding operation outputs
    // "intended encoded message length too short," output "RSA modulus
    // too short" and stop.

    int k = K.getBitLength() / 8;
    ByteArray EM;
    try {
        EM = emsaPKCS1Encode(M, k);
    }
    catch (EncodingException& e) {
        if (e.getMessage() == "Intended encoded message length too short") {
            throw new BadParameterException("RSA modulus too short");
        }
        else {
            throw e;
        }
    }

    // RSA signature
    //
    // Convert the encoded message EM to an integer message
    // representative m
    //
    //    m = OS2IP (EM).
    //
    // Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
    // private key K and the message representative m to produce an
    // integer signature representative s:
    //
    //    s = RSASP1 (K, m).

    BigInteger s(K.rsasp1(os2ip(EM)));  // The RSAPrivateKey class
                                        // carries the rsasp1 function
                                        // so that it can be specialized
                                        // for CRT and modulus keys.

    // Convert the signature representative s to a signature S of
    // length k octets:
    //
    //    S = I2OSP (s, k).
    return i2osp(s, k);

}

bool
PKCS1rsassa::verify(const RSAPublicKey& K, const ByteArray& M,
                                            const ByteArray& S) {
    return false;
}

}
