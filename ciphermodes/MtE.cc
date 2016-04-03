#include "ciphermodes/MtE.h"
#include "mac/HMAC.h"

namespace CK {

MtE::MtE(CipherMode *c, HMAC* h)
: cipher(c),
  hmac(h),
  authenticated(false) {
}

MtE::~MtE() {

    delete hmac;
    delete cipher;

}

ByteArray MtE::decrypt(const ByteArray& ciphertext,
                                    const ByteArray& key) {

    ByteArray ptm(cipher->decrypt(ciphertext, key));
    unsigned digestLength = hmac->getDigestLength();
    unsigned hmacOffset = ptm.getLength() - digestLength;
    ByteArray mac(ptm.range(hmacOffset, digestLength));
    ByteArray message(ptm.range(0, hmacOffset));
    hmac->setKey(key);
    hmac->setMessage(message);
    authenticated = hmac->authenticate(mac);
    return message;

}

ByteArray MtE::encrypt(const ByteArray& plaintext,
                                    const ByteArray& key) {

    hmac->setKey(key);
    hmac->setMessage(plaintext);
    ByteArray ptm(plaintext);
    ptm.append(hmac->getHMAC());
    return cipher->encrypt(ptm, key);

}

}
