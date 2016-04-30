#include "openpgp/mode/PGPCFM.h"
#include "cipher/Cipher.h"
#include <cmath>

namespace CKPGP {

PGPCFM::PGPCFM(CK::Cipher *c)
: cipher(c) {

    blockSize = cipher->blockSize();

}

PGPCFM::~PGPCFM() {

    delete cipher;

}

CK::ByteArray PGPCFM::decrypt(const CK::ByteArray& ciphertext,
                                            const CK::ByteArray& key) {

    CK::ByteArray P;

    return P;

}

CK::ByteArray PGPCFM::encrypt(const CK::ByteArray& plaintext,
                                            const CK::ByteArray& key) {


    CK::SecureRandom *rnd = CK::SecureRandom::getSecureRandom("Fortuna");
    CK::ByteArray prefix(blockSize);
    rnd->nextBytes(prefix);
    delete rnd;
    prefix.append(prefix[prefix.getLength() - 2]);
    prefix.append(prefix[prefix.getLength() - 1]);

    // 1.  The feedback register (FR) is set to the IV, which is all zeros.
    CK::ByteArray FR(blockSize, 0);
    // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
    CK::ByteArray FRE(cipher->encrypt(FR, key));
    // 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
    CK::ByteArray C(prefix.range(0, blockSize) ^ FRE);
    // 4.  FR is loaded with C[1] through C[BS].
    FR = C;
    // 5.  FR is encrypted to produce FRE, the encryption of the first BS
    //     octets of ciphertext.
    FRE = cipher->encrypt(FR, key);
    // 6.  The left two octets of FRE get xored with the next two octets of
    //     data that were prefixed to the plaintext.  This produces C[BS+1]
    //     and C[BS+2], the next two octets of ciphertext.
    C.append(FRE.range(FRE.getLength() - 2, 2) ^ prefix.range(blockSize, 2));
    // 7.  (The resynchronization step) FR is loaded with C[3] through
    //     C[BS+2].
    FR = C.range(3, blockSize);
    // 8.  FR is encrypted to produce FRE.
    FRE = cipher->encrypt(FR, key);
    // 9.  FRE is xored with the first BS octets of the given plaintext, now
    //     that we have finished encrypting the BS+2 octets of prefixed
    //     data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
    //     octets of ciphertext.
    // 10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
    //     an 8-octet block)
    // 11. FR is encrypted to produce FRE.
    // 12. FRE is xored with the next BS octets of plaintext, to produce
    //     the next BS octets of ciphertext.  These are loaded into FR, and
    //     the process is repeated until the plaintext is used up.
    C.append(fre ^ plaintext.range(0, blockSize));
    FR = C.range(blockSize + 3, blockSize);
    FRE = cipher->encrypt(FR, key);

    return C;

}

}

