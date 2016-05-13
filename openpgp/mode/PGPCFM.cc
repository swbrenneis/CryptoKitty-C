#include "openpgp/mode/PGPCFM.h"
#include "cipher/Cipher.h"
#include "random/SecureRandom.h"
#include <cmath>

namespace CKPGP {

PGPCFM::PGPCFM(CK::Cipher *c)
: cipher(c) {

    blockSize = cipher->blockSize();

}

PGPCFM::~PGPCFM() {

    delete cipher;

}

coder::ByteArray PGPCFM::decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key) {

    coder::ByteArray P;

    if (decryptPrefix(ciphertext.range(0, blockSize + 2), key)) {
        FR = ciphertext.range(2, blockSize);
        FRE = cipher->encrypt(FR, key);
        // Pull out the message ciphertext to make iterating easier.
        coder::ByteArray ct(ciphertext.range(blockSize + 2,
                                    ciphertext.getLength() - (blockSize + 2)));
        uint32_t index = 0;
        while (index < ct.getLength()) {
            if (index + blockSize < ct.getLength()) {
                P.append(FRE ^ ct.range(index, blockSize));
                FR = ct.range(index, blockSize);
                FRE = cipher->encrypt(FR, key);
            }
            else {
                uint32_t partSize = ct.getLength() - index;
                if (partSize > 0) {
                    coder::ByteArray pad(blockSize - partSize, 0);
                    coder::ByteArray partial(ct.range(index, partSize));
                    partial.append(pad);
                    partial = FRE ^ partial;
                    P.append(partial.range(0, partSize));
                }
            }
            index += blockSize;
        }

    }

    return P;

}

/*
 * See encryptPrefix for details.
 */
bool PGPCFM::decryptPrefix(const coder::ByteArray& ciphertext, const coder::ByteArray& key) {

    FR.setLength(blockSize, 0);
    FRE = cipher->encrypt(FR, key);
    coder::ByteArray prefix(ciphertext.range(0, blockSize) ^ FRE);
    FR = ciphertext.range(0, blockSize);
    FRE = cipher->encrypt(FR, key);
    prefix.append(FRE.range(FRE.getLength() - 2, 2) ^ ciphertext.range(blockSize, 2));

    return (prefix[blockSize - 2] == prefix[blockSize]
                                && prefix[blockSize - 1] == prefix[blockSize + 1]);

}

coder::ByteArray PGPCFM::encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key) {


    coder::ByteArray C(encryptPrefix(key));

    // 7.  (The resynchronization step) FR is loaded with C[3] through
    //     C[BS+2].
    // 8.  FR is encrypted to produce FRE.
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

    FR = C.range(2, blockSize);
    FRE = cipher->encrypt(FR, key);
    uint32_t index = 0;
    while (index < plaintext.getLength()) {
        if (index + blockSize < plaintext.getLength()) {
            C.append(FRE ^ plaintext.range(index, blockSize));
            FR = C.range(index + blockSize + 2, blockSize);
            FRE = cipher->encrypt(FR, key);
        }
        else {
            uint32_t partSize = plaintext.getLength() - index;
            if (partSize > 0) {
                coder::ByteArray pad(blockSize - partSize, 0);
                coder::ByteArray partial(plaintext.range(index, partSize));
                partial.append(pad);
                partial = FRE ^ partial;
                C.append(partial.range(0, partSize));
            }
        }
        index += blockSize;
    }

    return C;

}

/*
 * Sets up the PGP prefix and encrypts it to C. FRE contains the
 * last block size bytes of C.
 */
coder::ByteArray PGPCFM::encryptPrefix(const coder::ByteArray& key) {

    CK::SecureRandom *rnd = CK::SecureRandom::getSecureRandom("Fortuna");
    coder::ByteArray prefix(blockSize);
    rnd->nextBytes(prefix);
    delete rnd;
    prefix.append(prefix[prefix.getLength() - 2]);
    prefix.append(prefix[prefix.getLength() - 2]);

    // 1.  The feedback register (FR) is set to the IV, which is all zeros.
    FR.setLength(blockSize, 0);
    // 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    //     encryption of an all-zero value.
    FRE = cipher->encrypt(FR, key);
    // 3.  FRE is xored with the first BS octets of random data prefixed to
    //     the plaintext to produce C[1] through C[BS], the first BS octets
    //     of ciphertext.
    coder::ByteArray C(prefix.range(0, blockSize) ^ FRE);
    // 4.  FR is loaded with C[1] through C[BS].
    FR = C;
    // 5.  FR is encrypted to produce FRE, the encryption of the first BS
    //     octets of ciphertext.
    FRE = cipher->encrypt(FR, key);
    // 6.  The left two octets of FRE get xored with the next two octets of
    //     data that were prefixed to the plaintext.  This produces C[BS+1]
    //     and C[BS+2], the next two octets of ciphertext.
    C.append(FRE.range(FRE.getLength() - 2, 2) ^ prefix.range(blockSize, 2));

    return C;

}

}

