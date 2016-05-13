#ifndef PGPCFB_H_INCLUDE
#define PGPCFB_H_INCLUDE

#include "ciphermodes/CipherMode.h"

namespace CK {
    class Cipher;
}

namespace CKPGP {

class PGPCFM : public CK::CipherMode {

    public:
        PGPCFM(CK::Cipher *c);
        ~PGPCFM();

    private:
        PGPCFM(const PGPCFM& other);
        PGPCFM& operator= (const PGPCFM& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key);

    private:
        bool decryptPrefix(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key);
        coder::ByteArray encryptPrefix(const coder::ByteArray& key);

    private:
        CK::Cipher *cipher;
        unsigned blockSize;
        coder::ByteArray FR;
        coder::ByteArray FRE;

};

}

#endif  // PGPCFB_H_INCLUDE
