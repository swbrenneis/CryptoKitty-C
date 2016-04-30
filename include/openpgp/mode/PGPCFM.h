#ifndef PGPCFB_H_INCLUDE
#define PGPCFB_H_INCLUDE

#include "ciphermodes/CipherMode.h"

namespace CK {
    class Cipher;
    class ByteArray;
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
        CK::ByteArray decrypt(const CK::ByteArray& ciphertext,
                                        const CK::ByteArray& key);
        CK::ByteArray encrypt(const CK::ByteArray& plaintext,
                                        const CK::ByteArray& key);

    private:
        CK::Cipher *cipher;
        unsigned blockSize;

};

}

#endif  // PGPCFB_H_INCLUDE
