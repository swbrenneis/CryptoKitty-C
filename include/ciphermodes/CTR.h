#ifndef CTR_H_INCLUDED
#define CTR_H_INCLUDED

#include "ciphermodes/CipherMode.h"

namespace CK {

class Cipher;

class CTR : public CipherMode {

    public:
        CTR(Cipher *cipher, const coder::ByteArray& nonce);
        ~CTR();

    private:
        CTR(const CTR& other);
        CTR& operator= (const CTR& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key);

    private:
        void incrementCounter();

    private:
        Cipher *cipher;
        coder::ByteArray counter;

};

}

#endif  // CTR_H_INCLUDED
