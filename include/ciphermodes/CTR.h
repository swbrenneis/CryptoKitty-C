#ifndef CTR_H_INCLUDED
#define CTR_H_INCLUDED

#include "ciphermodes/CipherMode.h"

namespace CK {

class Cipher;

class CTR : public CipherMode {

    public:
        CTR(Cipher *cipher, const ByteArray& nonce);
        ~CTR();

    private:
        CTR(const CTR& other);
        CTR& operator= (const CTR& other);

    public:
        ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key);
        ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key);

    private:
        void incrementCounter();

    private:
        Cipher *cipher;
        ByteArray counter;

};

}

#endif  // CTR_H_INCLUDED
