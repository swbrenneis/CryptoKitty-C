#ifndef CIPHER_H_INCLUDED
#define CIPHER_H_INCLUDED

#include "coder/ByteArray.h"

namespace CK {

class Cipher {

    protected:
        Cipher() {}

    public:
        virtual ~Cipher() {}

    private:
        Cipher(const Cipher& other);
        Cipher& operator= (const Cipher& other);

    public:
        virtual unsigned blockSize() const=0;
        virtual coder::ByteArray
                encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key)=0;
        virtual coder::ByteArray
                decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key)=0;

};

}

#endif  // CIPHER_H_INCLUDED
