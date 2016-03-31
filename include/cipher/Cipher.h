#ifndef CIPHER_H_INCLUDED
#define CIPHER_H_INCLUDED

#include "data/ByteArray.h"

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
        virtual ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key)=0;
        virtual ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key)=0;

};

}

#endif  // CIPHER_H_INCLUDED
