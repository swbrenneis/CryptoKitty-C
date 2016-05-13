#ifndef CBC_H_INCLUDED
#define CBC_H_INCLUDED

#include "ciphermodes/CipherMode.h"

namespace CK {

class Cipher;

class CBC : public CipherMode {

    public:
        CBC(Cipher *c, const coder::ByteArray& i);
        ~CBC();

    private:
        CBC(const CBC& other);
        CBC& operator= (const CBC& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key);
    private:
        coder::ByteArray decrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const;
        coder::ByteArray encrypt(const coder::ByteArray& iv, const coder::ByteArray& block,
                                            const coder::ByteArray& key) const;

    private:
        unsigned blockSize;
        Cipher *cipher;
        coder::ByteArray iv;

};

}

#endif  // CBC_H_INCLUDED
