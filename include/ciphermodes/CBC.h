#ifndef CBC_H_INCLUDED
#define CBC_H_INCLUDED

#include "ciphermodes/CipherMode.h"

namespace CK {

class Cipher;

class CBC : public CipherMode {

    public:
        CBC(Cipher *c, const ByteArray& i);
        ~CBC();

    private:
        CBC(const CBC& other);
        CBC& operator= (const CBC& other);

    public:
        ByteArray decrypt(const ByteArray& ciphertext,
                                            const ByteArray& key);
        ByteArray encrypt(const ByteArray& plaintext,
                                            const ByteArray& key);
    private:
        ByteArray decrypt(const ByteArray& iv, const ByteArray& block,
                                            const ByteArray& key) const;
        ByteArray encrypt(const ByteArray& iv, const ByteArray& block,
                                            const ByteArray& key) const;

    private:
        unsigned blockSize;
        Cipher *cipher;
        ByteArray iv;

};

}

#endif  // CBC_H_INCLUDED
