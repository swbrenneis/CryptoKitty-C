#ifndef CIPHERMODE_H_INCLUDED
#define CIPHERMODE_H_INCLUDED

#include "coder/ByteArray.h"

namespace CK {

class CipherMode {

    protected:
        CipherMode() {}
        
    public:
        virtual ~CipherMode() {}

    private:
        CipherMode(const CipherMode& other);
        CipherMode& operator= (const CipherMode& other);

    public:
        virtual coder::ByteArray decrypt(const coder::ByteArray& ciphertext,
                                            const coder::ByteArray& key)=0;
        virtual coder::ByteArray encrypt(const coder::ByteArray& plaintext,
                                            const coder::ByteArray& key)=0;

};

}

#endif  // CIPHERMODE_H_INCLUDED
