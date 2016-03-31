#ifndef CIPHERMODE_H_INCLUDED
#define CIPHERMODE_H_INCLUDED

#include "data/ByteArray.h"

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
        virtual ByteArray decrypt(const ByteArray& ciphertext,
                                            const ByteArray& key)=0;
        virtual ByteArray encrypt(const ByteArray& plaintext,
                                            const ByteArray& key)=0;

};

}

#endif  // CIPHERMODE_H_INCLUDED
