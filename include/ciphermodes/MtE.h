#ifndef MTE_H_INCLUDED
#define MTE_H_INCLUDED

#include "ciphermodes/CipherMode.h"

namespace CK {

class HMAC;

class MtE : public CipherMode {

    public:
        MtE(CipherMode *c, HMAC* h);
        ~MtE();

    private:
        MtE(const MtE& other);
        MtE& operator= (const MtE& other);

    public:
        bool authenticate() { return authenticated; }
        ByteArray decrypt(const ByteArray& ciphertext,
                                            const ByteArray& key);
        ByteArray encrypt(const ByteArray& plaintext,
                                            const ByteArray& key);

    private:
        unsigned blockSize;
        CipherMode *cipher;
        HMAC *hmac;
        bool authenticated;


};

}

#endif  // MTE_H_INCLUDED
