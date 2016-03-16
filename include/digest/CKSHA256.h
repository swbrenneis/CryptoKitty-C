#ifndef CKSHA256_H_INCLUDED
#define CKSHA256_H_INCLUDED

#include "DigestBase.h"

/*
 * SHA-256 message digest implementation.
 */
class CKSHA256 : public DigestBase {

    public:
        CKSHA256();
        ~CKSHA256();

    private:
        CKSHA256(const CKSHA256& other);
        CKSHA256& operator= (const CKSHA256& other);

    protected:
        ByteArray finalize(const ByteArray& bytes);
        unsigned getDigestLength() const { return 32; }

};

#endif  // CKSHA256_H_INCLUDED
