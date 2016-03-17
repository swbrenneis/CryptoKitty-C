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

    private:
        unsigned Ch(unsigned x, unsigned y, unsigned z);
        unsigned *decompose(unsigned char *chunks);
        unsigned Maj(unsigned x, unsigned y, unsigned z);
        ByteArray pad(const ByteArray& in);
        unsigned ror(unsigned reg, int count);
        unsigned sigma0(unsigned w);
        unsigned sigma1(unsigned w);
        unsigned Sigma0(unsigned w);
        unsigned Sigma1(unsigned w);

    private:
        // Hash constants
        static const unsigned H1, H2, H3, H4,
                                H5, H6, H7, H8;
        // Round constants
        static const unsigned K[];

};

#endif  // CKSHA256_H_INCLUDED
