#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include "DigestBase.h"

namespace CK {

/*
 * SHA-256 message digest implementation.
 */
class SHA256 : public DigestBase {

    public:
        SHA256();
        ~SHA256();

    private:
        SHA256(const SHA256& other);
        SHA256& operator= (const SHA256& other);

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

}

#endif  // SHA256_H_INCLUDED