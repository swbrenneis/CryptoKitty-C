#ifndef SHA512_H_INCLUDED
#define SHA512_H_INCLUDED

#include "DigestBase.h"

namespace CK {
#include <deque>
        
/*
 * SHA-512 message digest implementation.
 */
class SHA512 : public DigestBase {

    public:
        SHA512();
        ~SHA512();

    private:
        SHA512(const SHA512& other);
        SHA512& operator= (const SHA512& other);

    public:
        uint32_t getBlockSize() const { return 64; }
        uint32_t getDigestLength() const { return 64; }

    protected:
        ByteArray finalize(const ByteArray& bytes) const;
        const ByteArray& getDER() const;

    private:
        typedef std::deque<uint64_t> W;
        
    private:
        uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) const;
        W decompose(const ByteArray& chunks) const;
        uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) const;
        ByteArray pad(const ByteArray& in) const;
        uint64_t ror(uint64_t reg, int count) const;
        uint64_t sigma0(uint64_t w) const;
        uint64_t sigma1(uint64_t w) const;
        uint64_t Sigma0(uint64_t w) const;
        uint64_t Sigma1(uint64_t w) const;

    private:
        typedef std::deque<ByteArray> Chunks;

        // Hash constants
        static const uint64_t H1, H2, H3, H4,
                                H5, H6, H7, H8;
        // Round constants
        static const uint64_t K[];
        // ASN.1 identifier encoding.
        static const ByteArray DER;

};

}

#endif  // SHA512_H_INCLUDED
