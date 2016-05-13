#ifndef GCM_H_INCLUDED
#define GCM_H_INCLUDED

#include "ciphermodes/CipherMode.h"
#include "data/BigInteger.h"
#include <cstdint>

namespace CK {

class Cipher;

/*
 * Galois Counter Mode stream AEAD cipher mode.
 * See RFC-5288.
 */
class GCM : public CipherMode {

    public:
        GCM(Cipher* c, const coder::ByteArray& iv);
        ~GCM();

    private:
        GCM(const GCM& other);
        GCM& operator= (const GCM& other);

    public:
        coder::ByteArray decrypt(const coder::ByteArray& ciphertext, const coder::ByteArray& key);
        coder::ByteArray encrypt(const coder::ByteArray& plaintext, const coder::ByteArray& key);
        const coder::ByteArray& getAuthTag() const;
        void setAuthTag(const coder::ByteArray& tag);
        void setAuthData(const coder::ByteArray& ad);

    private:
        coder::ByteArray GHASH(const coder::ByteArray& H, const coder::ByteArray& A,
                                                const coder::ByteArray& C) const;
        coder::ByteArray incr(const coder::ByteArray& X) const;
        coder::ByteArray multiply(const coder::ByteArray& X, const coder::ByteArray& Y) const;
        void shiftBlock(coder::ByteArray& block) const;

    private:
        struct GCMNonce {
            uint8_t salt[4];
            uint8_t nonce_explicit[8];
        };
        Cipher *cipher;
        coder::ByteArray T;    // Authentication tag;
        coder::ByteArray IV;   // Initial value;
        coder::ByteArray A;   // Authenticated data;

        static uint8_t t; // Authentication tag size;:w


};

}

#endif  // GCM_H_INCLUDED
