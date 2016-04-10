#ifndef GCM_H_INCLUDED
#define GCM_H_INCLUDED

#include "ciphermodes/CipherMode.h"
#include "data/ByteArray.h"
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
        GCM(Cipher* c, const ByteArray& iv);
        ~GCM();

    private:
        GCM(const GCM& other);
        GCM& operator= (const GCM& other);

    public:
        ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key);
        ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key);
        const ByteArray& getAuthTag() const;
        void setAuthTag(const ByteArray& tag);
        void setAuthData(const ByteArray& ad);

    private:
        ByteArray bitShift(const ByteArray& string) const;
        ByteArray expand(const ByteArray& packed) const;
        ByteArray GCTR(const ByteArray& ICB, const ByteArray& X) const;
        ByteArray GHASH(const ByteArray& H, const ByteArray& A,
                                                const ByteArray& C) const;
        ByteArray incr(const ByteArray& X) const;
        ByteArray multiply(const ByteArray& X, const ByteArray& Y) const;
        ByteArray pack(const ByteArray& string) const;
        void shiftBlock(ByteArray& block) const;

    private:
        struct GCMNonce {
            uint8_t salt[4];
            uint8_t nonce_explicit[8];
        };
        Cipher *cipher;
        ByteArray T;    // Authentication tag;
        ByteArray IV;   // Initial value;
        ByteArray A;   // Authenticated data;

        static ByteArray R;
        static uint8_t t; // Authentication tag size;:w


};

}

#endif  // GCM_H_INCLUDED
