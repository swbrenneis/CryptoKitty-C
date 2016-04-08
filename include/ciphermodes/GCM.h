#ifndef GCM_H_INCLUDED
#define GCM_H_INCLUDED

#include "ciphermodes/CipherMode.h"
#include "data/BigInteger.h"
#include "data/ByteArray.h"
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
        ByteArray GCM_AE(const ByteArray& P);
        ByteArray GCTR(const ByteArray& ICB, const ByteArray& X) const;
        ByteArray GHASH(const ByteArray& X, const BigInteger& H) const;
        BigInteger increment(const BigInteger& X, int bits) const;
        BigInteger multiply(const BigInteger& X, const BigInteger& Y) const;

    private:
        struct GCMNonce {
            uint8_t salt[4];
            uint8_t nonce_explicit[8];
        };
        Cipher *cipher;
        ByteArray K;    // Key.
        ByteArray T;    // Authentication tag;
        ByteArray IV;   // Initial value;
        ByteArray AD;   // Authenticated data;

        static BigInteger R;

};

}

#endif  // GCM_H_INCLUDED
