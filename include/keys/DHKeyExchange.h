#ifndef DHKEYEXCHANGE_H_INCLUDED
#define DHKEYEXCHANGE_H_INCLUDED

#include "data/BigInteger.h"

namespace CK {

/*
 * Diffie-Hellman key exchange.
 */
class DHKeyExchange {

    public:
        DHKeyExchange();
        ~DHKeyExchange();

    private:
        DHKeyExchange(const DHKeyExchange& other);
        DHKeyExchange& operator= (const DHKeyExchange& other);

    public:
        BigInteger generatePublicKey();
        BigInteger getGenerator() const;
        BigInteger getModulus() const;
        BigInteger getPublicKey() const;
        BigInteger getSecret();
        BigInteger getSecret(const BigInteger& fpk);
        void setBitsize(int b);
        void setGenerator(const BigInteger& gen);
        void setModulus(const BigInteger& mod);

    private:
        int bitsize;            // Modulus bit size
        BigInteger g;           // Generator
        BigInteger p;           // PrimeModulus
        BigInteger a;           // Private exponent
        BigInteger s;           // Secret, pk^a mod p, pk = foreign public key
        BigInteger publicKey;   // DH public key, g^a mod p

};

}

#endif  // DHKEYEXCHANGE_H_INCLUDED
