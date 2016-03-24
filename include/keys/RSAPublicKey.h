#ifndef RSAPUBLICKEY_H_INCLUDED
#define RSAPUBLICKEY_H_INCLUDED

#include "keys/PublicKey.h"
#include "data/BigInteger.h"

namespace CK {

class RSAPublicKey : public PublicKey {

    private:
        RSAPublicKey();
        RSAPublicKey(const RSAPublicKey& other);
        RSAPublicKey& operator= (const RSAPublicKey& other);

    public:
        RSAPublicKey(const BigInteger& n, const BigInteger& e);
        ~RSAPublicKey();

    public:
        const BigInteger& getExponent() const;
        const BigInteger& getModulus() const;

    private:
        BigInteger exp; // e
        BigInteger mod; // n

};

}

#endif  // RSAPUBLICKEY_H_INCLUDED
