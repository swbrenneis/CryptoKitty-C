#ifndef RSAPRIVATEMODKEY_H_INCLUDED
#define RSAPRIVATEMODKEY_H_INCLUDED

#include "keys/RSAPrivateKey.h"
#include "data/BigInteger.h"

namespace CK {

class RSAPrivateModKey : public RSAPrivateKey {

    private:
        RSAPrivateModKey();
        RSAPrivateModKey(const RSAPrivateModKey& other);
        RSAPrivateModKey& operator= (const RSAPrivateModKey& other);

    public:
        RSAPrivateModKey(const BigInteger& d, const BigInteger& n);
        ~RSAPrivateModKey();

    public:
        int getBitLength() const;
        const BigInteger& getPrivateExponent() const;
        const BigInteger& getModulus() const;

    protected:
        // Signature generation primitive.
        BigInteger rsasp1(const BigInteger& m) const;

    private:
        BigInteger prvExp;  // d
        BigInteger mod; // n
        int bitLength;

};

}

#endif  // RSAPRIVATEMODKEY_H_INCLUDED
