#ifndef RSAPRIVATECRTKEY_H_INCLUDED
#define RSAPRIVATECRTKEY_H_INCLUDED

#include "keys/RSAPrivateKey.h"
#include "data/BigInteger.h"

namespace CK {

class RSAPrivateCrtKey : public RSAPrivateKey {

    private:
        RSAPrivateCrtKey();
        RSAPrivateCrtKey(const RSAPrivateCrtKey& other);
        RSAPrivateCrtKey& operator= (const RSAPrivateCrtKey& other);

    public:
        RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                            const BigInteger& d, const BigInteger& e);
        ~RSAPrivateCrtKey();

    public:
        int getBitLength() const;
        const BigInteger& getCrtCoefficient() const;
        const BigInteger& getPrivateExponent() const;
        const BigInteger& getPrimeExponentP() const;
        const BigInteger& getPrimeExponentQ() const;
        const BigInteger& getPrimeP() const;
        const BigInteger& getPrimeQ() const;
        const BigInteger& getPublicExponent() const;
        const BigInteger& getModulus() const;

    protected:
        // Signature generation primitive.
        BigInteger rsasp1(const BigInteger& m) const;

    private:
        BigInteger prvExp;  // d
        BigInteger pPrimeExp;   // dP
        BigInteger qPrimeExp;   // dQ
        BigInteger pubExp;  // e
        BigInteger pPrime;  // p
        BigInteger qPrime;  // q
        BigInteger crtCoeff;    // qInv
        BigInteger mod; // n
        int bitLength;

};

}

#endif  // RSAPRIVATECRTKEY_H_INCLUDED
