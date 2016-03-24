#ifndef RSAPRIVATECRTKEY_H_INCLUDED
#define RSAPRIVATECRTKEY_H_INCLUDED

#include "keys/PrivateKey.h"
#include "data/BigInteger.h"

namespace CK {

class RSAPrivateCrtKey : public PrivateKey {

    private:
        RSAPrivateCrtKey();
        RSAPrivateCrtKey(const RSAPrivateCrtKey& other);
        RSAPrivateCrtKey& operator= (const RSAPrivateCrtKey& other);

    public:
        RSAPrivateCrtKey(const BigInteger& p, const BigInteger& q,
                            const BigInteger& d, const BigInteger& e);
        ~RSAPrivateCrtKey();

    public:
        const BigInteger& getCrtCoefficient() const;
        const BigInteger& getPrivateExponent() const;
        const BigInteger& getPrimeExponentP() const;
        const BigInteger& getPrimeExponentQ() const;
        const BigInteger& getPrimeP() const;
        const BigInteger& getPrimeQ() const;
        const BigInteger& getPublicExponent() const;
        const BigInteger& getModulus() const;

    private:
        BigInteger prvExp;  // d
        BigInteger pPrimeExp;   // dP
        BigInteger qPrimeExp;   // dQ
        BigInteger pubExp;  // e
        BigInteger pPrime;  // p
        BigInteger qPrime;  // q
        BigInteger crtCoeff;    // qInv
        BigInteger mod; // n

};

}

#endif  // RSAPRIVATECRTKEY_H_INCLUDED
