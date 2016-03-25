#ifndef RSAPRIVATEKEY_H_INCLUDED
#define RSAPRIVATEKEY_H_INCLUDED

#include "keys/PrivateKey.h"
#include "data/BigInteger.h"

namespace CK {

class RSAPrivateKey : public PrivateKey {

    private:
        RSAPrivateKey();

    protected:
       RSAPrivateKey(const std::string& alg);

    public:
        virtual ~RSAPrivateKey();

    private:
        RSAPrivateKey(const RSAPrivateKey& other);
        RSAPrivateKey& operator=(const RSAPrivateKey& other);

    public:
        virtual int getBitLength() const=0;

    protected:
        friend class PKCS1rsassa;
        // Signature generation primitive.
        virtual BigInteger rsasp1(const BigInteger& m) const=0;

};

}

#endif  // RSAPRIVATEKEY_H_INCLUDED
