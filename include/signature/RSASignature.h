#ifndef RSASIGNATURE_H_INCLUDED
#define RSASIGNATURE_H_INCLUDED

namespace CK {

class PublicKey;
class PrivateKey;

class RSASignature {

    protected:
        RSASignature();

    public:
        ~RSASignature();

    public:
        virtual void initVerify(const PublicKey& publicKey);
        virtual void initSign(const PrivateKey& privateKey);
};

}

#endif  // RSASIGNATURE_H_INCLUDED
