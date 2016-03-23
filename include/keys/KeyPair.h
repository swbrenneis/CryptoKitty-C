#ifndef KEYPAIR_H_INCLUDED
#define KEYPAIR_H_INCLUDED

class PublicKey;
class PrivateKey;

class KeyPair {

    private:
        KeyPair();
        KeyPair(const KeyPair& other);
        KeyPair& operator= (const KeyPair& other);

    public:
        KeyPair(PublicKey* pub, PrivateKey* prv);
        ~KeyPair();

    public:
        PublicKey& publicKey();
        PrivateKey& privateKey();

    private:
        PublicKey* pubKey;
        PrivateKey* prvKey;

};

#endif  // KEYPAIR_H_INCLUDED
