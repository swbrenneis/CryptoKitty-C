#ifndef PUBLICKEY_H_INCLUDED
#define PUBLICKEY_H_INCLUDED

class PublicKey {

    protected:
        PublicKey();

    private:
        PublicKey(const PublicKey& other);
        PublicKey& operator= (const PublicKey& other);

    public:
        virtual ~PublicKey();

};

#endif  // PUBLICKEY_H_INCLUDED
