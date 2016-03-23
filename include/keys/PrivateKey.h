#ifndef PRIVATEKEY_H_INCLUDED
#define PRIVATEKEY_H_INCLUDED

class PrivateKey {

    protected:
        PrivateKey();

    private:
        PrivateKey(const PrivateKey& other);
        PrivateKey& operator= (const PrivateKey& other);

    public:
        virtual ~PrivateKey();

};

#endif  // PRIVATEKEY_H_INCLUDED
