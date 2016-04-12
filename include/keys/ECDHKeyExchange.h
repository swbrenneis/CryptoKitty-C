#ifndef ECDHKEYEXCHANGE_H_INCLUDED
#define ECDHKEYEXCHANGE_H_INCLUDED

namespace CK {

class ECDHKeyExchange {

    public:
        ECDHKeyExchange();
        ~ECDHKeyExchange();

    private:
         ECDHKeyExchange(const ECDHKeyExchange& other);
         ECDHKeyExchange& operator= (const ECDHKeyExchange& other);

};

}

#endif  // ECDHKEYEXCHANGE_H_INCLUDED
