#ifndef DHKEYEXCHANGE_H_INCLUDED
#define DHKEYEXCHANGE_H_INCLUDED

namespace CK {

class DHKeyExchange {

    public:
        DHKeyExchange();
        ~DHKeyExchange();

    private:
         DHKeyExchange(const DHKeyExchange& other);
         DHKeyExchange& operator= (const DHKeyExchange& other);

};

}

#endif  // DHKEYEXCHANGE_H_INCLUDED
