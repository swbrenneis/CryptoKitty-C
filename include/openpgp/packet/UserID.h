#ifndef USERID_H_INCLUDED
#define USERID_H_INCLUDED

#include "packet/Packet.h"
#include "data/ByteArray.h"

namespace CKPGP {

class UserID : public Packet {

    public:
        UserID();
        ~UserID();

    private:
        UserID(const UserID& other);
        UserID& operator= (const UserID& other);

    private:
        CK::ByteArray userid;

};

}

#endif  // USERID_H_INCLUDED
