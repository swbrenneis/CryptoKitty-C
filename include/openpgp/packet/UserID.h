#ifndef USERID_H_INCLUDED
#define USERID_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/ByteArray.h"
#include <string>

namespace CKPGP {

class UserID : public Packet {

    public:
        UserID(const std::string& uid);
        UserID(const CK::ByteArray& encoded);
        ~UserID();

    public:
        UserID(const UserID& other);
        UserID& operator= (const UserID& other);

    public:
        void encode();

    private:
        CK::ByteArray userid;

};

}

#endif  // USERID_H_INCLUDED