#ifndef USERID_H_INCLUDED
#define USERID_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/ByteArray.h"
#include <string>

namespace CKPGP {

class UserID : public Packet {

    public:
        UserID();
        UserID(const std::string& uid);
        UserID(const CK::ByteArray& encoded);
        ~UserID();

    public:
        UserID(const UserID& other);
        UserID(UserID *other);              // Consumes the pointer.
        UserID& operator= (const UserID& other);
        UserID& operator= (UserID *other);  // Consumes the pointer.

    public:
        void encode();
        const std::string& getUserid() const;

    private:
        std::string userid;

};

}

bool operator== (const CKPGP::UserID& lhs, const CKPGP::UserID& rhs);

#endif  // USERID_H_INCLUDED
