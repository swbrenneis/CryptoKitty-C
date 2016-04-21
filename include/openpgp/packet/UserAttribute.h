#ifndef USERATTRIBUTE_H_INCLUDED
#define USERATTRIBUTE_H_INCLUDED

#include "packet/Packet.h"
#include "data/ByteArray.h"

namespace CKPGP {

class UserAttribute : public Packet {

    public:
        UserAttribute();
        ~UserAttribute();

    private:
        UserAttribute(const UserAttribute& other);
        UserAttribute& operator= (const UserAttribute& other);

    private:
        CK::ByteArray subPackets;

};

}

#endif  // USERATTRIBUTE_H_INCLUDED
