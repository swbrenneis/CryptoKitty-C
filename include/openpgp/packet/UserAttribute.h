#ifndef USERATTRIBUTE_H_INCLUDED
#define USERATTRIBUTE_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include "data/ByteArray.h"
#include <deque>

namespace CKPGP {

class UserAttribute : public Packet {

    public:
        UserAttribute();
        UserAttribute(const CK::ByteArray& encoded);
        ~UserAttribute();

    public:
        UserAttribute(const UserAttribute& other);
        UserAttribute& operator= (const UserAttribute& other);

    public:
        void encode();

    private:
        void decode(const CK::ByteArray& encoded);
        using Packet::encodeLength;
        CK::ByteArray encodeLength(uint32_t len) const;

    private:
        typedef std::deque<CK::ByteArray> SubpacketList;
        typedef SubpacketList::const_iterator SubConstIter;
        SubpacketList subPackets;

};

}

#endif  // USERATTRIBUTE_H_INCLUDED
