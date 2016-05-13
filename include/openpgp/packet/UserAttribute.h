#ifndef USERATTRIBUTE_H_INCLUDED
#define USERATTRIBUTE_H_INCLUDED

#include "openpgp/packet/Packet.h"
#include <deque>

namespace CKPGP {

class UserAttribute : public Packet {

    public:
        UserAttribute();
        UserAttribute(const coder::ByteArray& encoded);
        ~UserAttribute();

    public:
        UserAttribute(const UserAttribute& other);
        UserAttribute(UserAttribute *other);                // Consumes the pointer.
        UserAttribute& operator= (const UserAttribute& other);
        UserAttribute& operator= (UserAttribute *other);    // Consumes the pointer.

    public:
        void encode();

    private:
        void decode(const coder::ByteArray& encoded);
        using Packet::encodeLength;
        coder::ByteArray encodeLength(uint32_t len) const;

    private:
        typedef std::deque<coder::ByteArray> SubpacketList;
        typedef SubpacketList::const_iterator SubConstIter;
        SubpacketList subPackets;

};

}

#endif  // USERATTRIBUTE_H_INCLUDED
