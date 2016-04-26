#include "openpgp/packet/UserAttribute.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"

namespace CKPGP {

UserAttribute::UserAttribute()
: Packet(USERID) {
}

UserAttribute::UserAttribute(const CK::ByteArray& encoded)
: Packet(USERID) {

    decode(encoded);

}

UserAttribute::UserAttribute(const UserAttribute& other)
: Packet(other),
  subPackets(other.subPackets) {
}

UserAttribute::~UserAttribute() {
}

UserAttribute& UserAttribute::operator= (const UserAttribute& other) {
        
    Packet::operator= (other);
    subPackets = other.subPackets;
    return *this;

}

void UserAttribute::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[index];
            index++;
        }
        else if (encoded[index] == 0xff) {
            CK::Unsigned32 len(encoded.range(index+1, 4), CK::Unsigned32::BIGENDIAN);
            length = len.getUnsignedValue();
            index += 5;
        }
        else {
            CK::Unsigned16 len(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            length = len.getUnsignedValue();
            index += 2;
        }
        subPackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void UserAttribute::encode() {

    encoded.append(encodeTag());
    CK::ByteArray sub;

    for (SubConstIter it = subPackets.begin(); it != subPackets.end();
                                                    ++it) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    packetLength = sub.getLength();
    encoded.append(encodeLength());
    encoded.append(sub);

}

CK::ByteArray UserAttribute::encodeLength(uint32_t len) const {

    CK::ByteArray encoded;
    if (len < 192) {
        encoded.append(len);
    }
    else if (len < 8384) {
        CK::Unsigned16 len(len);
        encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    }
    else {
        encoded.append(0xff);
        CK::Unsigned32 len(len);
        encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    }

    return encoded;
    
}

}

