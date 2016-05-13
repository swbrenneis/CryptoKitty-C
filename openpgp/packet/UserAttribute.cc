#include "openpgp/packet/UserAttribute.h"
#include "coder/Unsigned16.h"
#include "coder/Unsigned32.h"

namespace CKPGP {

UserAttribute::UserAttribute()
: Packet(USERID) {
}

UserAttribute::UserAttribute(const coder::ByteArray& encoded)
: Packet(USERID) {

    decode(encoded);

}

UserAttribute::UserAttribute(const UserAttribute& other)
: Packet(other),
  subPackets(other.subPackets) {
}

UserAttribute::UserAttribute(UserAttribute *other)
: Packet(*other),
  subPackets(other->subPackets) {

      delete other;

}

UserAttribute::~UserAttribute() {
}

UserAttribute& UserAttribute::operator= (const UserAttribute& other) {
        
    Packet::operator= (other);
    subPackets = other.subPackets;
    return *this;

}

UserAttribute& UserAttribute::operator= (UserAttribute *other) {
        
    Packet::operator= (*other);
    subPackets = other->subPackets;
    delete other;

    return *this;

}

void UserAttribute::decode(const coder::ByteArray& encoded) {

    unsigned index = 0;
    unsigned length;
    while (index < encoded.getLength()) {
        if (encoded[index] < 192) {
            length = encoded[index];
            index++;
        }
        else if (encoded[index] == 0xff) {
            coder::Unsigned32 len(encoded.range(index + 1, 4), coder::bigendian);
            length = len.getValue();
            index += 5;
        }
        else {
            coder::ByteArray enc16(2);
            enc16[0] = encoded[index];
            enc16[1] = encoded[index + 1];
            enc16[0] -= 192;
            enc16[1] += 192;
            coder::Unsigned16 len(enc16, coder::bigendian);
            length = len.getValue();
            index += 2;
        }
        subPackets.push_back(encoded.range(index, length));
        index += length;
    }

}

void UserAttribute::encode() {

    encoded.append(encodeTag());
    coder::ByteArray sub;

    for (SubConstIter it = subPackets.begin(); it != subPackets.end();
                                                    ++it) {
        sub.append(encodeLength(it->getLength()));
        sub.append(*it);
    }

    packetLength = sub.getLength();
    encoded.append(encodeLength());
    encoded.append(sub);

}

coder::ByteArray UserAttribute::encodeLength(uint32_t len) const {

    coder::ByteArray encoded;
    if (len < 192) {
        encoded.append(len);
    }
    else if (len < 8384) {
        coder::Unsigned16 len(len);
        encoded.append(len.getEncoded(coder::bigendian));
    }
    else {
        encoded.append(0xff);
        coder::Unsigned32 len(len);
        encoded.append(len.getEncoded(coder::bigendian));
    }

    return encoded;
    
}

}

