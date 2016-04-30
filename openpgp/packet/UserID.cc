#include "openpgp/packet/UserID.h"

namespace CKPGP {

UserID::UserID(const std::string& uid)
: Packet(USERID),
  userid(uid) {
}

UserID::UserID(const CK::ByteArray& encoded)
: Packet(USERID),
  userid(encoded) {
}

UserID::UserID(const UserID& other)
: Packet(other),
  userid(other.userid) {
}

UserID::~UserID() {
}

UserID& UserID::operator= (const UserID& other) {

    Packet::operator= (other);
    userid = other.userid;
    return *this;

}

void UserID::encode() {

    encoded.append(encodeTag());
    packetLength = userid.getLength();
    encoded.append(encodeLength());
    encoded.append(userid);

}

}

