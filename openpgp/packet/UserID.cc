#include "openpgp/packet/UserID.h"

namespace CKPGP {

UserID::UserID()
: Packet(USERID) {
}

UserID::UserID(const std::string& uid)
: Packet(USERID),
  userid(uid) {
}

UserID::UserID(const CK::ByteArray& encoded)
: Packet(USERID) {

    uint8_t *enc = encoded.asArray();
    char *cbuf = reinterpret_cast<char*>(enc);
    userid = std::string(cbuf, encoded.getLength());
    delete[] enc;

}

UserID::UserID(const UserID& other)
: Packet(other),
  userid(other.userid) {
}

UserID::UserID(UserID *other)
: Packet(*other),
  userid(other->userid) {
}

UserID::~UserID() {
}

UserID& UserID::operator= (const UserID& other) {

    Packet::operator= (other);
    userid = other.userid;
    return *this;

}

UserID& UserID::operator= (UserID *other) {

    Packet::operator= (*other);
    userid = other->userid;
    delete other;
    return *this;

}

void UserID::encode() {

    encoded.append(encodeTag());
    packetLength = userid.length();
    encoded.append(encodeLength());
    encoded.append(CK::ByteArray(userid));

}

const std::string& UserID::getUserid() const {

    return userid;

}

}

bool operator== (const CKPGP::UserID& lhs, const CKPGP::UserID& rhs) {
    return lhs.getUserid() == rhs.getUserid();
}

