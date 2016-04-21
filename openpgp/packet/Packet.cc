#include "packet/Packet.h"

namespace CKPGP {

// Static initialization.
const uint8_t Packet::PKESESSIONKEY = 1;
const uint8_t Packet::SIGNATURE = 2;
const uint8_t Packet::PUBLICKEY = 6;
const uint8_t Packet::USERID = 13;
const uint8_t Packet::USERATTRIBUTE = 17;

Packet::Packet(uint8_t t)
: tag(t),
  newFormat(true) {
}

Packet::~Packet() {
}

uint8_t Packet::encodeTag() const {

    return tag | 0xc0;  // New packet format.

}

uint8_t Packet::getTag() const {

    return tag;

}

}

