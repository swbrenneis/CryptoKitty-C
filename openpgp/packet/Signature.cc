#include "packet/Signature.h"

namespace CKPGP {

// Static intialization
const uint8_t Signature::BINARY = 0x00;
const uint8_t Signature::TEXT = 0x01;
const uint8_t Signature::STANDALONE = 0x02;
const uint8_t Signature::GENERICPK = 0x10;
const uint8_t Signature::PERSONAPK = 0x11;
const uint8_t Signature::CASUALPK = 0x12;
const uint8_t Signature::POSITIVEPK = 0x13;
const uint8_t Signature::SUBKEY = 0x18;
const uint8_t Signature::PRIMARYKEY = 0x19;
const uint8_t Signature::DIRECT = 0x1f;
const uint8_t Signature::KEYREVOKE = 0x20;
const uint8_t Signature::SUBKEYREVOKE = 0x28;
const uint8_t Signature::CERTREVOKE = 0x30;
const uint8_t Signature::TIMESTAMP = 0x40;
const uint8_t Signature::CONFIRMATION = 0x50;

Signature::Signature()
: Packet(SIGNATURE),
  version(4) {
}

Signature::~Signature() {
}

void Signature::setType(uint8_t t) {

    type = t;

}

}

