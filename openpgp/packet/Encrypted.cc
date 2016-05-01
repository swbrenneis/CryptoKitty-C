#include "openpgp/packet/Encrypted.h"

namespace CKPGP {

Encrypted::Encrypted()
: Packet(ENCRYPTED) {
}

Encrypted::Encrypted(const CK::ByteArray& encoded)
: Packet(ENCRYPTED) {

    decode(encoded);

}

Encrypted::Encrypted(const Encrypted& other)
: Packet(other),
  ciphertext(other.ciphertext) {
}

Encrypted& Encrypted::operator= (const Encrypted& other) {

    Packet::operator=(other);
    ciphertext = other.ciphertext;
    return *this;

}

Encrypted::~Encrypted() {
}

void Encrypted::decode(const CK::ByteArray& encoded) {

    ciphertext.clear();
    ciphertext.append(encoded);

}

void Encrypted::encode() {

    encoded.append(encodeTag());
    packetLength = ciphertext.getLength();
    encoded.append(encodeLength());
    encoded.append(ciphertext);

}

const CK::ByteArray& Encrypted::getCiphertext() const {

    return ciphertext;

}

void Encrypted::setCiphertext(const CK::ByteArray& c) {

    ciphertext = c;

}

}

