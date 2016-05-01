#include "openpgp/packet/Packet.h"
#include "openpgp/packet/PKESessionKey.h"
#include "openpgp/packet/PublicKey.h"
#include "openpgp/packet/SecretKey.h"
#include "openpgp/packet/Encrypted.h"
#include "openpgp/packet/Signature.h"
#include "openpgp/packet/UserID.h"
#include "openpgp/packet/UserAttribute.h"
#include "exceptions/openpgp/EncodingException.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"

namespace CKPGP {

// Static initialization.
const uint8_t Packet::PKESESSIONKEY = 1;
const uint8_t Packet::SIGNATURE = 2;
const uint8_t Packet::SECRETKEY = 5;
const uint8_t Packet::PUBLICKEY = 6;
const uint8_t Packet::ENCRYPTED = 9;
const uint8_t Packet::USERID = 13;
const uint8_t Packet::PUBLICSUBKEY = 14;
const uint8_t Packet::USERATTRIBUTE = 17;

Packet::Packet(uint8_t t)
: tag(t),
  newFormat(true),
  packetLength(0),
  encoded(0) {
}

Packet::Packet(const Packet& other)
: tag(other.tag),
  newFormat(other.newFormat),
  packetLength(other.packetLength),
  encoded(other.encoded) {
}

Packet::~Packet() {
}

Packet& Packet::operator= (const Packet& other) {

     tag = other.tag;
     newFormat = other.newFormat;
     packetLength = other.packetLength;
     encoded = other.encoded;
     return *this;

}

Packet *Packet::decodePacket(const CK::ByteArray& encoded) {

    int index;
    uint32_t packetLength;
    if (encoded[1] < 192) {
        packetLength = encoded[1];
        index = 2;
    }
    else if (encoded[1] == 0xff) {
        CK::Unsigned32 len(encoded.range(2, 4), CK::Unsigned32::BIGENDIAN);
        packetLength = len.getUnsignedValue();
        index = 6;
    }
    else {
        CK::ByteArray enc16(2);
        enc16[0] = encoded[1] - 192;
        enc16[1] = encoded[2] + 192;
        CK::Unsigned16 len(enc16, CK::Unsigned16::BIGENDIAN);
        packetLength = len.getUnsignedValue();
        index = 3;
    }
    uint32_t headerLength = index;

    Packet *packet;
    switch (encoded[0] & 0x3f) {
        case PKESESSIONKEY:
            packet =  new PKESessionKey(encoded.range(index, packetLength));
            break;
        case SECRETKEY:
            packet = new SecretKey(encoded.range(index, packetLength));
            break;
        case PUBLICKEY:
            packet = new PublicKey(encoded.range(index, packetLength));
            break;
        case SIGNATURE:
            packet = new Signature(encoded.range(index, packetLength));
            break;
        case USERID:
            packet = new UserID(encoded.range(index, packetLength));
            break;
        case USERATTRIBUTE:
            packet = new UserAttribute(encoded.range(index, packetLength));
            break;
        case ENCRYPTED:
            packet = new Encrypted(encoded.range(index, packetLength));
            break;
        default:
            throw EncodingException("Invalid packet tag");
    }

    packet->packetLength = packetLength;
    packet->headerLength = headerLength;
    return packet;

}

CK::ByteArray Packet::encodeLength() const {

    CK::ByteArray encoded;
    if (packetLength < 192) {
        encoded.append(packetLength);
    }
    else if (packetLength < 8384) {
        CK::Unsigned16 len(packetLength);
        CK::ByteArray enc16(len.getEncoded(CK::Unsigned16::BIGENDIAN));
        encoded.append(enc16[0] + 192);
        encoded.append(enc16[1] - 192);
    }
    else {
        encoded.append(0xff);
        CK::Unsigned32 len(packetLength);
        encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    }

    return encoded;
    
}

uint8_t Packet::encodeTag() const {

    return newFormat ? tag | 0xc0 : tag | 0x80;

}

CK::ByteArray Packet::getEncoded() {

    if (encoded.getLength() == 0) {
        encode();
    }
    return encoded;

}

uint32_t Packet::getPacketLength() const {

    return packetLength;

}

uint32_t Packet::getHeaderLength() const {

    return headerLength;

}

uint8_t Packet::getTag() const {

    return tag;

}

}

