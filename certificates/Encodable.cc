#include "certificates/Encodable.h"

namespace CK {

Encodable::Encodable() {
}

Encodable::~Encodable() {
}

ByteArray Encodable::encodeLength(uint32_t len) const {

    ByteArray result;

    if (len < 0x80) {
        uint8_t l = len;
        result.append(l);
    }
    else {
        uint32_t l = len;
        while (l > 0) {
            uint8_t byte = l & 0xff;
            result.push(byte);
            l = l >> 8;
        }
        uint8_t ll = (result.getLength() & 0x6f) | 0x80;
        result.push(ll);
    }

    return result;

}

}

