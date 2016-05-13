#include "openpgp/packet/PKESessionKey.h"

namespace CKPGP {

PKESessionKey::PKESessionKey()
: Packet(PKESESSIONKEY) {
}

PKESessionKey::PKESessionKey(const coder::ByteArray& encoded)
: Packet(PKESESSIONKEY) {
}

PKESessionKey::~PKESessionKey() {
}

void PKESessionKey::encode() {
}

}

