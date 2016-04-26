#include "openpgp/packet/PKESessionKey.h"

namespace CKPGP {

PKESessionKey::PKESessionKey()
: Packet(PKESESSIONKEY) {
}

PKESessionKey::PKESessionKey(const CK::ByteArray& encoded)
: Packet(PKESESSIONKEY) {
}

PKESessionKey::~PKESessionKey() {
}

void PKESessionKey::encode() {
}

}

