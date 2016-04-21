#include "packet/PublicKey.h"

namespace CKPGP {

PublicKey::PublicKey()
: Packet(PUBLICKEY),
  version(4) {
}

PublicKey::~PublicKey() {
}

}

