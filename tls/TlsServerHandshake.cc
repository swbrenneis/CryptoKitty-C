#include "tls/TlsServerHandshake.h"
#include "tls/TCPConnection.h"

namespace CK {

TlsServerHandshake::TlsServerHandshake(TCPConnection *c)
: conn(c) {
}

TlsServerHandshake::~TlsServerHandshake() {
}

}
