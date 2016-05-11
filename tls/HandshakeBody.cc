#include "tls/HandshakeBody.h"

namespace CKTLS {

HandshakeBody::HandshakeBody() {
}

HandshakeBody::~HandshakeBody() {
}

void HandshakeBody::decode(const CK::ByteArray& stream) {

    encoded = stream;
    decode();

}

}

