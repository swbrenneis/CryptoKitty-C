#include "tls/HandshakeRecord.h"
#include "tls/HelloRequest.h"
#include "tls/ClientHello.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

HandshakeRecord::HandshakeRecord()
: RecordProtocol(handshake) {
}

HandshakeRecord::HandshakeRecord(HandshakeType h)
: RecordProtocol(handshake),
  type(h) {

    switch (type) {
        case hello_request:
            // TODO: Validate that this is a server.
            body = new HelloRequest;
            break;
        case client_hello:
            // TODO: Validate that this is a client.
            body = new ClientHello;
            break;
        default:
            throw RecordException("Invalid handshake type");
    }
    body->initState();

}

HandshakeRecord::~HandshakeRecord() {

    delete body;
}

/*
 * Decode a byte stream.
 */
void HandshakeRecord::decode(const CK::ByteArray& stream) {

    type = static_cast<HandshakeType>(stream[0]);
    // Decode the body length.
    uint32_t length = 0;
    for (int n = 1; n < 4; ++n) {
        length = length << 8;
        length |= stream[n];
    }
    if (length + 4 != stream.getLength()) {
        throw RecordException("Invalid body length");
    }

    CK::ByteArray bodyBytes(stream.range(4, length));

    switch (type) {
        case hello_request:
            // TODO: Validate that this is a client.
            body = new HelloRequest;
            break;
        case client_hello:
            // TODO: Validate that this is a server.
            body = new ClientHello;
            break;
        default:
            throw RecordException("Invalid handshake type");
    }
    body->decode(bodyBytes);

}

CK::ByteArray HandshakeRecord::encode() const {

    CK::ByteArray encoded;
    encoded.append(type);
    encoded.append(body->encode());
    return encoded;

}

}
