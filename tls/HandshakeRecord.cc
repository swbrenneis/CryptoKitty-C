#include "tls/HandshakeRecord.h"
#include "tls/HelloRequest.h"
#include "tls/ClientHello.h"
#include "tls/ServerHello.h"
#include "tls/ServerHelloDone.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

HandshakeRecord::HandshakeRecord()
: Plaintext(handshake),
  body(0),
  length(0) {
}

HandshakeRecord::HandshakeRecord(HandshakeType h)
: Plaintext(handshake),
  body(0),
  length(0),
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
        case server_hello:
            // TODO: Validate that this is a server.
            body = new ServerHello;
            break;
        case server_hello_done:
            // TODO: Validate that this is a server.
            body = new ServerHelloDone;
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
    length = 0;
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
        case server_hello:
            // TODO: Validate that this is a server.
            body = new ServerHello;
            break;
        case server_hello_done:
            // TODO: Validate that this is a server.
            body = new ServerHelloDone;
            break;
        default:
            throw RecordException("Invalid handshake type");
    }
    body->decode(bodyBytes);

}

CK::ByteArray HandshakeRecord::encode() {

    fragment.clear();
    fragment.append(type);
    CK::ByteArray encBody(body->encode());
    length = encBody.getLength();
    CK::Unsigned32 bodyLen(length);
    CK::ByteArray bl = bodyLen.encode(CK::Unsigned32::BIGENDIAN);
    fragment.append(bl.range(0, 3));
    fragment.append(encBody);
    fragLength = fragment.getLength();

    CK::ByteArray encoded;
    encoded.append(content);
    encoded.append(recordMajorVersion);
    encoded.append(recordMinorVersion);
    CK::Unsigned16 fl(fragLength);
    encoded.append(fl.encode(CK::Unsigned16::BIGENDIAN));
    encoded.append(fragment);

    return encoded;

}

HandshakeBody *HandshakeRecord::getBody() {

    return body;

}

HandshakeRecord::HandshakeType HandshakeRecord::getType() const {

    return type;

}

void HandshakeRecord::setBody(HandshakeBody *hs) {

    delete body;
    body = hs;

}

}
