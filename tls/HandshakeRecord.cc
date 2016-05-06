#include "tls/HandshakeRecord.h"
#include "tls/HelloRequest.h"
#include "tls/ClientHello.h"
#include "tls/ServerHello.h"
#include "tls/ServerCertificate.h"
#include "tls/ServerHelloDone.h"
#include "tls/ServerKeyExchange.h"
#include "tls/ClientKeyExchange.h"
#include "tls/ConnectionState.h"
#include "data/Unsigned16.h"
#include "data/Unsigned32.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

HandshakeRecord::HandshakeRecord()
: Plaintext(handshake),
  body(0) {
}

HandshakeRecord::HandshakeRecord(HandshakeType h)
: Plaintext(handshake),
  body(0),
  type(h) {

    ConnectionEnd end = ConnectionState::getPendingRead()->getEntity();

    switch (type) {
        case hello_request:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new HelloRequest;
            break;
        case client_hello:
            if (end != client) {
                throw RecordException("Wrong connection state");
            }
            body = new ClientHello;
            break;
        case certificate:
            if (end == server) {
                body = new ServerCertificate;
            }
            else {
                // TODO: Client certificate.
                body = 0;
            }
            break;
        case server_hello:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerHello;
            break;
        case server_hello_done:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerHelloDone;
            break;
        case server_key_exchange:
            if (end != server) {
                throw RecordException("Wrong connection state");
            }
            body = new ServerKeyExchange;
            break;
        case client_key_exchange:
            if (end != client) {
                throw RecordException("Wrong connection state");
            }
            body = new ClientKeyExchange;
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
void HandshakeRecord::decode() {

    if (content != handshake) {
        throw RecordException("Not a handshake record");
    }

    type = static_cast<HandshakeType>(fragment[0]);
    // Decode the body length.
    CK::ByteArray bLen(1, 0);
    bLen.append(fragment.range(1, 3));
    CK::Unsigned32 bodyLen(bLen, CK::Unsigned32::BIGENDIAN);
    uint32_t length = bodyLen.getUnsignedValue();
    if (length + 4 != fragment.getLength()) {
        throw RecordException("Invalid body length");
    }

    CK::ByteArray bodyBytes(fragment.range(4, length));

    switch (type) {
        case hello_request:
            body = new HelloRequest;
            break;
        case certificate:
            body = new ServerCertificate;
            break;
        case client_hello:
            body = new ClientHello;
            break;
        case server_hello:
            body = new ServerHello;
            break;
        case server_hello_done:
            body = new ServerHelloDone;
            break;
        case server_key_exchange:
            body = new ServerKeyExchange;
            break;
        case client_key_exchange:
            body = new ClientKeyExchange;
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
    CK::Unsigned32 bodyLen(encBody.getLength());
    CK::ByteArray bl = bodyLen.getEncoded(CK::Unsigned32::BIGENDIAN);
    fragment.append(bl.range(1, 3));
    fragment.append(encBody);
    fragLength = fragment.getLength();

    CK::ByteArray plaintext(encodePreamble());
    plaintext.append(fragment);
    return plaintext;

}

HandshakeBody *HandshakeRecord::getBody() {

    return body;

}

HandshakeType HandshakeRecord::getType() const {

    return type;

}

}
