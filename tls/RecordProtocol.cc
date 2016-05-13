#include "tls/RecordProtocol.h"
#include "tls/HandshakeRecord.h"
#include "coder/Unsigned16.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

// Static initialization.
const uint8_t RecordProtocol::MAJOR = 3;
const uint8_t RecordProtocol::MINOR = 3;

RecordProtocol::RecordProtocol(ContentType c)
: content(c) {
}

RecordProtocol::~RecordProtocol() {
}

ContentType RecordProtocol::decodePreamble(const coder::ByteArray& encoded) {

    if (encoded.getLength() != 5) {
        throw RecordException("Invalid record preamble");
    }

    content = static_cast<ContentType>(encoded[0]);
    switch (content) {
        case change_cipher_spec:
        case alert:
        case handshake:
        case application_data:
            recordMajorVersion = encoded[1];
            recordMinorVersion = encoded[2];
            break;
        default:
            throw RecordException("Invalid plaintext content type");
    }

    coder::Unsigned16 fLen(encoded.range(3, 2), coder::bigendian);
    fragLength = fLen.getValue();

    return content;

}

/*
 * Decode the record. The must be set before calling this.
 */
void RecordProtocol::decodeRecord() {

    decode();

}

/*coder::ByteArray HandshakeRecord::encodePreamble() const {

    coder::ByteArray preamble;

    preamble.append(content);
    preamble.append(recordMajorVersion);
    preamble.append(recordMinorVersion);
    coder::Unsigned16 fl(fragLength);
    preamble.append(fl.getEncoded(coder::bigendian));

    return preamble;
    
}*/

/*
 * Encode the record. Return a reference to the byte array with the
 * encoding.
 */
const coder::ByteArray& RecordProtocol::encodeRecord() {

    encoded.clear();
    encoded.append(content);
    encoded.append(recordMajorVersion);
    encoded.append(recordMinorVersion);
    // Type specific encoding. Encodes to fragment.
    encode();
    coder::Unsigned16 len(fragment.getLength());
    encoded.append(len.getEncoded(coder::bigendian));
    encoded.append(fragment);
    return encoded;

}

const coder::ByteArray& RecordProtocol::getFragment() const {

    return fragment;

}

uint16_t RecordProtocol::getFragmentLength() const {

    return fragLength;

}

uint8_t RecordProtocol::getRecordMajorVersion() const {

    return recordMajorVersion;

}

uint8_t RecordProtocol::getRecordMinorVersion() const {

    return recordMinorVersion;

}

ContentType RecordProtocol::getRecordType() const {

    return content;

}

void RecordProtocol::setFragment(const coder::ByteArray& frag) {

    fragment = frag;

}

}
