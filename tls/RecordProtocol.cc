#include "tls/RecordProtocol.h"
#include "tls/HandshakeRecord.h"
#include "data/Unsigned16.h"
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

ContentType RecordProtocol::decodePreamble(const CK::ByteArray& encoded) {

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

    CK::Unsigned16 fLen(encoded.range(3, 2), CK::Unsigned16::BIGENDIAN);
    fragLength = fLen.getUnsignedValue();

    return content;

}

/*
 * Decode the record. The must be set before calling this.
 */
void RecordProtocol::decodeRecord() {

    decode();

}

/*CK::ByteArray HandshakeRecord::encodePreamble() const {

    CK::ByteArray preamble;

    preamble.append(content);
    preamble.append(recordMajorVersion);
    preamble.append(recordMinorVersion);
    CK::Unsigned16 fl(fragLength);
    preamble.append(fl.getEncoded(CK::Unsigned16::BIGENDIAN));

    return preamble;
    
}*/

/*
 * Encode the record. Return a reference to the byte array with the
 * encoding.
 */
const CK::ByteArray& RecordProtocol::encodeRecord() {

    encoded.clear();
    encoded.append(content);
    encoded.append(recordMajorVersion);
    encoded.append(recordMinorVersion);
    // Type specific encoding. Encodes to fragment.
    encode();
    CK::Unsigned16 len(fragment.getLength());
    encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    encoded.append(fragment);
    return encoded;

}

const CK::ByteArray& RecordProtocol::getFragment() const {

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

void RecordProtocol::setFragment(const CK::ByteArray& frag) {

    fragment = frag;

}

}
