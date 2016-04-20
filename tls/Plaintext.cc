#include "tls/Plaintext.h"
#include "tls/HandshakeRecord.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned16.h"

namespace CKTLS {

// Static initialization.
const uint8_t Plaintext::MAJOR = 3;
const uint8_t Plaintext::MINOR = 3;

Plaintext::Plaintext(ContentType c)
: content(c),
  recordMajorVersion(MAJOR),
  recordMinorVersion(MINOR) {
}

Plaintext::~Plaintext() {
}

Plaintext::ContentType
Plaintext::decodePreamble(const CK::ByteArray& encoded) {

    if (encoded.getLength() != 5) {
        throw RecordException("Invalid plaintext preamble");
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

}

CK::ByteArray Plaintext::encodePreamble() const {

    CK::ByteArray preamble;

    preamble.append(content);
    preamble.append(recordMajorVersion);
    preamble.append(recordMinorVersion);
    CK::Unsigned16 fl(fragLength);
    preamble.append(fl.getEncoded(CK::Unsigned16::BIGENDIAN));

    return preamble;
    
}

uint16_t Plaintext::getFragmentLength() const {

    return fragLength;

}

CKTLS::Plaintext::ContentType Plaintext::getContentType() const {

    return content;

}

void Plaintext::setFragment(const CK::ByteArray& frag) {

    fragment = frag;

}

}
