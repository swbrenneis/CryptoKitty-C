#include "tls/RecordProtocol.h"

namespace CKTLS {

// Static initialization.
const uint8_t RecordProtocol::MAJOR = 3;
const uint8_t RecordProtocol::MINOR = 3;

RecordProtocol::RecordProtocol(ContentType c)
: content(c) {
}

RecordProtocol::~RecordProtocol() {
}

CK::ByteArray RecordProtocol::encode() const {

    CK::ByteArray encoded(static_cast<uint8_t>(content));
    encoded.append(MAJOR);
    encoded.append(MINOR);
    encoded.append(fragLength.encode(CK::Scalar16::BIGENDIAN));
    encoded.append(fragment);
    return encoded;

}

}
