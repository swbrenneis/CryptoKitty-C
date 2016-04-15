#include "tls/Plaintext.h"
#include "tls/HandshakeRecord.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned16.h"

namespace CKTLS {

// Static initialization.
const uint8_t Plaintext::MAJOR = 3;
const uint8_t Plaintext::MINOR = 3;

Plaintext::Plaintext(ContentType c)
: content(c) {
}

Plaintext::~Plaintext() {
}

uint16_t Plaintext::getFragmentLength() const {

    return fragLength;

}

uint8_t Plaintext::getRecordMajorVersion() const {

    return recordMajorVersion;

}

uint8_t Plaintext::getRecordMinorVersion() const {

    return recordMinorVersion;

}

CKTLS::Plaintext::ContentType Plaintext::getType() const {

    return content;

}

void Plaintext::setFragmentLength(uint16_t len) {

    fragLength = len;

}

void Plaintext::setRecordMajorVersion(uint8_t major) {

    recordMajorVersion = major;

}

void Plaintext::setRecordMinorVersion(uint8_t minor) {

    recordMinorVersion = minor;

}

void Plaintext::setType(CKTLS::Plaintext::ContentType c) {

    content = c;

}

Plaintext *Plaintext::startRecord(const CK::ByteArray& rec) {

    if (rec.getLength() != 5) {
        throw RecordException("Invalid record header message.");
    }

    Plaintext *result;
    switch (rec[0]) {
        case handshake:
            result = new HandshakeRecord;
            break;
        default:
            throw RecordException("Invalid plaintext record type");
    }

    result->setRecordMajorVersion(rec[1]);
    result->setRecordMinorVersion(rec[2]);
    CK::Unsigned16 fl(rec.range(3, 2), CK::Unsigned16::BIGENDIAN);
    result->setFragmentLength(fl.getUnsignedValue());
    result->setType(static_cast<ContentType>(rec[0]));

    return result;

}

}
