#include "tls/RecordProtocol.h"
#include "tls/HandshakeRecord.h"
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

uint16_t RecordProtocol::getFragmentLength() const {

    return fragLength;

}

uint8_t RecordProtocol::getRecordMajorVersion() const {

    return recordMajorVersion;

}

uint8_t RecordProtocol::getRecordMinorVersion() const {

    return recordMinorVersion;

}

CKTLS::RecordProtocol::ContentType RecordProtocol::getType() const {

    return content;

}

void RecordProtocol::setFragmentLength(uint16_t len) {

    fragLength = len;

}

void RecordProtocol::setRecordMajorVersion(uint8_t major) {

    recordMajorVersion = major;

}

void RecordProtocol::setRecordMinorVersion(uint8_t minor) {

    recordMinorVersion = minor;

}

void RecordProtocol::setType(CKTLS::RecordProtocol::ContentType c) {

    content = c;

}

}
