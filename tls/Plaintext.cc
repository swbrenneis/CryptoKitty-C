#include "tls/Plaintext.h"
#include "tls/HandshakeRecord.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned16.h"

namespace CKTLS {

Plaintext::Plaintext(ContentType c)
: RecordProtocol(c) {
}

Plaintext::~Plaintext() {
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
