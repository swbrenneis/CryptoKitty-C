#include "tls/ServerCertificate.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned64.h"
#include "data/Unsigned16.h"

namespace CKTLS {

ServerCertificate::ServerCertificate()
: cert(0),
  keyID(0),
  type(empty_cert) {
}

ServerCertificate::~ServerCertificate() {
}

void ServerCertificate::decode(const CK::ByteArray& encoded) {

    type = static_cast<OpenPGPCertDescriptorType>(encoded[0]);
    if (type != subkey_cert) {
        throw RecordException("Invalid certificate type");
    }

    uint8_t keySize = encoded[1];
    CK::Unsigned64 id(encoded.range(2, keySize), CK::Unsigned64::BIGENDIAN);
    keyID = id.getUnsignedValue();
    delete cert;
    cert = new PGPCertificate(encoded.range(10, encoded.getLength() - 9));

}

CK::ByteArray ServerCertificate::encode() const {

    CK::ByteArray encoded;

    encoded.append(type);
    CK::Unsigned64 id(keyID);
    encoded.append(8);
    encoded.append(id.getEncoded(CK::Unsigned64::BIGENDIAN));
    CK::ByteArray pgp(cert->encode());
    CK::Unsigned16 len(pgp.getLength());
    encoded.append(len.getEncoded(CK::Unsigned16::BIGENDIAN));
    encoded.append(pgp);

    return encoded;

}

void ServerCertificate::initState() {

     type = subkey_cert;

}

void ServerCertificate::setCertificate(PGPCertificate *c) {

    cert = c;

}

void ServerCertificate::setKeyID(uint64_t id) {

    keyID = id;

}

}

