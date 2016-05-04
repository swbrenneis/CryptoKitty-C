#include "tls/ServerCertificate.h"
#include "exceptions/tls/RecordException.h"
#include "data/Unsigned64.h"
#include "data/Unsigned16.h"

namespace CKTLS {

//Static initialization.
CK::RSAPrivateKey *ServerCertificate::rsaPrivateKey = 0;
CK::RSAPublicKey *ServerCertificate::rsaPublicKey = 0;

ServerCertificate::ServerCertificate()
: cert(0),
  keyID(0),
  type(empty_cert) {
}

ServerCertificate::~ServerCertificate() {
}

void ServerCertificate::debugOut(std::ostream& out) {

    out << "certificate" << std::endl;
    out << "Type: ";
    switch (type) {
        case empty_cert:
            out << "Empty certificate.";
            break;
        case subkey_cert:
            out << "Sub-key certificate.";
            break;
        case subkey_cert_fingerprint:
            out << "Sub-key certificate fingerprint.";
            break;
    }
    out << std::endl;
    out << "Key ID: " << keyID << std::endl;
    out << "Certificate: " << std::endl;

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
    uint32_t index = keySize + 2;
    CK::Unsigned16 len(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
    index += 2;
    cert = new PGPCertificate(encoded.range(index, len.getUnsignedValue()));
    rsaPublicKey = cert->getPublicKey()->getRSAPublicKey();

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

CK::RSAPrivateKey *ServerCertificate::getRSAPrivateKey() {

    return rsaPrivateKey;

};

CK::RSAPublicKey *ServerCertificate::getRSAPublicKey() {

    return rsaPublicKey;

};

void ServerCertificate::initState() {

     type = subkey_cert;

}

void ServerCertificate::setCertificate(PGPCertificate *c) {

    cert = c;
    rsaPublicKey = cert->getPublicKey()->getRSAPublicKey();

}

void ServerCertificate::setKeyID(uint64_t id) {

    keyID = id;

}

void ServerCertificate::setRSAPrivateKey(CK::RSAPrivateKey *pk) {

    rsaPrivateKey = pk;

}

}

