#include "certificates/Certificate.h"
#include "certificates/TBSCertificate.h"
#include "certificates/AlgorithmIdentifier.h"

namespace CK {

Certificate::Certificate()
: tbsCertificate(0),
  signatureAlgorithm(0),
  signatureValue(0) {
}

Certificate::~Certificate() {
}

void Certificate::decode(const ByteArray& encoded) {
}

ByteArray Certificate::encode() const {

    ByteArray cert(tbsCertificate->encode());
    ByteArray alg(signatureAlgorithm->encode());

    ByteArray sig(UNIVERSAL | PRIMITIVE | BITSTRING);
    sig.append(encodeLength(signatureValue.getLength()));
    sig.append(0x00);   // Unused bits
    sig.append(signatureValue);

    uint32_t certLen = cert.getLength() + alg.getLength() + sig.getLength();

    ByteArray result(UNIVERSAL | CONSTRUCTED | SEQUENCE);
    result.append(encodeLength(certLen));
    result.append(cert);
    result.append(alg);
    result.append(sig);

    return result;

}

AlgorithmIdentifier *Certificate::getAlgorithm() {

    return signatureAlgorithm;

}

TBSCertificate *Certificate::getCertificate() {

    return tbsCertificate;

}

ByteArray Certificate::getSignature() {

    return signatureValue;

}

void Certificate::setAlgorithm(AlgorithmIdentifier *alg) {

    signatureAlgorithm = alg;

}

void Certificate::setCertificate(TBSCertificate *cert) {

    tbsCertificate = cert;

}

void Certificate::setSignature(const ByteArray& sig) {

    signatureValue = sig;

}

}

