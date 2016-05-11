#include "tls/CipherText.h"
#include "tls/Constants.h"
#include "data/Unsigned16.h"
#include "ciphermodes/CipherMode.h"
#include "tls/ConnectionState.h"

namespace CKTLS {

CipherText::CipherText()
: RecordProtocol(application_data) {
}

CipherText::~CipherText() {
}

void CipherText::decode() {

    // TODO Decryption

}

void CipherText::encode() {

    // TODO Encryption

}

const CK::ByteArray& CipherText::getPlaintext() const {

    return plaintext;

}

void CipherText::setPlaintext(const CK::ByteArray& plain) {

    plaintext = plain;

}

}

