#include "tls/CipherText.h"
#include "tls/Constants.h"
#include "coder/Unsigned16.h"
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

const coder::ByteArray& CipherText::getPlaintext() const {

    return plaintext;

}

void CipherText::setPlaintext(const coder::ByteArray& plain) {

    plaintext = plain;

}

}

