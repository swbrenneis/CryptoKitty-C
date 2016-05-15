#include "tls/CipherText.h"
#include "tls/Constants.h"
#include "coder/Unsigned16.h"
#include "coder/Unsigned64.h"
#include "cipher/AES.h"
#include "ciphermodes/GCM.h"
#include "tls/ConnectionState.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

CipherText::CipherText()
: RecordProtocol(application_data) {
}

CipherText::~CipherText() {
}

void CipherText::decode() {

    uint8_t ivLength = fragment[0];
    iv = fragment.range(1, ivLength);

    CK::Cipher *cipher;
    switch (algorithm) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    switch (type) {
        case aead:
            {
            uint32_t ctLength = fragment.getLength() - ivLength - 1 - keyLength;
            coder::ByteArray ciphertext(fragment.range(ivLength, ctLength));
            // Auth tag is the same size as the key.
            coder::ByteArray
                tag(fragment.range(fragment.getLength() - keyLength, keyLength));
            decryptGCM(ciphertext, cipher, tag);
            }
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::encode() {

    fragment.clear();

    fragment.append(iv.getLength());
    fragment.append(iv);

    CK::Cipher *cipher;
    switch (algorithm) {
        case aes:
            cipher = new CK::AES(static_cast<CK::AES::KeySize>(keyLength));
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    switch (type) {
        case aead:
            encryptGCM(cipher);
            break;
        default:
            throw RecordException("Invalid cipher mode");
    }

}

void CipherText::decryptGCM(const coder::ByteArray& ciphertext,CK::Cipher *cipher,
                                                        const coder::ByteArray& tag) {

    CK::GCM gcm(cipher, iv);
    coder::ByteArray ad;
    coder::Unsigned64 u64(sequence);
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    // Full fragment size. Palintext + tag size + iv size + 1.
    coder::Unsigned16 u16(fragment.getLength());
    ad.append(u16.getEncoded(coder::bigendian));
    gcm.setAuthData(ad);
    gcm.setAuthTag(tag);
    plaintext = gcm.decrypt(ciphertext, key);

}

void CipherText::encryptGCM(CK::Cipher *cipher) {

    CK::GCM gcm(cipher, iv);
    coder::ByteArray ad;
    coder::Unsigned64 u64(sequence);
    ad.append(u64.getEncoded(coder::bigendian));
    ad.append(CKTLS::application_data);
    ad.append(3);
    ad.append(3);
    // Full fragment size. Palintext + tag size + iv size + 1.
    coder::Unsigned16 u16(plaintext.getLength() + keyLength + iv.getLength() + 1);
    ad.append(u16.getEncoded(coder::bigendian));
    gcm.setAuthData(ad);
    fragment.append(gcm.encrypt(plaintext, key));
    fragment.append(gcm.getAuthTag());

}

const coder::ByteArray& CipherText::getPlaintext() const {

    return plaintext;

}

void CipherText::setAlgorithm(BulkCipherAlgorithm alg) {

    algorithm = alg;

}

void CipherText::setCipherType(CipherType cipher) {

    type = cipher;

}

void CipherText::setIV(const coder::ByteArray& i) {

    iv = i;

}

void CipherText::setKey(const coder::ByteArray& k) {

    key = k;

}

void CipherText::setKeyLength(uint32_t keylength) {

    keyLength = keylength / 8;

}

void CipherText::setPlaintext(const coder::ByteArray& plain) {

    plaintext = plain;

}

void CipherText::setSequenceNumber(uint64_t seq) {

    sequence = seq;

}

}

