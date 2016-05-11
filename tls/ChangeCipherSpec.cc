#include "tls/ChangeCipherSpec.h"
#include "tls/ConnectionState.h"
#include "cipher/AES.h"
#include "ciphermodes/GCM.h"
#include "data/Unsigned64.h"
#include "data/Unsigned16.h"
#include "exceptions/tls/EncodingException.h"
#include "exceptions/tls/RecordException.h"

namespace CKTLS {

// Static initialization
const uint8_t ChangeCipherSpec::MAJORVERSION = 3;
const uint8_t ChangeCipherSpec::MINORVERSION = 3;

ChangeCipherSpec::ChangeCipherSpec()
: RecordProtocol(change_cipher_spec) {
}

ChangeCipherSpec::~ChangeCipherSpec() {
}

/*
 * Decode the message. Assumes that the preamble has been stripped off.
 */
void ChangeCipherSpec::decode() {

    ConnectionState *state = ConnectionState::getPendingRead();

    switch(state->getCipherType()) {
        case stream:
            // TODO
            break;
        case block:
            // TODO
            break;
        case aead:
            {
            CK::Cipher *cipher = getCipher(state);
            const CK::ByteArray& iv(state->getIV());
            //std::cout << "Decode IV = " << iv << std::endl;
            CK::GCM gcm(cipher, iv);
            const CK::ByteArray& key(state->getEncryptionKey());
            //std::cout << "Decode Key = " << key << std::endl;
            CK::Unsigned64 seq(state->getSequenceNumber());
            CK::ByteArray ad(seq.getEncoded(CK::Unsigned64::BIGENDIAN));
            ad.append(0);   // Compression type.
            ad.append(MAJORVERSION);   // Major version.
            ad.append(MINORVERSION);   // Minor version.
            ad.append(1);   // Data length.
            //std::cout << "Decode ad = " << ad << std::endl;
            gcm.setAuthData(ad);
            // See the encode method for an explanation of the auth tag.
            if (fragment.getLength() != 17) {
                throw EncodingException("Invalid ciphertext");
            }
            gcm.setAuthTag(fragment.range(1, 16));
            CK::ByteArray plaintext(gcm.decrypt(fragment.range(0, 1), key));
            if (plaintext.getLength() != 1 || plaintext[0] != 1) {
                throw EncodingException("Invalid plaintext");
            }
            }
            break;
    }

}

void ChangeCipherSpec::encode() {

    ConnectionState *state = ConnectionState::getPendingWrite();

    CK::ByteArray plaintext(1, 1);

    switch(state->getCipherType()) {
        case stream:
            // TODO
            break;
        case block:
            // TODO
            break;
        case aead:
            {
            CK::Cipher *cipher = getCipher(state);
            const CK::ByteArray& iv(state->getIV());
            //std::cout << "Encode IV = " << iv << std::endl;
            CK::GCM gcm(cipher, iv);
            const CK::ByteArray& key(state->getEncryptionKey());
            //std::cout << "Encode Key = " << key << std::endl;
            CK::Unsigned64 seq(state->getSequenceNumber());
            CK::ByteArray ad(seq.getEncoded(CK::Unsigned64::BIGENDIAN));
            ad.append(0);   // Compression type.
            ad.append(MAJORVERSION);   // Major version.
            ad.append(MINORVERSION);   // Minor version.
            ad.append(1);   // Data length.
            gcm.setAuthData(ad);
            //std::cout << "Decode ad = " << ad << std::endl;
            CK::ByteArray ciphertext(gcm.encrypt(plaintext, key));
            if (ciphertext.getLength() != 1) {
                throw RecordException("Invalid ciphertext");
            }
            fragment.append(ciphertext);
            // The RFC says there is no additional authentication, but GCM requires an
            // authentication tag. We could just set up the GCM cipher to ignore the tag,
            // but that would weaken the cipher since the AD is easy to recreate. So,
            // we're going to append the auth tag to the end of the block. The tag length
            // is always 16.
            fragment.append(gcm.getAuthTag());
            }
            break;
    }

}

CK::Cipher *ChangeCipherSpec::getCipher(ConnectionState *state) const {

    uint32_t keySize = state->getEncryptionKeyLength();

    CK::Cipher *cipher = 0;
    switch(state->getCipherAlgorithm()) {
        case rc4:
            // TODO
            break;
        case tdes:
            // TODO
            break;
        case aes:
            switch (keySize) {
                case 128:
                    cipher = new CK::AES(CK::AES::AES128);
                    break;
                case 256:
                    cipher = new CK::AES(CK::AES::AES256);
                    break;
                default:
                    throw RecordException("Invalid AES key size");
            }
            break;
        default:
            throw RecordException("Invalid cipher algorithm");
    }

    return cipher;

}

}
