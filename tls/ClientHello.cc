#include "tls/ClientHello.h"
#include "data/Scalar32.h"
#include "random/SecureRandom.h"
#include <time.h>

namespace CKTLS {

// Cipher suite constants.
static const ClientHello::Cipher
        TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x3D };
static const ClientHello::Cipher
        TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x3C };
static const uint8_t MAJOR = 3;
static const uint8_t MINOR = 3;

ClientHello::ClientHello()
: random(28, 0),
  compression(0),
  majorVersion(MAJOR),
  minorVersion(MINOR) {

}

ClientHello::~ClientHello() {
}

CK::ByteArray ClientHello::encode() const {

    // First three bytes are for 24 bit length.
    CK::ByteArray encoded(3, 0);

    encoded.append(majorVersion);
    encoded.append(minorVersion);

    CK::Scalar32 g(gmt);
    encoded.append(g.getEncoded(CK::Scalar32::BIGENDIAN));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(sessionID);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    CK::Scalar16 csize(ciphers.size() * 2);
    encoded.append(csize.getEncoded(CK::Scalar16::BIGENDIAN));
    for (CipherConstIter it = ciphers.begin();
                                    it != ciphers.end(); ++it) {
        encoded.append(it->sel[0]);
        encoded.append(it->sel[1]);
    }

    if (extensions.size() > 0) {
        // 2 byte length.
        CK::ByteArray ext(2, 0);
        for (ExtConstIter it = extensions.begin();
                                    it != extensions.end(); ++it) {
            ext.append(it->extensionType.getEncoded(CK::Scalar16::BIGENDIAN));
            CK::Scalar16 edlen(it->extensionData.getLength());
            ext.append(edlen.getEncoded(CK::Scalar16::BIGENDIAN));
            ext.append(it->extensionData);
        }
        unsigned elen = ext.getLength() - 2;
        ext[1] = elen & 0xff;
        elen = elen >> 8;
        ext[0] = elen & 0xff;
        encoded.append(ext);
    }

    return encoded;

}

void ClientHello::initState() {

    gmt = time(0);
    CK::SecureRandom *rnd =
            CK::SecureRandom::getSecureRandom("BBS");
    rnd->nextBytes(random);
    delete rnd;
    // TODO: SessionID.
    ciphers.push_back(TLS_RSA_WITH_AES_256_CBC_SHA256);
    ciphers.push_back(TLS_RSA_WITH_AES_128_CBC_SHA256);
    // TODO: Extensions

}

}
