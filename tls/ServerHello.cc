#include "tls/ServerHello.h"
#include "tls/ClientHello.h"
#include "data/Scalar32.h"
#include "random/SecureRandom.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/tls/RecordException.h"
#include "exceptions/tls/StateException.h"
#include <time.h>

namespace CKTLS {

static const uint8_t MAJOR = 3;
static const uint8_t MINOR = 3;

ServerHello::ServerHello()
: random(28, 0),
  majorVersion(MAJOR),
  minorVersion(MINOR) {
}

ServerHello::~ServerHello() {
}

void ServerHello::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    // Protocol version
    majorVersion = encoded[index++];
    minorVersion = encoded[index++];
    // Random
    CK::Scalar32 g(encoded.range(index, 4), CK::Scalar32::BIGENDIAN);
    gmt = g.getIntValue();
    index += 4;
    random = encoded.range(index, 28);
    index += 28;
    // Session ID
    uint8_t sidLen = encoded[index++];
    if (sidLen > 0) {
        sessionID = encoded.range(index, sidLen);
        index += sidLen;
    }
    // Cipher suites
    CK::Scalar16 csl(encoded.range(index, 2), CK::Scalar16::BIGENDIAN);
    int16_t csLen = csl.getIntValue();
    index += 2;
    while (csLen > 0) {
        CipherSuite c;
        c.sel[0] = encoded[index++];
        csLen--;
        if (csLen > 0) { // No overruns or underruns. Thanks anyway.
            c.sel[1] = encoded[index++];
            csLen--;
        }
        else {
            throw RecordException("Cipher suite length invalid");
        }
        suites.push_back(c);
    }
    // Compression methods
    uint8_t compMethods = encoded[index++];
    while (compMethods > 0) {
        compressionMethods.append(encoded[index++]);
        compMethods--;
    }
    // Extensions. Be very, very careful. Uses ByteArray bounds
    // check to validate lengths.
    try {
        if (index < encoded.getLength() -1) {
            CK::Scalar16 exl(encoded.range(index, 2), CK::Scalar16::BIGENDIAN);
            int16_t exLength = exl.getIntValue();
            index += 2;
            while (exLength > 0) {
                Extension e;
                e.type = CK::Scalar16(encoded.range(index, 2));
                exLength -= 2;
                index += 2;
                CK::Scalar16 edl(encoded.range(index, 2), CK::Scalar16::BIGENDIAN);
                int16_t edataLen = edl.getIntValue();
                exLength -=2;
                index +=2;
                e.data = encoded.range(index, edataLen);
                exLength -= edataLen;
                index += edataLen;
                extensions.push_back(e);
            }
        }

    }
    catch (CK::OutOfRangeException& ee) {
        throw RecordException("Extensions decode overrun");
    }

    if (index != encoded.getLength()) {
        throw RecordException("Decoding underrun");
    }

}

CK::ByteArray ServerHello::encode() const {

    // First three bytes are for 24 bit length.
    CK::ByteArray encoded(3, 0);

    encoded.append(majorVersion);
    encoded.append(minorVersion);

    CK::Scalar32 g(gmt);
    encoded.append(g.getEncoded(CK::Scalar32::BIGENDIAN));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(slen);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    CK::Scalar16 csize(suites.size() * 2);
    encoded.append(csize.getEncoded(CK::Scalar16::BIGENDIAN));
    for (CipherConstIter it = suites.begin();
                                    it != suites.end(); ++it) {
        encoded.append(it->sel[0]);
        encoded.append(it->sel[1]);
    }

    if (extensions.size() > 0) {
        // 2 byte length.
        CK::ByteArray ext(2, 0);
        for (ExtConstIter it = extensions.begin();
                                    it != extensions.end(); ++it) {
            ext.append(it->type.getEncoded(CK::Scalar16::BIGENDIAN));
            CK::Scalar16 edlen(it->data.getLength());
            ext.append(edlen.getEncoded(CK::Scalar16::BIGENDIAN));
            ext.append(it->data);
        }
        unsigned elen = ext.getLength() - 2;
        ext[1] = elen & 0xff;
        elen = elen >> 8;
        ext[0] = elen & 0xff;
        encoded.append(ext);
    }
    uint32_t encodedLength = encoded.getLength() - 3;
    encoded[2] = encodedLength & 0xff;
    encodedLength = encodedLength >> 8;
    encoded[1] = encodedLength & 0xff;
    encodedLength = encodedLength >> 8;
    encoded[0] = encodedLength & 0xff;

    return encoded;

}

void ServerHello::initState() {

    // Not sure if we really need this.

}

void ServerHello::initState(const ClientHello& hello) {

    gmt = time(0);
    CK::SecureRandom *rnd =
            CK::SecureRandom::getSecureRandom("BBS");
    rnd->nextBytes(random);
    delete rnd;

    bool matched = false;
    int next = 0;
    CipherSuiteManager *manager = CipherSuiteManager::getManager();
    CipherSuite c(manager->nextCipherSuite(next++));
    while (c != CipherSuiteManager::TLS_NULL_WITH_NULL_NULL && !matched) {
        if (hello.matchCipherSuite(c)) {
            suites.push_back(c);
            matched = true;
        }
        c = manager->nextCipherSuite(next++);
    }
    if (!matched) {
        throw StateException("No matching cipher suite");
    }

    compressionMethods.append(0);

}

}
