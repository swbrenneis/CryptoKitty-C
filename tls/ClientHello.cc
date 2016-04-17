#include "tls/ClientHello.h"
#include "tls/ExtensionManager.h"
#include "data/Unsigned32.h"
#include "random/SecureRandom.h"
#include "exceptions/OutOfRangeException.h"
#include "exceptions/tls/RecordException.h"
#include <time.h>

namespace CKTLS {

static const uint8_t MAJOR = 3;
static const uint8_t MINOR = 3;

ClientHello::ClientHello()
: random(28, 0),
  majorVersion(MAJOR),
  minorVersion(MINOR) {
}

ClientHello::~ClientHello() {
}

void ClientHello::debugOut(std::ostream& out) {

    int j = majorVersion;
    int n = minorVersion;
    out << "Version: " << j << "." << n << std::endl;
    out << "Random.gmt: " << gmt << std::endl;
    out << "Random.random: " << random.toString() << std::endl;
    out << "Session ID: " << sessionID.toString() << std::endl;
    suites.debugOut(out);
    out << "Compression methods: " << compressionMethods.toString() << std::endl;

    extensions.debugOut(out);

}

void ClientHello::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    // Protocol version
    majorVersion = encoded[index++];
    minorVersion = encoded[index++];
    // Random
    CK::Unsigned32 g(encoded.range(index, 4), CK::Unsigned32::BIGENDIAN);
    gmt = g.getUnsignedValue();
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
    CK::Unsigned16 csl(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
    uint16_t csLen = csl.getUnsignedValue();
    suites.decode(encoded.range(index, csLen));
    index += csLen + 2;
    // Compression methods
    uint8_t compMethods = encoded[index++];
    while (compMethods > 0) {
        compressionMethods.append(encoded[index++]);
        compMethods--;
    }
    // Extensions. Be very, very careful. Uses ByteArray bounds
    // check to validate lengths.
    try {
        if (index < encoded.getLength() - 1) {
            CK::Unsigned16 exl(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            uint16_t exLength = exl.getUnsignedValue();
            index += 2;
            extensions.decode(encoded.range(index, exLength));
            index += exLength;
        }

    }
    catch (CK::OutOfRangeException& ee) {
        throw RecordException("Extensions decode overrun");
    }

    if (index != encoded.getLength()) {
        throw RecordException("Decoding underrun");
    }

}

CK::ByteArray ClientHello::encode() const {

    // First three bytes are for 24 bit length.
    CK::ByteArray encoded(3, 0);

    encoded.append(majorVersion);
    encoded.append(minorVersion);

    CK::Unsigned32 g(gmt);
    encoded.append(g.getEncoded(CK::Unsigned32::BIGENDIAN));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(sessionID);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    encoded.append(suites.encode());

    encoded.append(compressionMethods.getLength());
    for (unsigned i = 0; i < compressionMethods.getLength(); ++i) {
        encoded.append(compressionMethods[i]);
    }

    encoded.append(extensions.encode());

    uint32_t encodedLength = encoded.getLength() - 3;
    encoded[2] = encodedLength & 0xff;
    encodedLength = encodedLength >> 8;
    encoded[1] = encodedLength & 0xff;
    encodedLength = encodedLength >> 8;
    encoded[0] = encodedLength & 0xff;

    return encoded;

}

CK::ByteArray ClientHello::getExtensionData(uint16_t etype) const {

    Extension ext;
    if (extensions.getExtension(ext, etype)) {
        return ext.data;
    }

    return CK::ByteArray(0);

}

uint8_t ClientHello::getMajorVersion() const {

    return majorVersion;

}

uint8_t ClientHello::getMinorVersion() const {

    return minorVersion;

}

void ClientHello::initState() {

    gmt = time(0);
    CK::SecureRandom *rnd =
            CK::SecureRandom::getSecureRandom("BBS");
    rnd->nextBytes(random);
    delete rnd;
    compressionMethods.append(0);
    // TODO: SessionID.
    // TODO: Extensions

}

const CipherSuite& ClientHello::getPreferred() const {

    return suites.matchCipherSuite();

}

}
