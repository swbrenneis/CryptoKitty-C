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
  sessionID(0),
  majorVersion(MAJOR),
  minorVersion(MINOR) {
}

ClientHello::ClientHello(const ClientHello& other) 
: gmt(other.gmt),
  random(other.random),
  sessionID(other.sessionID),
  majorVersion(other.majorVersion),
  minorVersion(other.minorVersion),
  compressionMethods(other.compressionMethods),
  suites(other.suites),
  extensions(other.extensions) {
}

ClientHello::~ClientHello() {
}

#ifdef _DEBUG
void ClientHello::debugOut(std::ostream& out) {

    out << "client_hello" << std::endl;
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
#endif

void ClientHello::decode() {

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
    suites.decode(encoded.range(index+2, csLen));
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

const CK::ByteArray& ClientHello::encode() {

    encoded.append(majorVersion);
    encoded.append(minorVersion);

    CK::Unsigned32 g(gmt);
    encoded.append(g.getEncoded(CK::Unsigned32::BIGENDIAN));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(slen);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    CK::ByteArray s(suites.encode());
    CK::Unsigned16 suiteLen(s.getLength());
    encoded.append(suiteLen.getEncoded(CK::Unsigned16::BIGENDIAN));
    encoded.append(s);

    encoded.append(compressionMethods.getLength());
    for (unsigned i = 0; i < compressionMethods.getLength(); ++i) {
        encoded.append(compressionMethods[i]);
    }

    encoded.append(extensions.encode());

    return encoded;

}

bool ClientHello::getExtension(uint16_t eType, Extension& ext) const {

    ext = extensions.getExtension(eType);
    return ext.type.getUnsignedValue() == eType;

}

uint8_t ClientHello::getMajorVersion() const {

    return majorVersion;

}

uint8_t ClientHello::getMinorVersion() const {

    return minorVersion;

}

CipherSuite ClientHello::getPreferred() const {

    return suites.matchCipherSuite();

}

const CK::ByteArray& ClientHello::getRandom() const {

    return random;

}

void ClientHello::initState() {

    gmt = time(0);
    CK::SecureRandom *rnd =
            CK::SecureRandom::getSecureRandom("Fortuna");
    rnd->nextBytes(random);
    delete rnd;
    suites.loadPreferred();
    compressionMethods.append(0);
    extensions.loadDefaults();

}

}
