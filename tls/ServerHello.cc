#include "tls/ServerHello.h"
#include "tls/ClientHello.h"
#include "tls/Constants.h"
#include "tls/ServerKeyExchange.h"
#include "data/Unsigned32.h"
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

void ServerHello::debugOut(std::ostream& out) {

    out << "server_hello" << std::endl;
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

void ServerHello::decode(const CK::ByteArray& encoded) {

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

CK::ByteArray ServerHello::encode() const {

    // First three bytes are for 24 bit length.
    CK::ByteArray encoded;

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

CipherSuite ServerHello::getCipherSuite() const {

    return suites.getServerSuite();

}

const CK::ByteArray& ServerHello::getRandom() const {

    return random;

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

    CipherSuite c = hello.getPreferred();
    suites.setPreferred(c);

    compressionMethods.append(0);

    Extension ext;
    // Set up extensions
    if (suites.isCurve(c)) {
        if (hello.getExtension(ExtensionManager::SUPPORTED_CURVES, ext)) {
            CK::ByteArray edata(ext.data);
            ext.data.clear();
            ext.data.append(0x00);
            ext.data.append(0x02);  // Curve data byte count
            bool matched = false;
            CK::Unsigned16 cCount(ext.data.range(0, 2), CK::Unsigned16::BIGENDIAN);
            for (unsigned i = 0; i < cCount.getUnsignedValue() && !matched; i += 2) {
                CK::Unsigned16 curve(edata.range((i+2)*2, 2), CK::Unsigned16::BIGENDIAN);
                if (static_cast<NamedCurve>(curve.getUnsignedValue()) == secp384r1) {
                    ext.data.append(curve.getEncoded(CK::Unsigned16::BIGENDIAN));
                    matched = true;
                }
                else if (static_cast<NamedCurve>(curve.getUnsignedValue()) == secp256r1) {
                    ext.data.append(curve.getEncoded(CK::Unsigned16::BIGENDIAN));
                    matched = true;
                }
            }
            if (matched) {
                extensions.addExtension(ext);
            }
            else {
                throw RecordException("No matching elliptic curve");
            }

            ext.data.clear();
            ext.type.setValue(ExtensionManager::POINT_FORMATS);
            ext.data.append(0x01);
            ext.data.append(0x00); // Uncompressed curve coordinates only
            extensions.addExtension(ext);
        }
        else {
            throw RecordException("EC cipher chosen without EC extensions");
        }
    }

    if (!hello.getExtension(ExtensionManager::CERT_TYPE, ext)) {
        throw RecordException("No valid certificate type");
    }
    else if (ext.data[0] != 0x01 || ext.data[1] != openpgp) {
        throw RecordException("Invalid certificate type");
    }
    extensions.addExtension(ext);

}

}
