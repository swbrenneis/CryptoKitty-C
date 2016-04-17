#include "tls/ServerHello.h"
#include "tls/ClientHello.h"
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

    int j = majorVersion;
    int n = minorVersion;
    out << "Version: " << j << "." << n << std::endl;
    out << "Random.gmt: " << gmt << std::endl;
    out << "Random.random: " << random.toString() << std::endl;
    out << "Session ID: " << sessionID.toString() << std::endl;
    for (CipherConstIter it = suites.begin(); it != suites.end(); ++it) {
        CK::ByteArray s(2);
        s[0] = (*it).sel[0];
        s[1] = (*it).sel[1];
        out << "Cipher suite: " << s.toString() << std::endl;
    }
    out << "Compression methods: " << compressionMethods.toString() << std::endl;
    for (ExtConstIter it = extensions.begin(); it != extensions.end(); ++it) {
        CK::ByteArray et((*it).type.getEncoded(CK::Unsigned32::BIGENDIAN));
        out << "Extension.type: " << et.toString() << std::endl;
        out << "Extension.data: " << (*it).data.toString() << std::endl;
    }

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
            CK::Unsigned16 exl(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
            uint16_t exLength = exl.getUnsignedValue();
            index += 2;
            while (exLength > 0) {
                Extension e;
                e.type = CK::Unsigned16(encoded.range(index, 2));
                exLength -= 2;
                index += 2;
                CK::Unsigned16 edl(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
                uint16_t edataLen = edl.getUnsignedValue();
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

    CK::Unsigned32 g(gmt);
    encoded.append(g.getEncoded(CK::Unsigned32::BIGENDIAN));
    encoded.append(random);

    uint8_t slen = sessionID.getLength();
    encoded.append(slen);
    if (slen > 0) {
        encoded.append(sessionID);
    }

    CK::Unsigned16 csize(suites.size() * 2);
    encoded.append(csize.getEncoded(CK::Unsigned16::BIGENDIAN));
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
            ext.append(it->type.getEncoded(CK::Unsigned16::BIGENDIAN));
            CK::Unsigned16 edlen(it->data.getLength());
            ext.append(edlen.getEncoded(CK::Unsigned16::BIGENDIAN));
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

    CipherSuite c(hello.getPreferred());
    suites.push_back(c);

    compressionMethods.append(0);

    // Set up extensions
    if (c.ec) { // Elliptic curves
        Extension ext;
        ext.type.setValue(0x000b);
        ext.data.append(0x01);
        ext.data.append(0x00); // Uncompressed curve coordinates only
        extensions.push_back(ext);

        CK::ByteArray edata(hello.getExtensionData(0x000a));
        if (edata.getLength() == 0) {
            throw StateException("No client named curve extension");
        }

        bool matched = false;
        ext.type.setValue(0x000a);
        for (unsigned i = 0; i < edata.getLength() && !matched; i += 2) {
            CK::Unsigned16 curve(edata.range(i, 2), CK::Unsigned16::BIGENDIAN);
            if (static_cast<NamedCurve>(curve.getUnsignedValue()) == secp384r1) {
                ext.data = curve.getEncoded(CK::Unsigned16::BIGENDIAN);
                matched = true;
            }
            else if (static_cast<NamedCurve>(curve.getUnsignedValue()) == secp256r1) {
                ext.data = curve.getEncoded(CK::Unsigned16::BIGENDIAN);
                matched = true;
            }
        }
        if (matched) {
            extensions.push_back(ext);
        }
        else {
            throw StateException("No matching elliptic curve");
        }
    }

}

}
