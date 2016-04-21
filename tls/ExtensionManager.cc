#include "tls/ExtensionManager.h"

namespace CKTLS {

// Static initialization;
const uint16_t ExtensionManager::CERT_TYPE = 0x0009;
const uint16_t ExtensionManager::SUPPORTED_CURVES = 0x000a;
const uint16_t ExtensionManager::POINT_FORMATS = 0x000b;
const Extension ExtensionManager::dummy = { CK::Unsigned16(0xffff), CK::ByteArray(0) };

ExtensionManager::ExtensionManager() {
}

ExtensionManager::~ExtensionManager() {
}

void ExtensionManager::addExtension(const Extension& ext) {

    extensions[ext.type.getUnsignedValue()] = ext;

}

void ExtensionManager::debugOut(std::ostream& out) const {

    for (ExtConstIter it = extensions.begin(); it != extensions.end(); ++it) {
        out << "Extension.type: " << it->second.type.getUnsignedValue() << std::endl;
        out << "Extension.data: " << it->second.data.toString() << std::endl;
    }

}

void ExtensionManager::decode(const CK::ByteArray& encoded) {

    unsigned index = 0;
    while (index < encoded.getLength()) {
        Extension e;
        e.type = CK::Unsigned16(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
        index += 2;
        CK::Unsigned16 edl(encoded.range(index, 2), CK::Unsigned16::BIGENDIAN);
        uint16_t edataLen = edl.getUnsignedValue();
        index +=2;
        e.data = encoded.range(index, edataLen);
        index += edataLen;
        extensions[e.type.getUnsignedValue()] = e;
    }

}

CK::ByteArray ExtensionManager::encode() const {

    CK::ByteArray encoded;
    if (extensions.size() > 0) {
        // 2 byte length.
        CK::ByteArray ext;
        for (ExtConstIter it = extensions.begin();
                                    it != extensions.end(); ++it) {
            ext.append(it->second.type.getEncoded(CK::Unsigned16::BIGENDIAN));
            CK::Unsigned16 edlen(it->second.data.getLength());
            ext.append(edlen.getEncoded(CK::Unsigned16::BIGENDIAN));
            ext.append(it->second.data);
        }
        CK::Unsigned16 elen(ext.getLength());
        encoded.append(elen.getEncoded(CK::Unsigned16::BIGENDIAN));
        encoded.append(ext);
    }

    return encoded;

}

const Extension& ExtensionManager::getExtension(uint16_t etype) const {

    ExtConstIter it = extensions.find(etype);
    if (it == extensions.end()) {
        return dummy;
    }

    return it->second;

}

void ExtensionManager::loadDefaults() {

    Extension ext;

    ext.type.setValue(SUPPORTED_CURVES);
    CK::Unsigned16 extCount(4);     // Bytes of extension data
    ext.data.append(extCount.getEncoded(CK::Unsigned16::BIGENDIAN));
    CK::Unsigned16 curve(secp384r1);
    ext.data.append(curve.getEncoded(CK::Unsigned16::BIGENDIAN));
    curve.setValue(secp256r1);
    ext.data.append(curve.getEncoded(CK::Unsigned16::BIGENDIAN));
    extensions[SUPPORTED_CURVES] = ext;
    ext.data.clear();
    ext.type.setValue(CERT_TYPE);
    ext.data.append(0x01);
    ext.data.append(openpgp);
    extensions[CERT_TYPE] = ext;
    ext.data.clear();
    ext.type.setValue(POINT_FORMATS);
    ext.data.append(0x01);
    ext.data.append(0x00); // Uncompressed point format.
    extensions[POINT_FORMATS] = ext;

}

}

