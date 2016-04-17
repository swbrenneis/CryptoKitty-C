#include "tls/ExtensionManager.h"

namespace CKTLS {

ExtensionManager::ExtensionManager() {
}

ExtensionManager::~ExtensionManager() {
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
        CK::ByteArray ext(2, 0);
        for (ExtConstIter it = extensions.begin();
                                    it != extensions.end(); ++it) {
            ext.append(it->second.type.getEncoded(CK::Unsigned16::BIGENDIAN));
            CK::Unsigned16 edlen(it->second.data.getLength());
            ext.append(edlen.getEncoded(CK::Unsigned16::BIGENDIAN));
            ext.append(it->second.data);
        }
        uint32_t elen = ext.getLength() - 2;
        ext[1] = elen & 0xff;
        elen = elen >> 8;
        ext[0] = elen & 0xff;
        encoded.append(ext);
    }

    return encoded;

}

bool ExtensionManager::getExtension(Extension& ext, uint16_t etype) const {

    ExtConstIter it = extensions.find(etype);
    if (it == extensions.end()) {
        return false;
    }

    ext = it->second;
    return true;

}

void ExtensionManager::setExtension(const Extension& ext) {

    extensions[ext.type.getUnsignedValue()] = ext;

}

}

