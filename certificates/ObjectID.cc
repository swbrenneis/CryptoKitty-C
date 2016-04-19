#include "certificates/ObjectID.h"
#include <sstream>

namespace CK {

ObjectID::ObjectID() {
}

ObjectID::~ObjectID() {
}

ByteArray ObjectID::encode() const {

    ByteArray result;
    result.append(UNIVERSAL | PRIMITIVE | OBJECTID);

    ByteArray oidBytes;
    ByteArray encoded;
    unsigned index = 0;
    while (index < oidValues.size()) {
        uint32_t value = oidValues[index++];
        if (index == 1) {
            value = (value * 40) + oidValues[index++];
        }
        while (value > 0) {
            encoded.push(value & 0x7f);
            value = value >> 7;
        }
        if (encoded.getLength() > 1) {
            for (unsigned i = 0; i < encoded.getLength() - 1; ++i) {
                encoded[i] |= 0x80;
            }
        }
        oidBytes.append(encoded);
        encoded.clear();
    }

    result.append(oidBytes.getLength());
    result.append(oidBytes);

    return result;

}

ObjectID::OID ObjectID::getObjectID() const {

    return oidValues;

}

void ObjectID::setObjectID(const OID& oid) {

    oidValues = oid;

    std::ostringstream str;
    for (unsigned i = 0; i < oidValues.size(); ++i) {
        str << oidValues[i];
        if (i < oidValues.size() -1) {
            str << ".";
        }
    }
    oidString = str.str();

}

std::string ObjectID::toString() const {

    return oidString;

}

}

