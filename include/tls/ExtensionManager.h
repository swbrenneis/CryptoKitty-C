#ifndef EXTENSIONMANAGER_H_INCLUDED
#define EXTENSIONMANAGER_H_INCLUDED

#include "data/ByteArray.h"
#include "data/Unsigned16.h"
#include <deque>
#include <map>
#include <iostream>

namespace CKTLS {

struct Extension {
    CK::Unsigned16 type;
    CK::ByteArray data;
};

typedef std::deque<Extension> ExtensionList;
typedef ExtensionList::const_iterator ExtConstIter;

class ExtensionManager {

    public:
        ExtensionManager();
        ~ExtensionManager();

    private:
        ExtensionManager(const ExtensionManager& other);
        ExtensionManager& operator= (const ExtensionManager& other);

    public:
        void addExtension(const Extension& ext);
        void debugOut(std::ostream& out) const;
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;
        const Extension& getExtension(uint16_t etype) const;
        void loadDefaults();

    public:
        static const uint16_t CERT_TYPE;
        static const uint16_t SUPPORTED_CURVES;
        static const uint16_t POINT_FORMATS;

    private:
        typedef std::map<uint32_t, Extension> ExtensionMap;
        typedef ExtensionMap::const_iterator ExtConstIter;
        ExtensionMap extensions;
        static const Extension dummy;

};

}

#endif  // EXTENSIONMANAGER_H_INCLUDED
