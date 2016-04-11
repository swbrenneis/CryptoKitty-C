#ifndef CLIENTHELLO_H_INCLUDED
#define CLIENTHELLO_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/CipherSuiteManager.h"
#include "data/Unsigned16.h"

namespace CKTLS {

class ClientHello : public HandshakeBody {

    public:
        ClientHello();
        ~ClientHello();

    public:
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;
        uint8_t getMajorVersion() const;
        uint8_t getMinorVersion() const;
        void initState();
        bool matchCipherSuite(const CipherSuite& cipher) const;

    private:
        uint32_t gmt;
        CK::ByteArray random;
        CK::ByteArray sessionID;
        uint8_t majorVersion;
        uint8_t minorVersion;
        CK::ByteArray compressionMethods;

        CipherSuiteList suites;

        struct Extension {
            CK::Unsigned16 type;
            CK::ByteArray data;
        };
        typedef std::deque<Extension> ExtensionList;
        typedef ExtensionList::const_iterator ExtConstIter;

        ExtensionList extensions;

};

}

#endif // CLIENTHELLO_H_INCLUDED
