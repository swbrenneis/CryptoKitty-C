#ifndef SERVERHELLO_H_INCLUDED
#define SERVERHELLO_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/CipherSuiteManager.h"
#include "data/Unsigned16.h"
#include <iostream>

namespace CKTLS {

class ClientHello;

class ServerHello : public HandshakeBody {

    public:
        ServerHello();
        ~ServerHello();

    public:
        void debugOut(std::ostream& out);
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;
        void initState();
        void initState(const ClientHello& hello);
        void setCipherSuite(const CipherSuite& cipher);

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

#endif // SERVERHELLO_H_INCLUDED
