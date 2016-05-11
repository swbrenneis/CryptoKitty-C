#ifndef SERVERHELLO_H_INCLUDED
#define SERVERHELLO_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/CipherSuiteManager.h"
#include "tls/ExtensionManager.h"
#include "data/Unsigned16.h"
#include <iostream>

namespace CKTLS {

class ClientHello;

class ServerHello : public HandshakeBody {

    public:
        ServerHello();
        ~ServerHello();

    public:
#ifdef _DEBUG
        void debugOut(std::ostream& out);
#endif
        const CK::ByteArray& encode();
        CipherSuite getCipherSuite() const;
        const CK::ByteArray& getRandom() const;
        void initState();
        void initState(const ClientHello& hello);

    protected:
        void decode();

    private:
        uint32_t gmt;
        CK::ByteArray random;
        CK::ByteArray sessionID;
        uint8_t majorVersion;
        uint8_t minorVersion;
        CK::ByteArray compressionMethods;

        CipherSuiteManager suites;
        ExtensionManager extensions;

};

}

#endif // SERVERHELLO_H_INCLUDED
