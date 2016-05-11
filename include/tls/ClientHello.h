#ifndef CLIENTHELLO_H_INCLUDED
#define CLIENTHELLO_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/CipherSuiteManager.h"
#include "tls/ExtensionManager.h"
#include "data/Unsigned16.h"
#include <iostream>

namespace CKTLS {

class ClientHello : public HandshakeBody {

    public:
        ClientHello();
        ~ClientHello();
        ClientHello(const ClientHello& other);

    public:
#ifdef _DEBUG
        void debugOut(std::ostream& out);
#endif
        const CK::ByteArray& encode();
        bool getExtension(uint16_t etype, Extension& ex) const;
        uint8_t getMajorVersion() const;
        uint8_t getMinorVersion() const;
        const CK::ByteArray& getRandom() const;
        void initState();
        CipherSuite getPreferred() const;

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

#endif // CLIENTHELLO_H_INCLUDED
