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

    public:
        void debugOut(std::ostream& out);
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;
        bool getExtension(uint16_t etype, Extension& ex) const;
        uint8_t getMajorVersion() const;
        uint8_t getMinorVersion() const;
        void initState();
        const CipherSuite& getPreferred() const;

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
