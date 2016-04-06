#ifndef CLIENTHELLO_H_INCLUDED
#define CLIENTHELLO_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "data/Scalar16.h"

namespace CKTLS {

class ClientHello : public HandshakeBody {

    public:
        ClientHello();
        ~ClientHello();

    public:
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;
        void initState();

    public:
        struct Cipher { uint8_t sel[2]; };

    private:
        uint32_t gmt;
        CK::ByteArray random;
        CK::ByteArray sessionID;
        uint8_t compression;
        uint8_t majorVersion;
        uint8_t minorVersion;

        typedef std::deque<Cipher> CipherSuite;
        CipherSuite ciphers;
        typedef CipherSuite::const_iterator CipherConstIter;

        struct Extension {
            CK::Scalar16 extensionType;
            CK::ByteArray extensionData;
        };
        typedef std::deque<Extension> ExtensionList;
        typedef ExtensionList::const_iterator ExtConstIter;

        ExtensionList extensions;

};

}

#endif // CLIENTHELLO_H_INCLUDED
