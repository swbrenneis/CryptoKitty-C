#ifndef SERVERCERTIFICATE_H_INCLUDED
#define SERVERCERTIFICATE_H_INCLUDED

#include "tls/HandshakeBody.h"
#include "tls/PGPCertificate.h"

namespace CK {
    class RSAPrivateKey;
}

namespace CKTLS {

class ServerCertificate : public HandshakeBody {

    public:
        ServerCertificate();
        ~ServerCertificate();

    private:
        ServerCertificate(const ServerCertificate& other);
        ServerCertificate& operator= (const ServerCertificate& other);

    public:
        enum OpenPGPCertDescriptorType { empty_cert=1, subkey_cert=2,
                                            subkey_cert_fingerprint=3 };

    public:
        void debugOut(std::ostream& out);
        void decode(const CK::ByteArray& encoded);
        CK::ByteArray encode() const;
        static CK::RSAPrivateKey *getRSAPrivateKey();
        static CK::RSAPublicKey *getRSAPublicKey();
        void initState();
        void setKeyID(uint64_t id);
        void setCertificate(PGPCertificate *c);
        static void setRSAPrivateKey(CK::RSAPrivateKey *pk);

    private:
        PGPCertificate *cert;
        uint64_t keyID;
        OpenPGPCertDescriptorType type;

        static CK::RSAPrivateKey *rsaPrivateKey;
        static CK::RSAPublicKey *rsaPublicKey;

};

}

#endif  // SERVERCERTIFICATE_H_INCLUDED
