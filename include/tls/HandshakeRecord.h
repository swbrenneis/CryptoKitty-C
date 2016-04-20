#ifndef HANDSHAKERECORD_H_INCLUDED
#define HANDSHAKERECORD_H_INCLUDED

#include "data/ByteArray.h"
#include "tls/Plaintext.h"

namespace CKTLS {

class HandshakeBody;

class HandshakeRecord : public Plaintext {

    public:
        enum HandshakeType { hello_request=0, client_hello=1,
                server_hello=2, certificate=11, server_key_exchange=12,
                certificate_request=13, server_hello_done=14,
                certificate_verify=15, client_key_exchange=16,
                finished=20 };

    public:
        HandshakeRecord();
        HandshakeRecord(HandshakeType h);
        HandshakeRecord(const HandshakeRecord& other);
        HandshakeRecord& operator= (const HandshakeRecord& other);
        ~HandshakeRecord();

    public:
        void decode();
        CK::ByteArray encode();
        HandshakeBody *getBody();
        HandshakeType getType() const;
        void setBody(HandshakeBody *hs);

    private:
        HandshakeBody *body;
        HandshakeType type;

};

}
#endif  // HANDSHAKERECORD_H_INCLUDED
