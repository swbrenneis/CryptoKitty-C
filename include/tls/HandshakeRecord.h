#ifndef HANDSHAKERECORD_H_INCLUDED
#define HANDSHAKERECORD_H_INCLUDED

#include "data/ByteArray.h"
#include "tls/RecordProtocol.h"

namespace CKTLS {

class HandshakeBody;

class HandshakeRecord : public RecordProtocol {

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
        void decode(const CK::ByteArray& stream);
        CK::ByteArray encode() const;

    private:
        HandshakeType type;
        HandshakeBody *body;

};

}
#endif  // HANDSHAKERECORD_H_INCLUDED
